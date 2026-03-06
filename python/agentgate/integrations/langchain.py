"""LangChain callback-based integration for AgentGate.

Provides :class:`AgentGateMiddleware`, a ``BaseCallbackHandler`` that
intercepts tool invocations in any LangChain agent pipeline and enforces
AgentGate policies.

Usage::

    from langchain.agents import AgentExecutor
    from agentgate.integrations.langchain import AgentGateMiddleware

    middleware = AgentGateMiddleware(policy="policy.yaml", agent_id="my-agent")
    executor = AgentExecutor(agent=..., tools=..., callbacks=[middleware])
    result = executor.invoke({"input": "..."})

If ``langchain-core`` is not installed the module can still be imported,
but instantiating :class:`AgentGateMiddleware` will raise a helpful
:exc:`ImportError`.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

from agentgate.core import AgentGate, ToolCallDenied
from agentgate.policy.schema import AgentGatePolicy

logger = logging.getLogger("agentgate.integrations.langchain")

# ---------------------------------------------------------------------------
# Lazy import of langchain-core
# ---------------------------------------------------------------------------

_LANGCHAIN_AVAILABLE = True
_LANGCHAIN_IMPORT_ERROR: str | None = None

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    _LANGCHAIN_IMPORT_ERROR = (
        "langchain-core is required for the LangChain integration.  "
        "Install it with:  pip install langchain-core"
    )

    # Define a stub so the class body below can reference BaseCallbackHandler
    # even when the dependency is absent.
    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub -- replaced at runtime by langchain_core.callbacks.BaseCallbackHandler."""


# ---------------------------------------------------------------------------
# AgentGateMiddleware
# ---------------------------------------------------------------------------


class AgentGateMiddleware(BaseCallbackHandler):  # type: ignore[misc]
    """LangChain-compatible callback handler for AgentGate policy enforcement.

    This handler hooks into LangChain's callback system to intercept tool
    calls at the ``on_tool_start`` event.  If the policy denies the call,
    a :class:`~agentgate.core.ToolCallDenied` exception is raised, which
    LangChain surfaces as a tool error to the agent.

    Parameters
    ----------
    policy : str | Path | AgentGatePolicy | None
        Path to a YAML/JSON policy file, a pre-built policy object, or
        ``None`` for the built-in default.  Ignored when *gate* is
        provided.
    gate : AgentGate | None
        An existing :class:`AgentGate` instance.  When provided, *policy*
        is ignored.
    agent_id : str
        Agent identifier for policy look-ups and audit records.
    session_id : str | None
        Session identifier.  Auto-generated (UUID-4) if not supplied.

    Raises
    ------
    ImportError
        If ``langchain-core`` is not installed.
    """

    # LangChain expects this attribute for handler identification.
    name: str = "AgentGateMiddleware"

    def __init__(
        self,
        policy: str | Path | AgentGatePolicy | None = None,
        gate: AgentGate | None = None,
        agent_id: str = "default",
        session_id: str | None = None,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(_LANGCHAIN_IMPORT_ERROR)

        super().__init__()

        self._gate = gate if gate is not None else AgentGate(policy=policy)
        self._agent_id = agent_id
        self._session_id = session_id or str(uuid.uuid4())
        # Tracks in-flight tool calls: run_id -> start_time
        self._inflight: dict[str, float] = {}

    # ------------------------------------------------------------------
    # BaseCallbackHandler overrides
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Sequence[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool is about to be invoked.

        Evaluates AgentGate policy and raises :class:`ToolCallDenied` if
        the tool call is not permitted.
        """
        tool_name = serialized.get("name", serialized.get("id", ["unknown"])[-1] if isinstance(serialized.get("id"), list) else "unknown")

        # Build tool_args from the best available source.
        if inputs is not None:
            tool_args = dict(inputs)
        elif input_str:
            tool_args = {"input": input_str}
        else:
            tool_args = {}

        run_id_str = str(run_id) if run_id is not None else str(uuid.uuid4())

        # Record start time for duration tracking in on_tool_end.
        self._inflight[run_id_str] = time.perf_counter()

        # Policy check (synchronous -- LangChain callbacks are sync).
        decision, reason = self._gate._engine.check_tool_call(
            self._agent_id, tool_name, tool_args
        )

        if decision == "denied":
            self._gate._audit_event(
                agent_id=self._agent_id,
                session_id=self._session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision="denied",
                deny_reason=reason,
            )
            self._inflight.pop(run_id_str, None)
            raise ToolCallDenied(
                decision="denied",
                tool_name=tool_name,
                reason=reason or "",
            )

        # Rate-limit check.
        rate_limit = self._gate._engine.get_rate_limit(self._agent_id, tool_name)
        if rate_limit is not None:
            rl_key = f"{self._agent_id}:{tool_name}"
            allowed, rl_reason = self._gate._rate_limiter.check(
                rl_key, rate_limit.max_calls, rate_limit.window_seconds
            )
            if not allowed:
                self._gate._audit_event(
                    agent_id=self._agent_id,
                    session_id=self._session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision="rate_limited",
                    deny_reason=rl_reason,
                )
                self._inflight.pop(run_id_str, None)
                raise ToolCallDenied(
                    decision="rate_limited",
                    tool_name=tool_name,
                    reason=rl_reason or "",
                )

        logger.debug("Tool '%s' allowed for agent '%s'", tool_name, self._agent_id)

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Sequence[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called after a tool invocation completes successfully."""
        run_id_str = str(run_id) if run_id is not None else ""
        start_time = self._inflight.pop(run_id_str, None)
        duration_ms = (
            (time.perf_counter() - start_time) * 1000.0
            if start_time is not None
            else None
        )

        # Summarise result.
        result_summary = str(output)[:200] if output else None

        self._gate._audit_event(
            agent_id=self._agent_id,
            session_id=self._session_id,
            tool_name="(langchain-tool)",
            tool_args={},
            decision="allowed",
            result_summary=result_summary,
            duration_ms=duration_ms,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Sequence[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool invocation raises an exception."""
        run_id_str = str(run_id) if run_id is not None else ""
        start_time = self._inflight.pop(run_id_str, None)
        duration_ms = (
            (time.perf_counter() - start_time) * 1000.0
            if start_time is not None
            else None
        )

        # Do not double-audit ToolCallDenied errors (already recorded in
        # on_tool_start).
        if isinstance(error, ToolCallDenied):
            return

        self._gate._audit_event(
            agent_id=self._agent_id,
            session_id=self._session_id,
            tool_name="(langchain-tool)",
            tool_args={},
            decision="allowed",
            result_summary=f"ERROR: {type(error).__name__}: {error}",
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def gate(self) -> AgentGate:
        """The underlying :class:`AgentGate` instance."""
        return self._gate

    def close(self) -> None:
        """Close the underlying gate (only if this middleware created it)."""
        self._gate.close()

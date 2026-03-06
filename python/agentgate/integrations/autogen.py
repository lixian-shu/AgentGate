"""AutoGen event-based integration for AgentGate.

Provides :class:`AgentGateAutoGenAdapter`, an event adapter that
intercepts tool/function invocations in Microsoft AutoGen multi-agent
conversations and enforces AgentGate policies.

Usage::

    from autogen import AssistantAgent, UserProxyAgent
    from agentgate.integrations.autogen import AgentGateAutoGenAdapter

    adapter = AgentGateAutoGenAdapter(policy="policy.yaml")
    assistant = AssistantAgent("assistant", ...)
    user_proxy = UserProxyAgent("user_proxy", ...)

    # Register the adapter to intercept function calls.
    adapter.install(user_proxy)

    user_proxy.initiate_chat(assistant, message="...")

If ``pyautogen`` (or ``autogen``) is not installed the module can still
be imported, but instantiating :class:`AgentGateAutoGenAdapter` will
raise a helpful :exc:`ImportError`.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from agentgate.core import AgentGate, ToolCallDenied
from agentgate.integrations.base import BaseInterceptor
from agentgate.policy.schema import AgentGatePolicy

logger = logging.getLogger("agentgate.integrations.autogen")

# ---------------------------------------------------------------------------
# Lazy import of autogen
# ---------------------------------------------------------------------------

_AUTOGEN_AVAILABLE = True
_AUTOGEN_IMPORT_ERROR: str | None = None

try:
    import autogen  # noqa: F401
except ImportError:
    _AUTOGEN_AVAILABLE = False
    _AUTOGEN_IMPORT_ERROR = (
        "pyautogen is required for the AutoGen integration.  "
        "Install it with:  pip install pyautogen"
    )


# ---------------------------------------------------------------------------
# AgentGateAutoGenAdapter
# ---------------------------------------------------------------------------


class AgentGateAutoGenAdapter(BaseInterceptor):
    """AutoGen-compatible event adapter for AgentGate policy enforcement.

    This adapter wraps AutoGen's function/tool call mechanism by monkey-
    patching the ``execute_function`` method on ``ConversableAgent``
    subclasses.  When a function call is about to be executed, the
    adapter checks AgentGate policy first and denies the call if the
    policy forbids it.

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
        Default agent identifier.  When installed on an AutoGen agent,
        the agent's ``name`` attribute is used instead if available.
    session_id : str | None
        Session identifier.  Auto-generated (UUID-4) if not supplied.

    Raises
    ------
    ImportError
        If ``pyautogen`` is not installed.
    """

    def __init__(
        self,
        policy: str | Path | AgentGatePolicy | None = None,
        gate: AgentGate | None = None,
        agent_id: str = "default",
        session_id: str | None = None,
    ) -> None:
        if not _AUTOGEN_AVAILABLE:
            raise ImportError(_AUTOGEN_IMPORT_ERROR)

        resolved_gate = gate if gate is not None else AgentGate(policy=policy)
        super().__init__(resolved_gate)

        self._agent_id = agent_id
        self._session_id = session_id or str(uuid.uuid4())
        # Track original methods for uninstall.
        self._patched_agents: list[tuple[Any, Callable[..., Any]]] = []

    # ------------------------------------------------------------------
    # BaseInterceptor interface
    # ------------------------------------------------------------------

    def install(self, agent_or_framework: Any) -> None:
        """Install the interceptor on an AutoGen ``ConversableAgent``.

        This replaces the agent's ``execute_function`` method with a
        wrapped version that checks AgentGate policy before executing.

        Parameters
        ----------
        agent_or_framework :
            An AutoGen ``ConversableAgent`` (or subclass such as
            ``UserProxyAgent`` or ``AssistantAgent``).
        """
        if not hasattr(agent_or_framework, "execute_function"):
            raise TypeError(
                f"Expected an AutoGen ConversableAgent with an "
                f"'execute_function' method, got {type(agent_or_framework).__name__}"
            )

        agent = agent_or_framework
        original_execute = agent.execute_function

        # Determine agent_id from the AutoGen agent's name.
        resolved_agent_id = getattr(agent, "name", None) or self._agent_id

        def guarded_execute(func_call: dict[str, Any], **kwargs: Any) -> Any:
            """Wrapper around ConversableAgent.execute_function."""
            tool_name = func_call.get("name", "unknown")
            tool_args_raw = func_call.get("arguments", "{}")
            if isinstance(tool_args_raw, str):
                import json

                try:
                    tool_args = json.loads(tool_args_raw)
                except (json.JSONDecodeError, TypeError):
                    tool_args = {"raw": tool_args_raw}
            elif isinstance(tool_args_raw, dict):
                tool_args = tool_args_raw
            else:
                tool_args = {}

            # Policy check.
            decision, reason = self.gate._engine.check_tool_call(
                resolved_agent_id, tool_name, tool_args
            )

            if decision == "denied":
                self.gate._audit_event(
                    agent_id=resolved_agent_id,
                    session_id=self._session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision="denied",
                    deny_reason=reason,
                )
                # Return a structured error response that AutoGen can
                # relay back to the LLM, rather than crashing the
                # conversation.
                return (
                    False,
                    {
                        "name": tool_name,
                        "role": "function",
                        "content": (
                            f"AgentGate DENIED: {reason or 'policy violation'}"
                        ),
                    },
                )

            # Rate-limit check.
            rate_limit = self.gate._engine.get_rate_limit(
                resolved_agent_id, tool_name
            )
            if rate_limit is not None:
                rl_key = f"{resolved_agent_id}:{tool_name}"
                allowed, rl_reason = self.gate._rate_limiter.check(
                    rl_key, rate_limit.max_calls, rate_limit.window_seconds
                )
                if not allowed:
                    self.gate._audit_event(
                        agent_id=resolved_agent_id,
                        session_id=self._session_id,
                        tool_name=tool_name,
                        tool_args=tool_args,
                        decision="rate_limited",
                        deny_reason=rl_reason,
                    )
                    return (
                        False,
                        {
                            "name": tool_name,
                            "role": "function",
                            "content": (
                                f"AgentGate RATE LIMITED: "
                                f"{rl_reason or 'rate limit exceeded'}"
                            ),
                        },
                    )

            # Execute the original function.
            start = time.perf_counter()
            try:
                result = original_execute(func_call, **kwargs)
            except Exception as exc:
                duration_ms = (time.perf_counter() - start) * 1000.0
                self.gate._audit_event(
                    agent_id=resolved_agent_id,
                    session_id=self._session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision="allowed",
                    result_summary=f"ERROR: {type(exc).__name__}: {exc}",
                    duration_ms=duration_ms,
                )
                raise

            duration_ms = (time.perf_counter() - start) * 1000.0

            # Summarise result for audit.
            result_summary: str | None = None
            if isinstance(result, tuple) and len(result) >= 2:
                content = result[1].get("content", "") if isinstance(result[1], dict) else str(result[1])
                result_summary = str(content)[:200]
            else:
                result_summary = str(result)[:200]

            self.gate._audit_event(
                agent_id=resolved_agent_id,
                session_id=self._session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision="allowed",
                result_summary=result_summary,
                duration_ms=duration_ms,
            )

            logger.debug(
                "AutoGen tool '%s' allowed for agent '%s' (%.1fms)",
                tool_name,
                resolved_agent_id,
                duration_ms,
            )

            return result

        # Patch the agent.
        agent.execute_function = guarded_execute
        self._patched_agents.append((agent, original_execute))
        logger.info(
            "AgentGate installed on AutoGen agent '%s'", resolved_agent_id
        )

    def uninstall(self) -> None:
        """Restore original ``execute_function`` on all patched agents."""
        for agent, original_execute in self._patched_agents:
            agent.execute_function = original_execute
            agent_name = getattr(agent, "name", "unknown")
            logger.info(
                "AgentGate uninstalled from AutoGen agent '%s'", agent_name
            )
        self._patched_agents.clear()

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Uninstall from all agents and close the gate."""
        self.uninstall()
        self.gate.close()

"""CrewAI callback-based integration for AgentGate.

Provides :class:`AgentGateCrewCallback`, a callback handler that
intercepts tool invocations in CrewAI pipelines and enforces AgentGate
policies.

Usage::

    from crewai import Crew, Agent, Task
    from agentgate.integrations.crewai import AgentGateCrewCallback

    callback = AgentGateCrewCallback(policy="policy.yaml")
    crew = Crew(
        agents=[...],
        tasks=[...],
        step_callback=callback.step_callback,
    )
    result = crew.kickoff()

If ``crewai`` is not installed the module can still be imported, but
instantiating :class:`AgentGateCrewCallback` will raise a helpful
:exc:`ImportError`.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

from agentgate.core import AgentGate, ToolCallDenied
from agentgate.policy.schema import AgentGatePolicy

logger = logging.getLogger("agentgate.integrations.crewai")

# ---------------------------------------------------------------------------
# Lazy import of crewai
# ---------------------------------------------------------------------------

_CREWAI_AVAILABLE = True
_CREWAI_IMPORT_ERROR: str | None = None

try:
    import crewai  # noqa: F401
except ImportError:
    _CREWAI_AVAILABLE = False
    _CREWAI_IMPORT_ERROR = (
        "crewai is required for the CrewAI integration.  "
        "Install it with:  pip install crewai"
    )


# ---------------------------------------------------------------------------
# AgentGateCrewCallback
# ---------------------------------------------------------------------------


class AgentGateCrewCallback:
    """CrewAI-compatible callback for AgentGate policy enforcement.

    CrewAI supports ``step_callback`` on both ``Crew`` and ``Agent``
    objects.  This class provides callback methods that can be passed
    directly to those parameters.

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
        Default agent identifier.  Overridden per-call when the CrewAI
        step output includes agent information.
    session_id : str | None
        Session identifier.  Auto-generated (UUID-4) if not supplied.

    Raises
    ------
    ImportError
        If ``crewai`` is not installed.
    """

    def __init__(
        self,
        policy: str | Path | AgentGatePolicy | None = None,
        gate: AgentGate | None = None,
        agent_id: str = "default",
        session_id: str | None = None,
    ) -> None:
        if not _CREWAI_AVAILABLE:
            raise ImportError(_CREWAI_IMPORT_ERROR)

        self._gate = gate if gate is not None else AgentGate(policy=policy)
        self._agent_id = agent_id
        self._session_id = session_id or str(uuid.uuid4())

    # ------------------------------------------------------------------
    # CrewAI step_callback
    # ------------------------------------------------------------------

    def step_callback(self, step_output: Any) -> None:
        """Callback for CrewAI's ``step_callback`` parameter.

        Inspects each step's output to detect tool invocations and
        enforces AgentGate policy on them.

        Parameters
        ----------
        step_output :
            The CrewAI step output object.  Its structure depends on the
            CrewAI version, so we introspect carefully.
        """
        tool_name: str | None = None
        tool_args: dict[str, Any] = {}
        agent_id = self._agent_id

        # CrewAI's AgentFinish/AgentAction may vary by version.  We
        # inspect the object defensively.
        if hasattr(step_output, "tool"):
            tool_name = getattr(step_output, "tool", None)
            tool_input = getattr(step_output, "tool_input", None)
            if isinstance(tool_input, dict):
                tool_args = tool_input
            elif isinstance(tool_input, str):
                tool_args = {"input": tool_input}

        # Try to extract agent info.
        if hasattr(step_output, "agent") and step_output.agent is not None:
            agent_obj = step_output.agent
            agent_id = getattr(agent_obj, "role", None) or getattr(
                agent_obj, "name", self._agent_id
            )

        if tool_name is None:
            # Not a tool invocation step -- nothing to enforce.
            return

        # Policy check.
        decision, reason = self._gate._engine.check_tool_call(
            agent_id, tool_name, tool_args
        )

        if decision == "denied":
            self._gate._audit_event(
                agent_id=agent_id,
                session_id=self._session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision="denied",
                deny_reason=reason,
            )
            raise ToolCallDenied(
                decision="denied",
                tool_name=tool_name,
                reason=reason or "",
            )

        # Rate-limit check.
        rate_limit = self._gate._engine.get_rate_limit(agent_id, tool_name)
        if rate_limit is not None:
            rl_key = f"{agent_id}:{tool_name}"
            allowed, rl_reason = self._gate._rate_limiter.check(
                rl_key, rate_limit.max_calls, rate_limit.window_seconds
            )
            if not allowed:
                self._gate._audit_event(
                    agent_id=agent_id,
                    session_id=self._session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision="rate_limited",
                    deny_reason=rl_reason,
                )
                raise ToolCallDenied(
                    decision="rate_limited",
                    tool_name=tool_name,
                    reason=rl_reason or "",
                )

        # Audit the allowed call.
        self._gate._audit_event(
            agent_id=agent_id,
            session_id=self._session_id,
            tool_name=tool_name,
            tool_args=tool_args,
            decision="allowed",
        )

        logger.debug(
            "CrewAI tool '%s' allowed for agent '%s'", tool_name, agent_id
        )

    # ------------------------------------------------------------------
    # Task callback (for per-task interception)
    # ------------------------------------------------------------------

    def task_callback(self, task_output: Any) -> None:
        """Callback for CrewAI's ``task_callback`` parameter.

        This records task completion events in the audit log for
        visibility, but does not enforce tool-level policies (those are
        handled in :meth:`step_callback`).
        """
        task_desc = ""
        if hasattr(task_output, "description"):
            task_desc = str(getattr(task_output, "description", ""))[:200]
        elif hasattr(task_output, "raw"):
            task_desc = str(getattr(task_output, "raw", ""))[:200]

        self._gate._audit_event(
            agent_id=self._agent_id,
            session_id=self._session_id,
            tool_name="(crewai-task-complete)",
            tool_args={},
            decision="allowed",
            result_summary=task_desc or None,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def gate(self) -> AgentGate:
        """The underlying :class:`AgentGate` instance."""
        return self._gate

    def close(self) -> None:
        """Close the underlying gate."""
        self._gate.close()

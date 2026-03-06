"""Central orchestration engine for AgentGate.

All framework adapters (LangChain, CrewAI, AutoGen, generic decorator, etc.)
funnel through the single :class:`AgentGate` instance which coordinates
policy evaluation, audit collection, and anomaly detection.

Typical usage::

    from agentgate.core import AgentGate

    gate = AgentGate(policy="policy.yaml")
    result = await gate.intercept_tool_call(
        agent_id="assistant",
        session_id="sess-1",
        tool_name="read_file",
        tool_args={"path": "/tmp/data.txt"},
        execute_fn=actual_tool_function,
    )
    gate.close()
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from agentgate.audit.collector import AuditCollector
from agentgate.audit.models import AuditEvent
from agentgate.audit.store import AuditStore
from agentgate.policy.defaults import DEFAULT_POLICY
from agentgate.policy.schema import (
    AgentGatePolicy,
    AgentPolicy,
    ArgConstraint,
    RateLimit,
    ToolPermission,
)

logger = logging.getLogger("agentgate")

# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass
class AgentContext:
    """Contextual information about the agent making a tool call.

    Passed through the interception pipeline and available to audit
    collectors and anomaly detectors.
    """

    agent_id: str
    session_id: str
    role: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolCallDenied(Exception):
    """Raised when a tool call is denied by policy.

    Attributes
    ----------
    decision : str
        The policy decision (``"denied"`` or ``"rate_limited"``).
    tool_name : str
        The name of the tool that was denied.
    reason : str
        Human-readable explanation of why the call was denied.
    """

    def __init__(self, decision: str, tool_name: str, reason: str) -> None:
        self.decision = decision
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Tool '{tool_name}' {decision}: {reason}")


# ---------------------------------------------------------------------------
# Internal: Pure-Python policy engine (fallback when Rust core unavailable)
# ---------------------------------------------------------------------------


class _PolicyEngine:
    """Lightweight, pure-Python policy evaluation engine.

    Implements deny-first semantics identical to the Rust
    ``PolicyMatcher``, but without compiled pattern caching.
    When the Rust native extension (``agentgate._core.PolicyMatcher``)
    is available it should be preferred for production workloads.
    """

    def __init__(self, policy: AgentGatePolicy) -> None:
        self._policy = policy

    # -- Public API --------------------------------------------------------

    def get_agent_policy(self, agent_id: str) -> AgentPolicy | None:
        """Look up policy for *agent_id*, falling back to ``__default__``."""
        if agent_id in self._policy.agents:
            return self._policy.agents[agent_id]
        return self._policy.agents.get("__default__")

    def check_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[str, str | None]:
        """Evaluate policy for a tool call.

        Returns
        -------
        (decision, reason)
            *decision* is one of ``"allowed"``, ``"denied"``.
            *reason* is ``None`` when allowed, otherwise a human-readable
            explanation.
        """
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None:
            return ("denied", f"No policy found for agent '{agent_id}'")

        tools = agent_policy.tools
        if tools is None:
            # No tool policy defined -- default deny.
            return ("denied", f"No tools policy defined for agent '{agent_id}'")

        # Step 1: Check deny list (deny-first).
        for denied in tools.denied:
            if fnmatch.fnmatch(tool_name, denied.name):
                reason = denied.reason or f"Tool '{tool_name}' is explicitly denied"
                return ("denied", reason)

        # Step 2: Check allow list.
        for allowed in tools.allowed:
            if fnmatch.fnmatch(tool_name, allowed.name):
                # Validate argument constraints if present.
                if allowed.args:
                    violation = self._validate_args(tool_args, allowed.args)
                    if violation is not None:
                        return ("denied", violation)
                return ("allowed", None)

        # Step 3: Default deny (no matching allow rule).
        return ("denied", f"No matching allow rule for tool '{tool_name}'")

    def get_rate_limit(
        self, agent_id: str, tool_name: str
    ) -> RateLimit | None:
        """Return the rate-limit config for *tool_name* under *agent_id*, if any."""
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None or agent_policy.tools is None:
            return None
        for perm in agent_policy.tools.allowed:
            if fnmatch.fnmatch(tool_name, perm.name):
                return perm.rate_limit
        return None

    # -- Argument validation -----------------------------------------------

    @staticmethod
    def _validate_args(
        tool_args: dict[str, Any],
        constraints: dict[str, ArgConstraint],
    ) -> str | None:
        """Check *tool_args* against *constraints*.

        Returns ``None`` if all constraints pass, otherwise a description
        of the first violation.
        """
        for arg_name, constraint in constraints.items():
            value = tool_args.get(arg_name)
            if value is None:
                continue  # Missing args are not validated (tools may be optional)

            if constraint.enum is not None and value not in constraint.enum:
                return (
                    f"Argument '{arg_name}' value {value!r} not in allowed values "
                    f"{constraint.enum}"
                )

            if isinstance(value, str):
                if constraint.max_length is not None and len(value) > constraint.max_length:
                    return (
                        f"Argument '{arg_name}' length {len(value)} exceeds "
                        f"max_length {constraint.max_length}"
                    )
                if constraint.pattern is not None and not re.search(
                    constraint.pattern, value
                ):
                    return (
                        f"Argument '{arg_name}' value {value!r} does not match "
                        f"pattern '{constraint.pattern}'"
                    )

            if isinstance(value, (int, float)):
                if constraint.min is not None and value < constraint.min:
                    return (
                        f"Argument '{arg_name}' value {value} is below "
                        f"minimum {constraint.min}"
                    )
                if constraint.max is not None and value > constraint.max:
                    return (
                        f"Argument '{arg_name}' value {value} exceeds "
                        f"maximum {constraint.max}"
                    )

        return None


# ---------------------------------------------------------------------------
# Internal: Rate limiter (sliding window)
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Thread-safe, in-memory sliding-window rate limiter."""

    def __init__(self) -> None:
        # key -> list of timestamps (epoch seconds)
        self._windows: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(
        self,
        key: str,
        max_calls: int,
        window_seconds: int,
    ) -> tuple[bool, str | None]:
        """Return ``(allowed, reason)`` for the given rate-limit key.

        If allowed, the call is recorded in the window.  If denied,
        *reason* describes the limit.
        """
        now = time.monotonic()
        with self._lock:
            timestamps = self._windows.setdefault(key, [])
            cutoff = now - window_seconds
            # Prune old entries.
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= max_calls:
                return (
                    False,
                    f"Rate limit exceeded: {max_calls} calls per "
                    f"{window_seconds}s (key={key})",
                )
            timestamps.append(now)
            return (True, None)


# ---------------------------------------------------------------------------
# Internal: Session tracker
# ---------------------------------------------------------------------------


class _SessionTracker:
    """Tracks per-session call counts and start times for limit enforcement."""

    def __init__(self) -> None:
        # session_id -> {"call_count": int, "started_at": float}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def check_and_increment(
        self,
        session_id: str,
        max_calls: int | None,
        max_duration_seconds: int | None,
    ) -> tuple[bool, str | None]:
        """Check session limits and increment the call counter.

        Returns ``(allowed, reason)``.
        """
        now = time.monotonic()
        with self._lock:
            session = self._sessions.setdefault(
                session_id,
                {"call_count": 0, "started_at": now},
            )

            # Duration check.
            if max_duration_seconds is not None:
                elapsed = now - session["started_at"]
                if elapsed > max_duration_seconds:
                    return (
                        False,
                        f"Session duration {elapsed:.0f}s exceeds limit "
                        f"of {max_duration_seconds}s",
                    )

            # Call count check.
            if max_calls is not None and session["call_count"] >= max_calls:
                return (
                    False,
                    f"Session call count {session['call_count']} reached "
                    f"limit of {max_calls}",
                )

            session["call_count"] += 1
            return (True, None)


# ---------------------------------------------------------------------------
# Internal: Simple anomaly detector
# ---------------------------------------------------------------------------


class _AnomalyDetector:
    """Lightweight anomaly detection based on call-frequency heuristics.

    This is a deliberately simple implementation that flags obvious
    anomalies (burst activity, unusual tool diversity) without requiring
    ML models.  It is intended as a baseline that can be swapped out for
    more sophisticated detectors.
    """

    _SENSITIVITY_THRESHOLDS = {
        "low": {"burst_window": 5.0, "burst_count": 50, "base_score": 0.3},
        "medium": {"burst_window": 5.0, "burst_count": 20, "base_score": 0.5},
        "high": {"burst_window": 5.0, "burst_count": 10, "base_score": 0.7},
    }

    def __init__(self, sensitivity: str = "medium") -> None:
        self._sensitivity = sensitivity
        self._thresholds = self._SENSITIVITY_THRESHOLDS.get(
            sensitivity, self._SENSITIVITY_THRESHOLDS["medium"]
        )
        # agent_id -> list of (timestamp, tool_name)
        self._history: dict[str, list[tuple[float, str]]] = {}
        self._lock = threading.Lock()

    def analyze(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        duration_ms: float | None = None,
    ) -> tuple[float, list[str]]:
        """Analyze a tool call for anomalies.

        Returns
        -------
        (score, flags)
            *score* in ``[0.0, 1.0]`` and *flags* is a list of
            human-readable anomaly descriptions.
        """
        now = time.monotonic()
        flags: list[str] = []
        score = 0.0

        burst_window = self._thresholds["burst_window"]
        burst_count = self._thresholds["burst_count"]
        base_score = self._thresholds["base_score"]

        with self._lock:
            history = self._history.setdefault(agent_id, [])
            history.append((now, tool_name))

            # Prune entries older than 60 seconds.
            cutoff = now - 60.0
            history[:] = [(t, n) for t, n in history if t > cutoff]

            # Burst detection: too many calls in a short window.
            recent = [t for t, _ in history if t > now - burst_window]
            if len(recent) > burst_count:
                score = max(score, base_score)
                flags.append(
                    f"burst_activity: {len(recent)} calls in "
                    f"{burst_window:.0f}s (threshold={burst_count})"
                )

            # Tool diversity: many distinct tools in 60s may indicate
            # automated scanning.
            distinct_tools = {n for _, n in history}
            diversity_threshold = burst_count * 2
            if len(distinct_tools) > diversity_threshold:
                score = max(score, base_score * 0.8)
                flags.append(
                    f"high_tool_diversity: {len(distinct_tools)} distinct "
                    f"tools in 60s (threshold={diversity_threshold})"
                )

        # Unusually fast execution may indicate cached/mocked results.
        if duration_ms is not None and duration_ms < 0.1 and score > 0:
            score = min(score + 0.1, 1.0)
            flags.append("suspiciously_fast_execution")

        return (round(score, 4), flags)


# ---------------------------------------------------------------------------
# AgentGate -- the public orchestration engine
# ---------------------------------------------------------------------------


class AgentGate:
    """Central security engine for AI agent protection.

    Coordinates policy evaluation, rate limiting, session tracking, audit
    collection, and anomaly detection.  All framework integrations
    (LangChain, CrewAI, AutoGen, generic decorator) funnel through this
    class.

    Parameters
    ----------
    policy : AgentGatePolicy | str | Path | None
        A fully-constructed policy object, a file path to a YAML/JSON
        policy document, or ``None`` to use the built-in default policy.
    audit_db : str | Path
        Path to the SQLite audit database.  Use ``":memory:"`` for an
        in-memory store (useful in tests).
    enable_anomaly : bool
        Whether to enable the anomaly detection subsystem.
    """

    def __init__(
        self,
        policy: AgentGatePolicy | str | Path | None = None,
        audit_db: str | Path = "agentgate_audit.db",
        enable_anomaly: bool = True,
    ) -> None:
        # -- Load policy ---------------------------------------------------
        self._policy = self._resolve_policy(policy)

        # -- Policy engine -------------------------------------------------
        self._engine = _PolicyEngine(self._policy)

        # -- Rate limiter and session tracker ------------------------------
        self._rate_limiter = _RateLimiter()
        self._session_tracker = _SessionTracker()

        # -- Audit subsystem -----------------------------------------------
        self._audit_store: AuditStore | None = None
        self._audit_collector: AuditCollector | None = None
        self._signer: Any = None

        if self._policy.audit.enabled:
            self._audit_store = AuditStore(db_path=audit_db)

            # Try to initialise Rust signer if signing is requested.
            if self._policy.audit.sign_records:
                self._signer = self._try_init_signer()

            self._audit_collector = AuditCollector(
                store=self._audit_store,
                signer=self._signer,
            )

        # -- Anomaly detection ---------------------------------------------
        self._anomaly_detector: _AnomalyDetector | None = None
        if enable_anomaly and self._policy.anomaly.enabled:
            self._anomaly_detector = _AnomalyDetector(
                sensitivity=self._policy.anomaly.sensitivity,
            )

        logger.info(
            "AgentGate initialised (agents=%d, audit=%s, anomaly=%s)",
            len(self._policy.agents),
            "on" if self._policy.audit.enabled else "off",
            "on" if self._anomaly_detector is not None else "off",
        )

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def policy(self) -> AgentGatePolicy:
        """The active policy document."""
        return self._policy

    # ------------------------------------------------------------------
    # Core interception (async)
    # ------------------------------------------------------------------

    async def intercept_tool_call(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        execute_fn: Callable[..., Any],
    ) -> Any:
        """Core interception method.  All framework adapters call this.

        Parameters
        ----------
        agent_id :
            Identifier of the agent initiating the call.
        session_id :
            Current session identifier.
        tool_name :
            Name of the tool being invoked.
        tool_args :
            Arguments to pass to the tool.
        execute_fn :
            The actual tool function.  Will be called with ``**tool_args``
            if the policy allows the call.

        Returns
        -------
        Any
            The return value of *execute_fn*.

        Raises
        ------
        ToolCallDenied
            If the policy denies the call.
        """
        # Step 1: Policy check.
        decision, reason = self._engine.check_tool_call(
            agent_id, tool_name, tool_args
        )

        if decision == "denied":
            self._audit_event(
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision="denied",
                deny_reason=reason,
            )
            raise ToolCallDenied(decision="denied", tool_name=tool_name, reason=reason or "")

        # Step 2: Rate-limit check.
        rate_limit = self._engine.get_rate_limit(agent_id, tool_name)
        if rate_limit is not None:
            rl_key = f"{agent_id}:{tool_name}"
            allowed, rl_reason = self._rate_limiter.check(
                rl_key, rate_limit.max_calls, rate_limit.window_seconds
            )
            if not allowed:
                self._audit_event(
                    agent_id=agent_id,
                    session_id=session_id,
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

        # Step 3: Session limits.
        agent_policy = self._engine.get_agent_policy(agent_id)
        if agent_policy is not None and agent_policy.limits is not None:
            sess_allowed, sess_reason = self._session_tracker.check_and_increment(
                session_id,
                max_calls=agent_policy.limits.max_tool_calls_per_session,
                max_duration_seconds=agent_policy.limits.max_session_duration_seconds,
            )
            if not sess_allowed:
                self._audit_event(
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision="denied",
                    deny_reason=sess_reason,
                )
                raise ToolCallDenied(
                    decision="denied",
                    tool_name=tool_name,
                    reason=sess_reason or "",
                )
        else:
            # Still track session even without limits.
            self._session_tracker.check_and_increment(session_id, None, None)

        # Step 4: Execute the tool function.
        start = time.perf_counter()
        try:
            if asyncio.iscoroutinefunction(execute_fn):
                result = await execute_fn(**tool_args)
            else:
                result = execute_fn(**tool_args)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            self._audit_event(
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                tool_args=tool_args,
                decision="allowed",
                result_summary=f"ERROR: {type(exc).__name__}: {exc}",
                duration_ms=duration_ms,
            )
            raise

        duration_ms = (time.perf_counter() - start) * 1000.0

        # Step 5: Summarise result for audit.
        result_summary = self._summarise_result(result)

        # Step 6: Anomaly detection.
        anomaly_score = 0.0
        anomaly_flags: list[str] = []
        if self._anomaly_detector is not None:
            anomaly_score, anomaly_flags = self._anomaly_detector.analyze(
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                duration_ms=duration_ms,
            )

        # Step 7: Audit the successful call.
        self._audit_event(
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            tool_args=tool_args,
            decision="allowed",
            result_summary=result_summary,
            duration_ms=duration_ms,
            anomaly_score=anomaly_score,
            anomaly_flags=anomaly_flags,
        )

        return result

    # ------------------------------------------------------------------
    # Core interception (sync)
    # ------------------------------------------------------------------

    def intercept_tool_call_sync(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        execute_fn: Callable[..., Any],
    ) -> Any:
        """Synchronous version of :meth:`intercept_tool_call`.

        If a running event loop is detected, the async method is
        scheduled on it.  Otherwise a new loop is created.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # We are inside an already-running event loop (e.g. Jupyter).
            # Use a background thread to avoid deadlock.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.intercept_tool_call(
                        agent_id=agent_id,
                        session_id=session_id,
                        tool_name=tool_name,
                        tool_args=tool_args,
                        execute_fn=execute_fn,
                    ),
                )
                return future.result()
        else:
            return asyncio.run(
                self.intercept_tool_call(
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    execute_fn=execute_fn,
                )
            )

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def get_audit_summary(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Return an aggregate audit summary for the given time window.

        Parameters
        ----------
        agent_id :
            Filter by agent (optional).
        session_id :
            Filter by session (optional).
        hours :
            Look-back window in hours (default 24).

        Returns
        -------
        dict
            Summary statistics from the audit store.  Returns an empty
            dict if auditing is disabled.
        """
        if self._audit_store is None:
            return {}
        return self._audit_store.get_summary(
            agent_id=agent_id,
            session_id=session_id,
            hours=hours,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release all resources held by this AgentGate instance."""
        if self._audit_store is not None:
            self._audit_store.close()
            self._audit_store = None
        self._audit_collector = None
        self._anomaly_detector = None
        logger.info("AgentGate closed")

    def __enter__(self) -> "AgentGate":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_policy(
        policy: AgentGatePolicy | str | Path | None,
    ) -> AgentGatePolicy:
        """Resolve *policy* into a validated ``AgentGatePolicy`` object."""
        if policy is None:
            return AgentGatePolicy.model_validate(DEFAULT_POLICY)

        if isinstance(policy, AgentGatePolicy):
            return policy

        if isinstance(policy, dict):
            return AgentGatePolicy.model_validate(policy)

        # Assume it is a file path.
        path = Path(policy)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        elif path.suffix == ".json":
            data = json.loads(text)
        else:
            # Try YAML first, fall back to JSON.
            try:
                data = yaml.safe_load(text)
            except Exception:
                data = json.loads(text)

        return AgentGatePolicy.model_validate(data)

    @staticmethod
    def _try_init_signer() -> Any:
        """Attempt to import and instantiate the Rust AuditSigner.

        Returns ``None`` if the native extension is not available.
        """
        try:
            from agentgate._core import AuditSigner  # type: ignore[import-not-found]

            signer = AuditSigner()
            logger.debug("Rust AuditSigner initialised (pk=%s)", signer.public_key_hex())
            return signer
        except ImportError:
            logger.debug(
                "Rust extension (agentgate._core) not available; "
                "audit signing disabled"
            )
            return None

    def _audit_event(
        self,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        decision: str,
        deny_reason: str | None = None,
        result_summary: str | None = None,
        duration_ms: float | None = None,
        anomaly_score: float = 0.0,
        anomaly_flags: list[str] | None = None,
    ) -> AuditEvent | None:
        """Record an audit event if auditing is enabled."""
        if self._audit_collector is None:
            return None
        try:
            return self._audit_collector.collect(
                agent_id=agent_id,
                session_id=session_id,
                action_type="tool_call",
                tool_name=tool_name,
                tool_args=tool_args,
                decision=decision,
                deny_reason=deny_reason,
                result_summary=result_summary,
                duration_ms=duration_ms,
                anomaly_score=anomaly_score,
                anomaly_flags=anomaly_flags or [],
            )
        except Exception:
            logger.exception("Failed to record audit event")
            return None

    @staticmethod
    def _summarise_result(result: Any, max_length: int = 200) -> str:
        """Create a brief, audit-safe summary of a tool's return value."""
        if result is None:
            return "None"
        try:
            text = repr(result)
        except Exception:
            text = f"<{type(result).__name__}>"
        if len(text) > max_length:
            text = text[: max_length - 3] + "..."
        return text

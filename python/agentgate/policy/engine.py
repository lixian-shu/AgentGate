"""Policy evaluation engine for AgentGate.

This module implements the core policy decision logic:

* **Deny-first tool-call evaluation** -- deny rules are checked before allow
  rules.  If no allow rule matches, the default is to deny.
* **Argument constraint validation** -- regex patterns, enum checks, numeric
  bounds, and string-length limits on tool arguments.
* **Sliding-window rate limiting** -- per-(agent, tool) call-rate enforcement
  using in-memory timestamp deques.
* **Session-level limits** -- max tool calls and max session duration.

When the optional Rust extension (``agentgate._core.PolicyMatcher``) is
available it is used for tool-call matching, providing significantly faster
evaluation.  The engine falls back transparently to a pure-Python
implementation when the extension is not installed.

Typical usage::

    from agentgate.policy.loader import load_policy
    from agentgate.policy.engine import PolicyEngine

    policy = load_policy("policy.yaml")
    engine = PolicyEngine(policy)

    decision = engine.check_tool_call("code-agent", "file_read", {"path": "/tmp/x"})
    if decision.decision != "allowed":
        print(f"Blocked: {decision.reason}")
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from agentgate.policy.schema import (
    AgentGatePolicy,
    AgentPolicy,
    ArgConstraint,
    RateLimit,
    ToolPermission,
    ToolsPolicy,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PolicyDecision
# ---------------------------------------------------------------------------

# Sentinel used by the fallback name list so we only look it up once.
_FALLBACK_AGENT_NAMES: tuple[str, ...] = ("default", "__default__")


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The outcome of a policy evaluation.

    Attributes
    ----------
    decision:
        One of ``"allowed"``, ``"denied"``, or ``"rate_limited"``.
    reason:
        Human-readable explanation (empty string when allowed).
    matched_rule:
        Identifier of the rule that produced this decision (for audit
        trails).  May be empty when no specific rule matched.
    """

    decision: Literal["allowed", "denied", "rate_limited"]
    reason: str = ""
    matched_rule: str = ""

    # Convenience helpers -----------------------------------------------------

    @property
    def is_allowed(self) -> bool:
        return self.decision == "allowed"

    @property
    def is_denied(self) -> bool:
        return self.decision == "denied"

    @property
    def is_rate_limited(self) -> bool:
        return self.decision == "rate_limited"


# Pre-built singletons for the most common outcomes.
_ALLOWED = PolicyDecision(decision="allowed")


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Evaluate tool calls, rate limits, and session limits against a policy.

    Parameters
    ----------
    policy:
        A validated :class:`~agentgate.policy.schema.AgentGatePolicy`.
    """

    def __init__(self, policy: AgentGatePolicy) -> None:
        self._policy = policy

        # Rust acceleration (optional).
        self._rust_matcher: Any | None = None
        self._rust_available: bool = False
        self._try_init_rust()

        # Rate-limit state: (agent_id, tool_name) -> deque of timestamps.
        self._rate_counters: dict[tuple[str, str], deque[float]] = {}

        # Pre-compile regex patterns referenced in arg constraints so we
        # pay the compilation cost once rather than on every check.
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}

    # ------------------------------------------------------------------
    # Rust integration
    # ------------------------------------------------------------------

    def _try_init_rust(self) -> None:
        """Attempt to load the Rust extension and compile all policies."""
        try:
            from agentgate._core import PolicyMatcher  # type: ignore[import-untyped]

            self._rust_matcher = PolicyMatcher()
            self._compile_rust_policies()
            self._rust_available = True
            logger.debug("Rust PolicyMatcher initialised successfully")
        except ImportError:
            logger.debug(
                "Rust extension (agentgate._core) not available; "
                "using pure-Python policy engine"
            )
            self._rust_available = False
        except Exception:
            logger.warning(
                "Rust PolicyMatcher failed to initialise; "
                "falling back to pure-Python engine",
                exc_info=True,
            )
            self._rust_matcher = None
            self._rust_available = False

    def _compile_rust_policies(self) -> None:
        """Compile all agent policies into the Rust matcher.

        Each agent's denied and allowed tool rules are serialised as JSON
        arrays of ``ToolRuleRaw`` objects compatible with the Rust
        ``PolicyMatcher.compile_policy`` API.
        """
        if self._rust_matcher is None:
            return

        for agent_id, agent_policy in self._policy.agents.items():
            if agent_policy.tools is None:
                continue

            deny_rules = self._tool_permissions_to_rust_rules(
                agent_policy.tools.denied, is_deny=True
            )
            allow_rules = self._tool_permissions_to_rust_rules(
                agent_policy.tools.allowed, is_deny=False
            )

            try:
                self._rust_matcher.compile_policy(
                    agent_id,
                    json.dumps(deny_rules),
                    json.dumps(allow_rules),
                )
            except Exception:
                logger.warning(
                    "Failed to compile Rust policy for agent '%s'; "
                    "this agent will use Python fallback",
                    agent_id,
                    exc_info=True,
                )

    @staticmethod
    def _tool_permissions_to_rust_rules(
        permissions: list[ToolPermission],
        *,
        is_deny: bool,
    ) -> list[dict[str, Any]]:
        """Convert Pydantic ToolPermission objects to Rust-compatible dicts."""
        rules: list[dict[str, Any]] = []
        for perm in permissions:
            rule: dict[str, Any] = {
                "tool_pattern": perm.name,
                "is_deny": is_deny,
                "arg_constraints": [],
            }
            if is_deny and perm.reason:
                rule["deny_reason"] = perm.reason

            if perm.args:
                for arg_name, constraint in perm.args.items():
                    ac: dict[str, Any] = {"key": arg_name}
                    if constraint.pattern is not None:
                        ac["pattern"] = constraint.pattern
                    if constraint.max_length is not None:
                        ac["max_length"] = constraint.max_length
                    if constraint.enum is not None:
                        ac["allowed_values"] = [str(v) for v in constraint.enum]
                    if constraint.min is not None:
                        ac["min"] = float(constraint.min)
                    if constraint.max is not None:
                        ac["max"] = float(constraint.max)
                    rule["arg_constraints"].append(ac)

            rules.append(rule)
        return rules

    # ------------------------------------------------------------------
    # Tool-call checking (public entry point)
    # ------------------------------------------------------------------

    def check_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> PolicyDecision:
        """Evaluate whether a tool call is permitted by the policy.

        The evaluation order is:

        1. Resolve the effective agent policy (specific agent, then
           ``"default"`` / ``"__default__"`` fallback).
        2. **Deny rules first** -- if any deny pattern matches the tool
           name, the call is immediately denied.
        3. **Allow rules second** -- the first matching allow rule is used
           to validate argument constraints.
        4. If no allow rule matches, the call is denied by default.

        Parameters
        ----------
        agent_id:
            Identifier of the calling agent.
        tool_name:
            The tool being invoked.
        tool_args:
            Dictionary of arguments being passed to the tool.

        Returns
        -------
        PolicyDecision
        """
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None:
            return PolicyDecision(
                decision="denied",
                reason=f"No policy defined for agent '{agent_id}' and no default policy exists",
            )

        if agent_policy.tools is None:
            return PolicyDecision(
                decision="denied",
                reason=f"Agent '{agent_id}' has no tool rules; all calls denied by default",
            )

        # Determine the effective agent_id for Rust look-up (may be a
        # fallback name).
        effective_id = self._resolve_agent_id(agent_id)

        # Try Rust path first.
        if self._rust_available and self._rust_matcher is not None:
            if self._rust_matcher.has_policy(effective_id):
                return self._check_tool_call_rust(
                    effective_id, tool_name, tool_args
                )

        # Pure-Python fallback.
        return self._check_tool_call_python(agent_id, tool_name, tool_args)

    def _check_tool_call_rust(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> PolicyDecision:
        """Delegate tool-call checking to the Rust PolicyMatcher."""
        args_json = json.dumps(tool_args)
        result = self._rust_matcher.check_tool_call(agent_id, tool_name, args_json)

        decision_label: str = result["decision"]
        reason: str = result["reason"] or ""

        if decision_label == "allowed":
            return _ALLOWED
        elif decision_label == "rate_limited":
            return PolicyDecision(
                decision="rate_limited",
                reason=reason,
                matched_rule=f"rust:{agent_id}",
            )
        else:
            return PolicyDecision(
                decision="denied",
                reason=reason,
                matched_rule=f"rust:{agent_id}",
            )

    def _check_tool_call_python(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> PolicyDecision:
        """Pure-Python deny-first policy evaluation.

        Parameters
        ----------
        agent_id:
            Identifier of the calling agent.
        tool_name:
            The tool being invoked.
        tool_args:
            Dictionary of arguments being passed to the tool.

        Returns
        -------
        PolicyDecision
        """
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None or agent_policy.tools is None:
            return PolicyDecision(
                decision="denied",
                reason=f"No tool rules for agent '{agent_id}'",
            )

        tools = agent_policy.tools

        # ---- Step 1: Deny rules (evaluated first) -------------------------
        for perm in tools.denied:
            if self._tool_name_matches(perm.name, tool_name):
                reason = perm.reason or f"Tool '{tool_name}' is explicitly denied"
                return PolicyDecision(
                    decision="denied",
                    reason=reason,
                    matched_rule=f"deny:{perm.name}",
                )

        # ---- Step 2: Allow rules ------------------------------------------
        for perm in tools.allowed:
            if self._tool_name_matches(perm.name, tool_name):
                # Tool name matches -- now validate argument constraints.
                violation = self._validate_args(perm, tool_args)
                if violation is not None:
                    return PolicyDecision(
                        decision="denied",
                        reason=violation,
                        matched_rule=f"allow:{perm.name}:arg_violation",
                    )
                return PolicyDecision(
                    decision="allowed",
                    matched_rule=f"allow:{perm.name}",
                )

        # ---- Step 3: Default deny -----------------------------------------
        return PolicyDecision(
            decision="denied",
            reason=f"No matching allow rule for tool '{tool_name}'",
        )

    # ------------------------------------------------------------------
    # Rate-limit checking
    # ------------------------------------------------------------------

    def check_rate_limit(
        self,
        agent_id: str,
        tool_name: str,
    ) -> PolicyDecision:
        """Check whether a tool call exceeds its configured rate limit.

        Uses a sliding-window algorithm: timestamps of previous calls are
        stored in an in-memory deque, and expired entries are evicted on
        each check.  If the call is within the limit, the current
        timestamp is recorded.

        Parameters
        ----------
        agent_id:
            Identifier of the calling agent.
        tool_name:
            The tool being invoked.

        Returns
        -------
        PolicyDecision
            ``"allowed"`` if under the limit, ``"rate_limited"`` otherwise.
        """
        rate_limit = self._get_rate_limit(agent_id, tool_name)
        if rate_limit is None:
            return _ALLOWED

        now = time.monotonic()
        key = (agent_id, tool_name)
        window = rate_limit.window_seconds

        # Lazily create deque for this (agent, tool) pair.
        timestamps = self._rate_counters.get(key)
        if timestamps is None:
            timestamps = deque()
            self._rate_counters[key] = timestamps

        # Evict timestamps outside the current window.
        cutoff = now - window
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= rate_limit.max_calls:
            oldest = timestamps[0]
            retry_after = window - (now - oldest)
            return PolicyDecision(
                decision="rate_limited",
                reason=(
                    f"Rate limit exceeded for tool '{tool_name}': "
                    f"{rate_limit.max_calls} calls per {window}s window. "
                    f"Retry after {retry_after:.1f}s."
                ),
                matched_rule=f"rate_limit:{agent_id}:{tool_name}",
            )

        # Record this call.
        timestamps.append(now)
        return _ALLOWED

    # ------------------------------------------------------------------
    # Session-limit checking
    # ------------------------------------------------------------------

    def check_session_limits(
        self,
        agent_id: str,
        session_id: str,
        call_count: int,
        session_start: datetime,
    ) -> PolicyDecision:
        """Check session-level limits for an agent.

        Parameters
        ----------
        agent_id:
            Identifier of the calling agent.
        session_id:
            Unique identifier for the current session (used in the
            decision reason for traceability).
        call_count:
            Total number of tool calls made so far in this session.
        session_start:
            The UTC datetime when the session began.

        Returns
        -------
        PolicyDecision
        """
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None or agent_policy.limits is None:
            return _ALLOWED

        limits = agent_policy.limits

        # ---- Max tool calls per session ------------------------------------
        if limits.max_tool_calls_per_session is not None:
            if call_count >= limits.max_tool_calls_per_session:
                return PolicyDecision(
                    decision="denied",
                    reason=(
                        f"Session '{session_id}' for agent '{agent_id}' has "
                        f"reached the maximum of "
                        f"{limits.max_tool_calls_per_session} tool calls"
                    ),
                    matched_rule=f"session_limit:max_tool_calls:{agent_id}",
                )

        # ---- Max session duration ------------------------------------------
        if limits.max_session_duration_seconds is not None:
            now = datetime.now(timezone.utc)
            # Handle both naive and aware datetimes
            if session_start.tzinfo is None:
                session_start = session_start.replace(tzinfo=timezone.utc)
            elapsed = (now - session_start).total_seconds()
            if elapsed >= limits.max_session_duration_seconds:
                return PolicyDecision(
                    decision="denied",
                    reason=(
                        f"Session '{session_id}' for agent '{agent_id}' has "
                        f"exceeded the maximum duration of "
                        f"{limits.max_session_duration_seconds}s "
                        f"(elapsed: {elapsed:.0f}s)"
                    ),
                    matched_rule=f"session_limit:max_duration:{agent_id}",
                )

        return _ALLOWED

    # ------------------------------------------------------------------
    # Agent policy resolution
    # ------------------------------------------------------------------

    def get_agent_policy(self, agent_id: str) -> AgentPolicy | None:
        """Resolve the effective policy for an agent.

        Look-up order:

        1. Exact match on *agent_id*.
        2. Fallback to ``"default"`` agent.
        3. Fallback to ``"__default__"`` agent.
        4. Return ``None`` if no policy is found.

        Parameters
        ----------
        agent_id:
            The agent identifier to look up.

        Returns
        -------
        AgentPolicy or None
        """
        # Direct match.
        policy = self._policy.agents.get(agent_id)
        if policy is not None:
            return policy

        # Fallback names.
        for fallback in _FALLBACK_AGENT_NAMES:
            policy = self._policy.agents.get(fallback)
            if policy is not None:
                return policy

        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_agent_id(self, agent_id: str) -> str:
        """Return the actual key in the agents dict for *agent_id*.

        This mirrors the fallback logic of :meth:`get_agent_policy` but
        returns the key string rather than the policy object.
        """
        if agent_id in self._policy.agents:
            return agent_id

        for fallback in _FALLBACK_AGENT_NAMES:
            if fallback in self._policy.agents:
                return fallback

        return agent_id

    @staticmethod
    def _tool_name_matches(pattern: str, tool_name: str) -> bool:
        """Check if *tool_name* matches a glob *pattern* using fnmatch."""
        return fnmatch.fnmatchcase(tool_name, pattern)

    def _validate_args(
        self,
        perm: ToolPermission,
        tool_args: dict[str, Any],
    ) -> str | None:
        """Validate tool arguments against a permission's arg constraints.

        Returns
        -------
        str or None
            An error message if validation fails, ``None`` if all
            constraints pass.
        """
        if not perm.args:
            return None

        for arg_name, constraint in perm.args.items():
            value = tool_args.get(arg_name)

            if value is None:
                # If there are actual constraints defined, a missing arg
                # is a violation.
                if _has_active_constraints(constraint):
                    return f"Required argument '{arg_name}' is missing"
                continue

            error = self._validate_single_arg(arg_name, value, constraint)
            if error is not None:
                return error

        return None

    def _validate_single_arg(
        self,
        arg_name: str,
        value: Any,
        constraint: ArgConstraint,
    ) -> str | None:
        """Validate a single argument value against its constraint."""
        str_value = str(value) if not isinstance(value, str) else value

        # --- max_length ------------------------------------------------------
        if constraint.max_length is not None:
            if len(str_value) > constraint.max_length:
                return (
                    f"Argument '{arg_name}' exceeds max length "
                    f"{constraint.max_length} (got {len(str_value)})"
                )

        # --- pattern (regex) -------------------------------------------------
        if constraint.pattern is not None:
            compiled = self._get_compiled_pattern(constraint.pattern)
            if not compiled.search(str_value):
                return (
                    f"Argument '{arg_name}' value '{str_value}' does not "
                    f"match required pattern '{constraint.pattern}'"
                )

        # --- min / max (numeric) ---------------------------------------------
        if constraint.min is not None or constraint.max is not None:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return (
                    f"Argument '{arg_name}' must be numeric for "
                    f"min/max validation (got {type(value).__name__})"
                )
            if constraint.min is not None and numeric < constraint.min:
                return (
                    f"Argument '{arg_name}' value {numeric} is below "
                    f"minimum {constraint.min}"
                )
            if constraint.max is not None and numeric > constraint.max:
                return (
                    f"Argument '{arg_name}' value {numeric} exceeds "
                    f"maximum {constraint.max}"
                )

        # --- enum (allowed values) -------------------------------------------
        if constraint.enum is not None:
            if value not in constraint.enum:
                return (
                    f"Argument '{arg_name}' value {value!r} is not in "
                    f"allowed values: {constraint.enum}"
                )

        return None

    def _get_compiled_pattern(self, pattern: str) -> re.Pattern[str]:
        """Return a cached compiled regex for *pattern*."""
        compiled = self._compiled_patterns.get(pattern)
        if compiled is None:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(
                    f"Invalid regex pattern in policy: '{pattern}': {exc}"
                ) from exc
            self._compiled_patterns[pattern] = compiled
        return compiled

    def _get_rate_limit(
        self,
        agent_id: str,
        tool_name: str,
    ) -> RateLimit | None:
        """Find the applicable rate limit for an (agent, tool) pair.

        Walks the allowed tool rules for the agent and returns the
        :class:`~agentgate.policy.schema.RateLimit` of the first rule
        whose pattern matches *tool_name*, or ``None`` if no rate limit
        applies.
        """
        agent_policy = self.get_agent_policy(agent_id)
        if agent_policy is None or agent_policy.tools is None:
            return None

        for perm in agent_policy.tools.allowed:
            if self._tool_name_matches(perm.name, tool_name):
                return perm.rate_limit

        return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _has_active_constraints(constraint: ArgConstraint) -> bool:
    """Return True if the constraint has any non-None validation fields."""
    return (
        constraint.max_length is not None
        or constraint.pattern is not None
        or constraint.min is not None
        or constraint.max is not None
        or constraint.enum is not None
    )

"""Tests for agentgate.policy.engine -- policy evaluation engine.

Requires Python >= 3.10 because the engine module uses
``@dataclass(slots=True)`` which was added in Python 3.10.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import pytest

# The engine module uses @dataclass(slots=True) which requires Python 3.10+.
# Guard the import so the entire module is skipped on older interpreters.
if sys.version_info < (3, 10):
    pytest.skip(
        "agentgate.policy.engine requires Python 3.10+ (@dataclass slots=True)",
        allow_module_level=True,
    )

from agentgate.policy.engine import PolicyDecision, PolicyEngine  # noqa: E402
from agentgate.policy.loader import load_policy_from_dict  # noqa: E402
from agentgate.policy.schema import (  # noqa: E402
    AgentGatePolicy,
    AgentLimits,
    AgentPolicy,
    ArgConstraint,
    RateLimit,
    ToolPermission,
    ToolsPolicy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_engine(sample_policy: dict) -> PolicyEngine:
    """Build a PolicyEngine from a sample policy dict."""
    policy = load_policy_from_dict(sample_policy)
    return PolicyEngine(policy)


# ---------------------------------------------------------------------------
# Deny-first behavior
# ---------------------------------------------------------------------------


class TestDenyFirst:
    """Deny rules should be evaluated before allow rules."""

    def test_denied_tool_returns_denied(self, sample_policy):
        """A tool matching a deny pattern should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "delete_user", {})
        assert decision.is_denied
        assert "denied" in decision.reason.lower() or "not permitted" in decision.reason.lower()

    def test_denied_exact_match(self, sample_policy):
        """An exact deny match should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "exec_shell", {})
        assert decision.is_denied

    def test_deny_takes_priority_over_allow(self):
        """When a tool matches both deny and allow, deny should win."""
        policy = AgentGatePolicy(
            agents={
                "agent": AgentPolicy(
                    tools=ToolsPolicy(
                        allowed=[ToolPermission(name="*")],
                        denied=[ToolPermission(name="dangerous_tool", reason="Too risky")],
                    ),
                ),
            },
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool_call("agent", "dangerous_tool", {})
        assert decision.is_denied
        assert "Too risky" in decision.reason


# ---------------------------------------------------------------------------
# Allowed tool passes
# ---------------------------------------------------------------------------


class TestAllowed:
    """Allowed tools should pass policy checks."""

    def test_allowed_exact_match(self, sample_policy):
        """An explicitly allowed tool should be allowed."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "read_file", {})
        assert decision.is_allowed

    def test_no_matching_rule_denied(self, sample_policy):
        """A tool with no matching allow rule should be denied by default."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "unknown_tool", {})
        assert decision.is_denied
        assert "No matching allow rule" in decision.reason


# ---------------------------------------------------------------------------
# Glob pattern matching
# ---------------------------------------------------------------------------


class TestGlobPatternMatching:
    """Tool name glob patterns should match correctly."""

    def test_prefix_glob_matches(self, sample_policy):
        """'delete_*' pattern should match 'delete_user'."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "delete_user", {})
        assert decision.is_denied

    def test_prefix_glob_matches_variant(self, sample_policy):
        """'delete_*' pattern should match 'delete_database'."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "delete_database", {})
        assert decision.is_denied

    def test_prefix_glob_no_match(self, sample_policy):
        """'delete_*' should NOT match 'remove_file'."""
        engine = _build_engine(sample_policy)
        # remove_file is not in deny list but also not in allow list
        decision = engine.check_tool_call("code-agent", "remove_file", {})
        assert decision.is_denied
        # Denied by default (no allow rule), not by deny pattern
        assert "No matching allow rule" in decision.reason

    def test_allowed_glob_matches(self, sample_policy):
        """'search_*' allow pattern should match 'search_code'."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "search_code", {})
        assert decision.is_allowed

    def test_allowed_glob_matches_variant(self, sample_policy):
        """'search_*' allow pattern should match 'search_files'."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("code-agent", "search_files", {})
        assert decision.is_allowed

    def test_wildcard_all(self):
        """A '*' pattern should match any tool name."""
        policy = AgentGatePolicy(
            agents={
                "open-agent": AgentPolicy(
                    tools=ToolsPolicy(
                        allowed=[ToolPermission(name="*")],
                    ),
                ),
            },
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool_call("open-agent", "anything_at_all", {})
        assert decision.is_allowed


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


class TestArgValidation:
    """Argument constraints should be enforced."""

    def test_regex_pattern_valid(self, sample_policy):
        """A path matching the pattern should be allowed."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "write_file",
            {"path": "/tmp/output.txt", "content": "hello"},
        )
        assert decision.is_allowed

    def test_regex_pattern_invalid(self, sample_policy):
        """A path not matching the pattern should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "write_file",
            {"path": "/etc/passwd", "content": "hack"},
        )
        assert decision.is_denied
        assert "pattern" in decision.reason.lower()

    def test_max_length_exceeded(self, sample_policy):
        """An argument exceeding max_length should be denied."""
        engine = _build_engine(sample_policy)
        long_path = "/tmp/" + "a" * 300
        decision = engine.check_tool_call(
            "code-agent",
            "write_file",
            {"path": long_path, "content": "x"},
        )
        assert decision.is_denied
        assert "max length" in decision.reason.lower() or "max_length" in decision.reason.lower()

    def test_min_max_valid(self, sample_policy):
        """A numeric value within bounds should pass."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "calculate",
            {"value": 500, "mode": "add"},
        )
        assert decision.is_allowed

    def test_min_violated(self, sample_policy):
        """A value below min should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "calculate",
            {"value": -1, "mode": "add"},
        )
        assert decision.is_denied
        assert "below" in decision.reason.lower() or "minimum" in decision.reason.lower()

    def test_max_violated(self, sample_policy):
        """A value above max should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "calculate",
            {"value": 9999, "mode": "add"},
        )
        assert decision.is_denied
        assert "exceed" in decision.reason.lower() or "maximum" in decision.reason.lower()

    def test_enum_valid(self, sample_policy):
        """A value in the enum list should pass."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "calculate",
            {"value": 10, "mode": "multiply"},
        )
        assert decision.is_allowed

    def test_enum_invalid(self, sample_policy):
        """A value not in the enum list should be denied."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call(
            "code-agent",
            "calculate",
            {"value": 10, "mode": "divide"},
        )
        assert decision.is_denied
        assert "not in" in decision.reason.lower() or "allowed values" in decision.reason.lower()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Rate limits should be enforced via sliding window."""

    def test_within_rate_limit(self, sample_policy):
        """Calls within the rate limit should be allowed."""
        engine = _build_engine(sample_policy)
        for _ in range(5):
            decision = engine.check_rate_limit("code-agent", "write_file")
            assert decision.is_allowed

    def test_rate_limit_exceeded(self, sample_policy):
        """Exceeding the rate limit should return rate_limited."""
        engine = _build_engine(sample_policy)
        # Fill up the window
        for _ in range(5):
            decision = engine.check_rate_limit("code-agent", "write_file")
            assert decision.is_allowed

        # Next call should be rate limited
        decision = engine.check_rate_limit("code-agent", "write_file")
        assert decision.is_rate_limited
        assert "Rate limit exceeded" in decision.reason

    def test_no_rate_limit_returns_allowed(self, sample_policy):
        """Tools without rate limits should always pass the rate check."""
        engine = _build_engine(sample_policy)
        for _ in range(100):
            decision = engine.check_rate_limit("code-agent", "read_file")
            assert decision.is_allowed


# ---------------------------------------------------------------------------
# Session limits
# ---------------------------------------------------------------------------


class TestSessionLimits:
    """Session-level limits should be enforced."""

    def test_within_session_call_limit(self, sample_policy):
        """Calls within the session limit should be allowed."""
        engine = _build_engine(sample_policy)
        now = datetime.now(timezone.utc)
        decision = engine.check_session_limits(
            "code-agent", "sess-1", call_count=50, session_start=now,
        )
        assert decision.is_allowed

    def test_session_call_limit_exceeded(self, sample_policy):
        """Exceeding max_tool_calls_per_session should be denied."""
        engine = _build_engine(sample_policy)
        now = datetime.now(timezone.utc)
        decision = engine.check_session_limits(
            "code-agent", "sess-1", call_count=100, session_start=now,
        )
        assert decision.is_denied
        assert "maximum" in decision.reason.lower()

    def test_session_duration_exceeded(self, sample_policy):
        """Exceeding max_session_duration_seconds should be denied."""
        engine = _build_engine(sample_policy)
        old_start = datetime.utcnow() - timedelta(seconds=7200)
        decision = engine.check_session_limits(
            "code-agent", "sess-1", call_count=1, session_start=old_start,
        )
        assert decision.is_denied
        assert "duration" in decision.reason.lower()

    def test_no_limits_always_allowed(self):
        """An agent with no limits should always pass session checks."""
        policy = AgentGatePolicy(
            agents={"free-agent": AgentPolicy(role="free")},
        )
        engine = PolicyEngine(policy)
        now = datetime.now(timezone.utc)
        decision = engine.check_session_limits(
            "free-agent", "sess-1", call_count=999999, session_start=now,
        )
        assert decision.is_allowed


# ---------------------------------------------------------------------------
# Default agent fallback
# ---------------------------------------------------------------------------


class TestDefaultAgentFallback:
    """Tests for fallback to 'default' or '__default__' agents."""

    def test_fallback_to_default(self, sample_policy):
        """An unknown agent should fall back to __default__."""
        engine = _build_engine(sample_policy)
        # __default__ allows read_file
        decision = engine.check_tool_call("unknown-agent", "read_file", {})
        assert decision.is_allowed

    def test_fallback_denies_write(self, sample_policy):
        """The __default__ agent should deny write_* tools."""
        engine = _build_engine(sample_policy)
        decision = engine.check_tool_call("unknown-agent", "write_file", {})
        assert decision.is_denied

    def test_specific_agent_not_affected_by_fallback(self, sample_policy):
        """A known agent should use its own policy, not the fallback."""
        engine = _build_engine(sample_policy)
        # code-agent has write_file allowed (with constraints)
        decision = engine.check_tool_call(
            "code-agent",
            "write_file",
            {"path": "/tmp/ok.txt", "content": "hi"},
        )
        assert decision.is_allowed


# ---------------------------------------------------------------------------
# Unknown agent denied
# ---------------------------------------------------------------------------


class TestUnknownAgentDenied:
    """An unknown agent with no default should be denied."""

    def test_no_default_denies_all(self):
        """With no default agent, unknown agents should be denied."""
        policy = AgentGatePolicy(
            agents={
                "known-agent": AgentPolicy(
                    tools=ToolsPolicy(
                        allowed=[ToolPermission(name="*")],
                    ),
                ),
            },
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool_call("rogue-agent", "anything", {})
        assert decision.is_denied
        assert "No policy defined" in decision.reason or "no default" in decision.reason.lower()

    def test_known_agent_still_works(self):
        """The known agent should still work even without a default."""
        policy = AgentGatePolicy(
            agents={
                "known-agent": AgentPolicy(
                    tools=ToolsPolicy(
                        allowed=[ToolPermission(name="*")],
                    ),
                ),
            },
        )
        engine = PolicyEngine(policy)
        decision = engine.check_tool_call("known-agent", "any_tool", {})
        assert decision.is_allowed


# ---------------------------------------------------------------------------
# PolicyDecision dataclass
# ---------------------------------------------------------------------------


class TestPolicyDecision:
    """Tests for the PolicyDecision helper properties."""

    def test_allowed_decision(self):
        d = PolicyDecision(decision="allowed")
        assert d.is_allowed
        assert not d.is_denied
        assert not d.is_rate_limited

    def test_denied_decision(self):
        d = PolicyDecision(decision="denied", reason="test")
        assert d.is_denied
        assert not d.is_allowed

    def test_rate_limited_decision(self):
        d = PolicyDecision(decision="rate_limited", reason="too fast")
        assert d.is_rate_limited
        assert not d.is_allowed
        assert not d.is_denied

    def test_frozen_dataclass(self):
        d = PolicyDecision(decision="allowed")
        with pytest.raises(AttributeError):
            d.decision = "denied"

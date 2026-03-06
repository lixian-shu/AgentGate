"""Tests for agentgate.core -- central orchestration engine."""

from __future__ import annotations

import pytest

from agentgate.core import AgentGate, ToolCallDenied
from agentgate.policy.schema import (
    AgentGatePolicy,
    AgentLimits,
    AgentPolicy,
    AuditConfig,
    AnomalyConfig,
    RateLimit,
    ToolPermission,
    ToolsPolicy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_permissive_policy() -> AgentGatePolicy:
    """Create a policy that allows all tools for __default__."""
    return AgentGatePolicy(
        agents={
            "__default__": AgentPolicy(
                role="test",
                tools=ToolsPolicy(
                    allowed=[ToolPermission(name="*")],
                ),
                limits=AgentLimits(
                    max_tool_calls_per_session=1000,
                    max_session_duration_seconds=3600,
                ),
            ),
        },
        audit=AuditConfig(enabled=True, storage="sqlite"),
        anomaly=AnomalyConfig(enabled=False),
    )


def _make_restrictive_policy() -> AgentGatePolicy:
    """Create a policy that denies all tools for __default__."""
    return AgentGatePolicy(
        agents={
            "__default__": AgentPolicy(
                role="restricted",
                tools=ToolsPolicy(
                    allowed=[],
                    denied=[ToolPermission(name="*", reason="All tools denied.")],
                ),
            ),
        },
        audit=AuditConfig(enabled=True, storage="sqlite"),
        anomaly=AnomalyConfig(enabled=False),
    )


def _dummy_tool(**kwargs) -> str:
    """A simple tool function that returns its arguments."""
    return f"executed with {kwargs}"


# ---------------------------------------------------------------------------
# AgentGate with default policy
# ---------------------------------------------------------------------------


class TestAgentGateDefault:
    """Tests for AgentGate with the built-in default policy."""

    def test_create_with_default_policy(self):
        """Creating AgentGate with no policy should use the default."""
        with AgentGate(audit_db=":memory:") as gate:
            assert gate.policy is not None
            assert "__default__" in gate.policy.agents

    def test_default_policy_denies_unknown_tools(self):
        """The default policy denies all tools for unregistered agents."""
        with AgentGate(audit_db=":memory:") as gate:
            with pytest.raises(ToolCallDenied):
                gate.intercept_tool_call_sync(
                    agent_id="some-agent",
                    session_id="sess-1",
                    tool_name="any_tool",
                    tool_args={},
                    execute_fn=_dummy_tool,
                )


# ---------------------------------------------------------------------------
# intercept_tool_call_sync -- allowed
# ---------------------------------------------------------------------------


class TestInterceptAllowed:
    """Tests for allowed tool calls through intercept_tool_call_sync."""

    def test_allowed_call_returns_result(self):
        """An allowed tool call should execute and return the result."""
        policy = _make_permissive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            result = gate.intercept_tool_call_sync(
                agent_id="test-agent",
                session_id="sess-1",
                tool_name="read_file",
                tool_args={"path": "/tmp/data.txt"},
                execute_fn=lambda **kw: f"content of {kw['path']}",
            )
            assert result == "content of /tmp/data.txt"

    def test_allowed_call_executes_function(self):
        """The execute_fn should actually be called for allowed tools."""
        policy = _make_permissive_policy()
        call_log = []

        def tracked_fn(**kwargs):
            call_log.append(kwargs)
            return "ok"

        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            gate.intercept_tool_call_sync(
                agent_id="test-agent",
                session_id="sess-1",
                tool_name="my_tool",
                tool_args={"key": "value"},
                execute_fn=tracked_fn,
            )
        assert len(call_log) == 1


# ---------------------------------------------------------------------------
# intercept_tool_call_sync -- denied (raises ToolCallDenied)
# ---------------------------------------------------------------------------


class TestInterceptDenied:
    """Tests for denied tool calls through intercept_tool_call_sync."""

    def test_denied_call_raises(self):
        """A denied tool call should raise ToolCallDenied."""
        policy = _make_restrictive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            with pytest.raises(ToolCallDenied) as exc_info:
                gate.intercept_tool_call_sync(
                    agent_id="test-agent",
                    session_id="sess-1",
                    tool_name="dangerous_tool",
                    tool_args={},
                    execute_fn=_dummy_tool,
                )
            assert exc_info.value.decision == "denied"
            assert exc_info.value.tool_name == "dangerous_tool"

    def test_denied_call_does_not_execute(self):
        """A denied tool call should NOT execute the function."""
        policy = _make_restrictive_policy()
        call_log = []

        def tracked_fn(**kwargs):
            call_log.append(kwargs)
            return "should not run"

        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            with pytest.raises(ToolCallDenied):
                gate.intercept_tool_call_sync(
                    agent_id="test-agent",
                    session_id="sess-1",
                    tool_name="blocked_tool",
                    tool_args={},
                    execute_fn=tracked_fn,
                )
        assert len(call_log) == 0

    def test_tool_call_denied_exception_message(self):
        """ToolCallDenied should have a descriptive message."""
        exc = ToolCallDenied(
            decision="denied",
            tool_name="exec_shell",
            reason="Too dangerous",
        )
        assert "exec_shell" in str(exc)
        assert "denied" in str(exc)
        assert "Too dangerous" in str(exc)


# ---------------------------------------------------------------------------
# Audit events are recorded
# ---------------------------------------------------------------------------


class TestAuditRecording:
    """Tests for audit event recording during interception."""

    def test_allowed_call_creates_audit_event(self):
        """An allowed call should record an audit event."""
        policy = _make_permissive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            gate.intercept_tool_call_sync(
                agent_id="test-agent",
                session_id="sess-audit",
                tool_name="read_file",
                tool_args={},
                execute_fn=lambda **kw: "result",
            )
            summary = gate.get_audit_summary(hours=1)
            assert summary["total_events"] >= 1

    def test_denied_call_creates_audit_event(self):
        """A denied call should also record an audit event."""
        policy = _make_restrictive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            with pytest.raises(ToolCallDenied):
                gate.intercept_tool_call_sync(
                    agent_id="test-agent",
                    session_id="sess-denied",
                    tool_name="bad_tool",
                    tool_args={},
                    execute_fn=_dummy_tool,
                )
            summary = gate.get_audit_summary(hours=1)
            assert summary["total_events"] >= 1
            assert summary["by_decision"].get("denied", 0) >= 1

    def test_audit_disabled_no_events(self):
        """When audit is disabled, no events should be recorded."""
        policy = AgentGatePolicy(
            agents={
                "__default__": AgentPolicy(
                    tools=ToolsPolicy(allowed=[ToolPermission(name="*")]),
                    limits=AgentLimits(max_tool_calls_per_session=1000),
                ),
            },
            audit=AuditConfig(enabled=False),
            anomaly=AnomalyConfig(enabled=False),
        )
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            gate.intercept_tool_call_sync(
                agent_id="test",
                session_id="s",
                tool_name="t",
                tool_args={},
                execute_fn=lambda **kw: "ok",
            )
            summary = gate.get_audit_summary()
            # Should return empty dict when audit is disabled
            assert summary == {}

    def test_multiple_calls_recorded(self):
        """Multiple calls should each produce an audit event."""
        policy = _make_permissive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            for i in range(5):
                gate.intercept_tool_call_sync(
                    agent_id="test-agent",
                    session_id="sess-multi",
                    tool_name=f"tool_{i}",
                    tool_args={},
                    execute_fn=lambda **kw: "ok",
                )
            summary = gate.get_audit_summary(hours=1)
            assert summary["total_events"] >= 5


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    """Tests for AgentGate as a context manager."""

    def test_context_manager_enters_and_exits(self):
        """AgentGate should work as a context manager."""
        policy = _make_permissive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            assert gate is not None
            assert gate.policy is not None

    def test_close_idempotent(self):
        """Calling close() multiple times should not raise."""
        policy = _make_permissive_policy()
        gate = AgentGate(policy=policy, audit_db=":memory:")
        gate.close()
        gate.close()  # Should not raise

    def test_gate_from_policy_object(self):
        """AgentGate should accept a pre-built AgentGatePolicy."""
        policy = _make_permissive_policy()
        with AgentGate(policy=policy, audit_db=":memory:") as gate:
            result = gate.intercept_tool_call_sync(
                agent_id="test",
                session_id="s",
                tool_name="tool",
                tool_args={},
                execute_fn=lambda **kw: 42,
            )
            assert result == 42

    def test_gate_from_yaml_file(self, tmp_path, sample_policy):
        """AgentGate should accept a YAML file path."""
        import yaml

        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(sample_policy), encoding="utf-8")

        with AgentGate(policy=str(policy_file), audit_db=":memory:") as gate:
            assert "code-agent" in gate.policy.agents


# ---------------------------------------------------------------------------
# Async interception
# ---------------------------------------------------------------------------


class TestAsyncIntercept:
    """Tests for async tool call interception."""

    @pytest.mark.asyncio
    async def test_async_allowed(self):
        """An allowed async tool call should work."""
        policy = _make_permissive_policy()
        gate = AgentGate(policy=policy, audit_db=":memory:")
        try:
            async def async_tool(**kwargs):
                return "async result"

            result = await gate.intercept_tool_call(
                agent_id="test",
                session_id="s",
                tool_name="async_tool",
                tool_args={},
                execute_fn=async_tool,
            )
            assert result == "async result"
        finally:
            gate.close()

    @pytest.mark.asyncio
    async def test_async_denied(self):
        """A denied async tool call should raise ToolCallDenied."""
        policy = _make_restrictive_policy()
        gate = AgentGate(policy=policy, audit_db=":memory:")
        try:
            async def async_tool(**kwargs):
                return "should not run"

            with pytest.raises(ToolCallDenied):
                await gate.intercept_tool_call(
                    agent_id="test",
                    session_id="s",
                    tool_name="blocked_tool",
                    tool_args={},
                    execute_fn=async_tool,
                )
        finally:
            gate.close()

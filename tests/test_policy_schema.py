"""Tests for agentgate.policy.schema -- Pydantic v2 policy models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentgate.policy.schema import (
    AgentGatePolicy,
    AgentLimits,
    AgentPolicy,
    AlertConfig,
    AnomalyConfig,
    ArgConstraint,
    AuditConfig,
    FilesystemPolicy,
    NetworkPolicy,
    RateLimit,
    ResourcesPolicy,
    ToolPermission,
    ToolsPolicy,
)


# ---------------------------------------------------------------------------
# AgentGatePolicy -- creation from dict
# ---------------------------------------------------------------------------


class TestAgentGatePolicyCreation:
    """Tests for creating a valid AgentGatePolicy from a dictionary."""

    def test_minimal_policy(self):
        """An empty dict should produce a valid policy with defaults."""
        policy = AgentGatePolicy.model_validate({})
        assert policy.version == "1"
        assert policy.description is None
        assert policy.agents == {}
        assert policy.audit.enabled is True
        assert policy.audit.storage == "sqlite"
        assert policy.anomaly.enabled is False

    def test_full_policy_from_dict(self, sample_policy):
        """A comprehensive dict should parse into a valid policy."""
        policy = AgentGatePolicy.model_validate(sample_policy)
        assert policy.version == "1"
        assert "code-agent" in policy.agents
        assert "__default__" in policy.agents
        assert policy.audit.retention_days == 30
        assert policy.anomaly.sensitivity == "medium"

    def test_agent_tools_parsed(self, sample_policy):
        """Tool permissions should be fully parsed including args."""
        policy = AgentGatePolicy.model_validate(sample_policy)
        code_agent = policy.agents["code-agent"]
        assert code_agent.tools is not None
        assert len(code_agent.tools.allowed) == 4
        assert len(code_agent.tools.denied) == 2

        # Check write_file has arg constraints
        write_perm = code_agent.tools.allowed[1]
        assert write_perm.name == "write_file"
        assert write_perm.args is not None
        assert "path" in write_perm.args
        assert write_perm.args["path"].pattern == r"^/tmp/"
        assert write_perm.args["path"].max_length == 256

    def test_rate_limit_parsed(self, sample_policy):
        """Rate limits should be parsed from the policy dict."""
        policy = AgentGatePolicy.model_validate(sample_policy)
        write_perm = policy.agents["code-agent"].tools.allowed[1]
        assert write_perm.rate_limit is not None
        assert write_perm.rate_limit.max_calls == 5
        assert write_perm.rate_limit.window_seconds == 60

    def test_resources_parsed(self, sample_policy):
        """Resource policies should be parsed correctly."""
        policy = AgentGatePolicy.model_validate(sample_policy)
        resources = policy.agents["code-agent"].resources
        assert resources is not None
        assert resources.filesystem is not None
        assert "/tmp/**" in resources.filesystem.read
        assert resources.network is not None
        assert "*.evil.com" in resources.network.denied_domains

    def test_limits_parsed(self, sample_policy):
        """Agent limits should be parsed correctly."""
        policy = AgentGatePolicy.model_validate(sample_policy)
        limits = policy.agents["code-agent"].limits
        assert limits is not None
        assert limits.max_tool_calls_per_session == 100
        assert limits.max_session_duration_seconds == 3600


# ---------------------------------------------------------------------------
# Validation errors for invalid data
# ---------------------------------------------------------------------------


class TestValidationErrors:
    """Tests for Pydantic validation on invalid data."""

    def test_bad_sensitivity(self):
        """Invalid anomaly sensitivity should raise ValidationError."""
        with pytest.raises(ValidationError, match="sensitivity"):
            AnomalyConfig(sensitivity="extreme")

    def test_bad_storage_type(self):
        """Invalid audit storage type should raise ValidationError."""
        with pytest.raises(ValidationError, match="storage"):
            AuditConfig(storage="postgresql")

    def test_bad_alert_type(self):
        """Invalid alert type should raise ValidationError."""
        with pytest.raises(ValidationError, match="alert type"):
            AlertConfig(type="sms")

    def test_rate_limit_zero_calls(self):
        """max_calls=0 should fail (must be >0)."""
        with pytest.raises(ValidationError):
            RateLimit(max_calls=0, window_seconds=60)

    def test_rate_limit_negative_window(self):
        """Negative window_seconds should fail."""
        with pytest.raises(ValidationError):
            RateLimit(max_calls=10, window_seconds=-1)

    def test_retention_days_zero(self):
        """retention_days=0 should fail (must be >=1)."""
        with pytest.raises(ValidationError):
            AuditConfig(retention_days=0)

    def test_tool_permission_empty_name(self):
        """Tool name must have at least 1 character."""
        with pytest.raises(ValidationError, match="at least 1 character"):
            ToolPermission(name="")

    def test_max_length_negative(self):
        """Negative max_length should fail (ge=0)."""
        with pytest.raises(ValidationError):
            ArgConstraint(max_length=-1)

    def test_agent_limits_zero_calls(self):
        """max_tool_calls_per_session=0 should fail (ge=1)."""
        with pytest.raises(ValidationError):
            AgentLimits(max_tool_calls_per_session=0)

    def test_agent_limits_zero_duration(self):
        """max_session_duration_seconds=0 should fail (ge=1)."""
        with pytest.raises(ValidationError):
            AgentLimits(max_session_duration_seconds=0)


# ---------------------------------------------------------------------------
# ArgConstraint validation
# ---------------------------------------------------------------------------


class TestArgConstraint:
    """Tests for ArgConstraint field validation."""

    def test_min_max_valid(self):
        """min <= max should pass."""
        c = ArgConstraint(min=0, max=100)
        assert c.min == 0
        assert c.max == 100

    def test_min_equals_max(self):
        """min == max should be valid."""
        c = ArgConstraint(min=50, max=50)
        assert c.min == c.max == 50

    def test_min_greater_than_max_fails(self):
        """min > max should raise a ValidationError."""
        with pytest.raises(ValidationError, match="must be greater than or equal"):
            ArgConstraint(min=100, max=50)

    def test_pattern_string(self):
        """A valid regex pattern should be accepted as-is."""
        c = ArgConstraint(pattern=r"^[a-z]+$")
        assert c.pattern == r"^[a-z]+$"

    def test_enum_list(self):
        """An enum list should be stored correctly."""
        c = ArgConstraint(enum=["a", "b", "c"])
        assert c.enum == ["a", "b", "c"]

    def test_all_none_defaults(self):
        """All fields should default to None."""
        c = ArgConstraint()
        assert c.max_length is None
        assert c.pattern is None
        assert c.min is None
        assert c.max is None
        assert c.enum is None


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestDefaults:
    """Tests for schema default values."""

    def test_policy_version_default(self):
        policy = AgentGatePolicy()
        assert policy.version == "1"

    def test_audit_config_defaults(self):
        audit = AuditConfig()
        assert audit.enabled is True
        assert audit.storage == "sqlite"
        assert audit.sign_records is False
        assert audit.retention_days is None

    def test_anomaly_config_defaults(self):
        anomaly = AnomalyConfig()
        assert anomaly.enabled is False
        assert anomaly.sensitivity == "medium"
        assert anomaly.alerts == []

    def test_tools_policy_defaults(self):
        tools = ToolsPolicy()
        assert tools.allowed == []
        assert tools.denied == []

    def test_filesystem_policy_defaults(self):
        fs = FilesystemPolicy()
        assert fs.read == []
        assert fs.write == []

    def test_network_policy_defaults(self):
        net = NetworkPolicy()
        assert net.allowed_domains == []
        assert net.denied_domains == []

    def test_agent_policy_defaults(self):
        agent = AgentPolicy()
        assert agent.role is None
        assert agent.tools is None
        assert agent.resources is None
        assert agent.limits is None


# ---------------------------------------------------------------------------
# ToolPermission with glob patterns
# ---------------------------------------------------------------------------


class TestToolPermissionGlobs:
    """Tests for ToolPermission name patterns."""

    def test_wildcard_pattern(self):
        perm = ToolPermission(name="*")
        assert perm.name == "*"

    def test_prefix_glob(self):
        perm = ToolPermission(name="file_*")
        assert perm.name == "file_*"

    def test_permission_with_reason(self):
        perm = ToolPermission(name="delete_*", reason="Too dangerous")
        assert perm.reason == "Too dangerous"

    def test_permission_with_args_and_rate_limit(self):
        perm = ToolPermission(
            name="query_db",
            args={"sql": ArgConstraint(max_length=1000)},
            rate_limit=RateLimit(max_calls=10, window_seconds=60),
        )
        assert perm.args is not None
        assert perm.args["sql"].max_length == 1000
        assert perm.rate_limit.max_calls == 10


# ---------------------------------------------------------------------------
# Nested model creation
# ---------------------------------------------------------------------------


class TestNestedModelCreation:
    """Test creating deeply nested model hierarchies."""

    def test_full_agent_policy(self):
        agent = AgentPolicy(
            role="assistant",
            tools=ToolsPolicy(
                allowed=[
                    ToolPermission(
                        name="read_*",
                        args={"path": ArgConstraint(pattern=r"^/safe/")},
                    ),
                ],
                denied=[ToolPermission(name="exec_*")],
            ),
            resources=ResourcesPolicy(
                filesystem=FilesystemPolicy(
                    read=["/safe/**"],
                    write=[],
                ),
                network=NetworkPolicy(
                    allowed_domains=["*.trusted.com"],
                    denied_domains=["*.malware.com"],
                ),
            ),
            limits=AgentLimits(
                max_tool_calls_per_session=500,
                max_session_duration_seconds=7200,
            ),
        )
        assert agent.role == "assistant"
        assert len(agent.tools.allowed) == 1
        assert agent.tools.allowed[0].args["path"].pattern == r"^/safe/"
        assert agent.resources.filesystem.read == ["/safe/**"]
        assert agent.limits.max_tool_calls_per_session == 500

    def test_full_policy_object(self):
        policy = AgentGatePolicy(
            version="2",
            description="Programmatic policy",
            agents={
                "bot": AgentPolicy(role="bot"),
            },
            audit=AuditConfig(enabled=False),
            anomaly=AnomalyConfig(
                enabled=True,
                sensitivity="high",
                alerts=[AlertConfig(type="log")],
            ),
        )
        assert policy.version == "2"
        assert "bot" in policy.agents
        assert policy.audit.enabled is False
        assert policy.anomaly.sensitivity == "high"
        assert len(policy.anomaly.alerts) == 1

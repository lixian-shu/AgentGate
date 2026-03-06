"""Tests for agentgate.policy.loader -- YAML policy loading and validation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from agentgate.policy.loader import (
    load_policy,
    load_policy_from_dict,
    load_policy_from_string,
    merge_policies,
    validate_policy_file,
)
from agentgate.policy.schema import AgentGatePolicy, AgentPolicy, AuditConfig, ToolsPolicy


# ---------------------------------------------------------------------------
# load_policy_from_dict
# ---------------------------------------------------------------------------


class TestLoadPolicyFromDict:
    """Tests for load_policy_from_dict."""

    def test_valid_dict(self, sample_policy):
        """A well-formed dict should parse successfully."""
        policy = load_policy_from_dict(sample_policy)
        assert isinstance(policy, AgentGatePolicy)
        assert "code-agent" in policy.agents

    def test_empty_dict(self):
        """An empty dict should produce a valid default policy."""
        policy = load_policy_from_dict({})
        assert policy.version == "1"
        assert policy.agents == {}

    def test_non_dict_raises_type_error(self):
        """Passing a non-dict should raise TypeError."""
        with pytest.raises(TypeError, match="Expected a dict"):
            load_policy_from_dict("not a dict")

    def test_invalid_data_raises_value_error(self):
        """Invalid schema data should raise ValueError."""
        with pytest.raises(ValueError, match="Policy validation failed"):
            load_policy_from_dict({"anomaly": {"sensitivity": "ultra"}})


# ---------------------------------------------------------------------------
# load_policy_from_string
# ---------------------------------------------------------------------------


class TestLoadPolicyFromString:
    """Tests for load_policy_from_string."""

    def test_valid_yaml_string(self):
        """A valid YAML string should parse into a policy."""
        yaml_str = textwrap.dedent("""\
            version: "1"
            description: "String test"
            agents:
              test-agent:
                role: tester
                tools:
                  allowed:
                    - name: read_file
        """)
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, AgentGatePolicy)
        assert "test-agent" in policy.agents
        assert policy.description == "String test"

    def test_empty_string_raises(self):
        """An empty string should raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            load_policy_from_string("")

    def test_whitespace_only_raises(self):
        """Whitespace-only string should raise ValueError."""
        with pytest.raises(ValueError, match="empty"):
            load_policy_from_string("   \n\t  ")

    def test_invalid_yaml_raises(self):
        """Malformed YAML should raise YAMLError."""
        with pytest.raises(yaml.YAMLError):
            load_policy_from_string("key: [unclosed")

    def test_non_dict_yaml_raises(self):
        """YAML that parses to a list should raise ValueError."""
        with pytest.raises(ValueError, match="mapping"):
            load_policy_from_string("- item1\n- item2")

    def test_invalid_schema_raises(self):
        """YAML with invalid schema values should raise ValueError."""
        yaml_str = textwrap.dedent("""\
            audit:
              storage: mongodb
        """)
        with pytest.raises(ValueError, match="Policy validation failed"):
            load_policy_from_string(yaml_str)


# ---------------------------------------------------------------------------
# load_policy (from file)
# ---------------------------------------------------------------------------


class TestLoadPolicyFromFile:
    """Tests for load_policy using a file path."""

    def test_load_valid_file(self, tmp_path, sample_policy):
        """Loading a valid YAML file should work."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(sample_policy), encoding="utf-8")

        policy = load_policy(policy_file)
        assert isinstance(policy, AgentGatePolicy)
        assert "code-agent" in policy.agents

    def test_load_string_path(self, tmp_path, sample_policy):
        """Loading from a string path should also work."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(sample_policy), encoding="utf-8")

        policy = load_policy(str(policy_file))
        assert isinstance(policy, AgentGatePolicy)

    def test_file_not_found(self):
        """A nonexistent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="not found"):
            load_policy("/nonexistent/path/policy.yaml")

    def test_empty_file(self, tmp_path):
        """An empty YAML file should raise ValueError."""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="empty"):
            load_policy(empty_file)

    def test_directory_path_raises(self, tmp_path):
        """Passing a directory should raise ValueError."""
        with pytest.raises(ValueError, match="not a regular file"):
            load_policy(tmp_path)

    def test_invalid_yaml_file(self, tmp_path):
        """A file with invalid YAML should raise YAMLError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("key: [unclosed", encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            load_policy(bad_file)


# ---------------------------------------------------------------------------
# merge_policies
# ---------------------------------------------------------------------------


class TestMergePolicies:
    """Tests for merge_policies."""

    def test_single_policy_returns_copy(self, sample_policy):
        """Merging a single policy should return a deep copy."""
        original = load_policy_from_dict(sample_policy)
        merged = merge_policies(original)
        assert merged is not original
        assert merged.version == original.version
        assert set(merged.agents.keys()) == set(original.agents.keys())

    def test_merge_two_policies_agents_combined(self):
        """Agents from both policies should appear in the result."""
        p1 = AgentGatePolicy(
            agents={"agent-a": AgentPolicy(role="first")},
        )
        p2 = AgentGatePolicy(
            agents={"agent-b": AgentPolicy(role="second")},
        )
        merged = merge_policies(p1, p2)
        assert "agent-a" in merged.agents
        assert "agent-b" in merged.agents

    def test_later_policy_overrides_agent(self):
        """Later policies should override agent definitions."""
        p1 = AgentGatePolicy(
            agents={"bot": AgentPolicy(role="old-role")},
        )
        p2 = AgentGatePolicy(
            agents={"bot": AgentPolicy(role="new-role")},
        )
        merged = merge_policies(p1, p2)
        assert merged.agents["bot"].role == "new-role"

    def test_version_from_last_policy(self):
        """The version should come from the last policy."""
        p1 = AgentGatePolicy(version="1")
        p2 = AgentGatePolicy(version="2")
        merged = merge_policies(p1, p2)
        assert merged.version == "2"

    def test_description_last_non_none_wins(self):
        """Description should be the last non-None value."""
        p1 = AgentGatePolicy(description="first")
        p2 = AgentGatePolicy(description="second")
        p3 = AgentGatePolicy()  # description is None
        merged = merge_policies(p1, p2, p3)
        # p3 has None description, so p2's should persist
        assert merged.description == "second"

    def test_audit_replaced_by_later(self):
        """Audit config should be replaced wholesale by later policies."""
        p1 = AgentGatePolicy(audit=AuditConfig(retention_days=90))
        p2 = AgentGatePolicy(audit=AuditConfig(retention_days=7))
        merged = merge_policies(p1, p2)
        assert merged.audit.retention_days == 7

    def test_no_policies_raises(self):
        """Merging zero policies should raise ValueError."""
        with pytest.raises(ValueError, match="at least one"):
            merge_policies()


# ---------------------------------------------------------------------------
# validate_policy_file
# ---------------------------------------------------------------------------


class TestValidatePolicyFile:
    """Tests for validate_policy_file."""

    def test_valid_file_returns_warnings(self, tmp_path, sample_policy):
        """A valid file with a default agent should only return warnings, not errors."""
        policy_file = tmp_path / "valid.yaml"
        policy_file.write_text(yaml.dump(sample_policy), encoding="utf-8")
        issues = validate_policy_file(policy_file)
        # Should have no errors (may have warnings)
        errors = [i for i in issues if i.startswith("error:")]
        assert len(errors) == 0

    def test_nonexistent_file_returns_error(self):
        """A missing file should return a single error."""
        issues = validate_policy_file("/no/such/file.yaml")
        assert len(issues) == 1
        assert "not found" in issues[0]

    def test_empty_file_returns_error(self, tmp_path):
        """An empty file should return an error."""
        empty = tmp_path / "empty.yaml"
        empty.write_text("", encoding="utf-8")
        issues = validate_policy_file(empty)
        assert any("empty" in i for i in issues)

    def test_invalid_schema_returns_errors(self, tmp_path):
        """Invalid schema values should produce error lines."""
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            yaml.dump({"audit": {"storage": "redis"}}),
            encoding="utf-8",
        )
        issues = validate_policy_file(bad)
        assert any("error:" in i for i in issues)

    def test_no_agents_warning(self, tmp_path):
        """A policy with no agents should produce a warning."""
        no_agents = tmp_path / "noagents.yaml"
        no_agents.write_text(yaml.dump({"version": "1"}), encoding="utf-8")
        issues = validate_policy_file(no_agents)
        assert any("No agents defined" in i for i in issues)

    def test_agent_no_tools_warning(self, tmp_path):
        """An agent with no tools should produce a warning."""
        data = {
            "agents": {
                "lazy-agent": {"role": "idle"},
            },
        }
        f = tmp_path / "notools.yaml"
        f.write_text(yaml.dump(data), encoding="utf-8")
        issues = validate_policy_file(f)
        assert any("no tool rules" in i for i in issues)

    def test_no_default_agent_warning(self, tmp_path):
        """A policy with agents but no 'default' should warn."""
        data = {
            "agents": {
                "specific-agent": {
                    "role": "worker",
                    "tools": {"allowed": [{"name": "*"}]},
                },
            },
        }
        f = tmp_path / "nodefault.yaml"
        f.write_text(yaml.dump(data), encoding="utf-8")
        issues = validate_policy_file(f)
        assert any("No 'default'" in i for i in issues)

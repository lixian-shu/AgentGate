"""Shared pytest fixtures for AgentGate tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agentgate.audit.models import AuditEvent


# ---------------------------------------------------------------------------
# Policy fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_policy() -> dict:
    """Return a comprehensive policy dict suitable for most tests."""
    return {
        "version": "1",
        "description": "Test policy for unit tests",
        "agents": {
            "code-agent": {
                "role": "code assistant",
                "tools": {
                    "allowed": [
                        {"name": "read_file"},
                        {
                            "name": "write_file",
                            "args": {
                                "path": {
                                    "pattern": r"^/tmp/",
                                    "max_length": 256,
                                },
                                "content": {
                                    "max_length": 10000,
                                },
                            },
                            "rate_limit": {
                                "max_calls": 5,
                                "window_seconds": 60,
                            },
                        },
                        {
                            "name": "search_*",
                        },
                        {
                            "name": "calculate",
                            "args": {
                                "value": {"min": 0, "max": 1000},
                                "mode": {"enum": ["add", "subtract", "multiply"]},
                            },
                        },
                    ],
                    "denied": [
                        {
                            "name": "delete_*",
                            "reason": "Deletion is not permitted for code agents.",
                        },
                        {"name": "exec_shell"},
                    ],
                },
                "resources": {
                    "filesystem": {
                        "read": ["/tmp/**", "/data/**"],
                        "write": ["/tmp/**"],
                    },
                    "network": {
                        "allowed_domains": ["api.example.com"],
                        "denied_domains": ["*.evil.com"],
                    },
                },
                "limits": {
                    "max_tool_calls_per_session": 100,
                    "max_session_duration_seconds": 3600,
                },
            },
            "__default__": {
                "role": "unregistered",
                "tools": {
                    "allowed": [{"name": "read_file"}],
                    "denied": [
                        {
                            "name": "write_*",
                            "reason": "Default agents cannot write.",
                        },
                    ],
                },
            },
        },
        "audit": {
            "enabled": True,
            "storage": "sqlite",
            "sign_records": False,
            "retention_days": 30,
        },
        "anomaly": {
            "enabled": True,
            "sensitivity": "medium",
            "alerts": [{"type": "log"}],
        },
    }


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def temp_db(tmp_path):
    """Return a path to a temporary SQLite database file."""
    return str(tmp_path / "test_audit.db")


# ---------------------------------------------------------------------------
# Audit event fixtures
# ---------------------------------------------------------------------------


def _make_event(
    agent_id: str = "test-agent",
    session_id: str = "sess-001",
    action_type: str = "tool_call",
    tool_name: str = "read_file",
    tool_args: dict | None = None,
    decision: str = "allowed",
    deny_reason: str | None = None,
    anomaly_score: float = 0.0,
    anomaly_flags: list[str] | None = None,
) -> AuditEvent:
    """Helper to create an AuditEvent with sensible defaults."""
    return AuditEvent(
        agent_id=agent_id,
        session_id=session_id,
        action_type=action_type,
        tool_name=tool_name,
        tool_args=tool_args if tool_args is not None else {},
        decision=decision,
        deny_reason=deny_reason,
        anomaly_score=anomaly_score,
        anomaly_flags=anomaly_flags if anomaly_flags is not None else [],
    )


@pytest.fixture()
def sample_audit_events() -> list[AuditEvent]:
    """Return a list of varied audit events for query/filter tests."""
    return [
        _make_event(
            agent_id="agent-a",
            session_id="sess-1",
            tool_name="read_file",
            decision="allowed",
        ),
        _make_event(
            agent_id="agent-a",
            session_id="sess-1",
            tool_name="write_file",
            decision="denied",
            deny_reason="Not allowed",
        ),
        _make_event(
            agent_id="agent-b",
            session_id="sess-2",
            tool_name="delete_file",
            decision="denied",
            deny_reason="Dangerous operation",
            anomaly_score=0.8,
            anomaly_flags=["new_tool:delete_file"],
        ),
        _make_event(
            agent_id="agent-a",
            session_id="sess-1",
            tool_name="search_code",
            decision="allowed",
        ),
        _make_event(
            agent_id="agent-b",
            session_id="sess-2",
            tool_name="read_file",
            decision="allowed",
            tool_args={"path": "/tmp/data.txt"},
        ),
    ]

#!/usr/bin/env python3
"""AgentGate basic usage example.

This script demonstrates the core features of AgentGate:

1. Loading a policy from a YAML file or dict
2. Using the @protect decorator to guard tool functions
3. Creating an AgentGate instance directly
4. Querying audit logs for observability

Run this example from the project root::

    python examples/basic_usage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 1. Loading a policy
# ---------------------------------------------------------------------------

from agentgate.policy.loader import load_policy_from_dict
from agentgate.policy.schema import AgentGatePolicy

# You can load from a YAML file:
#   from agentgate.policy.loader import load_policy
#   policy = load_policy("examples/example_policy.yaml")

# Or build a policy dict in code:
policy_dict = {
    "version": "1",
    "description": "Basic usage example policy",
    "agents": {
        "my-agent": {
            "role": "example assistant",
            "tools": {
                "allowed": [
                    {"name": "read_file"},
                    {
                        "name": "write_file",
                        "args": {
                            "path": {"pattern": r"^/tmp/", "max_length": 256},
                        },
                        "rate_limit": {"max_calls": 5, "window_seconds": 60},
                    },
                    {"name": "search_*"},
                ],
                "denied": [
                    {
                        "name": "delete_*",
                        "reason": "Deletion is not allowed.",
                    },
                    {
                        "name": "exec_shell",
                        "reason": "Shell execution is forbidden.",
                    },
                ],
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
                "denied": [{"name": "*", "reason": "Unregistered agents are restricted."}],
            },
        },
    },
    "audit": {
        "enabled": True,
        "storage": "sqlite",
        "sign_records": False,
    },
    "anomaly": {
        "enabled": False,
    },
}

policy = load_policy_from_dict(policy_dict)
print(f"Loaded policy: {policy.description}")
print(f"  Agents defined: {list(policy.agents.keys())}")
print()

# ---------------------------------------------------------------------------
# 2. Using the @protect decorator
# ---------------------------------------------------------------------------

from agentgate.core import AgentGate, ToolCallDenied
from agentgate.integrations.generic import protect

# Create a gate instance (use ":memory:" for the demo so no file is created)
gate = AgentGate(policy=policy, audit_db=":memory:")


@protect(gate=gate, agent_id="my-agent", session_id="demo-session")
def read_file(path: str = "") -> str:
    """Simulated file read tool."""
    return f"[Contents of {path}]"


@protect(gate=gate, agent_id="my-agent", session_id="demo-session")
def write_file(path: str = "", content: str = "") -> str:
    """Simulated file write tool."""
    return f"Wrote {len(content)} bytes to {path}"


@protect(gate=gate, agent_id="my-agent", session_id="demo-session")
def delete_file(path: str = "") -> str:
    """Simulated file delete tool -- should be denied by policy."""
    return f"Deleted {path}"


# Call allowed tools:
print("--- Calling allowed tools ---")
result = read_file(path="/tmp/data.txt")
print(f"read_file result: {result}")

result = write_file(path="/tmp/output.txt", content="Hello, AgentGate!")
print(f"write_file result: {result}")

# Call a denied tool:
print()
print("--- Calling denied tool ---")
try:
    delete_file(path="/tmp/important.txt")
    print("ERROR: delete_file should have been denied!")
except ToolCallDenied as exc:
    print(f"Caught ToolCallDenied: {exc}")

# ---------------------------------------------------------------------------
# 3. Using AgentGate directly (without decorator)
# ---------------------------------------------------------------------------

print()
print("--- Using AgentGate directly ---")


def search_code(query: str = "") -> str:
    """Simulated code search tool."""
    return f"Found 3 results for '{query}'"


# Allowed: search_* matches search_code
result = gate.intercept_tool_call_sync(
    agent_id="my-agent",
    session_id="demo-session",
    tool_name="search_code",
    tool_args={"query": "def main"},
    execute_fn=search_code,
)
print(f"search_code result: {result}")

# Denied: exec_shell is explicitly denied
try:
    gate.intercept_tool_call_sync(
        agent_id="my-agent",
        session_id="demo-session",
        tool_name="exec_shell",
        tool_args={"command": "rm -rf /"},
        execute_fn=lambda **kw: "should not run",
    )
except ToolCallDenied as exc:
    print(f"exec_shell denied: {exc}")

# ---------------------------------------------------------------------------
# 4. Querying audit logs
# ---------------------------------------------------------------------------

print()
print("--- Audit Summary ---")
summary = gate.get_audit_summary(hours=1)
print(f"  Total events: {summary.get('total_events', 0)}")
print(f"  By decision:  {summary.get('by_decision', {})}")
print(f"  By tool:      {summary.get('by_tool', {})}")

if summary.get("top_denied_tools"):
    print(f"  Top denied:   {summary['top_denied_tools']}")

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

gate.close()
print()
print("Done. AgentGate closed.")

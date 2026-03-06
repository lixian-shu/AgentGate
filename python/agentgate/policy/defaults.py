"""Built-in default policy configurations for AgentGate.

Each constant is a plain ``dict`` that can be loaded directly into
:class:`~agentgate.policy.schema.AgentGatePolicy`::

    from agentgate.policy.schema import AgentGatePolicy
    from agentgate.policy.defaults import DEFAULT_POLICY

    policy = AgentGatePolicy.model_validate(DEFAULT_POLICY)

Three presets are provided:

* **DEFAULT_POLICY** -- Restrictive.  Unregistered agents are denied all
  tools; basic audit is enabled.
* **PERMISSIVE_POLICY** -- All tools allowed for every agent, but every
  action is logged.
* **DEVELOPMENT_POLICY** -- Fully open with verbose audit logging and
  anomaly detection enabled at high sensitivity.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# DEFAULT_POLICY -- secure-by-default
# ---------------------------------------------------------------------------

DEFAULT_POLICY: dict[str, Any] = {
    "version": "1",
    "description": (
        "Restrictive default policy. Unregistered agents have no tool access. "
        "Audit logging is enabled with signed records."
    ),
    "agents": {
        # A catch-all agent entry with no allowed tools effectively denies
        # everything for any agent that is not explicitly listed.
        "__default__": {
            "role": "unregistered",
            "tools": {
                "allowed": [],
                "denied": [
                    {
                        "name": "*",
                        "reason": "No tools are permitted for unregistered agents.",
                    },
                ],
            },
            "resources": {
                "filesystem": {
                    "read": [],
                    "write": [],
                },
                "network": {
                    "allowed_domains": [],
                    "denied_domains": ["*"],
                },
            },
            "limits": {
                "max_tool_calls_per_session": 1,
                "max_session_duration_seconds": 60,
            },
        },
    },
    "audit": {
        "enabled": True,
        "storage": "sqlite",
        "sign_records": True,
        "retention_days": 90,
    },
    "anomaly": {
        "enabled": False,
        "sensitivity": "medium",
        "alerts": [
            {"type": "log"},
        ],
    },
}


# ---------------------------------------------------------------------------
# PERMISSIVE_POLICY -- allow everything, log everything
# ---------------------------------------------------------------------------

PERMISSIVE_POLICY: dict[str, Any] = {
    "version": "1",
    "description": (
        "Permissive policy. All tools are allowed for every agent. "
        "Every action is logged for auditability."
    ),
    "agents": {
        "__default__": {
            "role": "any",
            "tools": {
                "allowed": [
                    {"name": "*"},
                ],
                "denied": [],
            },
            "resources": {
                "filesystem": {
                    "read": ["**"],
                    "write": ["**"],
                },
                "network": {
                    "allowed_domains": ["*"],
                    "denied_domains": [],
                },
            },
            "limits": {
                "max_tool_calls_per_session": 10_000,
                "max_session_duration_seconds": 86_400,
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
        "enabled": False,
        "sensitivity": "low",
        "alerts": [
            {"type": "log"},
        ],
    },
}


# ---------------------------------------------------------------------------
# DEVELOPMENT_POLICY -- wide open with full observability
# ---------------------------------------------------------------------------

DEVELOPMENT_POLICY: dict[str, Any] = {
    "version": "1",
    "description": (
        "Development policy. All tools are allowed with no rate limits. "
        "Verbose audit logging and high-sensitivity anomaly detection are enabled "
        "to surface issues during development."
    ),
    "agents": {
        "__default__": {
            "role": "developer",
            "tools": {
                "allowed": [
                    {"name": "*"},
                ],
                "denied": [],
            },
            "resources": {
                "filesystem": {
                    "read": ["**"],
                    "write": ["**"],
                },
                "network": {
                    "allowed_domains": ["*"],
                    "denied_domains": [],
                },
            },
            "limits": {
                "max_tool_calls_per_session": 50_000,
                "max_session_duration_seconds": 86_400,
            },
        },
    },
    "audit": {
        "enabled": True,
        "storage": "sqlite",
        "sign_records": False,
        "retention_days": 7,
    },
    "anomaly": {
        "enabled": True,
        "sensitivity": "high",
        "alerts": [
            {"type": "log"},
        ],
    },
}

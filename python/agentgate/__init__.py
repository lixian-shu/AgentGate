"""AgentGate: Runtime security for autonomous AI agents."""

# Core
from agentgate.core import AgentGate, ToolCallDenied, AgentContext

# Decorator
from agentgate.integrations.generic import protect

# Policy
from agentgate.policy.schema import AgentGatePolicy
from agentgate.policy.loader import load_policy, load_policy_from_string, load_policy_from_dict

# Audit
from agentgate.audit.models import AuditEvent, AuditQuery

__version__ = "0.1.0"

__all__ = [
    "AgentGate",
    "ToolCallDenied",
    "AgentContext",
    "protect",
    "AgentGatePolicy",
    "load_policy",
    "load_policy_from_string",
    "load_policy_from_dict",
    "AuditEvent",
    "AuditQuery",
    "__version__",
]

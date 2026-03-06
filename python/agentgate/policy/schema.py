"""Pydantic v2 schema models for AgentGate YAML policy files.

This module defines the complete data model hierarchy for agent gateway
policies, covering tool permissions, resource access controls, rate limits,
audit configuration, and anomaly detection settings.

All models use Pydantic v2 with strict validation and sensible defaults
so that a minimal policy file is sufficient to get started.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Tool-level constraints
# ---------------------------------------------------------------------------


class ArgConstraint(BaseModel):
    """Validation constraints for a single tool argument.

    Each field is optional -- only the constraints that are specified will be
    enforced at runtime.
    """

    max_length: Optional[int] = Field(
        default=None,
        ge=0,
        description="Maximum string length for this argument.",
    )
    pattern: Optional[str] = Field(
        default=None,
        description="Regular expression the argument value must match.",
    )
    min: Optional[float] = Field(
        default=None,
        description="Minimum numeric value (inclusive).",
    )
    max: Optional[float] = Field(
        default=None,
        description="Maximum numeric value (inclusive).",
    )
    enum: Optional[list[Any]] = Field(
        default=None,
        description="Explicit list of allowed values.",
    )

    @field_validator("max")
    @classmethod
    def _max_ge_min(cls, v: Optional[float], info: Any) -> Optional[float]:
        min_val = info.data.get("min")
        if v is not None and min_val is not None and v < min_val:
            raise ValueError(
                f"'max' ({v}) must be greater than or equal to 'min' ({min_val})"
            )
        return v


class RateLimit(BaseModel):
    """Sliding-window rate limit for a tool invocation."""

    max_calls: int = Field(
        ...,
        gt=0,
        description="Maximum number of calls permitted within the window.",
    )
    window_seconds: int = Field(
        ...,
        gt=0,
        description="Duration of the sliding window in seconds.",
    )


class ToolPermission(BaseModel):
    """A single tool permission entry (used in both *allowed* and *denied* lists).

    ``name`` supports glob patterns (e.g. ``"file_*"`` or ``"*"``).
    """

    name: str = Field(
        ...,
        min_length=1,
        description="Tool name or glob pattern (e.g. 'read_file', 'delete_*').",
    )
    args: Optional[dict[str, ArgConstraint]] = Field(
        default=None,
        description="Per-argument validation constraints.",
    )
    rate_limit: Optional[RateLimit] = Field(
        default=None,
        description="Rate limit applied to this tool.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Human-readable reason (typically used for denied entries).",
    )


class ToolsPolicy(BaseModel):
    """Allowed and denied tool lists for an agent."""

    allowed: list[ToolPermission] = Field(
        default_factory=list,
        description="Tools (or patterns) the agent is permitted to call.",
    )
    denied: list[ToolPermission] = Field(
        default_factory=list,
        description="Tools (or patterns) the agent is explicitly forbidden from calling.",
    )


# ---------------------------------------------------------------------------
# Resource access controls
# ---------------------------------------------------------------------------


class FilesystemPolicy(BaseModel):
    """Filesystem access control using glob path patterns."""

    read: list[str] = Field(
        default_factory=list,
        description="Glob patterns for paths the agent may read.",
    )
    write: list[str] = Field(
        default_factory=list,
        description="Glob patterns for paths the agent may write.",
    )


class NetworkPolicy(BaseModel):
    """Network access control by domain.

    Domains support glob patterns (``"*.example.com"``).  The deny list is
    evaluated before the allow list -- an explicit deny always wins.
    """

    allowed_domains: list[str] = Field(
        default_factory=list,
        description="Domain glob patterns the agent may connect to.",
    )
    denied_domains: list[str] = Field(
        default_factory=list,
        description="Domain glob patterns the agent must never connect to.",
    )


class ResourcesPolicy(BaseModel):
    """Aggregate resource access policy."""

    filesystem: Optional[FilesystemPolicy] = Field(
        default=None,
        description="Filesystem read/write controls.",
    )
    network: Optional[NetworkPolicy] = Field(
        default=None,
        description="Network domain controls.",
    )


# ---------------------------------------------------------------------------
# Agent-level limits
# ---------------------------------------------------------------------------


class AgentLimits(BaseModel):
    """Hard limits on agent activity within a session."""

    max_tool_calls_per_session: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum total tool calls allowed in a single session.",
    )
    max_session_duration_seconds: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum session duration in seconds before forced termination.",
    )


# ---------------------------------------------------------------------------
# Per-agent policy
# ---------------------------------------------------------------------------


class AgentPolicy(BaseModel):
    """Complete policy for a single named agent."""

    role: Optional[str] = Field(
        default=None,
        description="Human-readable description of the agent's role.",
    )
    tools: Optional[ToolsPolicy] = Field(
        default=None,
        description="Tool-level permission and rate-limit rules.",
    )
    resources: Optional[ResourcesPolicy] = Field(
        default=None,
        description="Resource access (filesystem, network) controls.",
    )
    limits: Optional[AgentLimits] = Field(
        default=None,
        description="Session-level hard limits.",
    )


# ---------------------------------------------------------------------------
# Audit configuration
# ---------------------------------------------------------------------------


class AuditConfig(BaseModel):
    """Configuration for the audit subsystem."""

    enabled: bool = Field(
        default=True,
        description="Whether audit logging is active.",
    )
    storage: str = Field(
        default="sqlite",
        description="Audit storage backend ('sqlite' or 'file').",
    )
    sign_records: bool = Field(
        default=False,
        description="Whether to cryptographically sign each audit record.",
    )
    retention_days: Optional[int] = Field(
        default=None,
        ge=1,
        description="Number of days to retain audit records before automatic purge.",
    )

    @field_validator("storage")
    @classmethod
    def _validate_storage(cls, v: str) -> str:
        allowed = {"sqlite", "file"}
        if v not in allowed:
            raise ValueError(f"storage must be one of {allowed}, got '{v}'")
        return v


# ---------------------------------------------------------------------------
# Anomaly detection configuration
# ---------------------------------------------------------------------------


class AlertConfig(BaseModel):
    """A single alert delivery channel."""

    type: str = Field(
        ...,
        description="Alert channel type ('log', 'webhook', or 'email').",
    )
    url: Optional[str] = Field(
        default=None,
        description="Destination URL (required for 'webhook' type).",
    )
    email: Optional[str] = Field(
        default=None,
        description="Destination email address (required for 'email' type).",
    )

    @field_validator("type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        allowed = {"log", "webhook", "email"}
        if v not in allowed:
            raise ValueError(f"alert type must be one of {allowed}, got '{v}'")
        return v


class AnomalyConfig(BaseModel):
    """Configuration for the anomaly-detection subsystem."""

    enabled: bool = Field(
        default=False,
        description="Whether anomaly detection is active.",
    )
    sensitivity: str = Field(
        default="medium",
        description="Detection sensitivity ('low', 'medium', or 'high').",
    )
    alerts: list[AlertConfig] = Field(
        default_factory=list,
        description="Alert channels for anomaly notifications.",
    )

    @field_validator("sensitivity")
    @classmethod
    def _validate_sensitivity(cls, v: str) -> str:
        allowed = {"low", "medium", "high"}
        if v not in allowed:
            raise ValueError(f"sensitivity must be one of {allowed}, got '{v}'")
        return v


# ---------------------------------------------------------------------------
# Top-level policy document
# ---------------------------------------------------------------------------


class AgentGatePolicy(BaseModel):
    """Root model representing a complete AgentGate policy document.

    This is the model you deserialise your YAML/JSON policy file into::

        import yaml
        from agentgate.policy.schema import AgentGatePolicy

        with open("policy.yaml") as fh:
            data = yaml.safe_load(fh)
        policy = AgentGatePolicy.model_validate(data)
    """

    version: str = Field(
        default="1",
        description="Policy schema version.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of this policy.",
    )
    agents: dict[str, AgentPolicy] = Field(
        default_factory=dict,
        description="Per-agent policy definitions keyed by agent name.",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Audit subsystem configuration.",
    )
    anomaly: AnomalyConfig = Field(
        default_factory=AnomalyConfig,
        description="Anomaly detection subsystem configuration.",
    )

"""Pydantic v2 models for the AgentGate audit subsystem.

Provides two primary models:

* :class:`AuditEvent` -- an immutable, cryptographically-signable record of
  every action an agent performs.
* :class:`AuditQuery` -- a structured query object for filtering and paginating
  through stored audit events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Audit event record
# ---------------------------------------------------------------------------

_ACTION_TYPES = Literal[
    "tool_call",
    "file_access",
    "network_request",
    "memory_change",
]

_DECISION_TYPES = Literal[
    "allowed",
    "denied",
    "rate_limited",
]


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _new_event_id() -> str:
    """Generate a new UUID-4 string for an audit event."""
    return str(uuid.uuid4())


class AuditEvent(BaseModel):
    """Immutable audit record for a single agent action.

    Instances are frozen after creation so that they can be safely hashed,
    serialised, and (optionally) cryptographically signed.

    Example::

        event = AuditEvent(
            agent_id="code-assistant",
            session_id="sess-abc123",
            action_type="tool_call",
            tool_name="read_file",
            tool_args={"path": "/etc/hosts"},
            decision="allowed",
        )
    """

    model_config = {"frozen": True}

    # --- Identity --------------------------------------------------------

    event_id: str = Field(
        default_factory=_new_event_id,
        description="Unique identifier for this audit event (UUID-4).",
    )
    timestamp: datetime = Field(
        default_factory=_utcnow,
        description="UTC timestamp of when the event occurred.",
    )

    # --- Context ---------------------------------------------------------

    agent_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the agent that initiated the action.",
    )
    session_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the session within which the action occurred.",
    )

    # --- Action ----------------------------------------------------------

    action_type: _ACTION_TYPES = Field(
        ...,
        description="Category of the action being audited.",
    )
    tool_name: str = Field(
        default="",
        description="Name of the tool invoked (empty for non-tool actions).",
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool.",
    )

    # --- Decision --------------------------------------------------------

    decision: _DECISION_TYPES = Field(
        ...,
        description="Policy decision applied to this action.",
    )
    deny_reason: Optional[str] = Field(
        default=None,
        description="Human-readable reason when the decision is 'denied' or 'rate_limited'.",
    )

    # --- Outcome ---------------------------------------------------------

    result_summary: Optional[str] = Field(
        default=None,
        description="Brief summary of the tool's return value or side-effect.",
    )
    duration_ms: Optional[float] = Field(
        default=None,
        ge=0,
        description="Wall-clock execution time of the action in milliseconds.",
    )

    # --- Anomaly ---------------------------------------------------------

    anomaly_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Anomaly score between 0.0 (normal) and 1.0 (highly anomalous).",
    )
    anomaly_flags: list[str] = Field(
        default_factory=list,
        description="Descriptive flags raised by anomaly detectors.",
    )

    # --- Integrity -------------------------------------------------------

    signature: Optional[str] = Field(
        default=None,
        description="Ed25519 signature of the canonical event payload (hex-encoded).",
    )

    # --- Extensibility ---------------------------------------------------

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary key-value metadata attached to the event.",
    )

    # --- Validators ------------------------------------------------------

    @field_validator("timestamp", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> datetime:
        """Normalise naive datetimes to UTC."""
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
        return v

    # --- Convenience helpers --------------------------------------------

    def canonical_payload(self) -> dict[str, Any]:
        """Return the fields that should be included in the signature.

        The ``signature`` field itself is excluded so that the payload can
        be signed and then attached.
        """
        data = self.model_dump(mode="json")
        data.pop("signature", None)
        return data


# ---------------------------------------------------------------------------
# Audit query (for filtering stored events)
# ---------------------------------------------------------------------------


class AuditQuery(BaseModel):
    """Structured query for filtering and paginating audit events.

    All filter fields are optional.  When multiple filters are provided
    they are combined with AND semantics.

    Example::

        query = AuditQuery(
            agent_id="code-assistant",
            decision="denied",
            time_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
            min_anomaly_score=0.5,
            limit=50,
        )
    """

    # --- Equality filters ------------------------------------------------

    agent_id: Optional[str] = Field(
        default=None,
        description="Filter by agent identifier (exact match).",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Filter by session identifier (exact match).",
    )
    action_type: Optional[_ACTION_TYPES] = Field(
        default=None,
        description="Filter by action type.",
    )
    decision: Optional[_DECISION_TYPES] = Field(
        default=None,
        description="Filter by policy decision.",
    )

    # --- Time range ------------------------------------------------------

    time_from: Optional[datetime] = Field(
        default=None,
        description="Inclusive lower bound on event timestamp (UTC).",
    )
    time_to: Optional[datetime] = Field(
        default=None,
        description="Inclusive upper bound on event timestamp (UTC).",
    )

    # --- Tool filter -----------------------------------------------------

    tool_name: Optional[str] = Field(
        default=None,
        description="Filter by tool name (supports glob patterns, e.g. 'file_*').",
    )

    # --- Anomaly filter --------------------------------------------------

    min_anomaly_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Return only events with anomaly_score >= this value.",
    )

    # --- Pagination ------------------------------------------------------

    limit: int = Field(
        default=100,
        ge=1,
        le=10_000,
        description="Maximum number of events to return.",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Number of events to skip (for pagination).",
    )

    # --- Cross-field validation ------------------------------------------

    @model_validator(mode="after")
    def _time_range_order(self) -> "AuditQuery":
        if (
            self.time_from is not None
            and self.time_to is not None
            and self.time_from > self.time_to
        ):
            raise ValueError("'time_from' must not be later than 'time_to'")
        return self

"""Audit event collection and enrichment for AgentGate.

The :class:`AuditCollector` acts as the primary entry point for recording
audit events.  It generates unique identifiers, captures timestamps,
optionally signs events via a Rust-backed signer, and persists them to
the configured :class:`~agentgate.audit.store.AuditStore`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from agentgate.audit.models import AuditEvent, AuditQuery
from agentgate.audit.store import AuditStore


class AuditCollector:
    """High-level facade for collecting and querying audit events.

    Parameters
    ----------
    store:
        The :class:`AuditStore` instance used for persistence.
    signer:
        An optional signer object (typically provided by the Rust core via
        PyO3).  When present, each event is signed before storage.  The
        signer must expose a ``sign(data: str) -> str`` method.
    """

    def __init__(self, store: AuditStore, signer: Any | None = None) -> None:
        self._store = store
        self._signer = signer

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(
        self,
        agent_id: str,
        session_id: str,
        action_type: str,
        tool_name: str,
        tool_args: dict[str, Any],
        decision: str,
        deny_reason: str | None = None,
        result_summary: str | None = None,
        duration_ms: float | None = None,
        anomaly_score: float = 0.0,
        anomaly_flags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Create, optionally sign, persist, and return an audit event.

        This is the primary method called by the AgentGate runtime each time
        a policy decision is made.

        Parameters
        ----------
        agent_id:
            Identifier of the agent.
        session_id:
            Current session identifier.
        action_type:
            Category such as ``tool_call``, ``resource_access``, etc.
        tool_name:
            Name of the tool or resource being invoked.
        tool_args:
            Arguments supplied to the tool.
        decision:
            Policy engine decision (``allowed``, ``denied``, ``rate_limited``).
        deny_reason:
            Human-readable reason when *decision* is ``denied``.
        result_summary:
            Optional brief summary of the execution result.
        duration_ms:
            Optional execution duration in milliseconds.
        anomaly_score:
            Anomaly detection score in ``[0, 1]``.  Defaults to ``0.0``.
        anomaly_flags:
            Optional list of anomaly flag identifiers.
        metadata:
            Optional extra key-value metadata.

        Returns
        -------
        AuditEvent
            The fully constructed (and possibly signed) event.
        """
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            agent_id=agent_id,
            session_id=session_id,
            action_type=action_type,
            tool_name=tool_name,
            tool_args=tool_args,
            decision=decision,
            deny_reason=deny_reason,
            result_summary=result_summary,
            duration_ms=duration_ms,
            anomaly_score=anomaly_score,
            anomaly_flags=anomaly_flags if anomaly_flags is not None else [],
            metadata=metadata if metadata is not None else {},
        )

        # Sign the event if a signer is available.  AuditEvent is frozen,
        # so we create a copy with the signature attached.
        if self._signer is not None:
            payload = event.model_dump_json(exclude={"signature"})
            signature = self._signer.sign(payload)
            event = event.model_copy(update={"signature": signature})

        self._store.record(event)
        return event

    # ------------------------------------------------------------------
    # Convenience query helpers
    # ------------------------------------------------------------------

    def get_session_events(self, session_id: str) -> list[AuditEvent]:
        """Return all events belonging to the given session.

        Events are returned in reverse chronological order.
        """
        q = AuditQuery(session_id=session_id, limit=10000)
        return self._store.query(q)

    def get_agent_events(self, agent_id: str, limit: int = 100) -> list[AuditEvent]:
        """Return recent events for the given agent.

        Parameters
        ----------
        agent_id:
            The agent whose events to retrieve.
        limit:
            Maximum number of events (default 100).
        """
        q = AuditQuery(agent_id=agent_id, limit=limit)
        return self._store.query(q)

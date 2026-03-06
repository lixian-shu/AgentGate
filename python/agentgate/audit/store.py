"""SQLite-based audit storage backend for AgentGate.

Provides thread-safe, persistent storage for audit events with flexible
querying, counting, and summary statistics.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from agentgate.audit.models import AuditEvent, AuditQuery

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id       TEXT PRIMARY KEY,
    timestamp      TEXT    NOT NULL,
    agent_id       TEXT    NOT NULL,
    session_id     TEXT    NOT NULL,
    action_type    TEXT    NOT NULL,
    tool_name      TEXT    NOT NULL,
    tool_args      TEXT    NOT NULL DEFAULT '{}',
    decision       TEXT    NOT NULL,
    deny_reason    TEXT,
    result_summary TEXT,
    duration_ms    REAL,
    anomaly_score  REAL    NOT NULL DEFAULT 0.0,
    anomaly_flags  TEXT    NOT NULL DEFAULT '[]',
    signature      TEXT,
    metadata       TEXT    NOT NULL DEFAULT '{}'
);
"""

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_events (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_audit_agent_id    ON audit_events (agent_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_session_id  ON audit_events (session_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_tool_name   ON audit_events (tool_name);",
    "CREATE INDEX IF NOT EXISTS idx_audit_decision    ON audit_events (decision);",
]

_INSERT_SQL = """
INSERT OR REPLACE INTO audit_events (
    event_id, timestamp, agent_id, session_id, action_type, tool_name,
    tool_args, decision, deny_reason, result_summary, duration_ms,
    anomaly_score, anomaly_flags, signature, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_COLUMNS = [
    "event_id", "timestamp", "agent_id", "session_id", "action_type",
    "tool_name", "tool_args", "decision", "deny_reason", "result_summary",
    "duration_ms", "anomaly_score", "anomaly_flags", "signature", "metadata",
]


def _event_to_row(event: AuditEvent) -> tuple[Any, ...]:
    """Serialise an AuditEvent into a row tuple suitable for SQLite insertion."""
    return (
        event.event_id,
        event.timestamp.isoformat(),
        event.agent_id,
        event.session_id,
        event.action_type,
        event.tool_name,
        json.dumps(event.tool_args, default=str),
        event.decision,
        event.deny_reason,
        event.result_summary,
        event.duration_ms,
        event.anomaly_score,
        json.dumps(event.anomaly_flags),
        event.signature,
        json.dumps(event.metadata, default=str),
    )


def _row_to_event(row: sqlite3.Row | tuple[Any, ...]) -> AuditEvent:
    """Deserialise a database row back into an AuditEvent."""
    data = dict(zip(_COLUMNS, row))
    data["tool_args"] = json.loads(data["tool_args"])
    data["anomaly_flags"] = json.loads(data["anomaly_flags"])
    data["metadata"] = json.loads(data["metadata"])
    return AuditEvent.model_validate(data)


def _build_where_clause(query: AuditQuery) -> tuple[str, list[Any]]:
    """Build a SQL WHERE clause and parameter list from an AuditQuery."""
    conditions: list[str] = []
    params: list[Any] = []

    if query.agent_id is not None:
        conditions.append("agent_id = ?")
        params.append(query.agent_id)
    if query.session_id is not None:
        conditions.append("session_id = ?")
        params.append(query.session_id)
    if query.action_type is not None:
        conditions.append("action_type = ?")
        params.append(query.action_type)
    if query.decision is not None:
        conditions.append("decision = ?")
        params.append(query.decision)
    if query.time_from is not None:
        conditions.append("timestamp >= ?")
        params.append(query.time_from.isoformat())
    if query.time_to is not None:
        conditions.append("timestamp <= ?")
        params.append(query.time_to.isoformat())
    if query.tool_name is not None:
        conditions.append("tool_name GLOB ?")
        params.append(query.tool_name)
    if query.min_anomaly_score is not None:
        conditions.append("anomaly_score >= ?")
        params.append(query.min_anomaly_score)

    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    return where, params


class AuditStore:
    """Thread-safe SQLite storage backend for audit events.

    Parameters
    ----------
    db_path:
        File path for the SQLite database.  Defaults to
        ``agentgate_audit.db`` in the current working directory.
        Use ``":memory:"`` for an ephemeral in-memory store (useful in tests).
    """

    def __init__(self, db_path: str | Path = "agentgate_audit.db") -> None:
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._initialise_schema()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def _initialise_schema(self) -> None:
        with self._lock:
            self._conn.execute(_CREATE_TABLE_SQL)
            for idx_sql in _CREATE_INDEXES_SQL:
                self._conn.execute(idx_sql)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def record(self, event: AuditEvent) -> None:
        """Insert a single audit event into the store."""
        row = _event_to_row(event)
        with self._lock:
            self._conn.execute(_INSERT_SQL, row)
            self._conn.commit()

    def record_batch(self, events: list[AuditEvent]) -> None:
        """Insert multiple audit events in a single transaction."""
        rows = [_event_to_row(e) for e in events]
        with self._lock:
            self._conn.executemany(_INSERT_SQL, rows)
            self._conn.commit()

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def query(self, query: AuditQuery) -> list[AuditEvent]:
        """Return audit events matching the supplied filters.

        Results are ordered by timestamp descending (most recent first).
        """
        where, params = _build_where_clause(query)
        sql = (
            f"SELECT {', '.join(_COLUMNS)} FROM audit_events"
            f"{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
        )
        params.extend([query.limit, query.offset])
        with self._lock:
            cursor = self._conn.execute(sql, params)
            rows = cursor.fetchall()
        return [_row_to_event(r) for r in rows]

    def count(self, query: AuditQuery) -> int:
        """Return the number of events matching the supplied filters."""
        where, params = _build_where_clause(query)
        sql = f"SELECT COUNT(*) FROM audit_events{where};"
        with self._lock:
            cursor = self._conn.execute(sql, params)
            return int(cursor.fetchone()[0])

    def get_summary(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        hours: int = 24,
    ) -> dict[str, Any]:
        """Return aggregate statistics for recent events.

        Parameters
        ----------
        agent_id:
            Optional filter by agent.
        session_id:
            Optional filter by session.
        hours:
            Look-back window in hours (default 24).

        Returns
        -------
        dict with keys:
            total_events, by_decision, by_action_type, by_tool,
            top_denied_tools, avg_anomaly_score.
        """
        conditions: list[str] = []
        params: list[Any] = []

        conditions.append("timestamp >= datetime('now', ?)")
        params.append(f"-{hours} hours")

        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = " WHERE " + " AND ".join(conditions)

        with self._lock:
            # Total events
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM audit_events{where};", params
            ).fetchone()[0]

            # By decision
            by_decision: dict[str, int] = {}
            for row in self._conn.execute(
                f"SELECT decision, COUNT(*) FROM audit_events{where} GROUP BY decision;",
                params,
            ):
                by_decision[row[0]] = row[1]

            # By action type
            by_action_type: dict[str, int] = {}
            for row in self._conn.execute(
                f"SELECT action_type, COUNT(*) FROM audit_events{where} GROUP BY action_type;",
                params,
            ):
                by_action_type[row[0]] = row[1]

            # By tool
            by_tool: dict[str, int] = {}
            for row in self._conn.execute(
                f"SELECT tool_name, COUNT(*) FROM audit_events{where} GROUP BY tool_name;",
                params,
            ):
                by_tool[row[0]] = row[1]

            # Top denied tools (up to 10)
            top_denied_tools: list[dict[str, Any]] = []
            denied_where = where + " AND decision = 'denied'"
            for row in self._conn.execute(
                f"SELECT tool_name, COUNT(*) AS cnt FROM audit_events{denied_where} "
                "GROUP BY tool_name ORDER BY cnt DESC LIMIT 10;",
                params,
            ):
                top_denied_tools.append({"tool_name": row[0], "count": row[1]})

            # Average anomaly score
            avg_row = self._conn.execute(
                f"SELECT AVG(anomaly_score) FROM audit_events{where};", params
            ).fetchone()
            avg_anomaly_score: float = round(avg_row[0], 6) if avg_row[0] is not None else 0.0

        return {
            "total_events": total,
            "by_decision": by_decision,
            "by_action_type": by_action_type,
            "by_tool": by_tool,
            "top_denied_tools": top_denied_tools,
            "avg_anomaly_score": avg_anomaly_score,
        }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "AuditStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

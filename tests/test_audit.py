"""Tests for the agentgate audit subsystem (models, store, collector)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agentgate.audit.collector import AuditCollector
from agentgate.audit.models import AuditEvent, AuditQuery
from agentgate.audit.store import AuditStore


# ---------------------------------------------------------------------------
# AuditEvent creation
# ---------------------------------------------------------------------------


class TestAuditEventCreation:
    """Tests for AuditEvent auto-generated fields and validation."""

    def test_auto_event_id(self):
        """event_id should be auto-generated as a UUID-4."""
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
        )
        # Should be a valid UUID
        parsed = uuid.UUID(event.event_id)
        assert parsed.version == 4

    def test_auto_timestamp(self):
        """timestamp should be auto-generated as a recent UTC datetime."""
        before = datetime.now(timezone.utc)
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
        )
        after = datetime.now(timezone.utc)
        assert before <= event.timestamp <= after

    def test_frozen_model(self):
        """AuditEvent should be immutable (frozen)."""
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
        )
        with pytest.raises(ValidationError):
            event.agent_id = "modified"

    def test_default_fields(self):
        """Default fields should have sensible values."""
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
        )
        assert event.tool_name == ""
        assert event.tool_args == {}
        assert event.deny_reason is None
        assert event.result_summary is None
        assert event.duration_ms is None
        assert event.anomaly_score == 0.0
        assert event.anomaly_flags == []
        assert event.signature is None
        assert event.metadata == {}

    def test_full_event(self):
        """Creating a fully populated event should work."""
        event = AuditEvent(
            agent_id="assistant",
            session_id="sess-42",
            action_type="tool_call",
            tool_name="read_file",
            tool_args={"path": "/tmp/data.txt"},
            decision="allowed",
            result_summary="200 bytes read",
            duration_ms=12.5,
            anomaly_score=0.1,
            anomaly_flags=["minor_deviation"],
            metadata={"ip": "127.0.0.1"},
        )
        assert event.tool_name == "read_file"
        assert event.duration_ms == 12.5
        assert event.anomaly_flags == ["minor_deviation"]

    def test_canonical_payload_excludes_signature(self):
        """canonical_payload should not include the signature field."""
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
            signature="abc123hex",
        )
        payload = event.canonical_payload()
        assert "signature" not in payload

    def test_naive_timestamp_normalized_to_utc(self):
        """A naive datetime should be normalized to UTC."""
        naive = datetime(2025, 6, 15, 12, 0, 0)
        event = AuditEvent(
            agent_id="test",
            session_id="sess-1",
            action_type="tool_call",
            decision="allowed",
            timestamp=naive,
        )
        assert event.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# AuditQuery validation
# ---------------------------------------------------------------------------


class TestAuditQueryValidation:
    """Tests for AuditQuery field validation."""

    def test_default_query(self):
        """Default query should have limit=100, offset=0."""
        q = AuditQuery()
        assert q.limit == 100
        assert q.offset == 0

    def test_time_range_valid(self):
        """time_from < time_to should be valid."""
        q = AuditQuery(
            time_from=datetime(2025, 1, 1, tzinfo=timezone.utc),
            time_to=datetime(2025, 12, 31, tzinfo=timezone.utc),
        )
        assert q.time_from < q.time_to

    def test_time_range_inverted_raises(self):
        """time_from > time_to should raise ValueError."""
        with pytest.raises(ValidationError, match="time_from"):
            AuditQuery(
                time_from=datetime(2025, 12, 31, tzinfo=timezone.utc),
                time_to=datetime(2025, 1, 1, tzinfo=timezone.utc),
            )

    def test_limit_too_large(self):
        """limit > 10000 should fail."""
        with pytest.raises(ValidationError):
            AuditQuery(limit=20000)

    def test_limit_zero_fails(self):
        """limit=0 should fail (ge=1)."""
        with pytest.raises(ValidationError):
            AuditQuery(limit=0)

    def test_negative_offset_fails(self):
        """Negative offset should fail."""
        with pytest.raises(ValidationError):
            AuditQuery(offset=-1)

    def test_anomaly_score_bounds(self):
        """min_anomaly_score outside [0, 1] should fail."""
        with pytest.raises(ValidationError):
            AuditQuery(min_anomaly_score=1.5)

        with pytest.raises(ValidationError):
            AuditQuery(min_anomaly_score=-0.1)


# ---------------------------------------------------------------------------
# AuditStore -- record and query
# ---------------------------------------------------------------------------


class TestAuditStore:
    """Tests for AuditStore with a temporary SQLite database."""

    def test_record_and_query(self, temp_db):
        """Recording an event and querying it back should work."""
        with AuditStore(db_path=temp_db) as store:
            event = AuditEvent(
                agent_id="agent-x",
                session_id="sess-1",
                action_type="tool_call",
                tool_name="read_file",
                decision="allowed",
            )
            store.record(event)

            results = store.query(AuditQuery(agent_id="agent-x"))
            assert len(results) == 1
            assert results[0].event_id == event.event_id
            assert results[0].tool_name == "read_file"

    def test_record_batch(self, temp_db, sample_audit_events):
        """Batch recording should insert all events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            count = store.count(AuditQuery())
            assert count == len(sample_audit_events)

    def test_in_memory_store(self):
        """An in-memory store should work for tests."""
        with AuditStore(db_path=":memory:") as store:
            event = AuditEvent(
                agent_id="test",
                session_id="sess-1",
                action_type="tool_call",
                decision="allowed",
            )
            store.record(event)
            assert store.count(AuditQuery()) == 1


# ---------------------------------------------------------------------------
# AuditStore -- filters
# ---------------------------------------------------------------------------


class TestAuditStoreFilters:
    """Tests for AuditStore query filtering."""

    def test_filter_by_agent_id(self, temp_db, sample_audit_events):
        """Filtering by agent_id should return only matching events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            results = store.query(AuditQuery(agent_id="agent-a"))
            assert all(e.agent_id == "agent-a" for e in results)
            assert len(results) == 3

    def test_filter_by_decision(self, temp_db, sample_audit_events):
        """Filtering by decision should return only matching events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            results = store.query(AuditQuery(decision="denied"))
            assert all(e.decision == "denied" for e in results)
            assert len(results) == 2

    def test_filter_by_session_id(self, temp_db, sample_audit_events):
        """Filtering by session_id should return matching events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            results = store.query(AuditQuery(session_id="sess-2"))
            assert all(e.session_id == "sess-2" for e in results)
            assert len(results) == 2

    def test_filter_by_action_type(self, temp_db, sample_audit_events):
        """Filtering by action_type should return matching events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            results = store.query(AuditQuery(action_type="tool_call"))
            assert len(results) == 5  # all are tool_call in fixtures

    def test_filter_by_min_anomaly_score(self, temp_db, sample_audit_events):
        """Filtering by min_anomaly_score should return high-score events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            results = store.query(AuditQuery(min_anomaly_score=0.5))
            assert len(results) == 1
            assert results[0].anomaly_score >= 0.5

    def test_pagination(self, temp_db, sample_audit_events):
        """Limit and offset should paginate results."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            page1 = store.query(AuditQuery(limit=2, offset=0))
            page2 = store.query(AuditQuery(limit=2, offset=2))
            assert len(page1) == 2
            assert len(page2) == 2
            # Pages should not overlap
            page1_ids = {e.event_id for e in page1}
            page2_ids = {e.event_id for e in page2}
            assert page1_ids.isdisjoint(page2_ids)

    def test_count(self, temp_db, sample_audit_events):
        """count() should return the total matching events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            total = store.count(AuditQuery())
            assert total == 5
            denied_count = store.count(AuditQuery(decision="denied"))
            assert denied_count == 2


# ---------------------------------------------------------------------------
# AuditStore -- summary
# ---------------------------------------------------------------------------


class TestAuditStoreSummary:
    """Tests for AuditStore.get_summary."""

    def test_summary_structure(self, temp_db, sample_audit_events):
        """Summary should contain all expected keys."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            summary = store.get_summary(hours=9999)
            assert "total_events" in summary
            assert "by_decision" in summary
            assert "by_action_type" in summary
            assert "by_tool" in summary
            assert "top_denied_tools" in summary
            assert "avg_anomaly_score" in summary

    def test_summary_total(self, temp_db, sample_audit_events):
        """Total events should match the number of recorded events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            summary = store.get_summary(hours=9999)
            assert summary["total_events"] == 5

    def test_summary_by_decision(self, temp_db, sample_audit_events):
        """by_decision should have correct counts."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            summary = store.get_summary(hours=9999)
            assert summary["by_decision"].get("allowed", 0) == 3
            assert summary["by_decision"].get("denied", 0) == 2

    def test_summary_filtered_by_agent(self, temp_db, sample_audit_events):
        """Summary filtered by agent_id should only include that agent's events."""
        with AuditStore(db_path=temp_db) as store:
            store.record_batch(sample_audit_events)
            summary = store.get_summary(agent_id="agent-b", hours=9999)
            assert summary["total_events"] == 2

    def test_summary_empty_store(self, temp_db):
        """Summary of an empty store should return zeros."""
        with AuditStore(db_path=temp_db) as store:
            summary = store.get_summary(hours=9999)
            assert summary["total_events"] == 0
            assert summary["avg_anomaly_score"] == 0.0


# ---------------------------------------------------------------------------
# AuditCollector
# ---------------------------------------------------------------------------


class TestAuditCollector:
    """Tests for AuditCollector collect and retrieve methods."""

    def test_collect_creates_event(self, temp_db):
        """collect() should create and persist an AuditEvent."""
        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store)
            event = collector.collect(
                agent_id="agent-1",
                session_id="sess-1",
                action_type="tool_call",
                tool_name="read_file",
                tool_args={"path": "/tmp/data.txt"},
                decision="allowed",
            )
            assert isinstance(event, AuditEvent)
            assert event.agent_id == "agent-1"
            assert event.tool_name == "read_file"
            assert event.decision == "allowed"

    def test_collect_persists_to_store(self, temp_db):
        """Events created by collect() should be queryable from the store."""
        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store)
            collector.collect(
                agent_id="agent-1",
                session_id="sess-1",
                action_type="tool_call",
                tool_name="write_file",
                tool_args={},
                decision="denied",
                deny_reason="Not allowed",
            )
            results = store.query(AuditQuery(agent_id="agent-1"))
            assert len(results) == 1
            assert results[0].decision == "denied"
            assert results[0].deny_reason == "Not allowed"

    def test_get_session_events(self, temp_db):
        """get_session_events should return events for the given session."""
        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store)
            collector.collect(
                agent_id="a", session_id="s1", action_type="tool_call",
                tool_name="t1", tool_args={}, decision="allowed",
            )
            collector.collect(
                agent_id="a", session_id="s2", action_type="tool_call",
                tool_name="t2", tool_args={}, decision="allowed",
            )
            collector.collect(
                agent_id="a", session_id="s1", action_type="tool_call",
                tool_name="t3", tool_args={}, decision="denied",
            )
            events = collector.get_session_events("s1")
            assert len(events) == 2
            assert all(e.session_id == "s1" for e in events)

    def test_get_agent_events(self, temp_db):
        """get_agent_events should return events for the given agent."""
        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store)
            for i in range(5):
                collector.collect(
                    agent_id="bot",
                    session_id=f"s-{i}",
                    action_type="tool_call",
                    tool_name="read_file",
                    tool_args={},
                    decision="allowed",
                )
            collector.collect(
                agent_id="other",
                session_id="s-x",
                action_type="tool_call",
                tool_name="read_file",
                tool_args={},
                decision="allowed",
            )
            events = collector.get_agent_events("bot", limit=10)
            assert len(events) == 5
            assert all(e.agent_id == "bot" for e in events)

    def test_collect_with_anomaly_data(self, temp_db):
        """collect() should accept anomaly score and flags."""
        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store)
            event = collector.collect(
                agent_id="a",
                session_id="s",
                action_type="tool_call",
                tool_name="t",
                tool_args={},
                decision="allowed",
                anomaly_score=0.75,
                anomaly_flags=["burst_activity"],
            )
            assert event.anomaly_score == 0.75
            assert "burst_activity" in event.anomaly_flags

    def test_collect_with_signer(self, temp_db):
        """When a signer is provided, the event should have a signature."""

        class FakeSigner:
            def sign(self, data: str) -> str:
                return "fake_signature_hex"

        with AuditStore(db_path=temp_db) as store:
            collector = AuditCollector(store=store, signer=FakeSigner())
            event = collector.collect(
                agent_id="a",
                session_id="s",
                action_type="tool_call",
                tool_name="t",
                tool_args={},
                decision="allowed",
            )
            assert event.signature == "fake_signature_hex"

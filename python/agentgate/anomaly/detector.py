"""Statistical anomaly detection for agent behavior.

Tracks per-agent behavioral baselines and scores incoming audit events
against those baselines using a combination of frequency analysis,
sequential pattern detection, and distributional checks.

The anomaly score is a float in [0.0, 1.0] where 0.0 means the event
is completely normal and 1.0 means it is extremely anomalous.  The
``sensitivity`` setting in :class:`~agentgate.policy.schema.AnomalyConfig`
controls how aggressively deviations are flagged.
"""

from __future__ import annotations

import math
import statistics
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agentgate.audit.models import AuditEvent
from agentgate.policy.schema import AnomalyConfig

# ---------------------------------------------------------------------------
# Sensitivity threshold mapping
# ---------------------------------------------------------------------------

_SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "low": 0.8,
    "medium": 0.6,
    "high": 0.4,
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_TIMESTAMPS: int = 1000
_MAX_SESSION_DURATIONS: int = 200
_MIN_SAMPLES_FOR_STATS: int = 5
_Z_SCORE_THRESHOLD: float = 2.0
_NEW_TOOL_SCORE: float = 0.35
_FREQUENCY_SPIKE_SCORE: float = 0.30
_UNUSUAL_ARGS_SCORE: float = 0.15
_SESSION_DURATION_SCORE: float = 0.20
_DENIED_RATE_SCORE: float = 0.25
_SEQUENCE_BREAK_SCORE: float = 0.20


# ---------------------------------------------------------------------------
# Per-agent baseline
# ---------------------------------------------------------------------------


@dataclass
class AgentBaseline:
    """Tracks behavioral statistics for a single agent.

    All mutable collections are bounded to prevent unbounded memory growth.
    """

    # How many times each tool has been invoked.
    tool_usage_counts: dict[str, int] = field(default_factory=dict)

    # Timestamps of the most recent calls (bounded).
    call_timestamps: deque[datetime] = field(
        default_factory=lambda: deque(maxlen=_MAX_TIMESTAMPS)
    )

    # Running statistics for inter-call intervals (milliseconds).
    avg_inter_call_ms: float = 0.0
    std_inter_call_ms: float = 0.0

    # Observed session durations in seconds (bounded).
    session_durations: deque[float] = field(
        default_factory=lambda: deque(maxlen=_MAX_SESSION_DURATIONS)
    )

    # Counters for denied vs total events.
    denied_count: int = 0
    total_count: int = 0

    # Bigram frequencies: (tool_a, tool_b) -> count.
    tool_sequences: dict[tuple[str, str], int] = field(default_factory=dict)

    # Seen argument values per tool, keyed as "tool_name:arg_name".
    arg_value_sets: dict[str, set[Any]] = field(default_factory=dict)

    # The name of the last tool invoked (for bigram tracking).
    _last_tool: str | None = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------


class AnomalyDetector:
    """Detects anomalous agent behavior using statistical methods.

    The detector maintains per-agent baselines and scores each incoming
    :class:`~agentgate.audit.models.AuditEvent` against the accumulated
    history.

    Parameters
    ----------
    config:
        Optional :class:`~agentgate.policy.schema.AnomalyConfig`.  When
        ``None`` a default config with ``sensitivity="medium"`` is used.
    """

    def __init__(self, config: AnomalyConfig | None = None) -> None:
        self._config: AnomalyConfig = config or AnomalyConfig()
        self._threshold: float = _SENSITIVITY_THRESHOLDS.get(
            self._config.sensitivity, _SENSITIVITY_THRESHOLDS["medium"]
        )
        self._baselines: dict[str, AgentBaseline] = {}

    # -- public API ---------------------------------------------------------

    def analyze(self, event: AuditEvent) -> tuple[float, list[str]]:
        """Analyze an event and return ``(anomaly_score, anomaly_flags)``.

        The score is a float in [0.0, 1.0].  Flags are human-readable
        descriptions of the anomalies detected.

        The following checks are performed:

        1. **New tool usage** -- the tool has never been seen for this agent.
        2. **Call frequency spike** -- inter-call time is >2 std deviations
           from the historical mean.
        3. **Unusual arguments** -- argument values not in the historical set.
        4. **Session duration anomaly** -- current session much longer than
           the historical average.
        5. **Denied action rate spike** -- sudden increase in denied actions.
        6. **Sequential pattern break** -- unexpected tool call ordering
           (bigram never or rarely observed).
        """
        agent_id = event.agent_id
        baseline = self._ensure_baseline(agent_id)
        flags: list[str] = []
        raw_score: float = 0.0

        # 1. New tool usage
        new_tool_score, new_tool_flag = self._check_new_tool(event, baseline)
        raw_score += new_tool_score
        if new_tool_flag:
            flags.append(new_tool_flag)

        # 2. Call frequency spike
        freq_score, freq_flag = self._check_frequency_spike(event, baseline)
        raw_score += freq_score
        if freq_flag:
            flags.append(freq_flag)

        # 3. Unusual arguments
        args_score, args_flags = self._check_unusual_args(event, baseline)
        raw_score += args_score
        flags.extend(args_flags)

        # 4. Session duration anomaly
        dur_score, dur_flag = self._check_session_duration(event, baseline)
        raw_score += dur_score
        if dur_flag:
            flags.append(dur_flag)

        # 5. Denied action rate spike
        denied_score, denied_flag = self._check_denied_rate(event, baseline)
        raw_score += denied_score
        if denied_flag:
            flags.append(denied_flag)

        # 6. Sequential pattern break
        seq_score, seq_flag = self._check_sequence_break(event, baseline)
        raw_score += seq_score
        if seq_flag:
            flags.append(seq_flag)

        # Clamp to [0.0, 1.0].
        anomaly_score = min(1.0, max(0.0, raw_score))

        # Apply sensitivity: only keep flags if the score meets the
        # threshold.  A *lower* threshold (high sensitivity) keeps more.
        if anomaly_score < (1.0 - self._threshold):
            flags = []
            anomaly_score = anomaly_score * 0.5  # dampen below-threshold scores

        # Update the baseline *after* analysis so the current event is
        # scored against the prior history.
        self.update_baseline(agent_id, event)

        return round(anomaly_score, 4), flags

    def update_baseline(self, agent_id: str, event: AuditEvent) -> None:
        """Update the agent's behavioral baseline with *event*."""
        baseline = self._ensure_baseline(agent_id)
        tool = event.tool_name or event.action_type

        # Tool counts
        baseline.tool_usage_counts[tool] = (
            baseline.tool_usage_counts.get(tool, 0) + 1
        )

        # Timestamps and inter-call stats
        baseline.call_timestamps.append(event.timestamp)
        self._recompute_inter_call_stats(baseline)

        # Session duration (stored in metadata by convention)
        session_dur = event.metadata.get("session_duration_seconds")
        if session_dur is not None:
            try:
                baseline.session_durations.append(float(session_dur))
            except (TypeError, ValueError):
                pass

        # Denied / total
        baseline.total_count += 1
        if event.decision == "denied":
            baseline.denied_count += 1

        # Bigram tracking
        if baseline._last_tool is not None:
            bigram = (baseline._last_tool, tool)
            baseline.tool_sequences[bigram] = (
                baseline.tool_sequences.get(bigram, 0) + 1
            )
        baseline._last_tool = tool

        # Argument value tracking
        if event.tool_args:
            for arg_name, arg_value in event.tool_args.items():
                key = f"{tool}:{arg_name}"
                if key not in baseline.arg_value_sets:
                    baseline.arg_value_sets[key] = set()
                # Only track hashable values.
                try:
                    hashable_val = (
                        arg_value
                        if isinstance(arg_value, (str, int, float, bool, type(None)))
                        else str(arg_value)
                    )
                    baseline.arg_value_sets[key].add(hashable_val)
                except TypeError:
                    baseline.arg_value_sets[key].add(str(arg_value))

    def get_baseline(self, agent_id: str) -> dict[str, Any]:
        """Return current baseline stats for *agent_id* as a plain dict.

        Returns an empty dict if no baseline exists for the agent.
        """
        if agent_id not in self._baselines:
            return {}
        bl = self._baselines[agent_id]
        return {
            "tool_usage_counts": dict(bl.tool_usage_counts),
            "call_count": len(bl.call_timestamps),
            "avg_inter_call_ms": round(bl.avg_inter_call_ms, 2),
            "std_inter_call_ms": round(bl.std_inter_call_ms, 2),
            "session_durations_count": len(bl.session_durations),
            "denied_count": bl.denied_count,
            "total_count": bl.total_count,
            "unique_sequences": len(bl.tool_sequences),
            "tracked_arg_keys": list(bl.arg_value_sets.keys()),
        }

    def reset_baseline(self, agent_id: str) -> None:
        """Reset all baseline data for *agent_id*.

        If no baseline exists this is a no-op.
        """
        self._baselines.pop(agent_id, None)

    # -- internal helpers ---------------------------------------------------

    def _ensure_baseline(self, agent_id: str) -> AgentBaseline:
        """Return the baseline for *agent_id*, creating one if needed."""
        if agent_id not in self._baselines:
            self._baselines[agent_id] = AgentBaseline()
        return self._baselines[agent_id]

    @staticmethod
    def _recompute_inter_call_stats(baseline: AgentBaseline) -> None:
        """Recompute the running mean / std of inter-call times."""
        timestamps = baseline.call_timestamps
        if len(timestamps) < 2:
            return
        intervals: list[float] = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds() * 1000.0
            intervals.append(delta)
        baseline.avg_inter_call_ms = statistics.mean(intervals)
        baseline.std_inter_call_ms = (
            statistics.stdev(intervals) if len(intervals) >= 2 else 0.0
        )

    # -- individual checks --------------------------------------------------

    @staticmethod
    def _check_new_tool(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, str | None]:
        """Check whether the agent is using a tool for the first time."""
        tool = event.tool_name or event.action_type
        if baseline.total_count > 0 and tool not in baseline.tool_usage_counts:
            return _NEW_TOOL_SCORE, f"new_tool:{tool}"
        return 0.0, None

    @staticmethod
    def _check_frequency_spike(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, str | None]:
        """Check whether the call frequency deviates significantly."""
        if (
            len(baseline.call_timestamps) < _MIN_SAMPLES_FOR_STATS
            or baseline.std_inter_call_ms == 0.0
        ):
            return 0.0, None

        last_ts = baseline.call_timestamps[-1]
        delta_ms = (event.timestamp - last_ts).total_seconds() * 1000.0

        # A very short inter-call time (well below mean) indicates a spike.
        if delta_ms < 0:
            # Timestamps out of order -- skip check.
            return 0.0, None

        z_score = (baseline.avg_inter_call_ms - delta_ms) / baseline.std_inter_call_ms
        if z_score > _Z_SCORE_THRESHOLD:
            return _FREQUENCY_SPIKE_SCORE, (
                f"frequency_spike:z={z_score:.1f},"
                f"interval_ms={delta_ms:.0f},"
                f"mean={baseline.avg_inter_call_ms:.0f}"
            )
        return 0.0, None

    @staticmethod
    def _check_unusual_args(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, list[str]]:
        """Check whether any argument values are outside the historical set."""
        if not event.tool_args:
            return 0.0, []

        tool = event.tool_name or event.action_type
        flags: list[str] = []
        unseen_count = 0
        total_checked = 0

        for arg_name, arg_value in event.tool_args.items():
            key = f"{tool}:{arg_name}"
            historical = baseline.arg_value_sets.get(key)
            if historical is None or len(historical) < _MIN_SAMPLES_FOR_STATS:
                # Not enough data to judge.
                continue
            total_checked += 1
            try:
                hashable_val = (
                    arg_value
                    if isinstance(arg_value, (str, int, float, bool, type(None)))
                    else str(arg_value)
                )
                if hashable_val not in historical:
                    unseen_count += 1
                    flags.append(f"unusual_arg:{tool}.{arg_name}")
            except TypeError:
                pass

        if total_checked == 0 or unseen_count == 0:
            return 0.0, []

        # Scale score by proportion of unusual args.
        proportion = unseen_count / total_checked
        return round(_UNUSUAL_ARGS_SCORE * proportion, 4), flags

    @staticmethod
    def _check_session_duration(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, str | None]:
        """Check whether the current session duration is anomalous."""
        current_dur = event.metadata.get("session_duration_seconds")
        if current_dur is None:
            return 0.0, None
        try:
            current_dur = float(current_dur)
        except (TypeError, ValueError):
            return 0.0, None

        if len(baseline.session_durations) < _MIN_SAMPLES_FOR_STATS:
            return 0.0, None

        durations = list(baseline.session_durations)
        mean_dur = statistics.mean(durations)
        std_dur = statistics.stdev(durations) if len(durations) >= 2 else 0.0

        if std_dur == 0.0:
            # All previous durations were identical.  Flag if current is
            # significantly different (>50% longer).
            if current_dur > mean_dur * 1.5:
                return _SESSION_DURATION_SCORE, (
                    f"session_duration_anomaly:"
                    f"current={current_dur:.0f}s,"
                    f"mean={mean_dur:.0f}s"
                )
            return 0.0, None

        z = (current_dur - mean_dur) / std_dur
        if z > _Z_SCORE_THRESHOLD:
            return _SESSION_DURATION_SCORE, (
                f"session_duration_anomaly:"
                f"z={z:.1f},"
                f"current={current_dur:.0f}s,"
                f"mean={mean_dur:.0f}s"
            )
        return 0.0, None

    @staticmethod
    def _check_denied_rate(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, str | None]:
        """Check whether the rate of denied actions is spiking."""
        if baseline.total_count < _MIN_SAMPLES_FOR_STATS:
            return 0.0, None

        historical_rate = baseline.denied_count / baseline.total_count

        # Look at the recent window (last 20 events worth of data).
        # We approximate by checking if a denied event would push the
        # rate significantly above the historical norm.
        if event.decision != "denied":
            return 0.0, None

        # Simulate adding this denied event.
        new_denied = baseline.denied_count + 1
        new_total = baseline.total_count + 1
        new_rate = new_denied / new_total

        # Flag if the new rate is more than double the historical rate
        # and the absolute rate is non-trivial.
        if historical_rate == 0.0:
            # First denial ever -- always flag.
            if new_total >= _MIN_SAMPLES_FOR_STATS:
                return _DENIED_RATE_SCORE, (
                    f"denied_rate_spike:"
                    f"first_denial_after_{baseline.total_count}_events"
                )
            return 0.0, None

        if new_rate > historical_rate * 2.0 and new_rate > 0.1:
            return _DENIED_RATE_SCORE, (
                f"denied_rate_spike:"
                f"rate={new_rate:.2f},"
                f"historical={historical_rate:.2f}"
            )
        return 0.0, None

    @staticmethod
    def _check_sequence_break(
        event: AuditEvent, baseline: AgentBaseline
    ) -> tuple[float, str | None]:
        """Check whether the tool call ordering is unexpected."""
        if baseline._last_tool is None:
            return 0.0, None

        if not baseline.tool_sequences:
            return 0.0, None

        tool = event.tool_name or event.action_type
        bigram = (baseline._last_tool, tool)

        if bigram not in baseline.tool_sequences:
            # This transition has never been observed.  Only flag it if
            # we have enough historical sequences to consider the
            # absence meaningful.
            total_transitions = sum(baseline.tool_sequences.values())
            if total_transitions >= _MIN_SAMPLES_FOR_STATS:
                return _SEQUENCE_BREAK_SCORE, (
                    f"sequence_break:{baseline._last_tool}->{tool}"
                )
        else:
            # The transition exists but might be very rare.
            total_from_last = sum(
                count
                for (src, _), count in baseline.tool_sequences.items()
                if src == baseline._last_tool
            )
            if total_from_last >= _MIN_SAMPLES_FOR_STATS:
                ratio = baseline.tool_sequences[bigram] / total_from_last
                if ratio < 0.05:
                    return round(_SEQUENCE_BREAK_SCORE * 0.5, 4), (
                        f"rare_sequence:{baseline._last_tool}->{tool}"
                        f"(freq={ratio:.2f})"
                    )
        return 0.0, None

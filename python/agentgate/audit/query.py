"""Query utilities and export helpers for AgentGate audit events.

Provides human-readable formatting (Rich-compatible tables and plain text)
as well as JSON and CSV export for further analysis.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any

from agentgate.audit.models import AuditEvent


# ----------------------------------------------------------------------
# Formatting helpers
# ----------------------------------------------------------------------

def format_events_table(events: list[AuditEvent]) -> str:
    """Format a list of audit events as a Rich-compatible table string.

    The output uses Rich markup so that it can be printed directly via
    ``rich.console.Console().print()`` or simply written to a terminal
    for a lightweight plain-text representation.

    Columns: Timestamp, Event ID (short), Agent, Session (short),
    Action, Tool, Decision, Anomaly.
    """
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover – graceful degradation
        return _format_events_plain(events)

    table = Table(
        title="Audit Events",
        show_lines=False,
        pad_edge=True,
        expand=False,
    )
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Event ID", style="cyan", no_wrap=True)
    table.add_column("Agent", style="green")
    table.add_column("Session", style="green", no_wrap=True)
    table.add_column("Action", style="magenta")
    table.add_column("Tool", style="yellow")
    table.add_column("Decision", no_wrap=True)
    table.add_column("Anomaly", justify="right")

    for evt in events:
        decision_style = {
            "allowed": "[bold green]allowed[/bold green]",
            "denied": "[bold red]denied[/bold red]",
            "rate_limited": "[bold yellow]rate_limited[/bold yellow]",
        }.get(evt.decision, evt.decision)

        anomaly_str = f"{evt.anomaly_score:.2f}"
        if evt.anomaly_score >= 0.8:
            anomaly_str = f"[bold red]{anomaly_str}[/bold red]"
        elif evt.anomaly_score >= 0.5:
            anomaly_str = f"[yellow]{anomaly_str}[/yellow]"

        table.add_row(
            evt.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            evt.event_id[:8],
            evt.agent_id,
            evt.session_id[:8],
            evt.action_type,
            evt.tool_name,
            decision_style,
            anomaly_str,
        )

    console = Console(file=StringIO(), force_terminal=True, width=140)
    console.print(table)
    return console.file.getvalue()  # type: ignore[union-attr]


def _format_events_plain(events: list[AuditEvent]) -> str:
    """Minimal plain-text fallback when Rich is not installed."""
    header = (
        f"{'Timestamp':<20} {'Event ID':<10} {'Agent':<16} {'Session':<10} "
        f"{'Action':<16} {'Tool':<20} {'Decision':<10} {'Anomaly':>7}"
    )
    lines = [header, "-" * len(header)]
    for evt in events:
        lines.append(
            f"{evt.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<20} "
            f"{evt.event_id[:8]:<10} "
            f"{evt.agent_id:<16} "
            f"{evt.session_id[:8]:<10} "
            f"{evt.action_type:<16} "
            f"{evt.tool_name:<20} "
            f"{evt.decision:<10} "
            f"{evt.anomaly_score:>7.2f}"
        )
    return "\n".join(lines)


def format_summary(summary: dict[str, Any]) -> str:
    """Format a summary dictionary (from ``AuditStore.get_summary``) as readable text.

    Returns a multi-line string suitable for terminal display.
    """
    lines: list[str] = []
    lines.append("=== Audit Summary ===")
    lines.append(f"Total events: {summary.get('total_events', 0)}")
    lines.append(f"Avg anomaly score: {summary.get('avg_anomaly_score', 0.0):.4f}")
    lines.append("")

    lines.append("By decision:")
    for decision, count in sorted(summary.get("by_decision", {}).items()):
        lines.append(f"  {decision:<12} {count}")
    lines.append("")

    lines.append("By action type:")
    for action, count in sorted(summary.get("by_action_type", {}).items()):
        lines.append(f"  {action:<24} {count}")
    lines.append("")

    lines.append("By tool:")
    for tool, count in sorted(
        summary.get("by_tool", {}).items(), key=lambda kv: kv[1], reverse=True
    ):
        lines.append(f"  {tool:<30} {count}")
    lines.append("")

    top_denied = summary.get("top_denied_tools", [])
    if top_denied:
        lines.append("Top denied tools:")
        for entry in top_denied:
            lines.append(f"  {entry['tool_name']:<30} {entry['count']}")
    else:
        lines.append("Top denied tools: (none)")

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Export helpers
# ----------------------------------------------------------------------

def export_events_json(events: list[AuditEvent], path: str) -> None:
    """Export audit events to a JSON file.

    Each event is serialised using its Pydantic ``model_dump`` method with
    ISO-formatted timestamps for maximum interoperability.

    Parameters
    ----------
    events:
        The events to export.
    path:
        Destination file path (will be overwritten if it exists).
    """
    payload = [
        event.model_dump(mode="json")
        for event in events
    ]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str, ensure_ascii=False)


def export_events_csv(events: list[AuditEvent], path: str) -> None:
    """Export audit events to a CSV file.

    JSON-typed fields (``tool_args``, ``anomaly_flags``, ``metadata``) are
    serialised as JSON strings within their respective CSV cells.

    Parameters
    ----------
    events:
        The events to export.
    path:
        Destination file path (will be overwritten if it exists).
    """
    fieldnames = [
        "event_id",
        "timestamp",
        "agent_id",
        "session_id",
        "action_type",
        "tool_name",
        "tool_args",
        "decision",
        "deny_reason",
        "result_summary",
        "duration_ms",
        "anomaly_score",
        "anomaly_flags",
        "signature",
        "metadata",
    ]

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = event.model_dump(mode="json")
            # Ensure complex fields are JSON-encoded strings.
            row["tool_args"] = json.dumps(row["tool_args"], default=str)
            row["anomaly_flags"] = json.dumps(row["anomaly_flags"])
            row["metadata"] = json.dumps(row["metadata"], default=str)
            writer.writerow(row)

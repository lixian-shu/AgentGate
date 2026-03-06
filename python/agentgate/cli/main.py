"""AgentGate CLI -- Typer-based command-line interface with Rich output.

Provides commands for policy management, audit log inspection, security
scanning, and report generation.

Usage::

    agentgate init --template default
    agentgate check policy.yaml
    agentgate audit --last 24h --decision denied
    agentgate report --last 7d
    agentgate scan ./my-agent-project
    agentgate proxy --policy policy.yaml --upstream http://localhost:3000
"""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Optional

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from agentgate.audit.models import AuditEvent, AuditQuery
from agentgate.audit.store import AuditStore
from agentgate.policy.defaults import (
    DEFAULT_POLICY,
    DEVELOPMENT_POLICY,
    PERMISSIVE_POLICY,
)
from agentgate.policy.loader import load_policy, validate_policy_file
from agentgate.policy.schema import AgentGatePolicy

# ---------------------------------------------------------------------------
# Application and console
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="agentgate",
    help="AgentGate -- Security gateway for AI agents.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VERSION = "0.1.0"
_DEFAULT_POLICY_FILENAME = "agentgate.yaml"
_DEFAULT_AUDIT_DB = "agentgate_audit.db"

_TEMPLATES: dict[str, dict[str, Any]] = {
    "default": DEFAULT_POLICY,
    "permissive": PERMISSIVE_POLICY,
    "development": DEVELOPMENT_POLICY,
}

# OWASP Agentic AI Top 10 (2025) mapping for scan findings
_OWASP_MAPPING: dict[str, dict[str, str]] = {
    "no_policy_file": {
        "id": "OWASP-AGENT-01",
        "title": "Excessive Agency",
        "description": "No policy file found -- agents operate without constraints.",
    },
    "unrestricted_tools": {
        "id": "OWASP-AGENT-01",
        "title": "Excessive Agency",
        "description": "Tool definitions found without AgentGate protection.",
    },
    "filesystem_access": {
        "id": "OWASP-AGENT-03",
        "title": "Insecure Output Handling",
        "description": "Unrestricted filesystem access patterns detected.",
    },
    "network_unrestricted": {
        "id": "OWASP-AGENT-05",
        "title": "Improper Access Control",
        "description": "Network calls without domain restrictions.",
    },
    "no_rate_limits": {
        "id": "OWASP-AGENT-04",
        "title": "Denial of Service",
        "description": "No rate limits configured for tool usage.",
    },
    "prompt_injection_risk": {
        "id": "OWASP-AGENT-02",
        "title": "Prompt Injection",
        "description": "User input passed directly to agent without sanitisation.",
    },
}

# Severity styles
_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "blue",
    "LOW": "dim",
}

# Agent framework imports to look for
_AGENT_FRAMEWORKS: dict[str, str] = {
    "langchain": "LangChain",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "llama_index": "LlamaIndex",
    "openai": "OpenAI Agents",
    "anthropic": "Anthropic",
    "smolagents": "SmolAgents",
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _parse_time_window(window: str) -> timedelta:
    """Parse a human-friendly time window string into a timedelta.

    Supported formats:
        "30m" -- 30 minutes
        "1h"  -- 1 hour
        "24h" -- 24 hours
        "7d"  -- 7 days
        "2w"  -- 2 weeks

    Raises
    ------
    typer.BadParameter
        If the format is not recognised.
    """
    match = re.fullmatch(r"(\d+)\s*([mhdw])", window.strip().lower())
    if not match:
        raise typer.BadParameter(
            f"Invalid time window '{window}'. Use format like 1h, 24h, 7d, 2w."
        )

    amount = int(match.group(1))
    unit = match.group(2)

    multipliers = {
        "m": timedelta(minutes=1),
        "h": timedelta(hours=1),
        "d": timedelta(days=1),
        "w": timedelta(weeks=1),
    }

    return multipliers[unit] * amount


def _policy_summary(policy: AgentGatePolicy) -> dict[str, Any]:
    """Extract a human-readable summary from a validated policy."""
    agent_count = len(policy.agents)
    total_allowed = 0
    total_denied = 0
    total_rate_limits = 0
    has_filesystem = False
    has_network = False

    for agent_policy in policy.agents.values():
        if agent_policy.tools:
            total_allowed += len(agent_policy.tools.allowed)
            total_denied += len(agent_policy.tools.denied)
            for tool in agent_policy.tools.allowed:
                if tool.rate_limit:
                    total_rate_limits += 1
        if agent_policy.resources:
            if agent_policy.resources.filesystem:
                has_filesystem = True
            if agent_policy.resources.network:
                has_network = True

    return {
        "agents": agent_count,
        "allowed_tool_rules": total_allowed,
        "denied_tool_rules": total_denied,
        "rate_limits": total_rate_limits,
        "filesystem_rules": has_filesystem,
        "network_rules": has_network,
        "audit_enabled": policy.audit.enabled,
        "anomaly_enabled": policy.anomaly.enabled,
    }


def _decision_style(decision: str) -> str:
    """Return a Rich-styled string for a decision value."""
    styles = {
        "allowed": "[bold green]ALLOWED[/bold green]",
        "denied": "[bold red]DENIED[/bold red]",
        "rate_limited": "[bold yellow]RATE_LIMITED[/bold yellow]",
    }
    return styles.get(decision, decision.upper())


def _severity_text(severity: str) -> Text:
    """Return a Rich Text object styled for the given severity."""
    style = _SEVERITY_STYLE.get(severity.upper(), "")
    return Text(severity.upper(), style=style)


def _letter_grade(score: int) -> tuple[str, str]:
    """Return a letter grade and style based on score 0-100."""
    if score >= 90:
        return "A", "bold green"
    elif score >= 80:
        return "B", "green"
    elif score >= 70:
        return "C", "yellow"
    elif score >= 60:
        return "D", "bold yellow"
    else:
        return "F", "bold red"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def init(
    template: str = typer.Option(
        "default",
        "--template",
        "-t",
        help="Policy template: default, permissive, or development.",
    ),
    output: str = typer.Option(
        _DEFAULT_POLICY_FILENAME,
        "--output",
        "-o",
        help="Output file name for the generated policy.",
    ),
) -> None:
    """Create a default AgentGate policy file in the current directory."""

    if template not in _TEMPLATES:
        err_console.print(
            f"[bold red]Error:[/bold red] Unknown template '{escape(template)}'. "
            f"Choose from: {', '.join(_TEMPLATES.keys())}"
        )
        raise typer.Exit(code=1)

    output_path = Path(output)

    if output_path.exists():
        overwrite = typer.confirm(
            f"File '{output}' already exists. Overwrite?", default=False
        )
        if not overwrite:
            console.print("[dim]Aborted.[/dim]")
            raise typer.Exit(code=0)

    policy_data = _TEMPLATES[template]

    # Write as YAML with a header comment
    yaml_content = (
        f"# AgentGate Policy File\n"
        f"# Template: {template}\n"
        f"# Generated by: agentgate init\n"
        f"# Documentation: https://agentgate.dev/docs/policy\n"
        f"#\n"
        f"# Modify this file to define security policies for your AI agents.\n"
        f"# See https://agentgate.dev/docs/policy-reference for all options.\n"
        f"\n"
    )
    yaml_content += yaml.dump(
        policy_data,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    output_path.write_text(yaml_content, encoding="utf-8")

    # Display success panel
    console.print()
    console.print(
        Panel(
            f"[bold green]Policy file created:[/bold green] {output_path}\n"
            f"[dim]Template:[/dim] {template}\n"
            f"\n"
            f"[bold]Next steps:[/bold]\n"
            f"  1. Edit [cyan]{output_path}[/cyan] to add your agent definitions\n"
            f"  2. Run [cyan]agentgate check {output_path}[/cyan] to validate\n"
            f"  3. Import AgentGate in your agent code:\n"
            f"     [dim]from agentgate import AgentGate[/dim]\n"
            f"     [dim]gate = AgentGate(policy=\"{output_path}\")[/dim]",
            title="[bold]AgentGate Initialised[/bold]",
            border_style="green",
            padding=(1, 2),
        )
    )


@app.command()
def check(
    policy_file: str = typer.Argument(
        ...,
        help="Path to the YAML policy file to validate.",
    ),
) -> None:
    """Validate an AgentGate policy YAML file."""

    filepath = Path(policy_file)

    if not filepath.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] File not found: {escape(str(filepath))}"
        )
        raise typer.Exit(code=1)

    # Run validation
    issues = validate_policy_file(filepath)

    errors = [i for i in issues if i.startswith("error:")]
    warnings = [i for i in issues if i.startswith("warning:")]

    if errors:
        console.print()
        console.print(
            Panel(
                "[bold red]Policy validation failed[/bold red]",
                border_style="red",
            )
        )
        console.print()
        for err in errors:
            console.print(f"  [red]x[/red] {err.removeprefix('error: ')}")
        if warnings:
            console.print()
            for warn in warnings:
                console.print(
                    f"  [yellow]![/yellow] {warn.removeprefix('warning: ')}"
                )
        console.print()
        raise typer.Exit(code=1)

    # Successfully parsed -- show summary
    try:
        policy = load_policy(filepath)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    summary = _policy_summary(policy)

    console.print()
    console.print(
        Panel(
            "[bold green]Policy is valid[/bold green]",
            border_style="green",
        )
    )
    console.print()

    # Summary table
    summary_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        expand=False,
    )
    summary_table.add_column("Key", style="bold")
    summary_table.add_column("Value")

    summary_table.add_row("File", str(filepath))
    summary_table.add_row("Version", policy.version)
    summary_table.add_row(
        "Description", policy.description or "[dim]none[/dim]"
    )
    summary_table.add_row("Agents", str(summary["agents"]))
    summary_table.add_row("Allowed tool rules", str(summary["allowed_tool_rules"]))
    summary_table.add_row("Denied tool rules", str(summary["denied_tool_rules"]))
    summary_table.add_row("Rate limits", str(summary["rate_limits"]))
    summary_table.add_row(
        "Filesystem rules",
        "[green]yes[/green]" if summary["filesystem_rules"] else "[dim]no[/dim]",
    )
    summary_table.add_row(
        "Network rules",
        "[green]yes[/green]" if summary["network_rules"] else "[dim]no[/dim]",
    )
    summary_table.add_row(
        "Audit",
        "[green]enabled[/green]" if summary["audit_enabled"] else "[red]disabled[/red]",
    )
    summary_table.add_row(
        "Anomaly detection",
        "[green]enabled[/green]"
        if summary["anomaly_enabled"]
        else "[dim]disabled[/dim]",
    )

    console.print(summary_table)

    # Warnings
    if warnings:
        console.print()
        for warn in warnings:
            console.print(
                f"  [yellow]![/yellow] {warn.removeprefix('warning: ')}"
            )

    console.print()
    raise typer.Exit(code=0)


@app.command()
def audit(
    db: str = typer.Option(
        _DEFAULT_AUDIT_DB,
        "--db",
        help="Path to the SQLite audit database.",
    ),
    agent: Optional[str] = typer.Option(
        None, "--agent", "-a", help="Filter by agent ID."
    ),
    session: Optional[str] = typer.Option(
        None, "--session", "-s", help="Filter by session ID."
    ),
    last: Optional[str] = typer.Option(
        None,
        "--last",
        "-l",
        help="Time window (e.g. 1h, 24h, 7d).",
    ),
    decision: Optional[str] = typer.Option(
        None,
        "--decision",
        "-d",
        help="Filter by decision: allowed, denied, rate_limited.",
    ),
    tool: Optional[str] = typer.Option(
        None, "--tool", help="Filter by tool name (supports glob patterns)."
    ),
    limit: int = typer.Option(
        50, "--limit", "-n", help="Maximum number of results.", min=1, max=10000
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, csv.",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path (for json/csv export)."
    ),
) -> None:
    """Query and display audit logs from the SQLite database."""

    db_path = Path(db)
    if not db_path.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] Audit database not found: "
            f"{escape(str(db_path))}\n"
            f"[dim]Hint: Specify the path with --db or ensure AgentGate has been "
            f"run with audit enabled.[/dim]"
        )
        raise typer.Exit(code=1)

    # Validate decision filter
    valid_decisions = {"allowed", "denied", "rate_limited"}
    if decision is not None and decision not in valid_decisions:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid decision '{escape(decision)}'. "
            f"Choose from: {', '.join(sorted(valid_decisions))}"
        )
        raise typer.Exit(code=1)

    # Validate format
    valid_formats = {"table", "json", "csv"}
    if format not in valid_formats:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid format '{escape(format)}'. "
            f"Choose from: {', '.join(sorted(valid_formats))}"
        )
        raise typer.Exit(code=1)

    # Build query
    time_from: Optional[datetime] = None
    if last is not None:
        delta = _parse_time_window(last)
        time_from = datetime.now(timezone.utc) - delta

    query = AuditQuery(
        agent_id=agent,
        session_id=session,
        decision=decision,  # type: ignore[arg-type]
        tool_name=tool,
        time_from=time_from,
        limit=limit,
    )

    # Execute query
    try:
        store = AuditStore(db_path)
    except Exception as exc:
        err_console.print(
            f"[bold red]Error:[/bold red] Failed to open database: {exc}"
        )
        raise typer.Exit(code=1)

    try:
        events = store.query(query)
        total_count = store.count(query)
    finally:
        store.close()

    if not events:
        console.print("[dim]No audit events found matching the given filters.[/dim]")
        raise typer.Exit(code=0)

    # --- Output ---

    if format == "json":
        _output_json(events, output)
    elif format == "csv":
        _output_csv(events, output)
    else:
        _output_table(events, total_count, limit)


def _output_table(events: list[AuditEvent], total_count: int, limit: int) -> None:
    """Render audit events as a Rich table."""
    table = Table(
        title=f"Audit Events ({len(events)} of {total_count})",
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
        styled_decision = _decision_style(evt.decision)

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
            evt.tool_name or "[dim]-[/dim]",
            styled_decision,
            anomaly_str,
        )

    console.print()
    console.print(table)
    if total_count > limit:
        console.print(
            f"\n[dim]Showing {len(events)} of {total_count} results. "
            f"Use --limit to see more.[/dim]"
        )
    console.print()


def _output_json(events: list[AuditEvent], output_path: Optional[str]) -> None:
    """Export audit events as JSON."""
    payload = [event.model_dump(mode="json") for event in events]
    json_str = json.dumps(payload, indent=2, default=str, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")
        console.print(
            f"[green]Exported {len(events)} events to {escape(output_path)}[/green]"
        )
    else:
        console.print(json_str)


def _output_csv(events: list[AuditEvent], output_path: Optional[str]) -> None:
    """Export audit events as CSV."""
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

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for event in events:
        row = event.model_dump(mode="json")
        row["tool_args"] = json.dumps(row["tool_args"], default=str)
        row["anomaly_flags"] = json.dumps(row["anomaly_flags"])
        row["metadata"] = json.dumps(row["metadata"], default=str)
        writer.writerow(row)

    csv_str = buffer.getvalue()

    if output_path:
        Path(output_path).write_text(csv_str, encoding="utf-8")
        console.print(
            f"[green]Exported {len(events)} events to {escape(output_path)}[/green]"
        )
    else:
        console.print(csv_str)


@app.command()
def report(
    db: str = typer.Option(
        _DEFAULT_AUDIT_DB,
        "--db",
        help="Path to the SQLite audit database.",
    ),
    agent: Optional[str] = typer.Option(
        None, "--agent", "-a", help="Filter report to a specific agent."
    ),
    last: str = typer.Option(
        "24h",
        "--last",
        "-l",
        help="Time window for the report (e.g. 1h, 24h, 7d).",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    """Generate a security summary report from audit data."""

    db_path = Path(db)
    if not db_path.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] Audit database not found: "
            f"{escape(str(db_path))}"
        )
        raise typer.Exit(code=1)

    if format not in {"text", "json"}:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid format '{escape(format)}'. "
            f"Choose from: text, json."
        )
        raise typer.Exit(code=1)

    delta = _parse_time_window(last)
    hours = max(1, int(delta.total_seconds() / 3600))

    try:
        store = AuditStore(db_path)
    except Exception as exc:
        err_console.print(
            f"[bold red]Error:[/bold red] Failed to open database: {exc}"
        )
        raise typer.Exit(code=1)

    try:
        summary = store.get_summary(agent_id=agent, hours=hours)

        # Also get recent high-anomaly events for extra insight
        anomaly_query = AuditQuery(
            agent_id=agent,
            min_anomaly_score=0.5,
            time_from=datetime.now(timezone.utc) - delta,
            limit=100,
        )
        anomaly_events = store.query(anomaly_query)
    finally:
        store.close()

    # Build report data
    total = summary["total_events"]
    by_decision = summary["by_decision"]
    by_tool = summary["by_tool"]
    top_denied = summary["top_denied_tools"]
    avg_anomaly = summary["avg_anomaly_score"]

    allowed_count = by_decision.get("allowed", 0)
    denied_count = by_decision.get("denied", 0)
    rate_limited_count = by_decision.get("rate_limited", 0)
    denial_rate = (denied_count / total * 100) if total > 0 else 0.0

    # Recommendations
    recommendations: list[str] = []
    if denial_rate > 30:
        recommendations.append(
            "High denial rate ({:.1f}%). Review denied tool rules -- agents may "
            "need broader permissions or the policy may be too restrictive.".format(
                denial_rate
            )
        )
    if avg_anomaly > 0.3:
        recommendations.append(
            f"Elevated average anomaly score ({avg_anomaly:.3f}). "
            "Investigate flagged events for potential security issues."
        )
    if not by_decision:
        recommendations.append(
            "No events recorded in the time window. Verify audit is enabled "
            "and agents are routing through AgentGate."
        )
    if len(anomaly_events) > 10:
        recommendations.append(
            f"{len(anomaly_events)} high-anomaly events detected. "
            "Consider increasing monitoring sensitivity or setting up webhook alerts."
        )
    if denied_count == 0 and total > 0:
        recommendations.append(
            "Zero denials recorded. Verify that deny rules are configured -- "
            "a fully permissive policy may indicate misconfiguration."
        )
    if not recommendations:
        recommendations.append("No issues detected. Policy is operating normally.")

    report_data = {
        "time_window": last,
        "agent_filter": agent,
        "total_events": total,
        "decisions": {
            "allowed": allowed_count,
            "denied": denied_count,
            "rate_limited": rate_limited_count,
        },
        "denial_rate_percent": round(denial_rate, 2),
        "top_tools": dict(
            sorted(by_tool.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ),
        "top_denied_tools": top_denied,
        "anomaly_stats": {
            "avg_score": avg_anomaly,
            "high_anomaly_events": len(anomaly_events),
        },
        "recommendations": recommendations,
    }

    if format == "json":
        console.print(json.dumps(report_data, indent=2, default=str))
        raise typer.Exit(code=0)

    # --- Rich text report ---

    console.print()

    # Header
    title_text = f"Security Report -- Last {last}"
    if agent:
        title_text += f" -- Agent: {agent}"
    console.print(
        Panel(
            f"[bold]{title_text}[/bold]",
            border_style="blue",
        )
    )

    # Decision breakdown
    console.print()
    console.print("[bold]Event Summary[/bold]")
    decision_table = Table(show_header=True, box=None, padding=(0, 2))
    decision_table.add_column("Metric", style="bold")
    decision_table.add_column("Value", justify="right")
    decision_table.add_row("Total events", str(total))
    decision_table.add_row(
        "Allowed", f"[green]{allowed_count}[/green]"
    )
    decision_table.add_row(
        "Denied", f"[red]{denied_count}[/red]"
    )
    decision_table.add_row(
        "Rate limited", f"[yellow]{rate_limited_count}[/yellow]"
    )
    decision_table.add_row(
        "Denial rate",
        f"[{'red' if denial_rate > 30 else 'green'}]{denial_rate:.1f}%[/{'red' if denial_rate > 30 else 'green'}]",
    )
    console.print(decision_table)

    # Top tools
    if by_tool:
        console.print()
        console.print("[bold]Top Tools (by usage)[/bold]")
        tool_table = Table(show_header=True, box=None, padding=(0, 2))
        tool_table.add_column("Tool", style="yellow")
        tool_table.add_column("Calls", justify="right")
        for tool_name, count in sorted(
            by_tool.items(), key=lambda kv: kv[1], reverse=True
        )[:10]:
            tool_table.add_row(tool_name, str(count))
        console.print(tool_table)

    # Denied tools
    if top_denied:
        console.print()
        console.print("[bold]Top Denied Tools[/bold]")
        denied_table = Table(show_header=True, box=None, padding=(0, 2))
        denied_table.add_column("Tool", style="red")
        denied_table.add_column("Denials", justify="right")
        for entry in top_denied:
            denied_table.add_row(entry["tool_name"], str(entry["count"]))
        console.print(denied_table)

    # Anomaly stats
    console.print()
    console.print("[bold]Anomaly Detection[/bold]")
    anomaly_table = Table(show_header=False, box=None, padding=(0, 2))
    anomaly_table.add_column("Metric", style="bold")
    anomaly_table.add_column("Value", justify="right")
    anomaly_style = "red" if avg_anomaly > 0.3 else "green"
    anomaly_table.add_row(
        "Average anomaly score",
        f"[{anomaly_style}]{avg_anomaly:.4f}[/{anomaly_style}]",
    )
    anomaly_table.add_row(
        "High-anomaly events (score >= 0.5)", str(len(anomaly_events))
    )
    console.print(anomaly_table)

    # Recommendations
    console.print()
    console.print(
        Panel(
            "\n".join(f"  [bold]>[/bold] {r}" for r in recommendations),
            title="[bold]Recommendations[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    console.print()


@app.command()
def scan(
    project_path: str = typer.Argument(
        ...,
        help="Path to the agent project directory to scan.",
    ),
) -> None:
    """Scan an agent project directory for security issues."""

    scan_dir = Path(project_path).resolve()

    if not scan_dir.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] Directory not found: "
            f"{escape(str(scan_dir))}"
        )
        raise typer.Exit(code=1)

    if not scan_dir.is_dir():
        err_console.print(
            f"[bold red]Error:[/bold red] Path is not a directory: "
            f"{escape(str(scan_dir))}"
        )
        raise typer.Exit(code=1)

    findings: list[dict[str, Any]] = []
    frameworks_found: list[str] = []
    python_files: list[Path] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Phase 1: Discover Python files
        task_discover = progress.add_task("Discovering Python files...", total=None)
        for root, dirs, files in os.walk(scan_dir):
            # Skip hidden dirs, __pycache__, .git, node_modules, venvs
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d not in {"__pycache__", "node_modules", ".venv", "venv", "env"}
            ]
            for f in files:
                if f.endswith(".py"):
                    python_files.append(Path(root) / f)
        progress.update(
            task_discover,
            description=f"Found {len(python_files)} Python files",
            completed=True,
        )

        # Phase 2: Check for policy file
        task_policy = progress.add_task("Checking for policy file...", total=None)
        policy_files = list(scan_dir.glob("agentgate.yaml")) + list(
            scan_dir.glob("agentgate.yml")
        )
        has_policy = len(policy_files) > 0
        if not has_policy:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "category": "no_policy_file",
                    "message": "No agentgate.yaml policy file found in project root.",
                    "file": str(scan_dir),
                    "line": None,
                    "recommendation": (
                        "Run 'agentgate init' to create a policy file."
                    ),
                }
            )
        progress.update(
            task_policy,
            description=(
                "[green]Policy file found[/green]"
                if has_policy
                else "[red]No policy file[/red]"
            ),
            completed=True,
        )

        # Phase 3: Scan Python files
        task_scan = progress.add_task(
            "Scanning for security issues...", total=len(python_files)
        )

        for py_file in python_files:
            progress.advance(task_scan)
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            rel_path = str(py_file.relative_to(scan_dir))

            # Detect agent frameworks
            for import_key, framework_name in _AGENT_FRAMEWORKS.items():
                if re.search(
                    rf"^\s*(?:import|from)\s+{re.escape(import_key)}\b",
                    content,
                    re.MULTILINE,
                ):
                    if framework_name not in frameworks_found:
                        frameworks_found.append(framework_name)

            # Check for tool definitions without AgentGate protection
            _scan_unprotected_tools(content, lines, rel_path, findings)

            # Check for unrestricted filesystem access
            _scan_filesystem_access(content, lines, rel_path, findings)

            # Check for unrestricted network access
            _scan_network_access(content, lines, rel_path, findings)

            # Check for missing rate limit patterns
            _scan_rate_limits(content, lines, rel_path, findings)

        progress.update(
            task_scan,
            description=f"Scanned {len(python_files)} files, found {len(findings)} issues",
            completed=True,
        )

    # --- Compute score ---
    score = _compute_scan_score(findings, has_policy)
    grade, grade_style = _letter_grade(score)

    # --- Display Report Card ---
    console.print()

    # Header panel
    grade_display = Text(f"  {grade}  ", style=f"{grade_style} on default")
    console.print(
        Panel(
            f"[bold]Security Report Card[/bold]\n"
            f"\n"
            f"Project: [cyan]{escape(str(scan_dir))}[/cyan]\n"
            f"Files scanned: {len(python_files)}\n"
            f"Frameworks detected: {', '.join(frameworks_found) if frameworks_found else '[dim]none[/dim]'}\n"
            f"Policy file: {'[green]found[/green]' if has_policy else '[red]missing[/red]'}\n"
            f"\n"
            f"Score: [bold]{score}/100[/bold]  Grade: [{grade_style}]{grade}[/{grade_style}]",
            title="[bold]AgentGate Security Scan[/bold]",
            border_style=grade_style.replace("bold ", ""),
            padding=(1, 2),
        )
    )

    if not findings:
        console.print()
        console.print(
            Panel(
                "[bold green]No security issues detected![/bold green]\n"
                "[dim]Your project appears well-configured. Continue to monitor "
                "with regular scans.[/dim]",
                border_style="green",
                padding=(1, 2),
            )
        )
        console.print()
        raise typer.Exit(code=0)

    # Findings by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    findings_by_severity: dict[str, list[dict[str, Any]]] = {
        s: [] for s in severity_order
    }
    for f in findings:
        findings_by_severity.setdefault(f["severity"], []).append(f)

    console.print()
    console.print("[bold]Findings[/bold]")
    console.print()

    findings_table = Table(
        show_header=True,
        expand=True,
        pad_edge=True,
    )
    findings_table.add_column("Severity", no_wrap=True, width=10)
    findings_table.add_column("Issue", ratio=3)
    findings_table.add_column("Location", ratio=2, style="dim")
    findings_table.add_column("OWASP", no_wrap=True, width=18)

    for sev in severity_order:
        for f in findings_by_severity.get(sev, []):
            owasp = _OWASP_MAPPING.get(f["category"], {})
            owasp_id = owasp.get("id", "-")
            location = f["file"]
            if f.get("line") is not None:
                location += f":{f['line']}"

            sev_text = _severity_text(sev)
            findings_table.add_row(
                sev_text,
                f["message"],
                location,
                owasp_id,
            )

    console.print(findings_table)

    # Severity summary
    console.print()
    severity_counts = {s: len(findings_by_severity.get(s, [])) for s in severity_order}
    summary_parts = []
    for sev in severity_order:
        count = severity_counts[sev]
        if count > 0:
            style = _SEVERITY_STYLE.get(sev, "")
            summary_parts.append(f"[{style}]{count} {sev}[/{style}]")
    console.print(f"  Total: {len(findings)} issues ({', '.join(summary_parts)})")

    # OWASP mapping
    owasp_categories: dict[str, str] = {}
    for f in findings:
        owasp = _OWASP_MAPPING.get(f["category"], {})
        if owasp:
            owasp_categories[owasp["id"]] = owasp["title"]

    if owasp_categories:
        console.print()
        console.print("[bold]OWASP Agentic AI Top 10 Mapping[/bold]")
        console.print()
        for oid, title in sorted(owasp_categories.items()):
            console.print(f"  [cyan]{oid}[/cyan]  {title}")

    # Recommendations
    unique_recommendations: list[str] = []
    seen_recs: set[str] = set()
    for f in findings:
        rec = f.get("recommendation", "")
        if rec and rec not in seen_recs:
            unique_recommendations.append(rec)
            seen_recs.add(rec)

    if unique_recommendations:
        console.print()
        console.print(
            Panel(
                "\n".join(
                    f"  [bold]{i + 1}.[/bold] {r}"
                    for i, r in enumerate(unique_recommendations[:10])
                ),
                title="[bold]Recommendations[/bold]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    console.print()

    # Exit code: 1 if any CRITICAL findings
    if severity_counts.get("CRITICAL", 0) > 0:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Scan helper functions
# ---------------------------------------------------------------------------


def _scan_unprotected_tools(
    content: str,
    lines: list[str],
    rel_path: str,
    findings: list[dict[str, Any]],
) -> None:
    """Detect tool definitions that lack AgentGate wrapping."""
    # LangChain tool patterns
    tool_patterns = [
        # @tool decorator
        (r"@tool\b", "LangChain @tool decorator without AgentGate wrapper"),
        # BaseTool subclass
        (
            r"class\s+\w+\(.*BaseTool.*\)",
            "LangChain BaseTool subclass without AgentGate protection",
        ),
        # CrewAI tool
        (r"@crewai\.tool\b", "CrewAI tool without AgentGate protection"),
        # autogen function registration
        (
            r"register_function\s*\(",
            "AutoGen function registration without AgentGate protection",
        ),
    ]

    has_agentgate_import = "agentgate" in content

    for pattern, message in tool_patterns:
        for match in re.finditer(pattern, content, re.MULTILINE):
            if has_agentgate_import:
                continue
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                {
                    "severity": "HIGH",
                    "category": "unrestricted_tools",
                    "message": message,
                    "file": rel_path,
                    "line": line_num,
                    "recommendation": (
                        "Wrap tool calls with AgentGate to enforce policy controls. "
                        "See: https://agentgate.dev/docs/integrations"
                    ),
                }
            )


def _scan_filesystem_access(
    content: str,
    lines: list[str],
    rel_path: str,
    findings: list[dict[str, Any]],
) -> None:
    """Detect unrestricted filesystem access patterns."""
    fs_patterns = [
        (r"open\s*\([^)]*['\"]w['\"]", "File opened in write mode"),
        (r"os\.remove\s*\(", "os.remove() call"),
        (r"os\.unlink\s*\(", "os.unlink() call"),
        (r"shutil\.rmtree\s*\(", "shutil.rmtree() call -- recursive directory deletion"),
        (r"pathlib\.Path\([^)]*\)\.write_", "pathlib write operation"),
        (r"os\.makedirs\s*\(", "os.makedirs() call"),
        (r"shutil\.copy\s*\(", "shutil.copy() call"),
        (r"shutil\.move\s*\(", "shutil.move() call"),
    ]

    has_agentgate_import = "agentgate" in content

    for pattern, message in fs_patterns:
        for match in re.finditer(pattern, content, re.MULTILINE):
            if has_agentgate_import:
                continue
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                {
                    "severity": "MEDIUM",
                    "category": "filesystem_access",
                    "message": f"Unrestricted filesystem access: {message}",
                    "file": rel_path,
                    "line": line_num,
                    "recommendation": (
                        "Configure filesystem policies in agentgate.yaml to restrict "
                        "read/write paths. See: resources.filesystem"
                    ),
                }
            )


def _scan_network_access(
    content: str,
    lines: list[str],
    rel_path: str,
    findings: list[dict[str, Any]],
) -> None:
    """Detect network calls without domain restrictions."""
    net_patterns = [
        (r"requests\.(get|post|put|delete|patch|head)\s*\(", "requests library HTTP call"),
        (r"httpx\.(get|post|put|delete|patch|head)\s*\(", "httpx library HTTP call"),
        (r"urllib\.request\.urlopen\s*\(", "urllib.request.urlopen() call"),
        (r"aiohttp\.ClientSession\s*\(", "aiohttp ClientSession creation"),
        (r"subprocess\.(run|call|Popen)\s*\(\s*\[?\s*['\"]curl", "curl via subprocess"),
        (r"subprocess\.(run|call|Popen)\s*\(\s*\[?\s*['\"]wget", "wget via subprocess"),
    ]

    has_agentgate_import = "agentgate" in content

    for pattern, message in net_patterns:
        for match in re.finditer(pattern, content, re.MULTILINE):
            if has_agentgate_import:
                continue
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                {
                    "severity": "HIGH",
                    "category": "network_unrestricted",
                    "message": f"Network call without domain restriction: {message}",
                    "file": rel_path,
                    "line": line_num,
                    "recommendation": (
                        "Configure network policies in agentgate.yaml with "
                        "allowed_domains and denied_domains. "
                        "See: resources.network"
                    ),
                }
            )


def _scan_rate_limits(
    content: str,
    lines: list[str],
    rel_path: str,
    findings: list[dict[str, Any]],
) -> None:
    """Check for tool usage patterns that lack rate limiting.

    This looks for high-frequency loop patterns calling tools without any
    apparent throttling mechanism.
    """
    # Patterns indicating loops calling tools/APIs without rate limiting
    loop_call_patterns = [
        (
            r"for\s+\w+\s+in\s+.*:\s*\n\s+.*\.(run|execute|invoke|call)\s*\(",
            "Tool invocation inside loop without rate limiting",
        ),
        (
            r"while\s+.*:\s*\n\s+.*\.(run|execute|invoke|call)\s*\(",
            "Tool invocation inside while loop without rate limiting",
        ),
    ]

    has_rate_limit = (
        "rate_limit" in content
        or "RateLimit" in content
        or "throttle" in content
        or "sleep" in content
    )

    if has_rate_limit:
        return

    has_agentgate_import = "agentgate" in content

    for pattern, message in loop_call_patterns:
        for match in re.finditer(pattern, content, re.MULTILINE):
            if has_agentgate_import:
                continue
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                {
                    "severity": "MEDIUM",
                    "category": "no_rate_limits",
                    "message": message,
                    "file": rel_path,
                    "line": line_num,
                    "recommendation": (
                        "Add rate_limit configuration to tool permissions in "
                        "agentgate.yaml. Example: rate_limit: {max_calls: 10, "
                        "window_seconds: 60}"
                    ),
                }
            )


def _compute_scan_score(
    findings: list[dict[str, Any]], has_policy: bool
) -> int:
    """Compute a security score from 0 to 100.

    Deductions:
        CRITICAL: -25 each (max -50)
        HIGH:     -10 each (max -30)
        MEDIUM:    -5 each (max -20)
        LOW:       -2 each (max -10)
    Bonus:
        +10 if policy file exists
    """
    score = 100

    severity_deductions = {
        "CRITICAL": (25, 50),
        "HIGH": (10, 30),
        "MEDIUM": (5, 20),
        "LOW": (2, 10),
    }

    for severity, (per_finding, max_deduction) in severity_deductions.items():
        count = sum(1 for f in findings if f["severity"] == severity)
        deduction = min(count * per_finding, max_deduction)
        score -= deduction

    # Policy file is expected -- no bonus, but missing is already a CRITICAL finding.
    score = max(0, min(100, score))
    return score


@app.command()
def proxy(
    policy: str = typer.Option(
        ...,
        "--policy",
        "-p",
        help="Path to the AgentGate policy file.",
    ),
    upstream: str = typer.Option(
        ...,
        "--upstream",
        "-u",
        help="Upstream URL to proxy requests to.",
    ),
    host: str = typer.Option(
        "0.0.0.0",
        "--host",
        help="Host to bind the proxy server to.",
    ),
    port: int = typer.Option(
        8080,
        "--port",
        help="Port to bind the proxy server to.",
        min=1,
        max=65535,
    ),
) -> None:
    """Start an HTTP proxy for non-Python agents (Phase 2)."""

    # Validate policy file exists
    policy_path = Path(policy)
    if not policy_path.exists():
        err_console.print(
            f"[bold red]Error:[/bold red] Policy file not found: "
            f"{escape(str(policy_path))}"
        )
        raise typer.Exit(code=1)

    # Validate policy
    try:
        loaded_policy = load_policy(policy_path)
    except Exception as exc:
        err_console.print(f"[bold red]Error:[/bold red] Invalid policy: {exc}")
        raise typer.Exit(code=1)

    console.print()
    console.print(
        Panel(
            f"[bold yellow]AgentGate HTTP Proxy -- Coming Soon[/bold yellow]\n"
            f"\n"
            f"The HTTP proxy feature is planned for Phase 2.\n"
            f"\n"
            f"Configuration validated:\n"
            f"  Policy:   [cyan]{escape(str(policy_path))}[/cyan]\n"
            f"  Upstream: [cyan]{escape(upstream)}[/cyan]\n"
            f"  Bind:     [cyan]{host}:{port}[/cyan]\n"
            f"  Agents:   {len(loaded_policy.agents)}\n"
            f"\n"
            f"When available, the proxy will:\n"
            f"  [dim]1.[/dim] Accept HTTP requests from any language/framework\n"
            f"  [dim]2.[/dim] Enforce AgentGate policies on each request\n"
            f"  [dim]3.[/dim] Forward allowed requests to the upstream service\n"
            f"  [dim]4.[/dim] Log all decisions to the audit database\n"
            f"\n"
            f"[dim]Follow progress at: https://github.com/agentgate/agentgate[/dim]",
            title="[bold]AgentGate Proxy[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
    )
    console.print()


@app.command()
def version() -> None:
    """Show the AgentGate version."""
    console.print(f"agentgate {_VERSION}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point (called by ``python -m agentgate.cli`` or console_scripts)."""
    app()


if __name__ == "__main__":
    main()

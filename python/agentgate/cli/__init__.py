"""AgentGate CLI package.

Provides the ``agentgate`` command-line interface built on Typer with
Rich output formatting.

Quick start::

    from agentgate.cli.main import app, main
"""

from agentgate.cli.main import app, main

__all__ = ["app", "main"]

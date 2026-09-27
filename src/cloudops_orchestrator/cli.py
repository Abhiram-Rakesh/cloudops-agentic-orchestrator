"""`cloudops` CLI entry point (Typer).

Commands are added incrementally as the milestone that backs them lands:
``kb *`` in M2, ``run``/``resume``/``report *`` in M4/M5, ``exceptions *`` in
M5, ``trials``/``doctor`` in M7, ``eval`` in M9. See the module docstring in
each subcommand's implementation module for what backs it.
"""

from __future__ import annotations

import typer
from rich.console import Console

from cloudops_orchestrator import __version__

app = typer.Typer(
    name="cloudops",
    help="CloudOps Agentic Orchestrator CLI",
    no_args_is_help=True,
)

console = Console()


@app.callback(invoke_without_command=False)
def _main() -> None:
    """CloudOps Agentic Orchestrator."""


@app.command()
def version() -> None:
    """Print the installed package version."""
    console.print(__version__)


if __name__ == "__main__":
    app()

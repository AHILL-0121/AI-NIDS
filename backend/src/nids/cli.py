"""Command-line entry point: ``nids <command>``.

Plain subcommands only, with no interactive menus (audit OPS-05).
"""

import typer

from nids.core.settings import get_settings

app = typer.Typer(help="AI-NIDS v2 command line.", no_args_is_help=True)


@app.command()
def api() -> None:
    """Run the HTTP/WebSocket API (unprivileged)."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "nids.api.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


def _not_implemented(phase: str) -> None:
    typer.echo(f"Not implemented yet (see plan/checklist.md, {phase}).", err=True)
    raise typer.Exit(code=2)


@app.command()
def sensor() -> None:
    """Run the capture sensor (needs capture privileges)."""
    _not_implemented("Phase 1")


@app.command()
def train() -> None:
    """Train a detection model from a dataset."""
    _not_implemented("Phase 2")


@app.command()
def replay() -> None:
    """Stream a PCAP file through the detection pipeline."""
    _not_implemented("Phase 1")


if __name__ == "__main__":
    app()

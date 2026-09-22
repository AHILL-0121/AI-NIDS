"""Command-line entry point: ``nids <command>``.

Plain subcommands only, with no interactive menus (audit OPS-05).
"""

import json
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from typing import IO, TYPE_CHECKING, Annotated, Literal, cast

import typer

from nids.core.logging import configure_logging
from nids.core.settings import get_settings

if TYPE_CHECKING:
    from nids.sensor.capture import FlowSource

app = typer.Typer(help="AI-NIDS v2 command line.", no_args_is_help=True)

IdleOpt = Annotated[float, typer.Option(help="Seconds without packets before a flow ends.")]
ActiveOpt = Annotated[float, typer.Option(help="Maximum flow length in seconds before splitting.")]
OutOpt = Annotated[
    str,
    typer.Option("--out", "-o", help="Write flows as JSON Lines to this file, or '-' for stdout."),
]


@app.callback()
def main(
    log_level: Annotated[str, typer.Option(help="DEBUG, INFO, WARNING or ERROR.")] = "",
) -> None:
    configure_logging(log_level or get_settings().log_level)


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


@app.command()
def doctor(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Check whether this machine can capture packets, and how to fix it if not."""
    from nids.sensor.capability import check_capture

    report = check_capture()
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        marks = {"ok": "OK  ", "warning": "WARN", "error": "FAIL"}
        typer.echo(f"Platform: {report.platform}   Backend: {report.backend or 'none'}\n")
        for check in report.checks:
            typer.echo(f"[{marks[check.status]}] {check.name}: {check.detail}")
            if check.fix and check.status != "ok":
                typer.echo(f"       fix: {check.fix}")
        typer.echo("\nReady to capture." if report.ok else "\nCapture is not possible yet.")
    raise typer.Exit(code=0 if report.ok else 1)


@app.command()
def interfaces(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """List network interfaces that can be captured."""
    from nids.sensor.interfaces import list_interfaces

    items = list_interfaces()
    if json_output:
        typer.echo(json.dumps([i.model_dump() for i in items], indent=2))
        return
    for i in items:
        addr = ", ".join(i.ipv4) or "no IPv4"
        tag = "  (loopback)" if i.loopback else ""
        typer.echo(f"{i.label:<28} {addr:<32} {i.description}{tag}")
        typer.echo(f'{"":<28} --interface "{i.name}"')


def _open_out(path: str) -> "nullcontext[IO[str]] | IO[str]":
    if path == "-":
        return nullcontext(sys.stdout)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return open(path, "w", encoding="utf-8")


def _run(source: "FlowSource", out: str) -> None:
    """Run a flow source to completion (or Ctrl+C), then print a summary to stderr."""
    from nids.sensor.capture import CaptureError
    from nids.sensor.runner import JsonlSink, run_in_background

    started = time.monotonic()
    with _open_out(out) as stream:
        sink = JsonlSink(stream)
        thread, stop, errors = run_in_background(source, sink)
        try:
            while thread.is_alive():
                thread.join(timeout=0.5)
        except KeyboardInterrupt:
            typer.echo("\nStopping... (flushing open flows)", err=True)
            stop.set()
            thread.join()

    for exc in errors:
        if isinstance(exc, CaptureError):
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1)
        raise exc
    elapsed = time.monotonic() - started
    metrics = source.metrics()
    typer.echo(f"\n{sink.count} flows in {elapsed:.1f} s", err=True)
    typer.echo(json.dumps(metrics, indent=2), err=True)


@app.command()
def replay(
    pcap: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="pcap or pcapng file.")],
    out: OutOpt = "-",
    speed: Annotated[str, typer.Option(help="max or realtime.")] = "max",
    backend: Annotated[str, typer.Option(help="scapy (any OS) or nfstream (Linux).")] = "scapy",
    idle_timeout: IdleOpt = 15.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Stream a PCAP file through the flow pipeline and write the flows."""
    from nids.sensor.flows import FlowTableConfig
    from nids.sensor.runner import build_replay_source

    if speed not in ("max", "realtime") or backend not in ("scapy", "nfstream"):
        raise typer.BadParameter("speed must be max|realtime and backend scapy|nfstream")
    config = FlowTableConfig(idle_timeout=idle_timeout, active_timeout=active_timeout)
    source = build_replay_source(
        pcap,
        backend=cast(Literal["nfstream", "scapy"], backend),
        config=config,
        speed=cast(Literal["max", "realtime"], speed),
    )
    _run(source, out)


@app.command()
def sensor(
    interface: Annotated[str, typer.Option("--interface", "-i", help="See `nids interfaces`.")],
    out: OutOpt = "-",
    backend: Annotated[str, typer.Option(help="auto, nfstream or scapy.")] = "auto",
    bpf_filter: Annotated[
        str | None, typer.Option("--filter", help="BPF filter, e.g. 'tcp'.")
    ] = None,
    idle_timeout: IdleOpt = 15.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Capture live traffic (needs capture privileges). Stop with Ctrl+C."""
    from nids.sensor.capability import check_capture
    from nids.sensor.flows import FlowTableConfig
    from nids.sensor.runner import build_live_source

    report = check_capture()
    if not report.ok:
        for check in report.checks:
            if check.status == "error":
                typer.echo(f"Error: {check.detail} Fix: {check.fix}", err=True)
        raise typer.Exit(code=1)
    if backend not in ("auto", "nfstream", "scapy"):
        raise typer.BadParameter("backend must be auto|nfstream|scapy")
    config = FlowTableConfig(idle_timeout=idle_timeout, active_timeout=active_timeout)
    source = build_live_source(
        interface, cast(Literal["auto", "nfstream", "scapy"], backend), config, bpf_filter
    )
    typer.echo(f"Capturing on {interface} with {source.name}. Ctrl+C to stop.", err=True)
    _run(source, out)


@app.command()
def train() -> None:
    """Train a detection model from a dataset."""
    typer.echo("Not implemented yet (see plan/checklist.md, Phase 2).", err=True)
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()

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
    from nids.core.schemas.alert import Alert
    from nids.core.schemas.flow import FlowRecord
    from nids.sensor.capture import FlowSource
    from nids.sensor.detect import DetectionEngine

app = typer.Typer(help="AI-NIDS v2 command line.", no_args_is_help=True)

IdleOpt = Annotated[float, typer.Option(help="Seconds without packets before a flow ends.")]
ActiveOpt = Annotated[float, typer.Option(help="Maximum flow length in seconds before splitting.")]
OutOpt = Annotated[
    str,
    typer.Option(
        "--out", "-o", help="Write flows as JSON Lines to this file, '-' for stdout, or 'none'."
    ),
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


def _open_out(path: str) -> "nullcontext[IO[str] | None] | IO[str]":
    if path == "none":
        return nullcontext(None)
    if path == "-":
        return nullcontext(sys.stdout)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return open(path, "w", encoding="utf-8")


def _build_engine(model: Path | None) -> "tuple[DetectionEngine, dict[str, Alert]]":
    """Detection engine that prints each new alert to stderr and keeps the latest state of all."""
    from nids.sensor.detect import DetectionEngine

    alerts: dict[str, Alert] = {}

    def on_alert(alert: "Alert", is_new: bool) -> None:
        alerts[alert.id] = alert
        if is_new:
            where = f"{alert.src or '*'} -> {alert.dst or '*'}"
            typer.echo(f"[{alert.severity.value.upper():8}] {alert.title}: {where}", err=True)

    engine = DetectionEngine(on_alert)
    if model is not None:
        engine.load_model(model)
    return engine, alerts


def _run(
    source: "FlowSource",
    out: str,
    engine: "DetectionEngine",
    alerts: "dict[str, Alert]",
    alerts_out: Path | None,
) -> None:
    """Run a flow source to completion (or Ctrl+C), then print a summary to stderr."""
    from nids.sensor.capture import CaptureError
    from nids.sensor.runner import JsonlSink, run_in_background

    started = time.monotonic()
    with _open_out(out) as stream:
        jsonl = JsonlSink(stream) if stream is not None else None

        def sink(flow: "FlowRecord") -> None:
            if jsonl is not None:
                jsonl(flow)
            engine.on_flow(flow)

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
    if alerts_out is not None:
        alerts_out.parent.mkdir(parents=True, exist_ok=True)
        alerts_out.write_text(
            "".join(json.dumps(a.to_dict()) + "\n" for a in alerts.values()), encoding="utf-8"
        )
    elapsed = time.monotonic() - started
    summary = {
        "flows": source.metrics().get("flows_created"),
        "alerts": len(alerts),
        "alerts_by_type": dict(engine.detections),
        "suppressed": dict(engine.correlator.suppressed),
        "capture": source.metrics(),
    }
    typer.echo(f"\nDone in {elapsed:.1f} s", err=True)
    typer.echo(json.dumps(summary, indent=2), err=True)


AlertsOpt = Annotated[
    Path | None, typer.Option("--alerts", help="Write the final alerts as JSON Lines here.")
]
ModelOpt = Annotated[
    Path | None,
    typer.Option(exists=True, file_okay=False, help="Model artifact directory (from nids train)."),
]


@app.command()
def replay(
    pcap: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="pcap or pcapng file.")],
    out: OutOpt = "-",
    alerts: AlertsOpt = None,
    model: ModelOpt = None,
    speed: Annotated[str, typer.Option(help="max or realtime.")] = "max",
    backend: Annotated[str, typer.Option(help="scapy (any OS) or nfstream (Linux).")] = "scapy",
    idle_timeout: IdleOpt = 120.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Stream a PCAP file through flow assembly and detection."""
    from nids.sensor.flows import FlowTableConfig
    from nids.sensor.runner import build_replay_source

    if speed not in ("max", "realtime") or backend not in ("scapy", "nfstream"):
        raise typer.BadParameter("speed must be max|realtime and backend scapy|nfstream")
    engine, found = _build_engine(model)
    config = FlowTableConfig(idle_timeout=idle_timeout, active_timeout=active_timeout)
    source = build_replay_source(
        pcap,
        backend=cast(Literal["nfstream", "scapy"], backend),
        config=config,
        speed=cast(Literal["max", "realtime"], speed),
        observer=engine,
    )
    _run(source, out, engine, found, alerts)


@app.command()
def sensor(
    interface: Annotated[str, typer.Option("--interface", "-i", help="See `nids interfaces`.")],
    out: OutOpt = "none",
    alerts: AlertsOpt = None,
    model: ModelOpt = None,
    backend: Annotated[str, typer.Option(help="auto, nfstream or scapy.")] = "auto",
    bpf_filter: Annotated[
        str | None, typer.Option("--filter", help="BPF filter, e.g. 'tcp'.")
    ] = None,
    idle_timeout: IdleOpt = 120.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Capture live traffic and detect attacks (needs capture privileges). Stop with Ctrl+C."""
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
    engine, found = _build_engine(model)
    config = FlowTableConfig(idle_timeout=idle_timeout, active_timeout=active_timeout)
    source = build_live_source(
        interface,
        cast(Literal["auto", "nfstream", "scapy"], backend),
        config,
        bpf_filter,
        observer=engine,
    )
    typer.echo(f"Capturing on {interface} with {source.name}. Ctrl+C to stop.", err=True)
    _run(source, out, engine, found, alerts)


data_app = typer.Typer(help="Prepare training datasets.", no_args_is_help=True)
app.add_typer(data_app, name="data")

DataDirOpt = Annotated[Path, typer.Option(help="Where prepared datasets live.")]
ArtifactsOpt = Annotated[Path, typer.Option(help="Where model artifacts are written.")]


@data_app.command("prepare")
def data_prepare(
    dataset: Annotated[str, typer.Argument(help="cicids2017 or unsw-nb15.")],
    src: Annotated[Path, typer.Option(exists=True, file_okay=False, help="Folder with the CSVs.")],
    out: DataDirOpt = Path("data/processed"),
    attempted: Annotated[
        str, typer.Option(help="CIC-IDS2017 '- Attempted' flows: benign (default) or separate.")
    ] = "benign",
) -> None:
    """Convert a dataset's CSVs into features_v1 (parquet + metadata)."""
    from nids.ml.datasets import DatasetError
    from nids.ml.prepare import prepare

    if attempted not in ("benign", "separate"):
        raise typer.BadParameter("attempted must be benign or separate")
    try:
        path = prepare(dataset, src, out, cast(Literal["benign", "separate"], attempted))
    except DatasetError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
    typer.echo(f"Wrote {path} ({meta['rows']:,} flows)")
    for family, count in meta["families"].items():
        typer.echo(f"  {family:<14} {count:>10,}")


@app.command()
def train(
    dataset: Annotated[str, typer.Option(help="cicids2017 or unsw-nb15.")],
    protocol: Annotated[str, typer.Option(help="day, random or official.")] = "day",
    features: Annotated[str, typer.Option(help="full, or shared (cross-dataset subset).")] = "full",
    sample_frac: Annotated[float | None, typer.Option(help="Train on a per-family sample.")] = None,
    seed: int = 42,
    data_dir: DataDirOpt = Path("data/processed"),
    out: ArtifactsOpt = Path("artifacts"),
) -> None:
    """Train the detector on a prepared dataset, evaluate on the held-out split, save it."""
    from nids.ml import registry
    from nids.ml.datasets import DatasetError
    from nids.ml.prepare import load_prepared
    from nids.ml.train import TrainConfig
    from nids.ml.train import train as run_training

    if protocol not in ("day", "random", "official") or features not in ("full", "shared"):
        raise typer.BadParameter("protocol must be day|random|official, features full|shared")
    try:
        frame, _ = load_prepared(dataset, data_dir)
        config = TrainConfig(
            protocol=cast(Literal["day", "random", "official"], protocol),
            feature_set=cast(Literal["full", "shared"], features),
            seed=seed,
            sample_frac=sample_frac,
        )
        result = run_training(frame, dataset, config)
    except DatasetError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    directory = registry.save(result.bundle, result.report, out)
    typer.echo((directory / registry.CARD_FILE).read_text(encoding="utf-8"))
    typer.echo(f"Saved model to {directory}")


@app.command()
def evaluate(
    model: Annotated[Path, typer.Option(exists=True, file_okay=False, help="Artifact directory.")],
    dataset: Annotated[str, typer.Option(help="Prepared dataset to test on (e.g. the other one).")],
    split_name: Annotated[
        str, typer.Option("--split", help="all, train or test rows of that dataset.")
    ] = "all",
    data_dir: DataDirOpt = Path("data/processed"),
) -> None:
    """Evaluate a saved model on another dataset (cross-dataset generalisation)."""
    from nids.ml import registry
    from nids.ml.evaluate import evaluate as run_evaluation
    from nids.ml.prepare import load_prepared

    bundle, manifest = registry.load(model)
    frame, _ = load_prepared(dataset, data_dir)
    if split_name != "all":
        frame = frame[frame["split"] == split_name]
    report = run_evaluation(bundle, frame, trained_families=set(bundle.classes))
    alert = report["binary"]["alert_rule"]
    typer.echo(f"Model {manifest['version']} on {dataset} ({len(frame):,} flows):")
    typer.echo(json.dumps({"alert_rule": alert, "per_family": report["per_family"]}, indent=2))


if __name__ == "__main__":
    app()

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
    from collections.abc import Callable

    from nids.core.schemas.alert import Alert
    from nids.sensor.capture import FlowSource
    from nids.sensor.detect.base import PacketObserver

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
def openapi(
    out: Annotated[Path, typer.Option(help="Where to write the schema.")] = Path("openapi.json"),
) -> None:
    """Write the API's OpenAPI schema (the frontend generates its types from it)."""
    from nids.api.app import create_app

    schema = create_app(background=False).openapi()
    out.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"Wrote {out} ({len(schema['paths'])} paths)")


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


def _graceful_signals() -> None:
    """Treat SIGTERM (and CTRL_BREAK on Windows, sent by the API's supervisor) like Ctrl+C, so a
    stop request flushes open flows and closes the session instead of killing the process."""
    import signal

    def interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupt)


def _alert_printer(alert: "Alert", is_new: bool) -> None:
    if is_new:
        where = f"{alert.src or '*'} -> {alert.dst or '*'}"
        typer.echo(f"[{alert.severity.value.upper():8}] {alert.title}: {where}", err=True)


def _run(
    source_factory: "Callable[[PacketObserver], FlowSource]",
    *,
    kind: str,
    label: str,
    out: str,
    alerts_out: Path | None,
    model: Path | None,
    use_db: bool,
) -> None:
    """Run capture + detection (+ storage) until the input ends or Ctrl+C, then summarise."""
    from nids.core.schemas.runtime import RuntimeSettings
    from nids.sensor.capture import CaptureError
    from nids.sensor.detect import DetectionConfig, DetectionEngine
    from nids.sensor.pipeline import Pipeline
    from nids.sensor.runner import JsonlSink, run_in_background
    from nids.store import repo
    from nids.store.db import Database

    settings = get_settings()
    db = Database(settings.database_url) if use_db else None
    # Settings changed in the UI live in the database; without one, the defaults apply.
    runtime = repo.get_runtime(db, settings) if db is not None else RuntimeSettings()
    engine = DetectionEngine(config=DetectionConfig.from_runtime(runtime))
    if model is not None:
        engine.load_model(model)
        if engine.ml is not None and runtime.attack_threshold is not None:
            engine.ml.bundle.attack_threshold = runtime.attack_threshold
        if engine.ml is not None and runtime.novelty_threshold is not None:
            engine.ml.bundle.novelty_threshold = runtime.novelty_threshold

    started = time.monotonic()
    error: str | None = None
    with _open_out(out) as stream:
        pipeline = Pipeline(engine, db=db, flow_sample_rate=runtime.flow_sample_rate)
        source = source_factory(pipeline)
        if db is not None:
            pipeline.session_id = repo.start_session(
                db, kind, label, source.name, engine.ml.model_version if engine.ml else None
            )
            pipeline.pseudonymizer = (
                repo.Pseudonymizer.from_db(db) if runtime.pseudonymize_ips else None
            )
            pipeline.flow_writer = repo.FlowWriter(
                db,
                pipeline.session_id,
                runtime.flow_sample_rate,
                pseudonymizer=pipeline.pseudonymizer,
            )
        if stream is not None:
            pipeline.extra_flow_sinks.append(JsonlSink(stream))
        pipeline.alert_listeners.append(_alert_printer)

        _graceful_signals()
        thread, stop, errors = run_in_background(source, pipeline.on_flow)
        try:
            while thread.is_alive():
                thread.join(timeout=0.5)
        except KeyboardInterrupt:
            typer.echo("\nStopping... (flushing open flows)", err=True)
            stop.set()
            thread.join()
        for exc in errors:
            error = f"{type(exc).__name__}: {exc}"

    if db is not None and pipeline.session_id is not None:
        repo.finish_session(db, pipeline.session_id, source.metrics(), error)
    for exc in errors:
        if isinstance(exc, CaptureError):
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(code=1)
        raise exc
    if alerts_out is not None:
        alerts_out.parent.mkdir(parents=True, exist_ok=True)
        alerts_out.write_text(
            "".join(json.dumps(a.to_dict()) + "\n" for a in pipeline.alerts.values()),
            encoding="utf-8",
        )
    summary = {
        "session": pipeline.session_id,
        "alerts": len(pipeline.alerts),
        "detections_by_type": dict(engine.detections),
        "suppressed": dict(engine.correlator.suppressed),
        "stored": dict(pipeline.written)
        | ({"flows": pipeline.flow_writer.written} if pipeline.flow_writer else {}),
        "capture": source.metrics(),
    }
    typer.echo(f"\nDone in {time.monotonic() - started:.1f} s", err=True)
    typer.echo(json.dumps(summary, indent=2), err=True)


AlertsOpt = Annotated[
    Path | None, typer.Option("--alerts", help="Also write the final alerts as JSON Lines here.")
]
ModelOpt = Annotated[
    Path | None,
    typer.Option(exists=True, file_okay=False, help="Model artifact directory (from nids train)."),
]
DbOpt = Annotated[
    bool, typer.Option("--db/--no-db", help="Store the session, flows and alerts in the database.")
]


@app.command()
def replay(
    pcap: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="pcap or pcapng file.")],
    out: OutOpt = "none",
    alerts: AlertsOpt = None,
    model: ModelOpt = None,
    db: DbOpt = True,
    speed: Annotated[str, typer.Option(help="max or realtime.")] = "max",
    backend: Annotated[str, typer.Option(help="scapy (any OS) or nfstream (Linux).")] = "scapy",
    idle_timeout: IdleOpt = 120.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Stream a PCAP file through flow assembly, detection and storage."""
    from nids.sensor.flows import FlowTableConfig
    from nids.sensor.runner import build_replay_source

    if speed not in ("max", "realtime") or backend not in ("scapy", "nfstream"):
        raise typer.BadParameter("speed must be max|realtime and backend scapy|nfstream")
    config = FlowTableConfig(idle_timeout=idle_timeout, active_timeout=active_timeout)

    def factory(observer: "PacketObserver") -> "FlowSource":
        return build_replay_source(
            pcap,
            backend=cast(Literal["nfstream", "scapy"], backend),
            config=config,
            speed=cast(Literal["max", "realtime"], speed),
            observer=observer,
        )

    _run(
        factory, kind="replay", label=pcap.name, out=out, alerts_out=alerts, model=model, use_db=db
    )


@app.command()
def sensor(
    interface: Annotated[str, typer.Option("--interface", "-i", help="See `nids interfaces`.")],
    out: OutOpt = "none",
    alerts: AlertsOpt = None,
    model: ModelOpt = None,
    db: DbOpt = True,
    backend: Annotated[str, typer.Option(help="auto, nfstream or scapy.")] = "auto",
    bpf_filter: Annotated[
        str | None, typer.Option("--filter", help="BPF filter, e.g. 'tcp'.")
    ] = None,
    idle_timeout: IdleOpt = 120.0,
    active_timeout: ActiveOpt = 120.0,
) -> None:
    """Capture live traffic, detect attacks and store results. Stop with Ctrl+C."""
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

    def factory(observer: "PacketObserver") -> "FlowSource":
        return build_live_source(
            interface,
            cast(Literal["auto", "nfstream", "scapy"], backend),
            config,
            bpf_filter,
            observer=observer,
        )

    typer.echo(f"Capturing on {interface}. Ctrl+C to stop.", err=True)
    _run(factory, kind="live", label=interface, out=out, alerts_out=alerts, model=model, use_db=db)


db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)
app.add_typer(db_app, name="db")


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Create the database or apply pending migrations."""
    from nids.store.db import upgrade

    url = get_settings().database_url
    upgrade(url)
    typer.echo(f"Database is up to date: {url}")


@db_app.command("status")
def db_status() -> None:
    """Row counts per table."""
    from sqlalchemy import func, select

    from nids.store import models
    from nids.store.db import Database

    database = Database(get_settings().database_url)
    tables = (
        models.CaptureSession,
        models.Flow,
        models.AlertRow,
        models.Traffic,
        models.SuppressionRuleRow,
        models.ModelRow,
        models.AuditLog,
    )
    with database.session() as s:
        for table in tables:
            count = s.scalar(select(func.count()).select_from(table)) or 0
            typer.echo(f"{table.__tablename__:<18} {count:>12,}")


@db_app.command("retention")
def db_retention() -> None:
    """Roll up traffic and delete data older than the retention settings."""
    from nids.store.db import Database
    from nids.store.retention import RetentionPolicy, purge

    settings = get_settings()
    counts = purge(Database(settings.database_url), RetentionPolicy.from_settings(settings))
    typer.echo(json.dumps({"deleted": counts}, indent=2))


@db_app.command("backup")
def db_backup(
    out: Annotated[Path, typer.Argument(help="Where to write the backup copy (.db).")],
) -> None:
    """Consistent copy of a SQLite database while it's in use."""
    import sqlite3

    url = get_settings().database_url
    if not url.startswith("sqlite:///"):
        raise typer.BadParameter("backup supports SQLite only; use your database's own tools")
    out.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(url.removeprefix("sqlite:///")) as src, sqlite3.connect(out) as dst:
        src.backup(dst)
    typer.echo(f"Backed up to {out}")


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
    dataset: Annotated[str, typer.Option(help="Prepared dataset to test on.")],
    protocol: Annotated[
        str,
        typer.Option(
            help="Which rows: 'day'/'random'/'official' test split, or 'all' (cross-dataset)."
        ),
    ] = "all",
    heuristics: Annotated[
        bool, typer.Option("--heuristics", help="Also run the scan/sweep detectors and combine.")
    ] = False,
    data_dir: DataDirOpt = Path("data/processed"),
) -> None:
    """Evaluate a saved model (and optionally the heuristics) on a prepared dataset."""
    from nids.ml import registry
    from nids.ml.evaluate import evaluate as run_evaluation
    from nids.ml.prepare import load_prepared
    from nids.ml.splits import split

    if protocol not in ("all", "day", "random", "official"):
        raise typer.BadParameter("protocol must be all|day|random|official")
    bundle, manifest = registry.load(model)
    frame, _ = load_prepared(dataset, data_dir)
    if protocol != "all":
        _, frame, _ = split(
            frame, cast(Literal["day", "random", "official"], protocol), bundle.feature_names
        )
    report = run_evaluation(bundle, frame, trained_families=set(bundle.classes))
    summary: dict[str, object] = {
        "model": manifest["version"],
        "rows": len(frame),
        "alert_rule": report["binary"]["alert_rule"],
        "false_alerts_per_hour": report["false_alerts_per_hour"],
        "per_family_ml": {k: v["alert_rate"] for k, v in report["per_family"].items()},
    }
    if heuristics:
        from nids.ml.heuristics_eval import evaluate_heuristics

        ml_alert = bundle.score(frame)["alert"].to_numpy()
        combined = evaluate_heuristics(frame, ml_alert=ml_alert)
        summary["heuristics"] = combined
        if (
            report["false_alerts_per_hour"] is not None
            and combined["false_alerts_per_hour"] is not None
        ):
            summary["false_alerts_per_hour_combined"] = (
                report["false_alerts_per_hour"] + combined["false_alerts_per_hour"]
            )
    typer.echo(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    app()

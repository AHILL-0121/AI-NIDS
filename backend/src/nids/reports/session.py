"""Session report (audit API-01, API-06): what was captured, what was flagged, what to do next.

`collect()` reads one capture session from the database into plain data; `render()` turns that
into a single self-contained HTML page (inline CSS and SVG, no scripts, no external requests), in
the light theme whatever the UI uses. `write_report()` saves the HTML and, when a browser is
available, a PDF printed from it.
"""

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy import desc, func, select

from nids import __version__
from nids.core.schemas.alert import Severity
from nids.reports.pdf import PdfError, find_browser, html_to_pdf
from nids.store.db import Database
from nids.store.models import AlertRow, CaptureSession, Flow, Traffic, utcnow

SEVERITIES = [s.value for s in reversed(Severity)]  # critical first
OPEN = ("new", "acknowledged")
MAX_BARS = 240  # the traffic chart merges minutes beyond this many bars

PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}

GLOSSARY = [
    (
        "Flow",
        "All packets between two endpoints (addresses, ports and protocol) in one conversation, "
        "summarised into counts and timings.",
    ),
    (
        "Alert",
        "Something a detector flagged. Repeats of the same detection between the same hosts "
        "are merged into one alert with a hit count.",
    ),
    (
        "Severity",
        "How urgent an alert is: critical, high, medium, low or info. Start with the highest.",
    ),
    (
        "Confidence",
        "How sure the detector is, from 0 to 100 %. Rules report how far past their threshold "
        "the traffic went; the model reports its calibrated score.",
    ),
    (
        "Heuristic",
        "A fixed rule, such as 'one host tried 25+ ports on another within 30 seconds'.",
    ),
    (
        "Model (ML)",
        "A classifier trained on labelled traffic plus a novelty check for flows unlike "
        "anything seen during training.",
    ),
    (
        "Novelty",
        "A flow whose measurements fall outside the range seen in normal training traffic. "
        "Unusual isn't necessarily malicious.",
    ),
    (
        "MITRE ATT&CK",
        "A public catalogue of attacker techniques. Ids like T1046 (network service discovery) "
        "link an alert to how that technique works and how to defend against it.",
    ),
    (
        "False positive",
        "An alert about harmless traffic. Marking one adds a suppression rule so it isn't "
        "raised again.",
    ),
    (
        "Suppression rule",
        "A filter that drops matching detections before they become alerts.",
    ),
    ("Port scan", "One host probing many ports on another to find running services."),
    ("Host sweep", "One host probing the same port on many hosts to find live machines."),
    ("Flood", "Far more packets than normal aimed at one host, to exhaust it (denial of service)."),
    ("pps / B/s", "Packets per second / bytes per second."),
]


@dataclass
class ReportData:
    session: dict[str, Any]
    generated_at: float
    duration_s: float | None
    totals: dict[str, int]
    severity_counts: dict[str, int]
    open_counts: dict[str, int]
    status_counts: dict[str, int]
    alert_total: int
    top_alerts: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    talkers: list[dict[str, Any]]
    ports: list[dict[str, Any]]
    protocols: list[dict[str, Any]]
    buckets: list[dict[str, int]]  # per-minute (or coarser) traffic for the chart
    bucket_s: int
    health: list[tuple[str, str]]
    notes: list[str] = field(default_factory=list)


class ReportError(RuntimeError):
    pass


# --- collecting -------------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    return Severity(severity).rank if severity in Severity._value2member_map_ else -1


def _alert_dict(row: AlertRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at,
        "last_seen": row.last_seen,
        "type": row.type,
        "title": row.title,
        "source": row.source,
        "severity": row.severity,
        "confidence": row.confidence,
        "src": row.src,
        "dst": row.dst,
        "ports": list(row.ports or []),
        "protocol": row.protocol,
        "mitre": row.mitre_technique,
        "explanation": row.explanation,
        "recommendation": row.recommendation,
        "occurrences": row.occurrences,
        "status": row.status,
        "note": row.note,
    }


def _traffic(db: Database, session_id: str) -> list[dict[str, int]]:
    """Per-minute traffic: rolled-up minutes, plus minutes built from per-second rows the
    roll-up hasn't reached (the same rule as GET /api/stats/timeseries)."""
    counters = ("packets", "bytes", "alerts")

    def query(resolution: int, bucket: Any) -> Any:
        return (
            select(bucket.label("ts"), *(func.sum(getattr(Traffic, c)).label(c) for c in counters))
            .where(Traffic.session_id == session_id, Traffic.resolution == resolution)
            .group_by(bucket)
        )

    minutes: dict[int, dict[str, int]] = {}
    with db.session() as s:
        for stmt in (query(1, (Traffic.ts // 60) * 60), query(60, Traffic.ts)):
            for row in s.execute(stmt):
                minutes[int(row.ts)] = {
                    "ts": int(row.ts),
                    **{c: int(row[i + 1] or 0) for i, c in enumerate(counters)},
                }
    return [minutes[ts] for ts in sorted(minutes)]


def _merge_buckets(minutes: list[dict[str, int]]) -> tuple[list[dict[str, int]], int]:
    """At most MAX_BARS bars over the whole span, empty minutes included."""
    if not minutes:
        return [], 60
    start, end = minutes[0]["ts"], minutes[-1]["ts"]
    span_minutes = (end - start) // 60 + 1
    step = 60 * max(1, -(-span_minutes // MAX_BARS))
    bars: dict[int, dict[str, int]] = {}
    for m in minutes:
        ts = start + (m["ts"] - start) // step * step
        bar = bars.setdefault(ts, {"ts": ts, "packets": 0, "bytes": 0, "alerts": 0})
        for key in ("packets", "bytes", "alerts"):
            bar[key] += m[key]
    filled = [
        bars.get(ts, {"ts": ts, "packets": 0, "bytes": 0, "alerts": 0})
        for ts in range(start, end + 1, step)
    ]
    return filled, step


def collect(db: Database, session_id: str, now: float | None = None) -> ReportData:
    with db.session() as s:
        session = s.get(CaptureSession, session_id)
        if session is None:
            raise ReportError(f"Session {session_id} not found.")
        info: dict[str, Any] = {
            "id": session.id,
            "kind": session.kind,
            "source": session.source,
            "backend": session.backend,
            "model_version": session.model_version,
            "started_at": session.started_at,
            "stopped_at": session.stopped_at,
            "status": session.status,
            "error": session.error,
            "metrics": dict(session.metrics or {}),
        }
        rows = s.scalars(select(AlertRow).where(AlertRow.session_id == session_id)).all()
        alerts = [_alert_dict(r) for r in rows]

        flow_filter = Flow.session_id == session_id
        flow_count, flow_bytes = s.execute(
            select(func.count(), func.coalesce(func.sum(Flow.payload_bytes), 0)).where(flow_filter)
        ).one()
        talkers = [
            {"ip": r.ip, "bytes": int(r.bytes or 0), "flows": int(r.flows)}
            for r in s.execute(
                select(
                    Flow.src_ip.label("ip"),
                    func.sum(Flow.payload_bytes).label("bytes"),
                    func.count().label("flows"),
                )
                .where(flow_filter)
                .group_by(Flow.src_ip)
                .order_by(desc("bytes"), desc("flows"))
                .limit(8)
            )
        ]
        ports = [
            {
                "port": int(r.port),
                "protocol": PROTOCOLS.get(r.protocol, str(r.protocol)),
                "flows": int(r.flows),
            }
            for r in s.execute(
                select(
                    Flow.dst_port.label("port"),
                    Flow.protocol.label("protocol"),
                    func.count().label("flows"),
                )
                .where(flow_filter, Flow.protocol.in_((6, 17)))
                .group_by(Flow.dst_port, Flow.protocol)
                .order_by(desc("flows"))
                .limit(8)
            )
        ]
        protocols = [
            {"name": PROTOCOLS.get(r.protocol, f"IP {r.protocol}"), "flows": int(r.flows)}
            for r in s.execute(
                select(Flow.protocol.label("protocol"), func.count().label("flows"))
                .where(flow_filter)
                .group_by(Flow.protocol)
                .order_by(desc("flows"))
            )
        ]

    minutes = _traffic(db, session_id)
    buckets, bucket_s = _merge_buckets(minutes)
    metrics = info["metrics"]
    totals = {
        "packets": sum(m["packets"] for m in minutes) or int(metrics.get("packets_seen", 0) or 0),
        "bytes": sum(m["bytes"] for m in minutes),
        "flows": int(flow_count),
        "flow_bytes": int(flow_bytes),
    }

    by_priority = sorted(
        alerts,
        key=lambda a: (-_severity_rank(a["severity"]), -a["occurrences"], -a["confidence"]),
    )
    severity_counts = Counter(a["severity"] for a in alerts)
    open_counts = Counter(a["severity"] for a in alerts if a["status"] in OPEN)
    status_counts = Counter(a["status"] for a in alerts)

    # One action per kind of open problem, most urgent first, using the detector's own advice.
    actions: dict[str, dict[str, Any]] = {}
    for alert in by_priority:
        if alert["status"] not in OPEN:
            continue
        entry = actions.setdefault(
            alert["type"],
            {
                "type": alert["type"],
                "title": alert["title"],
                "severity": alert["severity"],
                "recommendation": alert["recommendation"],
                "count": 0,
                "sources": Counter(),
            },
        )
        entry["count"] += 1
        entry["sources"][alert["src"] or "*"] += 1
    action_list = [
        {**a, "sources": [ip for ip, _ in a["sources"].most_common(3)]} for a in actions.values()
    ]

    started, stopped = info["started_at"], info["stopped_at"]
    health = [
        (label, f"{int(metrics[key]):,}")
        for key, label in (
            ("packets_seen", "Packets seen"),
            ("packets_dropped", "Dropped by capture"),
            ("packets_malformed", "Malformed packets"),
            ("packets_non_ip", "Non-IP packets"),
            ("flows_created", "Flows created"),
            ("flows_open", "Flows still open at stop"),
        )
        if isinstance(metrics.get(key), int | float)
    ]
    notes = []
    if info["kind"] == "replay":
        notes.append(
            "This session replayed a capture file, so times are the original packet times."
        )
    if (
        totals["flows"]
        and metrics.get("flows_created", 0)
        and totals["flows"] < int(metrics["flows_created"])
    ):
        notes.append(
            f"Only {totals['flows']:,} of {int(metrics['flows_created']):,} flows were stored "
            "(flow sampling); flow figures cover the stored ones. Flows tied to alerts are always "
            "kept."
        )

    return ReportData(
        session=info,
        generated_at=utcnow() if now is None else now,
        duration_s=(stopped - started) if stopped else None,
        totals=totals,
        severity_counts={s: severity_counts.get(s, 0) for s in SEVERITIES},
        open_counts={s: open_counts.get(s, 0) for s in SEVERITIES},
        status_counts=dict(status_counts),
        alert_total=len(alerts),
        top_alerts=by_priority[:15],
        timeline=sorted(alerts, key=lambda a: a["created_at"])[:40],
        actions=action_list,
        talkers=talkers,
        ports=ports,
        protocols=protocols,
        buckets=buckets,
        bucket_s=bucket_s,
        health=health,
        notes=notes,
    )


# --- rendering --------------------------------------------------------------------------------


_LOCAL = datetime.now().astimezone().tzinfo


def _time(epoch: float | None, with_date: bool = True) -> str:
    if epoch is None:
        return "—"
    # One fixed offset for the whole report (stated in its header). Also avoids the OS time
    # functions, which reject the tiny epochs some test captures carry on Windows.
    moment = datetime.fromtimestamp(epoch, _LOCAL)
    return moment.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def _duration(seconds: float | None) -> str:
    if seconds is None:
        return "still running"
    seconds = round(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {secs:02d} s"
    return f"{secs} s"


def _bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1000 or unit == "TB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def _endpoint(alert: dict[str, Any]) -> str:
    dst = alert["dst"] or "*"
    ports = alert["ports"]
    if len(ports) == 1:
        dst = f"{dst}:{ports[0]}"
    elif len(ports) > 1:
        dst = f"{dst} ({len(ports)} ports)"
    return dst


def _chart(data: ReportData) -> dict[str, Any] | None:
    """Geometry for the inline SVG traffic chart: bars of bytes per bucket, alert ticks above."""
    bars = data.buckets
    if not bars:
        return None
    width, height, top, bottom = 720, 150, 14, 20
    plot = height - top - bottom
    peak = max(b["bytes"] for b in bars) or 1
    slot = width / len(bars)
    gap = 1 if slot > 3 else 0
    rects = []
    ticks = []
    for i, bar in enumerate(bars):
        h = bar["bytes"] / peak * plot
        x = i * slot
        rects.append(
            {
                "x": round(x, 2),
                "y": round(top + plot - h, 2),
                "w": round(max(slot - gap, 0.6), 2),
                "h": round(h, 2),
            }
        )
        if bar["alerts"]:
            ticks.append({"x": round(x + slot / 2, 2), "n": bar["alerts"]})
    rate = peak / data.bucket_s
    return {
        "width": width,
        "height": height,
        "top": top,
        "base": top + plot,
        "rects": rects,
        "ticks": ticks,
        "peak_label": f"peak {_bytes(rate)}/s",
        "start": _time(bars[0]["ts"]),
        "end": _time(bars[-1]["ts"] + data.bucket_s),
        "bucket": _duration(data.bucket_s),
    }


def _verdict(data: ReportData) -> str:
    open_total = sum(data.open_counts.values())
    if data.alert_total == 0:
        return (
            "No alerts were raised in this session. That means none of the detectors fired, "
            "not that the traffic is proven safe."
        )
    urgent = data.open_counts["critical"] + data.open_counts["high"]
    if urgent:
        return (
            f"{urgent} open alert{'s' if urgent != 1 else ''} at high or critical severity "
            "need attention. Start with the actions below."
        )
    if open_total:
        return (
            f"{open_total} open alert{'s' if open_total != 1 else ''}, none high or critical. "
            "Review them when you can."
        )
    return (
        f"All {data.alert_total} alerts have been reviewed (acknowledged, resolved or dismissed)."
    )


_env = Environment(
    loader=PackageLoader("nids.reports", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters.update(
    time=_time,
    clock=lambda e: _time(e, with_date=False),
    duration=_duration,
    bytes=_bytes,
    pct=lambda v: f"{v * 100:.0f} %",
    num=lambda v: f"{int(v):,}",
    endpoint=_endpoint,
    humanize=lambda v: str(v).replace("_", " ").capitalize(),
    protocol=lambda p: PROTOCOLS.get(p, f"IP {p}") if p is not None else "—",
)


def render(data: ReportData) -> str:
    peak = max(data.severity_counts.values(), default=0) or 1
    return _env.get_template("session.html.j2").render(
        d=data,
        s=data.session,
        chart=_chart(data),
        verdict=_verdict(data),
        severity_peak=peak,
        glossary=GLOSSARY,
        version=__version__,
        timezone=datetime.now().astimezone().strftime("%Z (UTC%z)"),
    )


def write_report(
    db: Database, session_id: str, out: Path, pdf: bool = True, browser: str | None = None
) -> dict[str, Any]:
    """Write `<out>.html` and, if asked and possible, `<out>.pdf`. Returns what was written."""
    html = render(collect(db, session_id))
    out.parent.mkdir(parents=True, exist_ok=True)
    html_path = out.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    result: dict[str, Any] = {"session_id": session_id, "html": True, "pdf": False}
    if pdf:
        found = find_browser(browser)
        if found is None:
            result["pdf_error"] = (
                "No Edge, Chrome or Chromium found; set NIDS_PDF_BROWSER to print PDFs."
            )
        else:
            try:
                html_to_pdf(html_path, out.with_suffix(".pdf"), found)
                result["pdf"] = True
            except PdfError as exc:
                result["pdf_error"] = str(exc)
    return result


def result_line(result: dict[str, Any]) -> str:
    """The line the CLI prints; the job supervisor parses it back."""
    return "Report written: " + json.dumps(result)

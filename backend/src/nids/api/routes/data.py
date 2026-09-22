"""Alerts, flows, sessions and statistics: the data the dashboard reads."""

import csv
import io
import json
import time
from collections.abc import Callable, Iterator
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Select, desc, func, select

from nids.api.auth import Principal, get_db, require_user
from nids.api.errors import ApiError
from nids.core.schemas.alert import AlertStatus
from nids.store import repo
from nids.store.db import Database
from nids.store.models import AlertRow, CaptureSession, Flow, Traffic

router = APIRouter(prefix="/api", tags=["data"])

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["new", "acknowledged", "resolved", "false_positive"]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str | None
    created_at: float
    last_seen: float
    updated_at: float
    type: str
    title: str
    source: str
    severity: Severity
    confidence: float
    src: str | None
    dst: str | None
    ports: list[int]
    protocol: int | None
    mitre_technique: str | None
    explanation: str
    recommendation: str
    evidence: dict[str, Any]
    occurrences: int
    flow_ids: list[str]
    family: str | None
    model_version: str | None
    status: Status
    note: str


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status | None = None
    note: str | None = Field(default=None, max_length=5000)


@router.get("/alerts")
def list_alerts(
    severity: list[Severity] = Query(default=[]),
    status: list[Status] = Query(default=[]),
    type: list[str] = Query(default=[]),
    src: str | None = None,
    dst: str | None = None,
    since: float | None = None,
    until: float | None = None,
    session_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> Page[AlertOut]:
    """Alerts, most recently active first, filtered and paginated."""
    query = repo.AlertQuery(
        severity=tuple(severity),
        status=tuple(status),
        type=tuple(type),
        src=src,
        dst=dst,
        since=since,
        until=until,
        session_id=session_id,
        limit=limit,
        offset=offset,
    )
    rows, total = repo.list_alerts(db, query)
    return Page(
        items=[AlertOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


# --- exports (the whole filtered result, not one page) ---------------------------------------

EXPORT_LIMIT = 100_000
_CHUNK = 2_000


def _csv_safe(value: Any) -> Any:
    """Stop spreadsheets from running a cell as a formula (CSV injection)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _export(
    db: Database,
    stmt: Select[Any],
    order: tuple[Any, ...],
    fmt: Literal["csv", "json"],
    columns: tuple[str, ...],
    row_dict: Callable[[Any], dict[str, Any]],
    name: str,
) -> StreamingResponse:
    """Stream rows in chunks (each read in its own short session), as CSV or a JSON array."""

    def rows() -> Iterator[dict[str, Any]]:
        for offset in range(0, EXPORT_LIMIT, _CHUNK):
            with db.session() as s:
                chunk = s.scalars(
                    stmt.order_by(*order).limit(min(_CHUNK, EXPORT_LIMIT - offset)).offset(offset)
                ).all()
                items = [row_dict(r) for r in chunk]
            yield from items
            if len(chunk) < _CHUNK:
                return

    def as_csv() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for i, row in enumerate(rows(), 1):
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})
            if i % 500 == 0:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate()
        yield buffer.getvalue()

    def as_json() -> Iterator[str]:
        yield "["
        for i, row in enumerate(rows()):
            yield ("," if i else "") + "\n" + json.dumps(row)
        yield "\n]\n"

    stamp = time.strftime("%Y%m%d-%H%M%S")
    return StreamingResponse(
        as_csv() if fmt == "csv" else as_json(),
        media_type="text/csv; charset=utf-8" if fmt == "csv" else "application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}-{stamp}.{fmt}"'},
    )


EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {"content": {"text/csv": {}, "application/json": {}}}
}

ALERT_EXPORT_COLUMNS = (
    "id",
    "session_id",
    "created_at",
    "last_seen",
    "severity",
    "type",
    "title",
    "source",
    "confidence",
    "src",
    "dst",
    "ports",
    "protocol",
    "mitre_technique",
    "occurrences",
    "status",
    "note",
    "family",
    "model_version",
    "explanation",
    "recommendation",
)


def _alert_row(row: AlertRow, flat: bool) -> dict[str, Any]:
    data = {c: getattr(row, c) for c in ALERT_EXPORT_COLUMNS}
    if flat:  # CSV: readable times and one cell per list
        data["created_at"], data["last_seen"] = _iso(row.created_at), _iso(row.last_seen)
        data["ports"] = " ".join(str(p) for p in row.ports or [])
        data["confidence"] = round(row.confidence, 4)
    return data


@router.get("/alerts/export", response_class=StreamingResponse, responses=EXPORT_RESPONSES)
def export_alerts(
    format: Literal["csv", "json"] = "csv",
    severity: list[Severity] = Query(default=[]),
    status: list[Status] = Query(default=[]),
    type: list[str] = Query(default=[]),
    src: str | None = None,
    dst: str | None = None,
    since: float | None = None,
    until: float | None = None,
    session_id: str | None = None,
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> StreamingResponse:
    """Every alert matching the filters (up to 100,000), as CSV or JSON. CSV cells that a
    spreadsheet would run as a formula are prefixed with an apostrophe."""
    query = repo.AlertQuery(
        severity=tuple(severity),
        status=tuple(status),
        type=tuple(type),
        src=src,
        dst=dst,
        since=since,
        until=until,
        session_id=session_id,
    )
    return _export(
        db,
        repo.filtered_alerts(query),
        (AlertRow.last_seen.desc(), AlertRow.id),
        format,
        ALERT_EXPORT_COLUMNS,
        lambda r: _alert_row(r, flat=format == "csv"),
        "alerts",
    )


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: str, _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> AlertOut:
    with db.session() as s:
        row = s.get(AlertRow, alert_id)
        if row is None:
            raise ApiError(404, f"Alert {alert_id} not found.")
        return AlertOut.model_validate(row)


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    body: AlertUpdate,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> AlertOut:
    """Acknowledge, resolve or mark as false positive (which also suppresses repeats), and/or
    change the note."""
    if body.status is None and body.note is None:
        raise ApiError(422, "Nothing to change.")
    with db.session() as s:
        current = s.get(AlertRow, alert_id)
        if current is None:
            raise ApiError(404, f"Alert {alert_id} not found.")
        status = AlertStatus(body.status or current.status)
    row = repo.set_alert_status(db, alert_id, status, principal.username, body.note)
    assert row is not None
    return AlertOut.model_validate(row)


class FlowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: str
    flow_id: str
    first_seen: float
    last_seen: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    payload_bytes: int
    ip_bytes: int | None
    end_reason: str
    app_protocol: str | None
    stats: dict[str, Any]


def flow_statement(
    session_id: str | None,
    ip: str | None,
    port: int | None,
    protocol: int | None,
    flow_id: list[str],
    since: float | None,
) -> Select[tuple[Flow]]:
    stmt = select(Flow)
    if session_id:
        stmt = stmt.where(Flow.session_id == session_id)
    if ip:
        stmt = stmt.where((Flow.src_ip == ip) | (Flow.dst_ip == ip))
    if port is not None:
        stmt = stmt.where((Flow.dst_port == port) | (Flow.src_port == port))
    if protocol is not None:
        stmt = stmt.where(Flow.protocol == protocol)
    if flow_id:
        stmt = stmt.where(Flow.flow_id.in_(flow_id))
    if since is not None:
        stmt = stmt.where(Flow.last_seen >= since)
    return stmt


@router.get("/flows")
def list_flows(
    session_id: str | None = None,
    ip: str | None = Query(default=None, description="Either endpoint"),
    port: int | None = Query(default=None, ge=0, le=65535),
    protocol: int | None = Query(default=None, ge=0, le=255),
    flow_id: list[str] = Query(default=[]),
    since: float | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> Page[FlowOut]:
    stmt = flow_statement(session_id, ip, port, protocol, flow_id, since)
    with db.session() as s:
        total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = s.scalars(stmt.order_by(desc(Flow.last_seen)).limit(limit).offset(offset)).all()
        return Page(
            items=[FlowOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
        )


FLOW_EXPORT_COLUMNS = (
    "session_id",
    "flow_id",
    "first_seen",
    "last_seen",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "packets",
    "payload_bytes",
    "ip_bytes",
    "end_reason",
    "app_protocol",
)


def _flow_row(row: Flow, flat: bool) -> dict[str, Any]:
    data = {c: getattr(row, c) for c in FLOW_EXPORT_COLUMNS}
    if flat:
        data["first_seen"], data["last_seen"] = _iso(row.first_seen), _iso(row.last_seen)
    else:
        data["stats"] = row.stats  # every measured feature, as stored
    return data


@router.get("/flows/export", response_class=StreamingResponse, responses=EXPORT_RESPONSES)
def export_flows(
    format: Literal["csv", "json"] = "csv",
    session_id: str | None = None,
    ip: str | None = Query(default=None, description="Either endpoint"),
    port: int | None = Query(default=None, ge=0, le=65535),
    protocol: int | None = Query(default=None, ge=0, le=255),
    since: float | None = None,
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> StreamingResponse:
    """Every flow matching the filters (up to 100,000), as CSV (summary columns) or JSON (with
    every measured feature)."""
    return _export(
        db,
        flow_statement(session_id, ip, port, protocol, [], since),
        (Flow.last_seen.desc(), Flow.id),
        format,
        FLOW_EXPORT_COLUMNS,
        lambda r: _flow_row(r, flat=format == "csv"),
        "flows",
    )


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    source: str
    backend: str
    model_version: str | None
    started_at: float
    stopped_at: float | None
    status: str
    error: str | None
    metrics: dict[str, Any]


@router.get("/sessions")
def list_sessions(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> Page[SessionOut]:
    with db.session() as s:
        total = s.scalar(select(func.count()).select_from(CaptureSession)) or 0
        rows = s.scalars(
            select(CaptureSession)
            .order_by(desc(CaptureSession.started_at))
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=[SessionOut.model_validate(r) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/sessions/{session_id}")
def get_session(
    session_id: str, _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> SessionOut:
    with db.session() as s:
        row = s.get(CaptureSession, session_id)
        if row is None:
            raise ApiError(404, f"Session {session_id} not found.")
        return SessionOut.model_validate(row)


class Bucket(BaseModel):
    ts: int
    packets: int
    bytes: int
    tcp: int
    udp: int
    icmp: int
    other: int
    flows_started: int
    flows_ended: int
    alerts: int


_COUNTERS = (
    "packets",
    "bytes",
    "tcp",
    "udp",
    "icmp",
    "other",
    "flows_started",
    "flows_ended",
    "alerts",
)


@router.get("/stats/timeseries")
def timeseries(
    # A Literal[1, 60] query parameter rejects the string "60", so validate by hand.
    resolution: int = Query(default=1, description="Bucket length in seconds: 1 or 60"),
    since: float | None = Query(default=None, description="Epoch seconds; default: last 15 min"),
    session_id: str | None = None,
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> list[Bucket]:
    """Traffic per second (resolution=1, last 24 h) or per minute (resolution=60), summed over
    sessions unless one is given. Replays keep their original timestamps; pass their session.

    Per-minute rows are written by the retention roll-up, which only covers complete minutes and
    lags behind capture, so minutes it hasn't reached yet are built from per-second rows. Where
    both exist the roll-up wins (its seconds may already have expired)."""
    if resolution not in (1, 60):
        raise ApiError(422, "resolution must be 1 or 60.")
    start = since if since is not None else time.time() - 900

    def query(res: int, bucket: Any) -> Any:
        stmt = (
            select(bucket.label("ts"), *(func.sum(getattr(Traffic, c)).label(c) for c in _COUNTERS))
            .where(Traffic.resolution == res, Traffic.ts >= start)
            .group_by(bucket)
            .order_by(bucket)
            .limit(20_000)
        )
        return stmt.where(Traffic.session_id == session_id) if session_id else stmt

    def rows(stmt: Any) -> dict[int, Bucket]:
        return {
            int(r.ts): Bucket(ts=int(r.ts), **{c: int(getattr(r, c)) for c in _COUNTERS})
            for r in s.execute(stmt)
        }

    with db.session() as s:
        if resolution == 1:
            return list(rows(query(1, Traffic.ts)).values())
        minutes = rows(query(1, (Traffic.ts // 60) * 60))
        minutes.update(rows(query(60, Traffic.ts)))
        return [minutes[ts] for ts in sorted(minutes)]


class Summary(BaseModel):
    open_alerts: dict[str, int]
    alerts_last_24h: int
    flows_last_hour: int
    top_talkers: list[dict[str, Any]]
    protocols_last_15m: dict[str, int]


@router.get("/stats/summary")
def summary(_: Principal = Depends(require_user), db: Database = Depends(get_db)) -> Summary:
    """Numbers for the Overview KPI strip."""
    now = time.time()
    with db.session() as s:
        open_by_severity = {
            str(severity): int(n)
            for severity, n in s.execute(
                select(AlertRow.severity, func.count())
                .where(AlertRow.status.in_(("new", "acknowledged")))
                .group_by(AlertRow.severity)
            )
        }
        alerts_24h = (
            s.scalar(
                select(func.count()).select_from(AlertRow).where(AlertRow.created_at >= now - 86400)
            )
            or 0
        )
        flows_hour = (
            s.scalar(select(func.count()).select_from(Flow).where(Flow.last_seen >= now - 3600))
            or 0
        )
        talkers = s.execute(
            select(
                Flow.src_ip,
                func.sum(Flow.payload_bytes).label("bytes"),
                func.count().label("flows"),
            )
            .where(Flow.last_seen >= now - 900)
            .group_by(Flow.src_ip)
            .order_by(desc("bytes"))
            .limit(5)
        ).all()
        protocols = s.execute(
            select(
                *(
                    func.coalesce(func.sum(getattr(Traffic, c)), 0).label(c)
                    for c in ("tcp", "udp", "icmp", "other")
                )
            ).where(Traffic.resolution == 1, Traffic.ts >= now - 900)
        ).one()
    return Summary(
        open_alerts={k: int(v) for k, v in open_by_severity.items()},
        alerts_last_24h=alerts_24h,
        flows_last_hour=flows_hour,
        top_talkers=[
            {"ip": t.src_ip, "bytes": int(t.bytes or 0), "flows": int(t.flows)} for t in talkers
        ],
        protocols_last_15m={k: int(getattr(protocols, k)) for k in ("tcp", "udp", "icmp", "other")},
    )

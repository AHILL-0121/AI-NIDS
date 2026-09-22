"""Traffic rollups and data retention (audit SEC-11): old data is summarised or deleted on a
schedule instead of growing forever.

Live data ages by its own timestamps. Replayed PCAPs carry their original (often years-old)
timestamps, so a replay session's data ages by when the replay was run instead.
"""

from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import ColumnElement, CursorResult, Delete, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from nids.core.settings import Settings
from nids.store.db import Database
from nids.store.models import AlertRow, AuditLog, CaptureSession, Flow, Traffic, utcnow
from nids.store.repo import audit, get_setting, set_setting

ROLLED_UNTIL = "traffic.rolled_until"
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
DAY = 86_400.0


@dataclass(frozen=True)
class RetentionPolicy:
    flows_days: float = 7
    alerts_days: float = 90
    traffic_1s_hours: float = 24
    traffic_1m_days: float = 90
    audit_days: float = 365

    @classmethod
    def from_settings(cls, s: Settings) -> "RetentionPolicy":
        return cls(
            flows_days=s.retention_flows_days,
            alerts_days=s.retention_alerts_days,
            traffic_1s_hours=s.retention_traffic_1s_hours,
            traffic_1m_days=s.retention_traffic_1m_days,
        )


def rollup_traffic(db: Database, now: float | None = None) -> int:
    """Add complete minutes of 1-second buckets into 60-second buckets. Returns rows written.
    Runs incrementally: a setting remembers how far it has rolled up. Replay buckets (old
    timestamps) are rolled up when their replay session has finished."""
    now = utcnow() if now is None else now
    cutoff = int((now - 120) // 60 * 60)  # leave the last two minutes: still being written
    with db.session() as s:
        start = int(get_setting(s, ROLLED_UNTIL, 0))
        replays_done = select(CaptureSession.id).where(
            CaptureSession.kind == "replay",
            CaptureSession.stopped_at.is_not(None),
            CaptureSession.stopped_at < cutoff,
            CaptureSession.metrics["rolled_up"].as_boolean().is_not(True),
        )
        done_ids = list(s.scalars(replays_done))
        live_window = and_(
            Traffic.ts >= start,
            Traffic.ts < cutoff,
            Traffic.session_id.not_in(
                select(CaptureSession.id).where(CaptureSession.kind == "replay")
            ),
        )
        which = or_(live_window, Traffic.session_id.in_(done_ids)) if done_ids else live_window
        minute = (Traffic.ts // 60) * 60
        rows = s.execute(
            select(
                Traffic.session_id,
                minute.label("minute"),
                *(func.sum(getattr(Traffic, c)).label(c) for c in _COUNTERS),
            )
            .where(Traffic.resolution == 1, which)
            .group_by(Traffic.session_id, minute)
        ).all()
        for row in rows:
            key = {"resolution": 60, "ts": int(row.minute), "session_id": row.session_id}
            bucket = s.get(Traffic, key)
            if bucket is None:
                s.add(Traffic(**key, **{c: int(getattr(row, c)) for c in _COUNTERS}))
            else:
                for c in _COUNTERS:
                    setattr(bucket, c, getattr(bucket, c) + int(getattr(row, c)))
        for session_id in done_ids:
            session = s.get(CaptureSession, session_id)
            if session is not None:
                session.metrics = {**session.metrics, "rolled_up": True}
        set_setting(s, ROLLED_UNTIL, max(start, cutoff))
        return len(rows)


def _older(
    ts_column: Any, session_column: Any, cutoff: float, expired_replays: list[str]
) -> ColumnElement[bool]:
    """Live rows older than the cutoff, plus every row of replay sessions run before it."""
    replay_ids = select(CaptureSession.id).where(CaptureSession.kind == "replay")
    live_old = and_(
        ts_column < cutoff, or_(session_column.is_(None), session_column.not_in(replay_ids))
    )
    return or_(live_old, session_column.in_(expired_replays)) if expired_replays else live_old


def _deleted(s: Session, stmt: Delete) -> int:
    return cast(CursorResult[Any], s.execute(stmt)).rowcount


def purge(db: Database, policy: RetentionPolicy, now: float | None = None) -> dict[str, int]:
    """Delete data older than the policy allows. Returns deleted row counts per table."""
    now = utcnow() if now is None else now
    rollup_traffic(db, now)
    with db.session() as s:

        def expired(days: float) -> list[str]:
            return list(
                s.scalars(
                    select(CaptureSession.id).where(
                        CaptureSession.kind == "replay",
                        CaptureSession.stopped_at < now - days * DAY,
                    )
                )
            )

        flows_cut, alerts_cut = now - policy.flows_days * DAY, now - policy.alerts_days * DAY
        t1_cut = now - policy.traffic_1s_hours * 3600
        t60_cut = now - policy.traffic_1m_days * DAY
        counts = {
            "flows": _deleted(
                s,
                delete(Flow).where(
                    _older(Flow.last_seen, Flow.session_id, flows_cut, expired(policy.flows_days))
                ),
            ),
            "alerts": _deleted(
                s,
                delete(AlertRow).where(
                    _older(
                        AlertRow.last_seen,
                        AlertRow.session_id,
                        alerts_cut,
                        expired(policy.alerts_days),
                    )
                ),
            ),
            "traffic_1s": _deleted(
                s,
                delete(Traffic).where(
                    Traffic.resolution == 1,
                    _older(
                        Traffic.ts,
                        Traffic.session_id,
                        t1_cut,
                        expired(policy.traffic_1s_hours / 24),
                    ),
                ),
            ),
            "traffic_1m": _deleted(
                s,
                delete(Traffic).where(
                    Traffic.resolution == 60,
                    _older(
                        Traffic.ts, Traffic.session_id, t60_cut, expired(policy.traffic_1m_days)
                    ),
                ),
            ),
            "audit_log": _deleted(
                s,
                delete(AuditLog).where(AuditLog.ts < now - policy.audit_days * DAY),
            ),
        }
        audit(s, "system", "retention.purge", None, **counts)
    return counts

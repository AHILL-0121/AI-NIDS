"""Reading and writing the database. Everything the sensor and (later) the API store goes
through here."""

import hmac
import ipaddress
import re
import secrets
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from nids.core.schemas.alert import Alert, AlertStatus
from nids.core.schemas.flow import FlowRecord
from nids.sensor.detect.correlator import SuppressionRule
from nids.store.db import Database
from nids.store.models import (
    AlertRow,
    AuditLog,
    CaptureSession,
    Flow,
    SettingRow,
    SuppressionRuleRow,
    utcnow,
)

# --- settings stored in the database --------------------------------------------------------


def get_setting(session: Session, key: str, default: Any = None) -> Any:
    row = session.get(SettingRow, key)
    return default if row is None else row.value.get("value", default)


def set_setting(session: Session, key: str, value: Any) -> None:
    row = session.get(SettingRow, key)
    if row is None:
        session.add(SettingRow(key=key, value={"value": value}))
    else:
        row.value = {"value": value}
        row.updated_at = utcnow()


def audit(session: Session, actor: str, action: str, target: str | None, **details: Any) -> None:
    session.add(AuditLog(actor=actor, action=action, target=target, details=details))


# --- IP pseudonymisation (audit SEC-11) ------------------------------------------------------


class Pseudonymizer:
    """Replace IP addresses with stable keyed hashes ("ip-3f9a1c0b2d4e"). The same address always
    maps to the same token, so correlation still works, but the database no longer reveals who
    talked to whom. The key lives in the settings table; losing it makes tokens unlinkable."""

    SETTING = "privacy.pseudonym_key"

    def __init__(self, key: bytes) -> None:
        self._key = key

    @classmethod
    def from_db(cls, db: Database) -> "Pseudonymizer":
        with db.session() as session:
            key = get_setting(session, cls.SETTING)
            if key is None:
                key = secrets.token_hex(32)
                set_setting(session, cls.SETTING, key)
        return cls(bytes.fromhex(key))

    def token(self, address: str) -> str:
        digest = hmac.new(self._key, address.encode(), sha256).hexdigest()[:12]
        return f"ip-{digest}"

    # IPv4 or IPv6-looking tokens, optionally with a /prefix; apply() ignores false matches.
    _IP_IN_TEXT = re.compile(
        r"(?<![\w.:])"
        r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)"
        r"(?:/\d{1,3})?"
    )

    def apply_text(self, text: str) -> str:
        """Pseudonymise every IP address (or CIDR) that appears inside free text."""
        return self._IP_IN_TEXT.sub(lambda m: str(self.apply(m.group(0))), text)

    def apply(self, value: Any) -> Any:
        if isinstance(value, str):
            try:
                if "/" in value:
                    net = ipaddress.ip_network(value, strict=False)
                    return f"{self.token(str(net.network_address))}/{net.prefixlen}"
                ipaddress.ip_address(value)
                return self.token(value)
            except ValueError:
                return value
        if isinstance(value, list):
            return [self.apply(v) for v in value]
        if isinstance(value, dict):
            return {k: self.apply(v) for k, v in value.items()}
        return value


# --- sessions (audit CAP-08) -------------------------------------------------------------------


def start_session(
    db: Database, kind: str, source: str, backend: str, model_version: str | None = None
) -> str:
    session_id = uuid.uuid4().hex[:16]
    with db.session() as s:
        s.add(
            CaptureSession(
                id=session_id,
                kind=kind,
                source=source,
                backend=backend,
                model_version=model_version,
            )
        )
    return session_id


def finish_session(
    db: Database, session_id: str, metrics: dict[str, Any], error: str | None = None
) -> None:
    with db.session() as s:
        row = s.get(CaptureSession, session_id)
        if row is None:
            return
        row.stopped_at = utcnow()
        row.status = "failed" if error else "stopped"
        row.error = error
        row.metrics = metrics


# --- flows --------------------------------------------------------------------------------------


class FlowWriter:
    """Batched flow inserts. With `sample_rate` < 1, a deterministic share of flows is stored
    (by flow-id hash, so reruns keep the same ones); flows that an alert refers to are always
    stored, even when the alert comes after the flow was dropped (`keep`)."""

    def __init__(
        self,
        db: Database,
        session_id: str,
        sample_rate: float = 1.0,
        batch_size: int = 500,
        pseudonymizer: Pseudonymizer | None = None,
        recent_dropped: int = 20_000,
    ) -> None:
        self.db = db
        self.session_id = session_id
        self.sample_rate = sample_rate
        self.batch_size = batch_size
        self.pseudonymizer = pseudonymizer
        self._pending: list[Flow] = []
        self._dropped: OrderedDict[str, FlowRecord] = OrderedDict()
        self._recent_dropped = recent_dropped
        self._kept_ids: set[str] = set()
        self.written = 0

    def _sampled(self, flow_id: str) -> bool:
        if self.sample_rate >= 1:
            return True
        bucket = int.from_bytes(sha256(flow_id.encode()).digest()[:4], "big") / 2**32
        return bucket < self.sample_rate

    def add(self, flow: FlowRecord) -> None:
        if self._sampled(flow.flow_id) or flow.flow_id in self._kept_ids:
            self._queue(flow)
        else:
            self._dropped[flow.flow_id] = flow
            if len(self._dropped) > self._recent_dropped:
                self._dropped.popitem(last=False)

    def keep(self, flow_ids: list[str]) -> None:
        """Make sure these flows get stored (called for flows an alert refers to)."""
        for flow_id in flow_ids:
            dropped = self._dropped.pop(flow_id, None)
            if dropped is not None:
                self._queue(dropped)
            else:
                self._kept_ids.add(flow_id)  # the flow hasn't ended yet

    def _queue(self, flow: FlowRecord) -> None:
        self._kept_ids.discard(flow.flow_id)
        data = flow.to_dict()
        if self.pseudonymizer is not None:
            data = self.pseudonymizer.apply(data)
        self._pending.append(
            Flow(
                session_id=self.session_id,
                flow_id=flow.flow_id,
                first_seen=flow.first_seen,
                last_seen=flow.last_seen,
                src_ip=data["src_ip"],
                dst_ip=data["dst_ip"],
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                packets=flow.packets,
                payload_bytes=flow.payload_bytes,
                ip_bytes=flow.ip_bytes,
                end_reason=flow.end_reason.value,
                app_protocol=flow.app_protocol,
                stats=data,
            )
        )
        if len(self._pending) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        with self.db.session() as s:
            s.add_all(batch)
        self.written += len(batch)


# --- alerts -------------------------------------------------------------------------------------

_DETECTION_FIELDS = (
    "last_seen",
    "title",
    "severity",
    "confidence",
    "ports",
    "mitre_technique",
    "explanation",
    "recommendation",
    "evidence",
    "occurrences",
    "flow_ids",
    "family",
    "model_version",
)


def upsert_alert(
    db: Database, alert: Alert, session_id: str | None, pseudonymizer: Pseudonymizer | None = None
) -> None:
    """Insert a new alert, or update the detection fields of an existing one. The analyst's
    fields (status, note) are never overwritten by the sensor."""
    data = alert.to_dict()
    if pseudonymizer is not None:
        for key in ("src", "dst", "evidence"):
            data[key] = pseudonymizer.apply(data[key])
        data["explanation"] = pseudonymizer.apply_text(data["explanation"])
    with db.session() as s:
        row = s.get(AlertRow, alert.id)
        if row is None:
            s.add(
                AlertRow(
                    id=alert.id,
                    session_id=session_id,
                    created_at=alert.created_at,
                    type=alert.type,
                    source=data["source"],
                    src=data["src"],
                    dst=data["dst"],
                    protocol=alert.protocol,
                    status=data["status"],
                    note=alert.note,
                    **{f: data[f] for f in _DETECTION_FIELDS},
                )
            )
        else:
            for field in _DETECTION_FIELDS:
                setattr(row, field, data[field])
            row.updated_at = utcnow()


def alert_statuses(db: Database, alert_ids: list[str]) -> dict[str, str]:
    if not alert_ids:
        return {}
    with db.session() as s:
        rows = s.execute(select(AlertRow.id, AlertRow.status).where(AlertRow.id.in_(alert_ids)))
        return {row.id: row.status for row in rows}


def set_alert_status(
    db: Database, alert_id: str, status: AlertStatus, actor: str, note: str | None = None
) -> AlertRow | None:
    """Analyst verdict. Marking a false positive also adds a suppression rule for the same
    (type, src, dst), which running sensors pick up on their next sync."""
    with db.session() as s:
        row = s.get(AlertRow, alert_id)
        if row is None:
            return None
        previous = row.status
        row.status = status.value
        if note is not None:
            row.note = note
        row.updated_at = utcnow()
        audit(s, actor, "alert.status", alert_id, previous=previous, status=status.value)
        if status is AlertStatus.FALSE_POSITIVE:
            s.add(
                SuppressionRuleRow(
                    type=row.type,
                    src=row.src,
                    dst=row.dst,
                    reason=f"false positive {alert_id}",
                    alert_id=alert_id,
                    created_by=actor,
                )
            )
            audit(s, actor, "suppression.add", alert_id, type=row.type, src=row.src, dst=row.dst)
        return row


@dataclass(frozen=True)
class AlertQuery:
    severity: tuple[str, ...] = ()
    status: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    src: str | None = None
    dst: str | None = None
    since: float | None = None
    until: float | None = None
    session_id: str | None = None
    limit: int = 100
    offset: int = 0


def _filtered(query: AlertQuery) -> Select[tuple[AlertRow]]:
    stmt = select(AlertRow)
    if query.severity:
        stmt = stmt.where(AlertRow.severity.in_(query.severity))
    if query.status:
        stmt = stmt.where(AlertRow.status.in_(query.status))
    if query.type:
        stmt = stmt.where(AlertRow.type.in_(query.type))
    if query.src:
        stmt = stmt.where(AlertRow.src == query.src)
    if query.dst:
        stmt = stmt.where(AlertRow.dst == query.dst)
    if query.since is not None:
        stmt = stmt.where(AlertRow.last_seen >= query.since)
    if query.until is not None:
        stmt = stmt.where(AlertRow.created_at <= query.until)
    if query.session_id:
        stmt = stmt.where(AlertRow.session_id == query.session_id)
    return stmt


def list_alerts(db: Database, query: AlertQuery) -> tuple[list[AlertRow], int]:
    stmt = _filtered(query)
    with db.session() as s:
        total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = s.scalars(
            stmt.order_by(AlertRow.last_seen.desc()).limit(query.limit).offset(query.offset)
        ).all()
        return list(rows), total


# --- suppression rules ----------------------------------------------------------------------------


def load_suppression_rules(db: Database, now: float | None = None) -> list[SuppressionRule]:
    now = utcnow() if now is None else now
    with db.session() as s:
        rows = s.scalars(
            select(SuppressionRuleRow).where(SuppressionRuleRow.active.is_(True))
        ).all()
        return [
            SuppressionRule(
                type=r.type,
                src=r.src,
                dst=r.dst,
                dst_port=r.dst_port,
                until=r.until,
                reason=r.reason,
            )
            for r in rows
            if r.until is None or r.until > now
        ]


def add_suppression_rule(
    db: Database, rule: SuppressionRule, actor: str, alert_id: str | None = None
) -> int:
    with db.session() as s:
        row = SuppressionRuleRow(
            type=rule.type,
            src=rule.src,
            dst=rule.dst,
            dst_port=rule.dst_port,
            until=rule.until,
            reason=rule.reason,
            alert_id=alert_id,
            created_by=actor,
        )
        s.add(row)
        s.flush()
        audit(s, actor, "suppression.add", str(row.id), type=rule.type, src=rule.src, dst=rule.dst)
        return row.id

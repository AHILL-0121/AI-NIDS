"""Database tables (SQLAlchemy 2). Schema changes go through Alembic migrations
(`src/nids/store/migrations`), never `create_all`, so existing databases can be upgraded."""

from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, MetaData, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> float:
    return datetime.now(UTC).timestamp()


class Base(DeclarativeBase):
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_N_name)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )
    type_annotation_map: ClassVar[dict[Any, Any]] = {dict[str, Any]: JSON, list[Any]: JSON}


class CaptureSession(Base):
    """One run of the sensor (live) or one PCAP replay. Counters never leak between runs."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # "live" | "replay"
    source: Mapped[str] = mapped_column(String(512))  # interface name or PCAP file name
    backend: Mapped[str] = mapped_column(String(16))
    model_version: Mapped[str | None] = mapped_column(String(128))
    started_at: Mapped[float] = mapped_column(Float, default=utcnow)
    stopped_at: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|stopped|failed
    error: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        Index(None, "session_id", "first_seen"),
        Index(None, "src_ip"),
        Index(None, "dst_ip"),
        Index(None, "flow_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    flow_id: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    src_ip: Mapped[str] = mapped_column(String(64))
    dst_ip: Mapped[str] = mapped_column(String(64))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)
    packets: Mapped[int] = mapped_column(Integer)
    payload_bytes: Mapped[int] = mapped_column(Integer)
    ip_bytes: Mapped[int | None] = mapped_column(Integer)
    end_reason: Mapped[str] = mapped_column(String(16))
    app_protocol: Mapped[str | None] = mapped_column(String(64))
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict)  # the full FlowRecord.to_dict()


class AlertRow(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index(None, "created_at"),
        Index(None, "severity", "status"),
        Index(None, "type"),
        Index(None, "src"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id", ondelete="SET NULL"))
    created_at: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    updated_at: Mapped[float] = mapped_column(Float, default=utcnow)
    type: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    src: Mapped[str | None] = mapped_column(String(64))
    dst: Mapped[str | None] = mapped_column(String(64))
    ports: Mapped[list[Any]] = mapped_column(default=list)
    protocol: Mapped[int | None] = mapped_column(Integer)
    mitre_technique: Mapped[str | None] = mapped_column(String(128))
    explanation: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    flow_ids: Mapped[list[Any]] = mapped_column(default=list)
    family: Mapped[str | None] = mapped_column(String(32))
    model_version: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="new")
    note: Mapped[str] = mapped_column(Text, default="")
    # Highest severity the notifier has already handled (None = not looked at yet), so an alert
    # that escalates past a channel's threshold is announced once, and restarts don't repeat.
    notified_severity: Mapped[str | None] = mapped_column(String(16))


class Traffic(Base):
    """Traffic counters per time bucket: 1-second buckets for live charts (kept 24 h), rolled up
    into 60-second buckets for history (audit CAP-07: rates from real buckets, not averages)."""

    __tablename__ = "traffic"

    resolution: Mapped[int] = mapped_column(Integer, primary_key=True)  # 1 or 60 seconds
    ts: Mapped[int] = mapped_column(Integer, primary_key=True)  # bucket start, epoch seconds
    session_id: Mapped[str] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), primary_key=True
    )
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    tcp: Mapped[int] = mapped_column(Integer, default=0)
    udp: Mapped[int] = mapped_column(Integer, default=0)
    icmp: Mapped[int] = mapped_column(Integer, default=0)
    other: Mapped[int] = mapped_column(Integer, default=0)
    flows_started: Mapped[int] = mapped_column(Integer, default=0)
    flows_ended: Mapped[int] = mapped_column(Integer, default=0)
    alerts: Mapped[int] = mapped_column(Integer, default=0)


class SuppressionRuleRow(Base):
    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str | None] = mapped_column(String(32))
    src: Mapped[str | None] = mapped_column(String(64))
    dst: Mapped[str | None] = mapped_column(String(64))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    until: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text, default="")
    alert_id: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[float] = mapped_column(Float, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ModelRow(Base):
    __tablename__ = "models"

    version: Mapped[str] = mapped_column(String(128), primary_key=True)
    path: Mapped[str] = mapped_column(String(1024))
    created_at: Mapped[float] = mapped_column(Float)
    registered_at: Mapped[float] = mapped_column(Float, default=utcnow)
    dataset: Mapped[str | None] = mapped_column(String(64))
    protocol: Mapped[str | None] = mapped_column(String(32))
    feature_set: Mapped[str | None] = mapped_column(String(32))
    schema_hash: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64))
    summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=False)


class SettingRow(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)  # {"value": ...}
    updated_at: Mapped[float] = mapped_column(Float, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index(None, "ts"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[float] = mapped_column(Float, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))  # e.g. "alert.status", "model.activate"
    target: Mapped[str | None] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)


class User(Base):
    """The single local admin (Phase 5 adds login). Password hashes are argon2id."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[float] = mapped_column(Float, default=utcnow)
    last_login_at: Mapped[float | None] = mapped_column(Float)


class AuthSession(Base):
    """Server-side login session. The cookie holds a random token; only its SHA-256 is stored,
    so a database leak doesn't hand out valid sessions."""

    __tablename__ = "auth_sessions"
    __table_args__ = (Index(None, "expires_at"),)

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=utcnow)
    expires_at: Mapped[float] = mapped_column(Float)
    last_seen_at: Mapped[float] = mapped_column(Float, default=utcnow)
    client: Mapped[str] = mapped_column(String(256), default="")


class Upload(Base):
    """A PCAP uploaded through the API, stored under data/uploads/<id> (never a client path)."""

    __tablename__ = "uploads"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    filename: Mapped[str] = mapped_column(String(256))  # original name, for display only
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(16))  # pcap | pcapng
    created_at: Mapped[float] = mapped_column(Float, default=utcnow)


class Job(Base):
    """Background work run as a `nids` subprocess: replay, train, prepare (audit API-05)."""

    __tablename__ = "jobs"
    __table_args__ = (Index(None, "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    params: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[str] = mapped_column(
        String(16), default="queued"
    )  # queued|running|done|failed|cancelled
    created_at: Mapped[float] = mapped_column(Float, default=utcnow)
    started_at: Mapped[float | None] = mapped_column(Float)
    finished_at: Mapped[float | None] = mapped_column(Float)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    pid: Mapped[int | None] = mapped_column(Integer)
    log_path: Mapped[str | None] = mapped_column(String(1024))
    result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[str] = mapped_column(String(64), default="system")

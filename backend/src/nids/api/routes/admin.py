"""Settings, jobs, uploads, logs and suppression rules."""

import hashlib
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import desc, select

from nids.api.auth import Principal, get_db, require_user
from nids.api.errors import ApiError
from nids.api.models import active_version
from nids.core.schemas.runtime import RuntimeSettings
from nids.sensor.detect.correlator import SuppressionRule
from nids.store import repo
from nids.store.db import Database
from nids.store.models import Job, SuppressionRuleRow, Upload

router = APIRouter(prefix="/api", tags=["admin"])

# --- settings ------------------------------------------------------------------------------


class SettingsOut(BaseModel):
    values: RuntimeSettings
    apply: dict[str, str]  # field -> "live" | "restart"


@router.get("/settings")
def get_runtime_settings(
    request: Request, _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> SettingsOut:
    return SettingsOut(
        values=repo.get_runtime(db, request.app.state.settings), apply=RuntimeSettings.apply_modes()
    )


@router.patch("/settings")
def update_runtime_settings(
    changes: dict[str, Any],
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> SettingsOut:
    """Change some settings. Unknown keys and out-of-range values are rejected (audit SEC-02)."""
    unknown = sorted(set(changes) - set(RuntimeSettings.model_fields))
    if unknown:
        raise ApiError(
            422, f"Unknown setting(s): {', '.join(unknown)}.", details={"unknown": unknown}
        )
    try:
        values = repo.update_runtime(db, request.app.state.settings, changes, principal.username)
    except ValidationError as exc:
        details = [
            {"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()
        ]
        raise ApiError(422, "Some values are invalid.", details=details) from exc
    return SettingsOut(values=values, apply=RuntimeSettings.apply_modes())


# --- suppression rules -----------------------------------------------------------------------


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str | None = Field(default=None, max_length=32)
    src: str | None = Field(default=None, max_length=64)
    dst: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    until: float | None = None
    reason: str = Field(default="", max_length=500)


class RuleOut(RuleIn):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: int
    created_at: float
    created_by: str
    active: bool
    alert_id: str | None


@router.get("/suppressions")
def list_rules(
    _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> list[RuleOut]:
    with db.session() as s:
        rows = s.scalars(
            select(SuppressionRuleRow).order_by(desc(SuppressionRuleRow.created_at))
        ).all()
        return [RuleOut.model_validate(r) for r in rows]


@router.post("/suppressions", status_code=201)
def add_rule(
    body: RuleIn, principal: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> RuleOut:
    if body.type is None and body.src is None and body.dst is None and body.dst_port is None:
        raise ApiError(
            422, "A rule needs at least one condition; an empty rule would hide every alert."
        )
    rule_id = repo.add_suppression_rule(
        db, SuppressionRule(**body.model_dump()), principal.username
    )
    with db.session() as s:
        return RuleOut.model_validate(s.get(SuppressionRuleRow, rule_id))


@router.delete("/suppressions/{rule_id}", status_code=204)
def disable_rule(
    rule_id: int, principal: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> None:
    with db.session() as s:
        row = s.get(SuppressionRuleRow, rule_id)
        if row is None:
            raise ApiError(404, f"Rule {rule_id} not found.")
        row.active = False
        repo.audit(s, principal.username, "suppression.disable", str(rule_id))


# --- uploads ---------------------------------------------------------------------------------

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap",  # nanosecond
    b"\xa1\xb2\x3c\x4d": "pcap",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


class UploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    size: int
    sha256: str
    format: str
    created_at: float


@router.post("/uploads", status_code=201)
async def upload_pcap(
    file: UploadFile,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> UploadOut:
    """Upload a pcap/pcapng file for replay. Stored under its own id; the file's type is checked
    by its signature, not its name (audit SEC-04)."""
    settings = request.app.state.settings
    limit = settings.upload_max_mb * 1024 * 1024
    head = await file.read(4)
    kind = _MAGIC.get(head)
    if kind is None:
        raise ApiError(415, "That isn't a pcap or pcapng file.")
    upload_id = uuid.uuid4().hex[:16]
    directory = Path(settings.data_dir) / "uploads"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{upload_id}.{kind}"
    digest, size = hashlib.sha256(head), len(head)
    try:
        with target.open("wb") as out:
            out.write(head)
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > limit:
                    raise ApiError(413, f"Uploads are limited to {settings.upload_max_mb} MB.")
                digest.update(chunk)
                out.write(chunk)
    except ApiError:
        target.unlink(missing_ok=True)
        raise
    name = Path(file.filename or "capture").name[:256]
    with db.session() as s:
        row = Upload(id=upload_id, filename=name, size=size, sha256=digest.hexdigest(), format=kind)
        s.add(row)
        repo.audit(s, principal.username, "upload", upload_id, filename=name, size=size)
    return UploadOut.model_validate(row)


@router.get("/uploads")
def list_uploads(
    _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> list[UploadOut]:
    with db.session() as s:
        return [
            UploadOut.model_validate(r)
            for r in s.scalars(select(Upload).order_by(desc(Upload.created_at)))
        ]


# --- jobs ------------------------------------------------------------------------------------


class ReplayJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["replay"]
    upload_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    use_model: bool = True  # the active model, if one is active


class TrainJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["train"]
    dataset: Literal["cicids2017", "unsw-nb15"]
    protocol: Literal["day", "random", "official"] = "day"
    features: Literal["full", "shared"] = "full"
    sample_frac: float | None = Field(default=None, gt=0, le=1)


class PrepareJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["prepare"]
    dataset: Literal["cicids2017", "unsw-nb15"]


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    params: dict[str, Any]
    status: str
    created_at: float
    started_at: float | None
    finished_at: float | None
    exit_code: int | None
    result: dict[str, Any]
    created_by: str


@router.post("/jobs", status_code=202)
def start_job(
    body: ReplayJob | TrainJob | PrepareJob,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> JobOut:
    params = body.model_dump(exclude={"kind"})
    if isinstance(body, ReplayJob):
        params = {
            "upload_id": body.upload_id,
            "model_version": active_version(db) if body.use_model else None,
        }
    job = request.app.state.supervisor.start(body.kind, params, principal.username)
    return JobOut.model_validate(job)


@router.get("/jobs")
def list_jobs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> list[JobOut]:
    request.app.state.supervisor.poll()
    with db.session() as s:
        rows = s.scalars(select(Job).order_by(desc(Job.created_at)).limit(limit)).all()
        return [JobOut.model_validate(r) for r in rows]


@router.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    request: Request,
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> JobOut:
    request.app.state.supervisor.poll()
    with db.session() as s:
        row = s.get(Job, job_id)
        if row is None:
            raise ApiError(404, f"Job {job_id} not found.")
        return JobOut.model_validate(row)


@router.post("/jobs/{job_id}/cancel", status_code=202)
def cancel_job(
    job_id: str, request: Request, principal: Principal = Depends(require_user)
) -> dict[str, str]:
    request.app.state.supervisor.cancel(job_id, principal.username)
    return {"status": "cancelling"}


# --- logs ------------------------------------------------------------------------------------


def tail(path: Path, lines: int) -> list[str]:
    """Last `lines` lines, reading backwards from the end (not the whole file: audit API-08)."""
    if not path.is_file():
        return []
    block, data = 8192, b""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        position = fh.tell()
        while position > 0 and data.count(b"\n") <= lines:
            step = min(block, position)
            position -= step
            fh.seek(position)
            data = fh.read(step) + data
    return list(deque(data.decode("utf-8", errors="replace").splitlines(), maxlen=lines))


class LogTail(BaseModel):
    source: str
    lines: list[str]


class AuditEntry(BaseModel):
    ts: float
    actor: str
    action: str
    target: str | None
    details: dict[str, Any] | None


@router.get("/logs")
def logs(
    request: Request,
    source: str = Query(default="api", pattern=r"^(api|job:[0-9a-f]{16})$"),
    lines: int = Query(default=200, ge=1, le=5000),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> LogTail:
    """Tail of the API log, or of one job's log (`job:<id>`, e.g. the sensor's)."""
    data_dir = Path(request.app.state.settings.data_dir)
    if source == "api":
        path = data_dir / "logs" / "api.log"
    else:
        with db.session() as s:
            job = s.get(Job, source.removeprefix("job:"))
            if job is None or not job.log_path:
                raise ApiError(404, "No such job log.")
            path = Path(job.log_path)
    return LogTail(source=source, lines=tail(path, lines))


@router.get("/audit")
def audit_log(
    limit: int = Query(default=100, ge=1, le=1000),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> list[AuditEntry]:
    from nids.store.models import AuditLog

    with db.session() as s:
        rows = s.scalars(select(AuditLog).order_by(desc(AuditLog.ts)).limit(limit)).all()
        return [
            AuditEntry(ts=r.ts, actor=r.actor, action=r.action, target=r.target, details=r.details)
            for r in rows
        ]

"""Session reports (audit API-01, API-06).

A report is made by a background job (`POST /api/jobs` with `kind: "report"`), which runs
`nids report` and writes `data/reports/<job id>.html` (+ `.pdf`). A report's id is its job's id,
so the file path is built from a validated id, never from client input.
"""

import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import desc, select

from nids.api.auth import Principal, get_db, require_user
from nids.api.errors import ApiError
from nids.store import repo
from nids.store.db import Database
from nids.store.models import Job

router = APIRouter(prefix="/api/reports", tags=["reports"])

ReportId = PathParam(pattern=r"^[0-9a-f]{16}$")
# Opened in the browser: styles only, no scripts, no requests, can't be framed.
REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; sandbox"
)


class ReportOut(BaseModel):
    id: str
    session_id: str
    status: str  # the job's: running | done | failed | cancelled
    created_at: float
    finished_at: float | None
    html: bool
    pdf: bool
    pdf_error: str | None
    error: str | None


def _dir(request: Request) -> Path:
    return Path(request.app.state.settings.data_dir) / "reports"


def _out(job: Job, directory: Path) -> ReportOut:
    result = job.result or {}
    return ReportOut(
        id=job.id,
        session_id=str(job.params.get("session_id", "")),
        status=job.status,
        created_at=job.created_at,
        finished_at=job.finished_at,
        html=(directory / f"{job.id}.html").is_file(),
        pdf=(directory / f"{job.id}.pdf").is_file(),
        pdf_error=result.get("pdf_error"),
        error=result.get("error"),
    )


@router.get("")
def list_reports(
    request: Request,
    session_id: str | None = Query(default=None, pattern=r"^[0-9a-f]{16}$"),
    limit: int = Query(default=50, ge=1, le=500),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> list[ReportOut]:
    """Reports, newest first (including ones still being generated)."""
    request.app.state.supervisor.poll()
    directory = _dir(request)
    with db.session() as s:
        # The session id lives in the job's JSON params, so filter here; reports are few.
        jobs = s.scalars(
            select(Job).where(Job.kind == "report").order_by(desc(Job.created_at)).limit(2000)
        ).all()
        reports = [_out(j, directory) for j in jobs]
    if session_id:
        reports = [r for r in reports if r.session_id == session_id]
    return reports[:limit]


@router.get("/{report_id}/{fmt}", response_class=FileResponse)
def download_report(
    request: Request,
    fmt: Literal["html", "pdf"],
    report_id: str = ReportId,
    download: bool = Query(default=False, description="Save instead of opening in the browser"),
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> FileResponse:
    with db.session() as s:
        job = s.get(Job, report_id)
        session_id = str(job.params.get("session_id", "")) if job and job.kind == "report" else None
    path = _dir(request) / f"{report_id}.{fmt}"
    if session_id is None or not path.is_file():
        raise ApiError(404, f"Report {report_id} has no {fmt.upper()} file.")
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime(path.stat().st_mtime))
    name = f"nids-report-{session_id}-{stamp}.{fmt}"
    response = FileResponse(
        path,
        media_type="application/pdf" if fmt == "pdf" else "text/html; charset=utf-8",
        filename=name,
        content_disposition_type="attachment" if download else "inline",
    )
    # Browsers' built-in PDF viewers don't run inside a sandboxed or default-src 'none' page.
    response.headers["Content-Security-Policy"] = (
        REPORT_CSP if fmt == "html" else "frame-ancestors 'none'"
    )
    return response


@router.delete("/{report_id}", status_code=204)
def delete_report(
    request: Request,
    report_id: str = ReportId,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> None:
    with db.session() as s:
        job = s.get(Job, report_id)
        if job is None or job.kind != "report":
            raise ApiError(404, f"Report {report_id} not found.")
        if job.status == "running":
            raise ApiError(409, "That report is still being generated.")
        s.delete(job)
        repo.audit(s, principal.username, "report.delete", report_id)
    for fmt in ("html", "pdf"):
        (_dir(request) / f"{report_id}.{fmt}").unlink(missing_ok=True)

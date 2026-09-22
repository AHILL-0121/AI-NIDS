"""Run the sensor and background jobs as child `nids` processes (audit CAP-10, API-05).

The API never captures packets itself: it starts `nids sensor` (which needs capture rights) and
`nids replay` / `nids train` / `nids data prepare` as subprocesses, each with its own log file
under data/jobs/. Arguments are built here from validated, allow-listed values only; nothing a
client sends is passed through as a path or a raw argument (audit SEC-04).

Stopping is graceful: SIGINT (POSIX) or CTRL_BREAK (Windows) makes the CLI flush open flows and
close its session before exiting; after a timeout the process is killed.
"""

import logging
import os
import re
import signal
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from nids.api.errors import ApiError
from nids.core.settings import Settings
from nids.store.db import Database
from nids.store.models import CaptureSession, Job, Upload, utcnow
from nids.store.repo import audit

log = logging.getLogger(__name__)

JobKind = Literal["sensor", "replay", "train", "prepare"]
DATASETS = ("cicids2017", "unsw-nb15")
_WINDOWS = sys.platform == "win32"
_MODEL_SAVED = re.compile(r"Saved model to (\S+)")
_SESSION = re.compile(r'"session": "([0-9a-f]+)"')


@dataclass(frozen=True)
class SensorStatus:
    running: bool
    job_id: str | None
    pid: int | None
    interface: str | None
    session_id: str | None
    started_at: float | None


class Supervisor:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.data_dir = Path(settings.data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._procs: dict[str, subprocess.Popen[bytes]] = {}
        self._lock = threading.Lock()

    # --- lifecycle ---

    def recover(self) -> None:
        """After an API restart, child processes from the previous run are no longer tracked:
        mark their jobs and any still-"running" capture sessions as interrupted."""
        with self.db.session() as s:
            for job in s.query(Job).filter(Job.status.in_(("queued", "running"))):
                job.status, job.finished_at = "failed", utcnow()
                job.result = {**job.result, "error": "interrupted: the API restarted"}
            for session in s.query(CaptureSession).filter(CaptureSession.status == "running"):
                session.status, session.stopped_at = "failed", utcnow()
                session.error = "interrupted: the API restarted"

    def shutdown(self) -> None:
        for job_id in list(self._procs):
            try:
                self.cancel(job_id, actor="system", wait=True)
            except ApiError:  # already finished
                continue

    # --- commands ---

    def _model_args(self, model_version: str | None) -> list[str]:
        if model_version is None:
            return []
        from nids.api.models import model_path  # validated against the registry

        return ["--model", str(model_path(self.db, self.settings, model_version))]

    def _args(self, kind: JobKind, params: dict[str, Any]) -> list[str]:
        if kind == "sensor":
            args = [
                "sensor",
                "--interface",
                params["interface"],
                "--backend",
                params.get("backend", "auto"),
            ]
            return args + self._model_args(params.get("model_version"))
        if kind == "replay":
            with self.db.session() as s:
                upload = s.get(Upload, params["upload_id"])
                if upload is None:
                    raise ApiError(404, f"Upload {params['upload_id']} not found.")
                path = self.data_dir / "uploads" / f"{upload.id}.{upload.format}"
            return ["replay", str(path), *self._model_args(params.get("model_version"))]
        if kind == "train":
            args = [
                "train",
                "--dataset",
                params["dataset"],
                "--protocol",
                params.get("protocol", "day"),
                "--features",
                params.get("features", "full"),
                "--out",
                self.settings.artifacts_dir,
            ]
            if params.get("sample_frac"):
                args += ["--sample-frac", str(float(params["sample_frac"]))]
            return args
        if kind == "prepare":
            src = self.data_dir / "raw" / params["dataset"]
            return ["data", "prepare", params["dataset"], "--src", str(src)]
        raise ApiError(400, f"Unknown job kind '{kind}'.")

    def start(self, kind: JobKind, params: dict[str, Any], actor: str) -> Job:
        with self._lock:
            self._reap()
            running = [j for j in self._procs if self._kind(j) != "sensor"]
            if kind == "sensor" and self.sensor_status().running:
                raise ApiError(409, "The sensor is already running.")
            if kind != "sensor" and len(running) >= self.settings.max_concurrent_jobs:
                raise ApiError(409, "Too many jobs are running. Wait for one to finish.")
            args = self._args(kind, params)
            job_id = uuid.uuid4().hex[:16]
            log_path = self.jobs_dir / f"{job_id}.log"
            env = {
                **os.environ,
                "NIDS_DATABASE_URL": self.settings.database_url,
                "PYTHONUNBUFFERED": "1",
            }
            with log_path.open("wb") as log_file:
                proc = subprocess.Popen(  # noqa: S603 - fixed executable, validated arguments
                    [sys.executable, "-m", "nids.cli", "--log-level", "INFO", *args],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if _WINDOWS else 0,
                    start_new_session=not _WINDOWS,
                )
            self._procs[job_id] = proc
            with self.db.session() as s:
                job = Job(
                    id=job_id,
                    kind=kind,
                    params=params,
                    status="running",
                    started_at=utcnow(),
                    pid=proc.pid,
                    log_path=str(log_path),
                    created_by=actor,
                )
                s.add(job)
                audit(s, actor, f"job.start.{kind}", job_id, **params)
            log.info("Started %s job %s (pid %s)", kind, job_id, proc.pid)
            return job

    def cancel(self, job_id: str, actor: str, wait: bool = False) -> None:
        proc = self._procs.get(job_id)
        if proc is None or proc.poll() is not None:
            raise ApiError(409, "That job isn't running.")
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT if _WINDOWS else signal.SIGINT)
        except OSError:
            proc.terminate()
        with self.db.session() as s:
            job = s.get(Job, job_id)
            if job is not None and job.kind != "sensor":  # stopping the sensor is its normal end
                job.status = "cancelled"
            audit(s, actor, "job.cancel", job_id)
        if wait:
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
            self._reap()

    # --- status ---

    def _kind(self, job_id: str) -> str | None:
        with self.db.session() as s:
            job = s.get(Job, job_id)
            return job.kind if job else None

    def _reap(self) -> list[str]:
        """Record finished processes. Returns the ids of jobs that just finished."""
        finished = []
        for job_id, proc in list(self._procs.items()):
            code = proc.poll()
            if code is None:
                continue
            del self._procs[job_id]
            finished.append(job_id)
            with self.db.session() as s:
                job = s.get(Job, job_id)
                if job is None:
                    continue
                job.exit_code, job.finished_at = code, utcnow()
                if job.status != "cancelled":
                    job.status = "done" if code == 0 else "failed"
                job.result = {**job.result, **self._parse_result(job.log_path)}
        return finished

    def poll(self) -> list[str]:
        with self._lock:
            return self._reap()

    @staticmethod
    def _parse_result(log_path: str | None) -> dict[str, Any]:
        if not log_path or not Path(log_path).is_file():
            return {}
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")[-20000:]
        result: dict[str, Any] = {}
        if match := _MODEL_SAVED.search(text):
            result["model_path"] = match.group(1)
        if match := _SESSION.search(text):
            result["session_id"] = match.group(1)
        errors = [line for line in text.splitlines() if line.startswith("Error:")]
        if errors:
            result["error"] = errors[-1].removeprefix("Error:").strip()
        return result

    def sensor_status(self) -> SensorStatus:
        self._reap()
        for job_id, proc in self._procs.items():
            if proc.poll() is None and self._kind(job_id) == "sensor":
                with self.db.session() as s:
                    job = s.get(Job, job_id)
                    session = (
                        s.query(CaptureSession)
                        .filter(CaptureSession.kind == "live", CaptureSession.status == "running")
                        .order_by(CaptureSession.started_at.desc())
                        .first()
                    )
                    return SensorStatus(
                        running=True,
                        job_id=job_id,
                        pid=proc.pid,
                        interface=job.params.get("interface") if job else None,
                        session_id=session.id if session else None,
                        started_at=job.started_at if job else None,
                    )
        return SensorStatus(False, None, None, None, None, None)

    def running_job_ids(self) -> list[str]:
        return [j for j, p in self._procs.items() if p.poll() is None]

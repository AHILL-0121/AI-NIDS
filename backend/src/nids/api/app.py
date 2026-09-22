"""FastAPI application factory."""

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import func, select, text

from nids import __version__
from nids.api import auth, errors, models, web, ws
from nids.api.routes import admin, data, sensor
from nids.api.supervisor import Supervisor
from nids.core.settings import Settings, get_settings
from nids.store.db import Database
from nids.store.models import AlertRow, Job

log = logging.getLogger(__name__)


def _file_logging(data_dir: Path) -> None:
    """API log file with rotation (audit API-08); tail it via GET /api/logs."""
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)
    path = (data_dir / "logs" / "api.log").resolve()
    root = logging.getLogger()
    if any(
        isinstance(h, RotatingFileHandler) and Path(h.baseFilename) == path for h in root.handlers
    ):
        return
    handler = RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(handler)


async def _daily_retention(app: FastAPI) -> None:
    from nids.store import repo
    from nids.store.retention import RetentionPolicy, purge

    while True:
        try:
            settings: Settings = app.state.settings
            runtime = await asyncio.to_thread(repo.get_runtime, app.state.db, settings)
            policy = RetentionPolicy(
                flows_days=runtime.retention_flows_days,
                alerts_days=runtime.retention_alerts_days,
                traffic_1s_hours=settings.retention_traffic_1s_hours,
                traffic_1m_days=settings.retention_traffic_1m_days,
            )
            deleted = await asyncio.to_thread(purge, app.state.db, policy)
            log.info("Retention: %s", deleted)
        except Exception:
            log.exception("Retention run failed")
        await asyncio.sleep(24 * 3600)


def create_app(settings: Settings | None = None, background: bool = True) -> FastAPI:
    settings = settings or get_settings()
    data_dir = Path(settings.data_dir)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _file_logging(data_dir)
        app.state.supervisor.recover()
        tasks = []
        if background:
            tasks = [
                asyncio.create_task(app.state.broadcaster.run()),
                asyncio.create_task(_daily_retention(app)),
            ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.to_thread(app.state.supervisor.shutdown)

    app = FastAPI(
        title="AI-NIDS",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.db = Database(settings.database_url)
    app.state.supervisor = Supervisor(app.state.db, settings)
    app.state.broadcaster = ws.Broadcaster(app)
    errors.install(app)

    @app.get("/healthz", tags=["system"])
    def healthz() -> dict[str, str]:
        """Liveness: the process answers."""
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["system"])
    def readyz(request: Request) -> JSONResponse:
        """Readiness: the database answers."""
        try:
            with request.app.state.db.session() as s:
                s.execute(text("SELECT 1"))
        except Exception as exc:
            return JSONResponse({"status": "unavailable", "reason": str(exc)}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics", tags=["system"], response_class=PlainTextResponse)
    def metrics(request: Request) -> str:
        """Prometheus metrics (loopback-only by default, like the rest of the API)."""
        db: Database = request.app.state.db
        with db.session() as s:
            by_severity = s.execute(
                select(AlertRow.severity, func.count())
                .where(AlertRow.status.in_(("new", "acknowledged")))
                .group_by(AlertRow.severity)
            ).all()
            jobs_running = (
                s.scalar(select(func.count()).select_from(Job).where(Job.status == "running")) or 0
            )
        sensor_up = int(request.app.state.supervisor.sensor_status().running)
        lines = ["# TYPE nids_open_alerts gauge"]
        lines += [f'nids_open_alerts{{severity="{sev}"}} {n}' for sev, n in by_severity]
        lines += [
            "# TYPE nids_sensor_running gauge",
            f"nids_sensor_running {sensor_up}",
            "# TYPE nids_jobs_running gauge",
            f"nids_jobs_running {jobs_running}",
            "# TYPE nids_up gauge",
            f"nids_up 1 {int(time.time() * 1000)}",
        ]
        return "\n".join(lines) + "\n"

    for router in (auth.router, sensor.router, data.router, admin.router, models.router, ws.router):
        app.include_router(router)
    web.install(app, Path(settings.frontend_dir), settings.secure_cookies)
    return app

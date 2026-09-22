"""Sensor discovery and control."""

from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from nids.api.auth import Principal, get_db, require_user
from nids.api.errors import ApiError
from nids.api.models import active_version
from nids.sensor.capability import CapabilityReport, check_capture
from nids.sensor.interfaces import InterfaceInfo, list_interfaces
from nids.store.db import Database

router = APIRouter(prefix="/api/sensor", tags=["sensor"])


@router.get("/capabilities")
def capabilities(_: Principal = Depends(require_user)) -> CapabilityReport:
    """Whether this machine can capture, which backend will be used, and how to fix problems."""
    return check_capture()


def _interfaces() -> list[InterfaceInfo]:
    try:
        return list_interfaces()
    except ImportError as exc:
        raise ApiError(
            503, "Capture support is not installed: cd backend && uv sync --extra capture"
        ) from exc


@router.get("/interfaces")
def interfaces(_: Principal = Depends(require_user)) -> list[InterfaceInfo]:
    """Capture interfaces: adapters with a routable IPv4 address first, loopback last."""
    return _interfaces()


class SensorState(BaseModel):
    running: bool
    job_id: str | None
    pid: int | None
    interface: str | None
    session_id: str | None
    started_at: float | None
    managed: bool  # False when the sensor is its own service (Docker): no start/stop from here
    model_version: str | None


class StartSensor(BaseModel):
    interface: str = Field(min_length=1, max_length=256)
    backend: Literal["auto", "scapy", "nfstream"] = "auto"


def _managed_here(request: Request) -> None:
    if request.app.state.settings.external_sensor:
        raise ApiError(
            409,
            "The sensor runs as its own service here. Start or stop it with "
            "`docker compose --profile capture up -d sensor` / `docker compose stop sensor`.",
            code="external_sensor",
        )


def _state(request: Request, db: Database) -> SensorState:
    status = request.app.state.supervisor.sensor_status()
    return SensorState(**status.__dict__, model_version=active_version(db))


@router.get("/status")
def status(
    request: Request, _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> SensorState:
    return _state(request, db)


@router.post("/start")
def start(
    body: StartSensor,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> SensorState:
    """Start capturing on an interface, with the active model (if any)."""
    _managed_here(request)
    report = check_capture()
    if not report.ok:
        problems = [c.model_dump() for c in report.checks if c.status == "error"]
        raise ApiError(
            409, "This machine can't capture yet.", code="capture_unavailable", details=problems
        )
    known = {i.name for i in _interfaces()}
    if body.interface not in known:  # only a listed interface, never an arbitrary string
        raise ApiError(
            422, f"Unknown interface '{body.interface}'.", details={"known": sorted(known)}
        )
    params = {
        "interface": body.interface,
        "backend": body.backend,
        "model_version": active_version(db),
    }
    request.app.state.supervisor.start("sensor", params, principal.username)
    return _state(request, db)


@router.post("/stop")
def stop(
    request: Request, principal: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> SensorState:
    """Stop capturing. Open flows are flushed and the session is closed before the sensor exits."""
    _managed_here(request)
    supervisor = request.app.state.supervisor
    current = supervisor.sensor_status()
    if not current.running or current.job_id is None:
        raise ApiError(409, "The sensor isn't running.")
    supervisor.cancel(current.job_id, principal.username, wait=True)
    return _state(request, db)

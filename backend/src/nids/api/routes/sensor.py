"""Sensor discovery endpoints. Read-only; auth is added in Phase 5 (the API binds to loopback
until then)."""

from fastapi import APIRouter, HTTPException

from nids.sensor.capability import CapabilityReport, check_capture
from nids.sensor.interfaces import InterfaceInfo, list_interfaces

router = APIRouter(prefix="/api/sensor", tags=["sensor"])


@router.get("/capabilities")
def capabilities() -> CapabilityReport:
    """Whether this machine can capture, which backend will be used, and how to fix problems."""
    return check_capture()


@router.get("/interfaces")
def interfaces() -> list[InterfaceInfo]:
    """Capture interfaces: adapters with a routable IPv4 address first, loopback last."""
    try:
        return list_interfaces()
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Capture support is not installed: cd backend && uv sync --extra capture",
        ) from exc

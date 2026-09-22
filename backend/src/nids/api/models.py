"""Model registry endpoints (audit ML-14, SEC-03).

Models are found by scanning the artifacts directory and verified (manifest, feature schema,
file hash) before they're registered. The UI activates a model by *version*; a path never comes
from the client.
"""

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select

from nids.api.auth import Principal, get_db, require_user
from nids.api.errors import ApiError
from nids.core.settings import Settings
from nids.store.db import Database
from nids.store.models import ModelRow
from nids.store.repo import audit, get_setting, set_setting

log = logging.getLogger(__name__)
ACTIVE_KEY = "model.active"


class ModelOut(BaseModel):
    version: str
    created_at: float
    dataset: str | None
    protocol: str | None
    feature_set: str | None
    summary: dict[str, Any]
    active: bool


def sync_models(db: Database, settings: Settings) -> list[str]:
    """Register every valid artifact under the artifacts directory. Returns their versions."""
    from nids.ml.registry import ModelLoadError, verify  # needs the ml extra

    root = Path(settings.artifacts_dir)
    found = []
    for directory in sorted(root.glob("*/")) if root.is_dir() else []:
        try:
            manifest = verify(directory)
        except ModelLoadError as exc:
            log.warning("Skipping %s: %s", directory.name, exc)
            continue
        info = manifest.get("info", {})
        with db.session() as s:
            row = s.get(ModelRow, manifest["version"])
            if row is None:
                row = ModelRow(version=manifest["version"])
                s.add(row)
            row.path = str(directory.resolve())
            row.created_at = _epoch(manifest.get("created_at"))
            row.dataset, row.protocol = info.get("dataset"), info.get("protocol")
            row.feature_set = info.get("feature_set")
            row.schema_hash, row.sha256 = manifest["schema_hash"], manifest["sha256"]
            row.summary = manifest.get("summary", {})
        found.append(manifest["version"])
    return found


def _epoch(iso: str | None) -> float:
    from datetime import datetime

    return datetime.fromisoformat(iso).timestamp() if iso else 0.0


def active_version(db: Database) -> str | None:
    with db.session() as s:
        value = get_setting(s, ACTIVE_KEY)
        return str(value) if value else None


def model_path(db: Database, settings: Settings, version: str) -> Path:
    """Filesystem path of a registered, verified model. Raises 404 for anything else."""
    from nids.ml.registry import ModelLoadError, verify

    with db.session() as s:
        row = s.get(ModelRow, version)
        path = Path(row.path) if row else None
    root = Path(settings.artifacts_dir).resolve()
    if path is None or root not in path.resolve().parents:
        raise ApiError(404, f"Model {version} is not registered.")
    try:
        verify(path)
    except ModelLoadError as exc:
        raise ApiError(409, str(exc)) from exc
    return path


router = APIRouter(prefix="/api/models", tags=["models"])


@router.get("")
def list_models(
    request: Request, _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> list[ModelOut]:
    sync_models(db, request.app.state.settings)
    active = active_version(db)
    with db.session() as s:
        rows = s.scalars(select(ModelRow).order_by(ModelRow.created_at.desc())).all()
        return [
            ModelOut(
                version=r.version,
                created_at=r.created_at,
                dataset=r.dataset,
                protocol=r.protocol,
                feature_set=r.feature_set,
                summary=r.summary,
                active=r.version == active,
            )
            for r in rows
        ]


@router.post("/{version}/activate")
def activate(
    version: str,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> dict[str, str]:
    """Use this model the next time the sensor starts."""
    model_path(db, request.app.state.settings, version)  # must be registered and verify
    with db.session() as s:
        previous = get_setting(s, ACTIVE_KEY)
        set_setting(s, ACTIVE_KEY, version)
        audit(s, principal.username, "model.activate", version, previous=previous)
    return {"active": version}


@router.post("/deactivate")
def deactivate(
    principal: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> dict[str, None]:
    """Run the sensor with heuristics only."""
    with db.session() as s:
        set_setting(s, ACTIVE_KEY, None)
        audit(s, principal.username, "model.deactivate", None)
    return {"active": None}


@router.get("/{version}/report")
def model_report(
    version: str,
    request: Request,
    _: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> dict[str, Any]:
    """The model's evaluation report (per-family results, confusion matrix, threshold sweep)."""
    import json

    path = model_path(db, request.app.state.settings, version) / "report.json"
    if not path.is_file():
        raise ApiError(404, f"Model {version} has no report.")
    report: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return report

"""Save and load model artifacts with integrity checks (audit ML-12, SEC-03).

Each version lives in its own directory:

    artifacts/<version>/model.joblib    the pickled DetectorBundle
    artifacts/<version>/manifest.json   sha256 of model.joblib, feature schema, library versions
    artifacts/<version>/report.json     evaluation results
    artifacts/<version>/model_card.md   human-readable summary

Loading refuses a model whose file hash, feature schema or ML library versions don't match.
Unpickling runs code, so the hash check is what stands between a swapped file and code execution.
Trust boundary: whoever can write to the artifacts directory can also rewrite the manifest.
Keep it writable only by the account that trains models (signing manifests is a later option).
"""

import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import lightgbm
import numpy
import pandas
import sklearn

from nids.core.schemas.features_v1 import SCHEMA_HASH, SCHEMA_VERSION
from nids.ml.bundle import DetectorBundle
from nids.ml.model_card import render_model_card

DEFAULT_ARTIFACTS_DIR = Path("artifacts")
MODEL_FILE, MANIFEST_FILE, REPORT_FILE, CARD_FILE = (
    "model.joblib",
    "manifest.json",
    "report.json",
    "model_card.md",
)


class ModelLoadError(RuntimeError):
    pass


def library_versions() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "numpy": numpy.__version__,
        "pandas": pandas.__version__,
        "scikit-learn": sklearn.__version__,
        "lightgbm": lightgbm.__version__,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def save(
    bundle: DetectorBundle, report: dict[str, Any], root: Path = DEFAULT_ARTIFACTS_DIR
) -> Path:
    created = datetime.now(UTC)
    info = bundle.info
    parts = (
        info.get("dataset", "model"),
        info.get("protocol", "x"),
        info.get("feature_set", "full"),
    )
    version = f"{'-'.join(parts)}-{created:%Y%m%dT%H%M%SZ}"
    directory = root / version
    directory.mkdir(parents=True, exist_ok=False)

    joblib.dump(bundle, directory / MODEL_FILE, compress=3)
    binary = report["binary"]
    manifest = {
        "version": version,
        "created_at": created.isoformat(timespec="seconds"),
        "schema_version": SCHEMA_VERSION,
        "schema_hash": bundle.schema_hash,
        "sha256": _sha256(directory / MODEL_FILE),
        "libraries": library_versions(),
        "classes": bundle.classes,
        "thresholds": {"attack": bundle.attack_threshold, "novelty": bundle.novelty_threshold},
        "info": info,
        "summary": {
            "split": report["training"]["split"],
            "alert_precision": binary["alert_rule"]["precision"],
            "alert_recall": binary["alert_rule"]["recall"],
            "supervised_pr_auc": binary["supervised"]["pr_auc"],
            "false_positives_per_hour": report["false_positives_per_hour"],
            "macro_f1_known_families": report["multiclass"]["macro_f1_known_families"],
        },
    }
    (directory / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (directory / REPORT_FILE).write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    (directory / CARD_FILE).write_text(render_model_card(manifest, report), encoding="utf-8")
    return directory


def verify(directory: Path) -> dict[str, Any]:
    """Check an artifact's manifest, feature schema and file hash WITHOUT unpickling it.
    Returns the manifest. Used to list and register models safely."""
    manifest_path, model_path = directory / MANIFEST_FILE, directory / MODEL_FILE
    if not manifest_path.is_file() or not model_path.is_file():
        raise ModelLoadError(
            f"{directory} is not a model artifact (manifest.json/model.joblib missing)."
        )
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_hash") != SCHEMA_HASH:
        raise ModelLoadError(
            f"Model {manifest.get('version')} expects feature schema "
            f"{manifest.get('schema_hash')}, but this code produces {SCHEMA_HASH}. Retrain it."
        )
    if _sha256(model_path) != manifest.get("sha256"):
        raise ModelLoadError(f"{model_path} does not match the hash in its manifest.")
    return manifest


def load(
    directory: Path, allow_library_mismatch: bool = False
) -> tuple[DetectorBundle, dict[str, Any]]:
    manifest_path, model_path = directory / MANIFEST_FILE, directory / MODEL_FILE
    if not manifest_path.is_file() or not model_path.is_file():
        raise ModelLoadError(
            f"{directory} is not a model artifact (manifest.json/model.joblib missing)."
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_hash") != SCHEMA_HASH:
        raise ModelLoadError(
            f"Model {manifest.get('version')} expects feature schema "
            f"{manifest.get('schema_hash')}, but this code produces {SCHEMA_HASH}. Retrain it."
        )
    if _sha256(model_path) != manifest.get("sha256"):
        raise ModelLoadError(
            f"{model_path} does not match the hash in its manifest; refusing to load it."
        )
    if not allow_library_mismatch:
        current, saved = library_versions(), manifest.get("libraries", {})
        for lib in ("scikit-learn", "lightgbm"):
            if _minor(current[lib]) != _minor(saved.get(lib, "")):
                raise ModelLoadError(
                    f"Model was trained with {lib} {saved.get(lib)}, this environment has "
                    f"{current[lib]}. Retrain, or pass allow_library_mismatch=True."
                )

    bundle = joblib.load(model_path)
    if not isinstance(bundle, DetectorBundle):
        raise ModelLoadError(f"{model_path} does not contain a DetectorBundle.")
    return bundle, manifest

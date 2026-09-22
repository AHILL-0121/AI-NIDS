"""Convert raw dataset CSVs into a prepared parquet file (+ a metadata JSON) once, so training
doesn't re-parse gigabytes of CSV every run."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from nids.core.schemas.features_v1 import SCHEMA_HASH, SCHEMA_VERSION
from nids.ml.datasets import DATASETS, DatasetError, cicids2017, unsw_nb15

DEFAULT_DATA_DIR = Path("data/processed")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_raw(
    dataset: str, src: Path, attempted: cicids2017.AttemptedMode = "benign"
) -> pd.DataFrame:
    if dataset == "cicids2017":
        return cicids2017.load(src, attempted)
    if dataset == "unsw-nb15":
        return unsw_nb15.load(src)
    raise DatasetError(f"Unknown dataset '{dataset}'. Choose from: {', '.join(DATASETS)}.")


def prepare(
    dataset: str,
    src: Path,
    out_dir: Path = DEFAULT_DATA_DIR,
    attempted: cicids2017.AttemptedMode = "benign",
) -> Path:
    frame = load_raw(dataset, src, attempted)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{dataset}.parquet"
    frame.to_parquet(path, index=False)
    meta: dict[str, Any] = {
        "dataset": dataset,
        "schema_version": SCHEMA_VERSION,
        "schema_hash": SCHEMA_HASH,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "attempted": attempted if dataset == "cicids2017" else None,
        "rows": len(frame),
        "families": frame["family"].value_counts().to_dict(),
        "labels": frame["label"].value_counts().to_dict(),
        "source_files": [
            {"name": p.name, "bytes": p.stat().st_size, "sha256": _sha256(p)}
            for p in sorted(src.glob("*.csv"))
        ],
    }
    path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return path


def load_prepared(
    dataset: str, data_dir: Path = DEFAULT_DATA_DIR
) -> tuple[pd.DataFrame, dict[str, Any]]:
    path = data_dir / f"{dataset}.parquet"
    meta_path = path.with_suffix(".meta.json")
    if not path.is_file() or not meta_path.is_file():
        raise DatasetError(
            f"{path} not found. Run `nids data prepare {dataset} --src <csv dir>` first."
        )
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("schema_hash") != SCHEMA_HASH:
        raise DatasetError(
            f"{path.name} was prepared with feature schema {meta.get('schema_hash')}, but the code "
            f"now uses {SCHEMA_HASH}. Re-run `nids data prepare {dataset}`."
        )
    return pd.read_parquet(path), meta

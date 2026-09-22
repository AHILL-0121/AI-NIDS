"""Pieces shared by the dataset loaders.

Every loader returns the same frame layout ("prepared frame"):

- one float32 column per feature in FEATURE_NAMES, in that order (NaN where the dataset lacks it);
- `label`: the dataset's own label, cleaned up;
- `family`: one of FAMILIES, comparable across datasets;
- `day`: weekday name when known (CIC-IDS2017's attack days), else "";
- `split`: "train"/"test" when the dataset ships an official split, else "";
- `timestamp`: flow start time when known (NaT otherwise), used for false positives per hour;
- `source_file`: the CSV the row came from.
"""

import re
from collections.abc import Mapping

import numpy as np
import pandas as pd

from nids.core.schemas.features_v1 import BASE_NAMES, FEATURE_NAMES, derive

FAMILIES = (
    "benign",
    "dos",
    "ddos",
    "recon",
    "brute_force",
    "web_attack",
    "botnet",
    "infiltration",
    "exploit",
    "attempted",
    "other",
)

META_COLUMNS = ("label", "family", "day", "split", "timestamp", "source_file")
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


class DatasetError(ValueError):
    """The input files aren't what the loader expects. The message says what's wrong."""


def norm(column: str) -> str:
    """Normalise a column name: ' Total Fwd Packets' and 'Total_Fwd_Packets' both match."""
    return re.sub(r"[^a-z0-9]", "", column.lower())


def weekday_from_name(name: str) -> str:
    lowered = name.lower()
    return next((d for d in WEEKDAYS if d in lowered), "")


def _vector_div(num: pd.Series, den: pd.Series) -> pd.Series:
    return (num / den).where(den > 0)


def build_frame(base: Mapping[str, pd.Series], meta: pd.DataFrame) -> pd.DataFrame:
    """Assemble a prepared frame from base feature columns and metadata columns.

    Missing base features become NaN, infinities (CICFlowMeter writes them) become NaN, and the
    derived features are computed with the same `derive()` the live sensor uses.
    """
    index = meta.index
    columns: dict[str, pd.Series] = {}
    for name in BASE_NAMES:
        column = base.get(name)
        if column is None:
            columns[name] = pd.Series(np.nan, index=index, dtype="float64")
        else:
            values = pd.to_numeric(column, errors="coerce").astype("float64")
            columns[name] = values.replace([np.inf, -np.inf], np.nan)
    features = derive(columns, div=_vector_div)
    frame = pd.DataFrame({name: features[name].astype("float32") for name in FEATURE_NAMES})
    for col in META_COLUMNS:
        frame[col] = meta[col].to_numpy() if col in meta else ""
    stamps = meta["timestamp"] if "timestamp" in meta else pd.Series(pd.NaT, index=index)
    frame["timestamp"] = pd.to_datetime(stamps.to_numpy(), errors="coerce").astype("datetime64[ns]")
    return frame

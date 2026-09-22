"""UNSW-NB15 loader (the official UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv).

Source: https://research.unsw.edu.au/projects/unsw-nb15-dataset (free for academic research).

UNSW-NB15 comes from Argus/Bro rather than CICFlowMeter, so only a subset of features_v1 can be
filled: duration, protocol, packet counts, IP-level bytes and mean sizes, and per-direction mean
inter-packet times. Everything else is NaN. Models meant to transfer between the datasets are
trained on that shared subset (`nids train --features shared`).

Assumption, documented in the model card: Argus' `sbytes`/`smean` count IP-level bytes.
"""

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from nids.ml.datasets.common import DatasetError, build_frame, norm

log = logging.getLogger(__name__)

_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58}

_FAMILIES = {
    "normal": "benign",
    "dos": "dos",
    "reconnaissance": "recon",
    "analysis": "recon",
    "exploits": "exploit",
    "shellcode": "exploit",
    "fuzzers": "other",
    "generic": "other",
    "backdoor": "other",
    "backdoors": "other",
    "worms": "other",
}

MS = 1e-3


def load_file(path: Path, split: str) -> pd.DataFrame:
    raw = pd.read_csv(path, low_memory=False)
    raw.columns = [norm(c) for c in raw.columns]
    needed = {
        "dur",
        "proto",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "sinpkt",
        "dinpkt",
        "smean",
        "dmean",
    }
    missing = sorted(needed - set(raw.columns))
    if missing or "attackcat" not in raw.columns:
        raise DatasetError(
            f"{path.name} doesn't look like a UNSW-NB15 CSV (missing: {missing or ['attack_cat']})."
        )

    base = {
        "duration_s": raw["dur"],
        "protocol": raw["proto"].str.lower().map(_PROTOCOLS).astype("float64"),
        "fwd_packets": raw["spkts"],
        "bwd_packets": raw["dpkts"],
        "fwd_ip_bytes": raw["sbytes"],
        "bwd_ip_bytes": raw["dbytes"],
        "fwd_ip_len_mean": raw["smean"],
        "bwd_ip_len_mean": raw["dmean"],
        "fwd_iat_mean": pd.to_numeric(raw["sinpkt"], errors="coerce") * MS,
        "bwd_iat_mean": pd.to_numeric(raw["dinpkt"], errors="coerce") * MS,
        # Payload bytes aren't in UNSW-NB15; derive() needs them for rates, so they stay NaN.
        "fwd_payload_bytes": pd.Series(np.nan, index=raw.index),
        "bwd_payload_bytes": pd.Series(np.nan, index=raw.index),
    }
    labels = raw["attackcat"].fillna("Normal").astype(str).str.strip()
    labels = labels.where(labels != "", "Normal")
    meta = pd.DataFrame(
        {
            "label": labels,
            "family": labels.str.lower().map(_FAMILIES).fillna("other"),
            "day": "",
            "split": split,
            "timestamp": pd.Series(pd.NaT, index=raw.index, dtype="datetime64[ns]"),
            "source_file": path.name,
        },
        index=raw.index,
    )
    frame = build_frame(base, meta)
    log.info("%s: %d flows (%s split)", path.name, len(frame), split)
    return frame


def load(src: Path) -> pd.DataFrame:
    frames = []
    for pattern, split in (("*training-set*.csv", "train"), ("*testing-set*.csv", "test")):
        frames += [load_file(p, split) for p in sorted(src.glob(pattern))]
    if not frames:
        raise DatasetError(
            f"No UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv in {src}. "
            "See backend/data/README.md."
        )
    return pd.concat(frames, ignore_index=True)

"""Synthetic data for testing the ML *plumbing* (loading, splitting, training, saving, scoring).

These rows are deliberately easy to separate. Scores measured on them say nothing about real
detection quality; real numbers come only from `nids train` on CIC-IDS2017 / UNSW-NB15.
"""

import csv
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from nids.core.schemas.features_v1 import BASE_NAMES
from nids.ml.datasets.common import build_frame

US = 1e6

# Base feature -> CIC-IDS2017 (original release) column name. Leading spaces as in the real files.
CIC_COLUMNS: dict[str, str] = {
    "duration_s": " Flow Duration",
    "fwd_packets": " Total Fwd Packets",
    "bwd_packets": " Total Backward Packets",
    "fwd_payload_bytes": "Total Length of Fwd Packets",
    "bwd_payload_bytes": " Total Length of Bwd Packets",
    "fwd_payload_len_max": " Fwd Packet Length Max",
    "fwd_payload_len_min": " Fwd Packet Length Min",
    "fwd_payload_len_mean": " Fwd Packet Length Mean",
    "fwd_payload_len_std": " Fwd Packet Length Std",
    "bwd_payload_len_max": "Bwd Packet Length Max",
    "bwd_payload_len_min": " Bwd Packet Length Min",
    "bwd_payload_len_mean": " Bwd Packet Length Mean",
    "bwd_payload_len_std": " Bwd Packet Length Std",
    "flow_iat_mean": " Flow IAT Mean",
    "flow_iat_std": " Flow IAT Std",
    "flow_iat_max": " Flow IAT Max",
    "flow_iat_min": " Flow IAT Min",
    "fwd_iat_mean": " Fwd IAT Mean",
    "fwd_iat_std": " Fwd IAT Std",
    "fwd_iat_max": " Fwd IAT Max",
    "fwd_iat_min": " Fwd IAT Min",
    "bwd_iat_mean": " Bwd IAT Mean",
    "bwd_iat_std": " Bwd IAT Std",
    "bwd_iat_max": " Bwd IAT Max",
    "bwd_iat_min": " Bwd IAT Min",
    "fwd_psh": "Fwd PSH Flags",
    "bwd_psh": " Bwd PSH Flags",
    "fwd_urg": " Fwd URG Flags",
    "bwd_urg": " Bwd URG Flags",
    "fin_count": "FIN Flag Count",
    "syn_count": " SYN Flag Count",
    "rst_count": " RST Flag Count",
    "psh_count": " PSH Flag Count",
    "ack_count": " ACK Flag Count",
    "urg_count": " URG Flag Count",
}
TIME_FEATURES = {k for k in CIC_COLUMNS if k == "duration_s" or "_iat_" in k}


def base_rows(family: str, n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Base features for `n` flows of a family, with clearly different behaviour per family."""
    if family == "benign":
        dur = rng.lognormal(0.0, 1.0, n)
        fwd, bwd = rng.poisson(10, n) + 2, rng.poisson(12, n) + 2
        fwd_len, bwd_len = rng.normal(300, 60, n).clip(0), rng.normal(900, 150, n).clip(0)
        syn, rst = np.ones(n), np.zeros(n)
    elif family == "dos":
        dur = rng.normal(90, 10, n).clip(1)
        fwd, bwd = rng.poisson(400, n) + 50, rng.poisson(2, n)
        fwd_len, bwd_len = rng.normal(20, 5, n).clip(0), np.zeros(n)
        syn, rst = np.ones(n), np.zeros(n)
    else:  # "recon": port-scan-like probes
        dur = rng.uniform(1e-5, 1e-4, n)
        fwd, bwd = np.ones(n), np.ones(n)
        fwd_len, bwd_len = np.zeros(n), np.zeros(n)
        syn, rst = np.ones(n), np.ones(n)
    fwd_bytes, bwd_bytes = fwd * fwd_len, bwd * bwd_len
    iat = dur / np.maximum(fwd + bwd - 1, 1)
    data: dict[str, Any] = {
        "duration_s": dur,
        "protocol": np.full(n, 6.0),
        "fwd_packets": fwd.astype(float),
        "bwd_packets": bwd.astype(float),
        "fwd_payload_bytes": fwd_bytes,
        "bwd_payload_bytes": bwd_bytes,
        "flow_iat_mean": iat,
        "flow_iat_std": iat * 0.2,
        "flow_iat_min": iat * 0.1,
        "flow_iat_max": iat * 3,
        "syn_count": syn,
        "fin_count": np.zeros(n),
        "rst_count": rst,
        "psh_count": np.minimum(fwd, 2),
        "ack_count": fwd + bwd - 1,
        "urg_count": np.zeros(n),
    }
    for d, pk, ln in (("fwd", fwd, fwd_len), ("bwd", bwd, bwd_len)):
        data |= {
            f"{d}_payload_len_mean": ln,
            f"{d}_payload_len_std": ln * 0.1,
            f"{d}_payload_len_min": ln * 0.5,
            f"{d}_payload_len_max": ln * 1.5,
            f"{d}_iat_mean": iat * 2,
            f"{d}_iat_std": iat * 0.3,
            f"{d}_iat_min": iat * 0.2,
            f"{d}_iat_max": iat * 4,
            f"{d}_psh": np.minimum(pk, 1),
            f"{d}_urg": np.zeros(n),
        }
    return pd.DataFrame(data)


def cic_like_frame(days: dict[str, dict[str, int]], seed: int = 0, split: str = "") -> pd.DataFrame:
    """Prepared frame. `days` maps weekday -> {family: count}."""
    rng = np.random.default_rng(seed)
    parts = []
    for day, families in days.items():
        start = pd.Timestamp("2017-07-03 09:00")
        for family, n in families.items():
            base = base_rows(family, n, rng)
            meta = pd.DataFrame(
                {
                    "label": family.upper(),
                    "family": family,
                    "day": day,
                    "split": split,
                    "timestamp": start + pd.to_timedelta(rng.uniform(0, 8 * 3600, n), unit="s"),
                    "source_file": f"{day}.csv",
                }
            )
            parts.append(build_frame({k: base[k] for k in base.columns if k in BASE_NAMES}, meta))
    return pd.concat(parts, ignore_index=True)


def write_cic_csv(
    path: Path, base: pd.DataFrame, labels: list[str], encoding: str = "latin-1"
) -> None:
    """Write base features as a CIC-IDS2017-style CSV (microseconds, original column names)."""
    header = [*CIC_COLUMNS.values(), " Destination Port", "Flow Bytes/s", " Timestamp", " Label"]
    with path.open("w", newline="", encoding=encoding) as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for (_, row), label in zip(base.iterrows(), labels, strict=True):
            values = [row[k] * US if k in TIME_FEATURES else row[k] for k in CIC_COLUMNS]
            writer.writerow([*values, 80, "Infinity", "7/7/2017 9:30", label])

"""CIC-IDS2017 loader: the corrected release (Engelen et al., WTMC 2021) or the original CSVs.

Recommended source: the corrected "Distrinet" release, https://downloads.distrinet-research.be/WTMC2021/
(also on Kaggle as "Distrinet-CIC-IDS2017"). It fixes the original CICFlowMeter's flow
termination (a single FIN ended the flow; RST was ignored) and relabels flows, adding
"<attack> - Attempted" for attack flows that never delivered a payload. The original
MachineLearningCSV files from UNB also load, with the known labelling problems.

Column names differ between releases (leading spaces, "Total Fwd Packets" vs "Total Fwd Packet",
CSE-CIC-IDS2018-style abbreviations), so columns are matched by normalised aliases. Times are in
microseconds and converted to seconds.
"""

import logging
import re
from pathlib import Path
from typing import Literal

import pandas as pd

from nids.ml.datasets.common import DatasetError, build_frame, norm, weekday_from_name

log = logging.getLogger(__name__)

US = 1e-6  # CICFlowMeter reports times in microseconds

# base feature -> (normalised column aliases, scale factor)
_COLUMNS: dict[str, tuple[tuple[str, ...], float]] = {
    "duration_s": (("flowduration",), US),
    "protocol": (("protocol",), 1.0),
    "fwd_packets": (("totalfwdpackets", "totalfwdpacket", "totfwdpkts"), 1.0),
    "bwd_packets": (
        ("totalbackwardpackets", "totalbwdpackets", "totalbwdpacket", "totbwdpkts"),
        1.0,
    ),
    "fwd_payload_bytes": (
        (
            "totallengthoffwdpackets",
            "totallengthoffwdpacket",
            "totlenfwdpkts",
            "fwdpacketslengthtotal",
        ),
        1.0,
    ),
    "bwd_payload_bytes": (
        (
            "totallengthofbwdpackets",
            "totallengthofbwdpacket",
            "totlenbwdpkts",
            "bwdpacketslengthtotal",
        ),
        1.0,
    ),
    "flow_iat_mean": (("flowiatmean",), US),
    "flow_iat_std": (("flowiatstd",), US),
    "flow_iat_min": (("flowiatmin",), US),
    "flow_iat_max": (("flowiatmax",), US),
    "syn_count": (("synflagcount", "synflagcnt"), 1.0),
    "fin_count": (("finflagcount", "finflagcnt"), 1.0),
    "rst_count": (("rstflagcount", "rstflagcnt"), 1.0),
    "psh_count": (("pshflagcount", "pshflagcnt"), 1.0),
    "ack_count": (("ackflagcount", "ackflagcnt"), 1.0),
    "urg_count": (("urgflagcount", "urgflagcnt"), 1.0),
}
for _d, _short in (("fwd", "fwd"), ("bwd", "bwd")):
    for _stat in ("max", "min", "mean", "std"):
        _COLUMNS[f"{_d}_payload_len_{_stat}"] = (
            (f"{_short}packetlength{_stat}", f"{_short}pktlen{_stat}"),
            1.0,
        )
        _COLUMNS[f"{_d}_iat_{_stat}"] = ((f"{_short}iat{_stat}",), US)
    _COLUMNS[f"{_d}_psh"] = ((f"{_short}pshflags",), 1.0)
    _COLUMNS[f"{_d}_urg"] = ((f"{_short}urgflags",), 1.0)

_REQUIRED = ("duration_s", "fwd_packets", "bwd_packets", "fwd_payload_bytes", "bwd_payload_bytes")

AttemptedMode = Literal["benign", "separate"]


def clean_label(raw: str) -> tuple[str, bool]:
    """Return (label, attempted). Fixes the original files' mangled dash in 'Web Attack - XSS'."""
    text = re.sub(r"[^\x20-\x7e]+", "-", str(raw)).strip()
    text = re.sub(r"\s*-+\s*", " - ", text)
    text = re.sub(r"\s+", " ", text)
    attempted = text.lower().endswith("attempted")
    if attempted:
        text = re.sub(r"\s*-\s*attempted$", "", text, flags=re.IGNORECASE)
    if text.upper() == "BENIGN":
        text = "BENIGN"
    return text, attempted


def family_of(label: str) -> str:
    s = label.lower()
    if s == "benign":
        return "benign"
    if "web attack" in s:
        return "web_attack"
    if "ddos" in s:
        return "ddos"
    if "heartbleed" in s:
        return "exploit"
    if "dos" in s:
        return "dos"
    if "portscan" in s or "port scan" in s:
        return "recon"
    if "patator" in s or "brute" in s:
        return "brute_force"
    if "bot" in s:
        return "botnet"
    if "infiltration" in s:
        return "infiltration"
    return "other"


def _pick(columns: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    return next((columns[a] for a in aliases if a in columns), None)


def load_file(path: Path, attempted: AttemptedMode = "benign") -> pd.DataFrame:
    header = pd.read_csv(path, nrows=0, encoding="latin-1", skipinitialspace=True)
    columns = {norm(c): c for c in header.columns}  # the first match wins for duplicate names
    wanted: dict[str, tuple[str, float]] = {}
    for feature, (aliases, scale) in _COLUMNS.items():
        col = _pick(columns, aliases)
        if col is not None:
            wanted[feature] = (col, scale)
    missing = [f for f in _REQUIRED if f not in wanted]
    label_col = columns.get("label")
    if missing or label_col is None:
        raise DatasetError(
            f"{path.name} doesn't look like a CICFlowMeter CSV "
            f"(missing: {', '.join(missing + ([] if label_col else ['Label']))})."
        )
    ts_col = columns.get("timestamp")
    endpoint_cols = {
        name: columns.get(alias)
        for name, alias in (
            ("src_ip", "srcip"),
            ("dst_ip", "dstip"),
            ("src_port", "srcport"),
            ("dst_port", "dstport"),
        )
    }
    if endpoint_cols["dst_port"] is None:  # the original release: " Destination Port" only
        endpoint_cols["dst_port"] = columns.get("destinationport")
    extra = {c for c in endpoint_cols.values() if c} | ({ts_col} if ts_col else set())
    usecols = {c for c, _ in wanted.values()} | {label_col} | extra
    raw = pd.read_csv(
        path, usecols=list(usecols), encoding="latin-1", skipinitialspace=True, low_memory=False
    )
    raw = raw.dropna(subset=[label_col])

    base = {
        feature: pd.to_numeric(raw[col], errors="coerce") * scale
        for feature, (col, scale) in wanted.items()
    }
    cleaned = raw[label_col].map(clean_label)
    labels = cleaned.map(lambda x: x[0])
    was_attempted = cleaned.map(lambda x: x[1])
    families = labels.map(family_of)
    if attempted == "benign":
        families = families.where(~was_attempted, "benign")  # Engelen et al.'s own choice
    else:
        families = families.where(~was_attempted, "attempted")
    labels = labels.where(~was_attempted, labels + " - Attempted")

    timestamps = (
        pd.to_datetime(raw[ts_col], errors="coerce", format="mixed", dayfirst=False)
        if ts_col
        else pd.Series(pd.NaT, index=raw.index)
    )
    day = weekday_from_name(path.name)
    days = (
        pd.Series(day, index=raw.index) if day else timestamps.dt.day_name().str.lower().fillna("")
    )
    meta = pd.DataFrame(
        {
            "label": labels,
            "family": families,
            "day": days,
            "split": "",
            "timestamp": timestamps,
            "source_file": path.name,
            **{name: raw[col] for name, col in endpoint_cols.items() if col},
        },
        index=raw.index,
    )
    frame = build_frame(base, meta)
    log.info("%s: %d flows, %d features found", path.name, len(frame), len(wanted))
    return frame


def load(src: Path, attempted: AttemptedMode = "benign") -> pd.DataFrame:
    files = sorted(p for p in src.glob("*.csv") if p.is_file())
    if not files:
        raise DatasetError(f"No CSV files in {src}. See backend/data/README.md for the download.")
    return pd.concat([load_file(p, attempted) for p in files], ignore_index=True)

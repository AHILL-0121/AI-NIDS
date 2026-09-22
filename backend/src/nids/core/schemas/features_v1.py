"""Feature schema v1: the one definition of what the models see (audit ML-07).

Live flows (`features_from_flow`) and training datasets (`nids.ml.datasets`) both fill the same
*base* features, then `derive()` computes the rates and ratios for both from those base values.
Nothing downstream computes features any other way, so training and inference can't drift apart.

Definitions follow CICFlowMeter (payload-based lengths, sample standard deviations), with times
in seconds. A value that a source can't provide is NaN (never 0: a missing value is not a small
value). The gradient-boosting model handles NaN natively.

Deliberately excluded: IP addresses, ports and timestamps. They identify the testbed rather than
the behaviour, and models trained on them score well on CIC-IDS2017 while learning shortcuts.
"""

import hashlib
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from nids.core.schemas.flow import FlowRecord

SCHEMA_VERSION = "features_v1"

Unit = Literal["s", "bytes", "packets", "count", "per_s", "ratio", "id"]


@dataclass(frozen=True, slots=True)
class FeatureSpec:
    name: str
    unit: Unit
    description: str
    unsw_nb15: bool = False  # also available from UNSW-NB15 (the cross-dataset subset)


def _dir(name: str, unit: Unit, what: str, unsw: bool = False) -> tuple[FeatureSpec, FeatureSpec]:
    return (
        FeatureSpec(f"fwd_{name}", unit, f"{what}, initiator to responder", unsw),
        FeatureSpec(f"bwd_{name}", unit, f"{what}, responder to initiator", unsw),
    )


BASE_FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("duration_s", "s", "Time from first to last packet", unsw_nb15=True),
    FeatureSpec("protocol", "id", "IANA protocol number (6 TCP, 17 UDP, 1 ICMP)", unsw_nb15=True),
    *_dir("packets", "packets", "Packets", unsw=True),
    *_dir("payload_bytes", "bytes", "Transport payload bytes"),
    *_dir("payload_len_min", "bytes", "Smallest payload"),
    *_dir("payload_len_max", "bytes", "Largest payload"),
    *_dir("payload_len_mean", "bytes", "Mean payload"),
    *_dir("payload_len_std", "bytes", "Payload standard deviation (sample)"),
    FeatureSpec("flow_iat_mean", "s", "Mean gap between packets, both directions"),
    FeatureSpec("flow_iat_std", "s", "Gap standard deviation, both directions"),
    FeatureSpec("flow_iat_min", "s", "Smallest gap, both directions"),
    FeatureSpec("flow_iat_max", "s", "Largest gap, both directions"),
    *_dir("iat_mean", "s", "Mean gap between packets", unsw=True),
    *_dir("iat_std", "s", "Gap standard deviation"),
    *_dir("iat_min", "s", "Smallest gap"),
    *_dir("iat_max", "s", "Largest gap"),
    FeatureSpec("syn_count", "count", "Packets with SYN set"),
    FeatureSpec("fin_count", "count", "Packets with FIN set"),
    FeatureSpec("rst_count", "count", "Packets with RST set"),
    FeatureSpec("psh_count", "count", "Packets with PSH set"),
    FeatureSpec("ack_count", "count", "Packets with ACK set"),
    FeatureSpec("urg_count", "count", "Packets with URG set"),
    *_dir("psh", "count", "Packets with PSH set"),
    *_dir("urg", "count", "Packets with URG set"),
    *_dir("ip_bytes", "bytes", "IP-level bytes (headers included)", unsw=True),
    *_dir("ip_len_mean", "bytes", "Mean IP-level packet size", unsw=True),
)

DERIVED_FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("flow_payload_bytes_per_s", "per_s", "Payload bytes per second, both directions"),
    FeatureSpec(
        "flow_packets_per_s", "per_s", "Packets per second, both directions", unsw_nb15=True
    ),
    *_dir("packets_per_s", "per_s", "Packets per second", unsw=True),
    FeatureSpec("down_up_ratio", "ratio", "Responder packets / initiator packets", unsw_nb15=True),
    FeatureSpec("fwd_payload_share", "ratio", "Share of payload bytes sent by the initiator"),
)

FEATURES: tuple[FeatureSpec, ...] = BASE_FEATURES + DERIVED_FEATURES
BASE_NAMES: tuple[str, ...] = tuple(f.name for f in BASE_FEATURES)
FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
UNSW_SHARED_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES if f.unsw_nb15)

SCHEMA_HASH = hashlib.sha256("|".join(f"{f.name}:{f.unit}" for f in FEATURES).encode()).hexdigest()[
    :16
]

NAN = math.nan


def _ratio(num: float, den: float) -> float:
    if math.isnan(num) or math.isnan(den) or den <= 0:
        return NAN
    return num / den


def derive(base: Mapping[str, Any], div: Callable[[Any, Any], Any] = _ratio) -> dict[str, Any]:
    """Add the derived features to the base features (returns a new dict).

    Works on single values (live flows) and on whole pandas columns (datasets): pass a vectorised
    `div` that returns NaN where the denominator is 0 or missing. Keeping one formula for both
    paths is what guarantees training/inference parity.
    """
    duration = base["duration_s"]
    fwd_pkts, bwd_pkts = base["fwd_packets"], base["bwd_packets"]
    payload = base["fwd_payload_bytes"] + base["bwd_payload_bytes"]
    out = dict(base)
    out["flow_payload_bytes_per_s"] = div(payload, duration)
    out["flow_packets_per_s"] = div(fwd_pkts + bwd_pkts, duration)
    out["fwd_packets_per_s"] = div(fwd_pkts, duration)
    out["bwd_packets_per_s"] = div(bwd_pkts, duration)
    out["down_up_ratio"] = div(bwd_pkts, fwd_pkts)
    out["fwd_payload_share"] = div(base["fwd_payload_bytes"], payload)
    return out


def _opt(value: float | None) -> float:
    return NAN if value is None else float(value)


def features_from_flow(flow: FlowRecord) -> dict[str, float]:
    """Feature dict (keys in FEATURE_NAMES order) for one live or replayed flow."""
    base: dict[str, float] = {
        "duration_s": flow.duration,
        "protocol": float(flow.protocol),
        "flow_iat_mean": flow.iat_mean,
        "flow_iat_std": flow.iat_std,
        "flow_iat_min": flow.iat_min,
        "flow_iat_max": flow.iat_max,
    }
    for prefix, d in (("fwd", flow.fwd), ("bwd", flow.bwd)):
        base |= {
            f"{prefix}_packets": float(d.packets),
            f"{prefix}_payload_bytes": float(d.payload_bytes),
            f"{prefix}_payload_len_min": d.payload_len_min,
            f"{prefix}_payload_len_max": d.payload_len_max,
            f"{prefix}_payload_len_mean": d.payload_len_mean,
            f"{prefix}_payload_len_std": d.payload_len_std,
            f"{prefix}_iat_mean": d.iat_mean,
            f"{prefix}_iat_std": d.iat_std,
            f"{prefix}_iat_min": d.iat_min,
            f"{prefix}_iat_max": d.iat_max,
            f"{prefix}_psh": float(d.psh),
            f"{prefix}_urg": float(d.urg),
            f"{prefix}_ip_bytes": _opt(d.ip_bytes),
            f"{prefix}_ip_len_mean": _opt(d.ip_len_mean),
        }
    for flag in ("syn", "fin", "rst", "psh", "ack", "urg"):
        base[f"{flag}_count"] = float(getattr(flow.fwd, flag) + getattr(flow.bwd, flag))
    features = derive(base)
    return {name: cast(float, features[name]) for name in FEATURE_NAMES}

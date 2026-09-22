"""Evaluate the heuristic detectors (Phase 3) on a labelled dataset split, the same way the ML
model is evaluated, so the two layers can be compared and combined.

The dataset rows are replayed in time order through the detection engine's flow-level path (the
one NFStream uses: each finished flow counts as a connection attempt). Packet-level detectors
(floods) can't run on flow CSVs and are left out. CIC-IDS2017 gives SYN/RST counts for the whole
flow, not per direction, so the per-direction flags are approximations; that only affects the
"unanswered" evidence, not what counts as a scan.

An attack flow counts as detected when an alert names its source and its destination (or the
destination's subnet, for sweeps) within the alert's lifetime plus the scan window. An alert that
covers no attack flow is a false alert.
"""

import ipaddress
from typing import Any

import numpy as np
import pandas as pd

from nids.core.schemas.alert import Alert
from nids.core.schemas.flow import DirectionStats, EndReason, FlowRecord
from nids.ml.evaluate import benign_hours
from nids.sensor.detect import DetectionConfig, DetectionEngine


def _direction(packets: float, syn: int, rst: int) -> DirectionStats:
    return DirectionStats(
        packets=int(packets),
        payload_bytes=0,
        payload_len_min=0.0,
        payload_len_max=0.0,
        payload_len_mean=0.0,
        payload_len_std=0.0,
        iat_mean=0.0,
        iat_std=0.0,
        iat_min=0.0,
        iat_max=0.0,
        syn=syn,
        fin=0,
        rst=rst,
        psh=0,
        ack=0,
        urg=0,
    )


def _flows(rows: pd.DataFrame) -> list[FlowRecord]:
    start = rows["timestamp"].astype("int64").to_numpy() / 1e9
    flows = []
    for i, (row, t0) in enumerate(zip(rows.itertuples(index=False), start, strict=True)):
        syn, rst = int(row.syn_count > 0), int(row.rst_count > 0)
        protocol = 6 if np.isnan(row.protocol) else int(row.protocol)
        flows.append(
            FlowRecord(
                flow_id=f"row-{i}",
                src_ip=row.src_ip,
                dst_ip=row.dst_ip,
                src_port=int(row.src_port),
                dst_port=int(row.dst_port),
                protocol=protocol,
                ip_version=6 if ":" in row.src_ip else 4,
                first_seen=float(t0),
                last_seen=float(t0) + float(np.nan_to_num(row.duration_s)),
                iat_mean=0.0,
                iat_std=0.0,
                iat_min=0.0,
                iat_max=0.0,
                fwd=_direction(row.fwd_packets, syn, 0),
                bwd=_direction(row.bwd_packets, 0, rst if row.bwd_packets > 0 else 0),
                end_reason=EndReason.FLUSH,
            )
        )
    return flows


def run_heuristics(rows: pd.DataFrame, config: DetectionConfig | None = None) -> list[Alert]:
    rows = rows[(rows["src_ip"] != "") & rows["timestamp"].notna()].sort_values("timestamp")
    alerts: dict[str, Alert] = {}
    engine = DetectionEngine(lambda a, _new: alerts.__setitem__(a.id, a), config)
    last_tick = None
    for flow in _flows(rows):
        second = int(flow.first_seen)
        if last_tick is None or second > last_tick:
            engine.tick(flow.first_seen)
            last_tick = second
        engine.on_flow(flow)
    engine.flush()
    return list(alerts.values())


def _covered(rows: pd.DataFrame, alert: Alert, window_s: float) -> np.ndarray:
    ts = rows["timestamp"].astype("int64").to_numpy() / 1e9
    mask: np.ndarray = (rows["src_ip"] == alert.src).to_numpy()
    mask &= (ts >= alert.created_at - window_s) & (ts <= alert.last_seen + window_s)
    if alert.dst and "/" in alert.dst:
        network = ipaddress.ip_network(alert.dst, strict=False)
        prefix = str(network.network_address).rsplit(".", 1)[0] + "."
        mask &= rows["dst_ip"].str.startswith(prefix).to_numpy()
    elif alert.dst:
        mask &= (rows["dst_ip"] == alert.dst).to_numpy()
    return mask


def evaluate_heuristics(
    rows: pd.DataFrame, config: DetectionConfig | None = None, ml_alert: np.ndarray | None = None
) -> dict[str, Any]:
    """Heuristic detection per family, false alerts per hour, and (if `ml_alert` is given) the
    coverage of heuristics and ML combined."""
    config = config or DetectionConfig()
    rows = rows.reset_index(drop=True)
    alerts = run_heuristics(rows, config)
    covered = np.zeros(len(rows), dtype=bool)
    attack = (rows["family"] != "benign").to_numpy()
    false_alerts = 0
    by_type: dict[str, int] = {}
    for alert in alerts:
        mask = _covered(rows, alert, config.scan.window_s)
        covered |= mask
        by_type[alert.type] = by_type.get(alert.type, 0) + 1
        if not (mask & attack).any():
            false_alerts += 1
    hours = benign_hours(rows)
    families = {}
    combined = covered | ml_alert if ml_alert is not None else None
    for family in sorted(rows["family"].unique()):
        in_family = (rows["family"] == family).to_numpy()
        families[family] = {
            "rows": int(in_family.sum()),
            "heuristics": float(covered[in_family].mean()),
            **(
                {"heuristics_or_ml": float(combined[in_family].mean())}
                if combined is not None
                else {}
            ),
        }
    return {
        "alerts": len(alerts),
        "alerts_by_type": by_type,
        "false_alerts": false_alerts,
        "false_alerts_per_hour": false_alerts / hours if hours else None,
        "per_family": families,
    }

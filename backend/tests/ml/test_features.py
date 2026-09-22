import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from nids.core.schemas.features_v1 import (
    FEATURE_NAMES,
    SCHEMA_HASH,
    UNSW_SHARED_NAMES,
    derive,
    features_from_flow,
)
from nids.core.schemas.flow import FlowRecord
from nids.ml.datasets import cicids2017
from nids.ml.datasets.common import _vector_div
from nids.sensor.flows import FlowTable
from nids.sensor.packets import ACK, FIN, PSH, SYN

from ..sensor.helpers import CLIENT, SERVER, meta
from .synth import CIC_COLUMNS, write_cic_csv


def a_tcp_flow() -> FlowRecord:
    flows: list[FlowRecord] = []
    table = FlowTable(flows.append)
    c = {"src": CLIENT, "dst": SERVER, "sport": 40000, "dport": 443}
    s = {"src": SERVER, "dst": CLIENT, "sport": 443, "dport": 40000}
    for ts, side, flags, payload in [
        (0.00, c, SYN, 0),
        (0.02, s, SYN | ACK, 0),
        (0.03, c, ACK, 0),
        (0.05, c, PSH | ACK, 120),
        (0.30, s, PSH | ACK, 1400),
        (0.31, s, PSH | ACK, 600),
        (0.40, c, FIN | ACK, 0),
        (0.42, s, FIN | ACK, 0),
    ]:
        table.add(meta(ts, **side, flags=flags, payload=payload, length=40 + payload))  # type: ignore[arg-type]
    table.flush()
    return flows[0]


def test_schema_is_well_formed() -> None:
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert len(SCHEMA_HASH) == 16
    assert set(UNSW_SHARED_NAMES) < set(FEATURE_NAMES)
    assert not {"src_ip", "dst_ip", "src_port", "dst_port"} & set(FEATURE_NAMES)


def test_features_from_flow() -> None:
    f = features_from_flow(a_tcp_flow())

    assert list(f) == list(FEATURE_NAMES)
    assert f["duration_s"] == pytest.approx(0.42)
    assert (f["fwd_packets"], f["bwd_packets"]) == (4, 4)
    assert (f["fwd_payload_bytes"], f["bwd_payload_bytes"]) == (120, 2000)
    assert (f["syn_count"], f["fin_count"], f["psh_count"]) == (2, 2, 3)
    assert f["flow_packets_per_s"] == pytest.approx(8 / 0.42)
    assert f["down_up_ratio"] == 1.0
    assert f["fwd_payload_share"] == pytest.approx(120 / 2120)
    assert f["fwd_ip_bytes"] == 4 * 40 + 120


def test_scalar_and_vector_derivation_agree() -> None:
    rng = np.random.default_rng(1)
    base = {
        k: rng.uniform(0, 100, 50)
        for k in (
            "duration_s",
            "fwd_packets",
            "bwd_packets",
            "fwd_payload_bytes",
            "bwd_payload_bytes",
        )
    }
    base["duration_s"][:5] = 0.0  # zero duration -> NaN rates
    base["fwd_packets"][5:8] = 0.0  # zero initiator packets -> NaN down/up ratio
    vector = derive({k: pd.Series(v) for k, v in base.items()}, div=_vector_div)
    for i in range(50):
        scalar = derive({k: float(v[i]) for k, v in base.items()})
        for name in (
            "flow_payload_bytes_per_s",
            "flow_packets_per_s",
            "down_up_ratio",
            "fwd_payload_share",
        ):
            a, b = scalar[name], float(vector[name].iloc[i])
            assert (math.isnan(a) and math.isnan(b)) or a == pytest.approx(b), name


def test_live_flow_and_cic_row_give_the_same_features(tmp_path: Path) -> None:
    """A flow measured live and the same flow written as a CICFlowMeter CSV row must produce the
    same features_v1 vector (apart from IP-level sizes, which CICFlowMeter doesn't report).

    This checks units, column mapping and derivation on both paths. It can't check that
    CICFlowMeter itself computes each statistic the same way; that needs the real tool."""
    flow = a_tcp_flow()
    live = features_from_flow(flow)
    base = pd.DataFrame([{k: v for k, v in live.items() if k in CIC_COLUMNS}])
    path = tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv"
    write_cic_csv(path, base, ["BENIGN"])

    row = cicids2017.load_file(path).iloc[0]

    for name in FEATURE_NAMES:
        if name.endswith(("ip_bytes", "ip_len_mean")):
            assert math.isnan(row[name]), name
        elif name == "protocol":
            assert math.isnan(row[name])  # the original CSVs have no protocol column
        else:
            assert row[name] == pytest.approx(live[name], rel=1e-5, abs=1e-6), name

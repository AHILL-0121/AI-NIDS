"""Property tests for feature schema v1 (audit ML-07, ML-10): whatever packets arrive, the feature
vector is complete, finite where defined, and internally consistent. Missing values are NaN by
design (e.g. no gaps in a one-packet flow), never infinity or garbage."""

import math

from hypothesis import given, settings
from hypothesis import strategies as st

from nids.core.schemas.features_v1 import FEATURE_NAMES, FEATURES, features_from_flow
from nids.core.schemas.flow import FlowRecord
from nids.sensor.flows import FlowTable
from nids.sensor.packets import ACK, FIN, PSH, RST, SYN, URG

from ..sensor.helpers import CLIENT, SERVER, meta

NEVER_MISSING = {f.name for f in FEATURES if f.unit in ("packets", "count", "id")} | {
    "duration_s",
    "fwd_payload_bytes",
    "bwd_payload_bytes",
    "fwd_ip_bytes",
    "bwd_ip_bytes",
}
RATES = {f.name for f in FEATURES if f.unit == "per_s"}

packet = st.tuples(
    st.floats(min_value=0.0, max_value=5.0, allow_nan=False),  # gap before this packet
    st.booleans(),  # True: initiator -> responder
    st.integers(min_value=0, max_value=0x3F),  # TCP flags
    st.integers(min_value=0, max_value=1460),  # payload
)


def build(protocol: int, packets: list[tuple[float, bool, int, int]]) -> list[FlowRecord]:
    flows: list[FlowRecord] = []
    table = FlowTable(flows.append)
    ts = 1000.0
    for i, (gap, forward, flags, payload) in enumerate(packets):
        ts += gap
        forward = forward or i == 0  # the first packet defines the initiator
        src, dst, sport, dport = (
            (CLIENT, SERVER, 40000, 443) if forward else (SERVER, CLIENT, 443, 40000)
        )
        table.add(
            meta(
                ts,
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                proto=protocol,
                flags=flags if protocol == 6 else 0,
                payload=payload,
                length=40 + payload,
            )
        )
    table.flush()
    return flows


@settings(max_examples=300, deadline=None)
@given(
    protocol=st.sampled_from([6, 17]),
    packets=st.lists(packet, min_size=1, max_size=40),
)
def test_feature_vectors_are_complete_and_sane(
    protocol: int, packets: list[tuple[float, bool, int, int]]
) -> None:
    for flow in build(protocol, packets):
        f = features_from_flow(flow)

        assert list(f) == list(FEATURE_NAMES)
        assert not any(math.isinf(v) for v in f.values())
        assert all(v >= 0 for v in f.values() if not math.isnan(v))
        assert not any(math.isnan(f[name]) for name in NEVER_MISSING)
        assert f["fwd_packets"] + f["bwd_packets"] == flow.packets
        assert f["fwd_packets"] >= 1  # the initiator sent at least one packet

        share = f["fwd_payload_share"]
        assert math.isnan(share) or 0.0 <= share <= 1.0
        # Rates exist exactly when the flow has a duration to divide by.
        assert all(math.isnan(f[r]) == (f["duration_s"] == 0) for r in RATES)
        for side in ("fwd", "bwd"):
            lo, mean, hi = (f[f"{side}_payload_len_{s}"] for s in ("min", "mean", "max"))
            if not math.isnan(mean):
                assert lo <= mean + 1e-9 and mean <= hi + 1e-9
        if not math.isnan(f["flow_iat_mean"]):
            assert f["flow_iat_min"] <= f["flow_iat_mean"] + 1e-9 <= f["flow_iat_max"] + 2e-9
            assert f["flow_iat_max"] <= f["duration_s"] + 1e-9


@settings(max_examples=100, deadline=None)
@given(st.lists(packet, min_size=1, max_size=40))
def test_flag_counts_match_the_packets(packets: list[tuple[float, bool, int, int]]) -> None:
    flows = build(6, packets)
    counted = {name: 0 for name in ("syn", "fin", "rst", "psh", "ack", "urg")}
    bits = {"syn": SYN, "fin": FIN, "rst": RST, "psh": PSH, "ack": ACK, "urg": URG}
    for _, _, flags, _ in packets:
        for name, bit in bits.items():
            counted[name] += bool(flags & bit)

    totals = {name: 0.0 for name in counted}
    for flow in flows:  # FIN/RST may end a flow early and start another
        f = features_from_flow(flow)
        for name in counted:
            totals[name] += f[f"{name}_count"]

    assert totals == {k: float(v) for k, v in counted.items()}

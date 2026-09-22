import math
from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nids.core.schemas.flow import EndReason, FlowRecord
from nids.sensor.flows import FlowTable, FlowTableConfig
from nids.sensor.packets import ACK, FIN, RST, SYN

from .helpers import CLIENT, SERVER, meta

Collect = tuple[list[FlowRecord], Callable[[FlowRecord], None]]


def reply(ts: float, **kw: object) -> object:
    return meta(ts, src=SERVER, dst=CLIENT, sport=443, dport=40000, **kw)  # type: ignore[arg-type]


def test_both_directions_form_one_flow_with_initiator_as_forward(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink)
    table.add(meta(0.0, length=100))
    table.add(reply(0.1, length=300))  # type: ignore[arg-type]
    table.add(meta(0.3, length=200))
    table.flush()

    (flow,) = flows
    assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == (CLIENT, 40000, SERVER, 443)
    assert (flow.fwd.packets, flow.bwd.packets) == (2, 1)
    assert (flow.fwd.bytes, flow.bwd.bytes) == (300, 300)
    assert flow.fwd.pkt_len_mean == 150 and flow.fwd.pkt_len_std == 50
    assert flow.duration == pytest.approx(0.3)
    assert flow.iat_min == pytest.approx(0.1) and flow.iat_max == pytest.approx(0.2)
    assert flow.fwd.iat_mean == pytest.approx(0.3)  # one gap in the forward direction
    assert flow.end_reason is EndReason.FLUSH


def test_idle_timeout_splits_flows(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink, FlowTableConfig(idle_timeout=10))
    table.add(meta(0.0, proto=17))
    table.add(meta(25.0, proto=17))  # arrives after the idle timeout
    table.flush()

    assert [f.end_reason for f in flows] == [EndReason.IDLE_TIMEOUT, EndReason.FLUSH]


def test_expire_emits_only_stale_flows(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink, FlowTableConfig(idle_timeout=10))
    table.add(meta(0.0, sport=1))
    table.add(meta(8.0, sport=2))

    table.expire(now=12.0)

    assert [f.src_port for f in flows] == [1]
    assert len(table) == 1


def test_active_timeout_splits_long_flows(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink, FlowTableConfig(idle_timeout=15, active_timeout=60))
    for second in range(0, 90):
        table.add(meta(float(second)))
    table.flush()

    assert [f.end_reason for f in flows] == [EndReason.ACTIVE_TIMEOUT, EndReason.FLUSH]
    assert flows[0].packets == 60 and flows[1].packets == 30


def test_tcp_closes_after_fin_from_both_sides_and_keeps_trailing_ack(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink, FlowTableConfig(tcp_close_linger=1.0))
    table.add(meta(0.00, flags=SYN))
    table.add(reply(0.01, flags=SYN | ACK))  # type: ignore[arg-type]
    table.add(meta(0.02, flags=FIN | ACK))
    table.expire(now=5.0)
    assert flows == []  # a FIN from one side only is a half-close, not the end

    table.add(reply(5.1, flags=FIN | ACK))  # type: ignore[arg-type]
    table.add(meta(5.2, flags=ACK))  # trailing ACK during the linger window
    table.expire(now=7.0)

    (flow,) = flows
    assert flow.end_reason is EndReason.TCP_FIN
    assert flow.packets == 5


def test_rst_closes_and_port_reuse_starts_a_new_flow(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink)
    table.add(meta(0.0, flags=SYN))
    table.add(reply(0.1, flags=RST | ACK))  # type: ignore[arg-type]
    table.add(meta(0.2, flags=SYN))  # same 5-tuple, new connection
    table.flush()

    assert [f.end_reason for f in flows] == [EndReason.TCP_RST, EndReason.FLUSH]
    assert [f.packets for f in flows] == [2, 1]


def test_full_table_evicts_least_recently_active(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink, FlowTableConfig(max_flows=2))
    table.add(meta(0.0, sport=1))
    table.add(meta(0.1, sport=2))
    table.add(meta(0.2, sport=1))  # sport=1 is now the most recent
    table.add(meta(0.3, sport=3))  # table full: evict sport=2

    assert [(f.src_port, f.end_reason) for f in flows] == [(2, EndReason.EVICTED)]
    assert table.stats.flows_emitted["evicted"] == 1


def test_counts_tcp_flags_per_direction(collect: Collect) -> None:
    flows, sink = collect
    table = FlowTable(sink)
    table.add(meta(0.0, flags=SYN))
    table.add(reply(0.1, flags=SYN | ACK))  # type: ignore[arg-type]
    table.add(meta(0.2, flags=ACK))
    table.flush()

    (flow,) = flows
    assert (flow.fwd.syn, flow.fwd.ack, flow.bwd.syn, flow.bwd.ack) == (1, 1, 1, 1)


@pytest.mark.parametrize(
    "kwargs",
    [{"idle_timeout": 0}, {"max_flows": 0}, {"idle_timeout": 1, "tcp_close_linger": 2}],
)
def test_config_rejects_invalid_values(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        FlowTableConfig(**kwargs)  # type: ignore[arg-type]


packet_strategy = st.lists(
    st.tuples(
        st.floats(min_value=0, max_value=0.5),  # gap since previous packet
        st.integers(min_value=0, max_value=3),  # which host pair
        st.booleans(),  # direction
        st.integers(min_value=40, max_value=1500),  # length
        st.sampled_from([0, SYN, ACK, FIN | ACK, RST, SYN | ACK]),
        st.sampled_from([6, 17]),
    ),
    max_size=200,
)


@settings(max_examples=150, deadline=None)
@given(packets=packet_strategy, max_flows=st.integers(min_value=1, max_value=5))
def test_every_packet_ends_up_in_exactly_one_flow(packets: list[tuple], max_flows: int) -> None:  # type: ignore[type-arg]
    flows: list[FlowRecord] = []
    table = FlowTable(
        flows.append, FlowTableConfig(idle_timeout=2, active_timeout=5, max_flows=max_flows)
    )
    ts = 0.0
    total_bytes = 0
    for gap, pair, forward, length, flags, proto in packets:
        ts += gap
        a, b = f"10.0.0.{pair}", "10.0.1.1"
        src, dst, sport, dport = (a, b, 1000 + pair, 80) if forward else (b, a, 80, 1000 + pair)
        table.add(
            meta(
                ts,
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                proto=proto,
                length=length,
                flags=flags,
            )
        )
        total_bytes += length
        if pair == 0:
            table.expire(ts)
    table.flush()

    assert sum(f.packets for f in flows) == len(packets)
    assert sum(f.bytes for f in flows) == total_bytes
    assert len(table) == 0
    for f in flows:
        assert f.packets >= 1 and f.fwd.packets >= 1  # the initiator sent at least one packet
        assert f.last_seen >= f.first_seen
        assert all(math.isfinite(v) for v in (f.iat_mean, f.iat_std, f.fwd.pkt_len_std))

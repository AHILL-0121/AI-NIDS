"""Soak test (audit CAP-05): replay labelled captures in a loop through one long-lived flow table,
detection engine and pipeline, and check memory stays flat (within 10 %).

Skipped unless NIDS_SOAK_SECONDS is set, e.g. `NIDS_SOAK_SECONDS=21600 uv run pytest tests/soak`
for the 6-hour run. Each loop shifts packet times forward, so the process sees an endless capture
with a scan every few minutes, as a long-running sensor would.
"""

import gc
import os
import time
import tracemalloc

import pytest
from scapy.utils import PcapReader

from nids.sensor.detect import DetectionEngine
from nids.sensor.flows import FlowTable
from nids.sensor.packets import PacketMeta, load_protocol_layers, parse_packet
from nids.sensor.pipeline import Pipeline

from ..fixtures.pcaps.make_fixtures import HERE

SECONDS = float(os.environ.get("NIDS_SOAK_SECONDS", "0"))
WARMUP_LOOPS = 20  # let caches, windows and baselines fill before measuring
TOLERANCE = 0.10

pytestmark = pytest.mark.skipif(SECONDS <= 0, reason="set NIDS_SOAK_SECONDS to run")


def load(name: str) -> list[PacketMeta]:
    load_protocol_layers()
    packets = []
    with PcapReader(str(HERE / name)) as reader:
        for packet in reader:
            meta = parse_packet(packet)
            if meta is not None:
                packets.append(meta)
    return packets


def shifted(packet: PacketMeta, offset: float) -> PacketMeta:
    return PacketMeta(
        ts=packet.ts + offset,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        ip_version=packet.ip_version,
        length=packet.length,
        payload_len=packet.payload_len,
        tcp_flags=packet.tcp_flags,
    )


def test_memory_stays_flat() -> None:
    capture = load("nmap_syn_scan.pcap") + load("benign_browsing.pcap")
    capture.sort(key=lambda p: p.ts)
    span = capture[-1].ts - capture[0].ts + 60

    pipeline = Pipeline(DetectionEngine(), max_alerts_kept=50)  # small, so the cap is exercised
    table = FlowTable(pipeline.on_flow, on_new_flow=pipeline.on_new_flow)
    tracemalloc.start()
    baseline = None
    loops = 0
    deadline = time.monotonic() + SECONDS
    while time.monotonic() < deadline or loops <= WARMUP_LOOPS:
        offset = loops * span
        second = None
        for packet in capture:
            packet = shifted(packet, offset)
            if second is not None and int(packet.ts) != second:
                table.expire(packet.ts)
                pipeline.tick(packet.ts)
            second = int(packet.ts)
            pipeline.on_packet(packet)
            table.add(packet)
        loops += 1
        if loops == WARMUP_LOOPS:
            gc.collect()
            baseline = tracemalloc.get_traced_memory()[0]

    gc.collect()
    current = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    assert baseline is not None
    growth = (current - baseline) / baseline
    print(
        f"{loops} loops, memory {baseline / 1e6:.1f} MB -> {current / 1e6:.1f} MB ({growth:+.1%})"
    )
    assert growth <= TOLERANCE, f"memory grew {growth:.1%} after warm-up ({loops} loops)"

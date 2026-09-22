"""Shared fixtures for sensor tests."""

from collections.abc import Callable
from pathlib import Path

import pytest
from scapy.utils import wrpcap

from nids.core.schemas.flow import FlowRecord

from .helpers import dns_exchange, other_packets, tcp_session


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    """TCP session (9 pkts), DNS exchange (2), IPv6 UDP, ICMP and ARP: 14 packets, 4 IP flows."""
    path = tmp_path / "sample.pcap"
    packets = sorted(tcp_session() + dns_exchange() + other_packets(), key=lambda p: p.time)
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def collect() -> tuple[list[FlowRecord], Callable[[FlowRecord], None]]:
    flows: list[FlowRecord] = []
    return flows, flows.append

"""Interfaces between capture sources and the detection engine."""

import ipaddress
from collections.abc import Callable
from functools import lru_cache
from typing import Protocol

from nids.core.schemas.alert import Detection
from nids.sensor.packets import PacketMeta

Emit = Callable[[Detection], None]

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    4: "IP-in-IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-in-IPv4",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}


class PacketObserver(Protocol):
    """What a capture source feeds besides finished flows. Sources that can't see packets
    (NFStream) only call `tick` and `flush`."""

    def on_packet(self, pkt: PacketMeta) -> None: ...

    def on_new_flow(self, pkt: PacketMeta, flow_id: str) -> None: ...

    def tick(self, now: float) -> None: ...

    def flush(self) -> None: ...


@lru_cache(maxsize=65536)
def is_unicast_target(address: str) -> bool:
    """False for multicast, broadcast and unspecified addresses. Traffic to those (mDNS, SSDP,
    LLMNR, DHCP) naturally reaches "many hosts" and must not count as scanning."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified:
        return False
    return not (ip.version == 4 and address.endswith(".255"))


def subnet_of(address: str) -> str:
    """/24 for IPv4, /64 for IPv6: the unit a host sweep walks through."""
    ip = ipaddress.ip_address(address)
    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))

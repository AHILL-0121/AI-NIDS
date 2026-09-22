"""Build packets and PCAP files in code, so tests need no binary fixtures."""

from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from nids.sensor.packets import PacketMeta

CLIENT, SERVER = "10.0.0.2", "93.184.216.34"


def eth() -> Any:
    """Ethernet header with fixed MACs, so Scapy never tries to resolve them (needs L2 access)."""
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def stamp(packet: Any, ts: float) -> Any:
    packet.time = ts
    return packet


def tcp_session(t0: float = 1000.0, sport: int = 50000) -> list[Any]:
    """Handshake, one request/response, FIN from both sides, final ACK: 9 packets."""
    c = eth() / IP(src=CLIENT, dst=SERVER)
    s = eth() / IP(src=SERVER, dst=CLIENT)
    pkts = [
        c / TCP(sport=sport, dport=80, flags="S"),
        s / TCP(sport=80, dport=sport, flags="SA"),
        c / TCP(sport=sport, dport=80, flags="A"),
        c / TCP(sport=sport, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        s / TCP(sport=80, dport=sport, flags="PA") / Raw(b"x" * 500),
        c / TCP(sport=sport, dport=80, flags="A"),
        c / TCP(sport=sport, dport=80, flags="FA"),
        s / TCP(sport=80, dport=sport, flags="FA"),
        c / TCP(sport=sport, dport=80, flags="A"),  # trailing ACK, must stay in the same flow
    ]
    return [stamp(p, t0 + i * 0.01) for i, p in enumerate(pkts)]


def dns_exchange(t0: float = 1000.5) -> list[Any]:
    q = eth() / IP(src=CLIENT, dst="10.0.0.1") / UDP(sport=53000, dport=53)
    q = q / DNS(rd=1, qd=DNSQR(qname="example.com"))
    r = eth() / IP(src="10.0.0.1", dst=CLIENT) / UDP(sport=53, dport=53000) / DNS(qr=1)
    return [stamp(q, t0), stamp(r, t0 + 0.02)]


def other_packets(t0: float = 1000.7) -> list[Any]:
    """One IPv6 UDP packet, one ICMP echo and one ARP (non-IP, must be skipped)."""
    return [
        stamp(eth() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=5353), t0),
        stamp(eth() / IP(src=CLIENT, dst="10.0.0.1") / ICMP(), t0 + 0.01),
        stamp(eth() / ARP(psrc=CLIENT, pdst="10.0.0.1"), t0 + 0.02),
    ]


def meta(
    ts: float,
    src: str = CLIENT,
    dst: str = SERVER,
    sport: int = 40000,
    dport: int = 443,
    proto: int = 6,
    length: int = 60,
    flags: int = 0,
    payload: int = 0,
) -> PacketMeta:
    return PacketMeta(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        ip_version=4,
        length=length,
        payload_len=payload,
        tcp_flags=flags,
    )

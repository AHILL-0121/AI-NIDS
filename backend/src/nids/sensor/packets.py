"""Turn a captured packet into the few fields the flow table needs.

Ported from v1's `_extract_packet_info` (audit §5), with IPv6, ICMPv6 and IP-level lengths added.
"""

from dataclasses import dataclass
from typing import Any

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

TCP, UDP, ICMP, ICMPV6 = 6, 17, 1, 58


@dataclass(frozen=True, slots=True)
class PacketMeta:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int  # 0 for protocols without ports
    dst_port: int
    protocol: int
    ip_version: int
    length: int  # IP-level length (header + payload)
    payload_len: int  # transport payload length
    tcp_flags: int  # 0 unless TCP


def load_protocol_layers() -> None:
    """Register Scapy's Ethernet/Linux-cooked/VLAN -> IPv4/IPv6 -> TCP/UDP bindings.

    Scapy only decodes past the link layer once these modules are imported. Call this before
    reading any packets, or every frame is dissected as Ether + raw bytes.
    """
    import scapy.layers.inet
    import scapy.layers.inet6
    import scapy.layers.l2  # noqa: F401


def parse_packet(packet: Any) -> PacketMeta | None:
    """Parse a Scapy packet. Returns None for anything that isn't IPv4/IPv6."""
    # Imported lazily so the module stays importable without the capture extra.
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if IP in packet:
        ip = packet[IP]
        version, protocol = 4, int(ip.proto)
    elif IPv6 in packet:
        ip = packet[IPv6]
        version, protocol = 6, int(ip.nh)
    else:
        return None

    src_port = dst_port = flags = 0
    transport = ip.payload
    if protocol in (TCP, UDP) and hasattr(transport, "sport"):
        src_port, dst_port = int(transport.sport), int(transport.dport)
        if protocol == TCP:
            flags = int(transport.flags)
    payload_len = len(transport.payload) if protocol in (TCP, UDP, ICMP, ICMPV6) else 0

    return PacketMeta(
        ts=float(packet.time),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_version=version,
        length=len(ip),
        payload_len=payload_len,
        tcp_flags=flags,
    )

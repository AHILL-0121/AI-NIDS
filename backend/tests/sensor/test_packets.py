from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from nids.sensor.packets import ACK, SYN, parse_packet

from .helpers import eth, stamp


def test_tcp_fields_and_ip_level_length() -> None:
    pkt = stamp(
        eth()
        / IP(src="1.1.1.1", dst="2.2.2.2")
        / TCP(sport=1234, dport=443, flags="SA")
        / Raw(b"abcd"),
        5.5,
    )

    meta = parse_packet(pkt)

    assert meta is not None
    assert (meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port) == (
        "1.1.1.1",
        "2.2.2.2",
        1234,
        443,
    )
    assert meta.protocol == 6 and meta.ip_version == 4 and meta.ts == 5.5
    assert meta.tcp_flags == SYN | ACK
    assert (
        meta.length == 20 + 20 + 4
    )  # IP + TCP headers + payload; the 14-byte Ethernet header is excluded
    assert meta.payload_len == 4


def test_length_does_not_depend_on_link_layer() -> None:
    body = IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1, dport=2) / Raw(b"x" * 10)
    with_ether = parse_packet(stamp(eth() / body, 0))
    raw_ip = parse_packet(stamp(body.copy(), 0))

    assert with_ether is not None and raw_ip is not None
    assert with_ether.length == raw_ip.length == 20 + 8 + 10


def test_ipv6_udp_and_icmp() -> None:
    v6 = parse_packet(
        stamp(eth() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=5353), 0)
    )
    icmp = parse_packet(stamp(eth() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(), 0))

    assert v6 is not None and v6.ip_version == 6 and v6.protocol == 17 and v6.dst_port == 5353
    assert icmp is not None and icmp.protocol == 1 and icmp.src_port == icmp.dst_port == 0


def test_non_ip_is_skipped() -> None:
    assert parse_packet(stamp(eth() / ARP(), 0)) is None

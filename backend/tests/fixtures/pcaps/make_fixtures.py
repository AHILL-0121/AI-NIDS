"""Build the labelled PCAP fixtures (audit QA-02).

    uv run python -m tests.fixtures.pcaps.make_fixtures

The captures are synthetic but mimic the real tools packet by packet: nmap's SYN scan (-sS, top
ports in random order, window 1024, MSS option, RST after a SYN/ACK), hping3's SYN flood (-S
--flood -p 80: incrementing source ports, window 512, no options), a masscan-style sweep of one
port across a /24, and ordinary desktop traffic. They are generated rather than recorded so they
contain no real addresses and can be rebuilt byte for byte (a test checks the committed files
match this script). Addresses use private and documentation ranges only.
"""

import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

HERE = Path(__file__).parent
T0 = 1_700_000_000.0  # fixed capture start, so files are reproducible

WORKSTATION = "192.168.1.20"
ROUTER = "192.168.1.1"
SERVER = "192.168.1.10"  # runs SSH and a web server
ATTACKER = "192.168.1.66"
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 199, 443, 445, 465, 587, 993, 995, 1025,
    1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
]  # fmt: skip


class Capture:
    """Collects packets with timestamps and MACs derived from the IP, like a real LAN."""

    def __init__(self) -> None:
        self.packets: list[Any] = []

    @staticmethod
    def _mac(ip: str) -> str:
        last = int(ip.split(".")[-1]) if ip.count(".") == 3 else 0
        return f"02:00:00:00:01:{last:02x}"

    def add(self, ts: float, src: str, dst: str, layer: Any) -> None:
        dst_mac = "01:00:5e:00:00:fb" if dst.startswith("224.") else self._mac(dst)
        packet = Ether(src=self._mac(src), dst=dst_mac) / IP(src=src, dst=dst, ttl=64) / layer
        packet.time = ts
        self.packets.append(packet)

    def tcp_session(
        self, ts: float, client: str, server: str, sport: int, dport: int, up: int, down: int
    ) -> None:
        """Handshake, request, response in MSS-sized segments, orderly close."""
        c = lambda f, **kw: TCP(sport=sport, dport=dport, flags=f, window=64240, **kw)  # noqa: E731
        s = lambda f, **kw: TCP(sport=dport, dport=sport, flags=f, window=65160, **kw)  # noqa: E731
        self.add(ts, client, server, c("S", options=[("MSS", 1460)]))
        self.add(ts + 0.012, server, client, s("SA", options=[("MSS", 1460)]))
        self.add(ts + 0.013, client, server, c("A"))
        self.add(ts + 0.014, client, server, c("PA") / Raw(b"q" * up))
        t = ts + 0.03
        for offset in range(0, down, 1448):
            self.add(t, server, client, s("A") / Raw(b"r" * min(1448, down - offset)))
            t += 0.002
        self.add(t + 0.001, client, server, c("A"))
        self.add(t + 0.5, client, server, c("FA"))
        self.add(t + 0.51, server, client, s("FA"))
        self.add(t + 0.511, client, server, c("A"))

    def dns(self, ts: float, client: str, name: str, answer: str, sport: int) -> None:
        self.add(
            ts,
            client,
            ROUTER,
            UDP(sport=sport, dport=53) / DNS(id=sport, rd=1, qd=DNSQR(qname=name)),
        )
        reply = DNS(
            id=sport, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer)
        )
        self.add(ts + 0.008, ROUTER, client, UDP(sport=53, dport=sport) / reply)

    def write(self, directory: Path, name: str) -> Path:
        self.packets.sort(key=lambda p: float(p.time))
        path = directory / name
        wrpcap(str(path), self.packets)
        return path


def benign_background(cap: Capture, rng: random.Random, t0: float, seconds: int) -> None:
    """A workstation browsing (DNS then HTTPS to many CDN hosts), QUIC, NTP, pings, mDNS/SSDP,
    and a second machine using the server's web and SSH services."""
    sport = 49152
    for i in range(seconds // 2):
        ts = t0 + i * 2 + rng.random()
        host = f"198.51.100.{rng.randint(1, 250)}"
        sport += 1
        cap.dns(ts, WORKSTATION, f"cdn{rng.randint(1, 40)}.example.com", host, 50000 + i)
        cap.tcp_session(
            ts + 0.02, WORKSTATION, host, sport, 443, rng.randint(300, 900), rng.randint(1000, 6000)
        )
    for i in range(seconds // 5):  # QUIC streams
        ts = t0 + i * 5 + 0.3
        for j in range(8):
            cap.add(
                ts + j * 0.01,
                "203.0.113.7",
                WORKSTATION,
                UDP(sport=443, dport=51000) / Raw(b"\x40" * 1200),
            )
        cap.add(
            ts + 0.25, WORKSTATION, "203.0.113.7", UDP(sport=51000, dport=443) / Raw(b"\x40" * 40)
        )
    for i in range(seconds // 15):
        ts = t0 + i * 15 + 1.1
        cap.add(ts, WORKSTATION, ROUTER, ICMP(type=8, id=1, seq=i))
        cap.add(ts + 0.001, ROUTER, WORKSTATION, ICMP(type=0, id=1, seq=i))
        cap.add(
            ts + 0.2,
            WORKSTATION,
            "224.0.0.251",
            UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_ipp._tcp.local", qtype="PTR")),
        )
        cap.add(
            ts + 0.4,
            WORKSTATION,
            "239.255.255.250",
            UDP(sport=51900, dport=1900) / Raw(b"M-SEARCH * HTTP/1.1\r\n\r\n"),
        )
    cap.add(
        t0 + 3, WORKSTATION, "192.0.2.123", UDP(sport=123, dport=123) / Raw(b"\x23" + b"\0" * 47)
    )
    cap.add(
        t0 + 3.03, "192.0.2.123", WORKSTATION, UDP(sport=123, dport=123) / Raw(b"\x24" + b"\0" * 47)
    )
    for i in range(seconds):  # the server's normal clients: a few web requests a second
        for j in range(3):
            client = f"192.168.1.{30 + (i + j) % 5}"
            cap.tcp_session(t0 + i + j * 0.3, client, SERVER, 40000 + i * 3 + j, 80, 350, 1400)
    cap.tcp_session(t0 + 10, WORKSTATION, SERVER, 55000, 22, 1200, 3000)


def benign(out: Path = HERE) -> Path:
    cap, rng = Capture(), random.Random(1)
    benign_background(cap, rng, T0, 90)
    return cap.write(out, "benign_browsing.pcap")


def nmap_syn_scan(out: Path = HERE) -> Path:
    """`nmap -sS 192.168.1.10` against a server with 22 and 80 open, amid normal traffic."""
    cap, rng = Capture(), random.Random(2)
    benign_background(cap, rng, T0, 30)
    ports = TOP_PORTS + [p for p in range(1000, 1400) if p not in TOP_PORTS]
    rng.shuffle(ports)
    t = T0 + 20
    for port in ports:
        t += rng.uniform(0.0005, 0.003)  # nmap -T3 against a LAN host
        probe = TCP(
            sport=rng.choice((41522, 41523)),
            dport=port,
            flags="S",
            window=1024,
            options=[("MSS", 1460)],
        )
        cap.add(t, ATTACKER, SERVER, probe)
        if port in (22, 80):
            cap.add(
                t + 0.0004,
                SERVER,
                ATTACKER,
                TCP(sport=port, dport=probe.sport, flags="SA", window=65160),
            )
            cap.add(t + 0.0006, ATTACKER, SERVER, TCP(sport=probe.sport, dport=port, flags="R"))
        else:
            cap.add(
                t + 0.0004,
                SERVER,
                ATTACKER,
                TCP(sport=port, dport=probe.sport, flags="RA", window=0),
            )
    return cap.write(out, "nmap_syn_scan.pcap")


def hping3_syn_flood(out: Path = HERE) -> Path:
    """`hping3 -S --flood -p 80 192.168.1.10` for 3 s after 60 s of normal web traffic. The
    server answers the first SYNs, then its backlog fills and it goes quiet."""
    cap, rng = Capture(), random.Random(3)
    benign_background(cap, rng, T0, 70)
    sport = rng.randint(1500, 3000)
    for i in range(4500):
        ts = T0 + 60 + i / 1500
        sport = 1024 + (sport + 1) % 64000
        cap.add(
            ts,
            ATTACKER,
            SERVER,
            TCP(sport=sport, dport=80, flags="S", window=512, seq=rng.getrandbits(32)),
        )
        if i < 150:
            cap.add(
                ts + 0.0003, SERVER, ATTACKER, TCP(sport=80, dport=sport, flags="SA", window=65160)
            )
    return cap.write(out, "hping3_syn_flood.pcap")


def host_sweep(out: Path = HERE) -> Path:
    """`masscan -p445 192.168.1.0/24 --rate 100`: one SYN per host; four hosts answer."""
    cap, rng = Capture(), random.Random(4)
    benign_background(cap, rng, T0, 30)
    hosts = list(range(1, 255))
    rng.shuffle(hosts)
    for i, last in enumerate(hosts):
        ts = T0 + 10 + i * 0.01
        target = f"192.168.1.{last}"
        cap.add(ts, ATTACKER, target, TCP(sport=61000, dport=445, flags="S", window=1024))
        if last in (10, 20, 31, 32):
            cap.add(ts + 0.0005, target, ATTACKER, TCP(sport=445, dport=61000, flags="SA"))
            cap.add(ts + 0.0007, ATTACKER, target, TCP(sport=61000, dport=445, flags="R"))
    return cap.write(out, "host_sweep_445.pcap")


BUILDERS: dict[str, Callable[[Path], Path]] = {
    "benign_browsing.pcap": benign,
    "nmap_syn_scan.pcap": nmap_syn_scan,
    "hping3_syn_flood.pcap": hping3_syn_flood,
    "host_sweep_445.pcap": host_sweep,
}

if __name__ == "__main__":
    for builder in BUILDERS.values():
        path = builder(HERE)
        print(f"{path.name}: {path.stat().st_size:,} bytes")

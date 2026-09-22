"""Detection engine tests. The benign scenarios are regressions for v1's false positives:
DNS/HTTPS counted as port scans (DET-01), downloads counted as DDoS (DET-02), IGMP flagged
(DET-03), and one attacker's alert hiding another's (DET-04)."""

import threading
from collections.abc import Iterable
from pathlib import Path

import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from nids.core.schemas.alert import Alert, AlertStatus, Severity
from nids.core.schemas.flow import FlowRecord
from nids.sensor.capture import PcapReplaySource
from nids.sensor.detect import DetectionEngine, SuppressionRule
from nids.sensor.detect.ml import MlDetector
from nids.sensor.flows import FlowTable
from nids.sensor.packets import ACK, PSH, RST, SYN, PacketMeta

from .helpers import eth, meta, stamp

VICTIM, ATTACKER, CLIENT = "10.0.0.5", "10.0.0.66", "10.0.0.2"


class Harness:
    """Feed packets through a flow table and the engine, the way the Scapy sources do."""

    def __init__(self) -> None:
        self.alerts: dict[str, Alert] = {}
        self.engine = DetectionEngine(self._on_alert)
        self.flows: list[FlowRecord] = []
        self.table = FlowTable(self._on_flow, on_new_flow=self.engine.on_new_flow)
        self._second: int | None = None

    def _on_alert(self, alert: Alert, is_new: bool) -> None:
        self.alerts[alert.id] = alert

    def _on_flow(self, flow: FlowRecord) -> None:
        self.flows.append(flow)
        self.engine.on_flow(flow)

    def feed(self, packets: Iterable[PacketMeta]) -> "Harness":
        for pkt in sorted(packets, key=lambda p: p.ts):
            second = int(pkt.ts)
            if self._second is not None and second != self._second:
                self.table.expire(pkt.ts)
                self.engine.tick(pkt.ts)
            self._second = second
            self.engine.on_packet(pkt)
            self.table.add(pkt)
        return self

    def finish(self) -> list[Alert]:
        self.table.flush()
        self.engine.flush()
        return list(self.alerts.values())

    def of_type(self, kind: str) -> list[Alert]:
        return [a for a in self.alerts.values() if a.type == kind]


def tcp(
    ts: float, src: str, dst: str, sport: int, dport: int, flags: int, payload: int = 0
) -> PacketMeta:
    return meta(
        ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=6,
        flags=flags,
        payload=payload,
        length=40 + payload,
    )


def udp(ts: float, src: str, dst: str, sport: int, dport: int, payload: int = 100) -> PacketMeta:
    return meta(
        ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=17,
        payload=payload,
        length=28 + payload,
    )


def normal_office_traffic(t0: float = 1000.0) -> list[PacketMeta]:
    """DNS lookups, HTTPS to 40 different servers, a fast download, a QUIC stream, mDNS, IGMP."""
    pkts: list[PacketMeta] = []
    for i in range(60):  # DNS: many queries to the resolver on port 53
        pkts += [
            udp(t0 + i * 0.2, CLIENT, "10.0.0.1", 50000 + i, 53, 40),
            udp(t0 + i * 0.2 + 0.01, "10.0.0.1", CLIENT, 53, 50000 + i, 120),
        ]
    for i in range(40):  # HTTPS to 40 servers in 40 different /24s (browser + CDNs)
        server, sport, ts = f"93.184.{i}.10", 40000 + i, t0 + i * 0.3
        pkts += [
            tcp(ts, CLIENT, server, sport, 443, SYN),
            tcp(ts + 0.02, server, CLIENT, 443, sport, SYN | ACK),
            tcp(ts + 0.03, CLIENT, server, sport, 443, ACK),
            tcp(ts + 0.05, CLIENT, server, sport, 443, PSH | ACK, 500),
            tcp(ts + 0.08, server, CLIENT, 443, sport, PSH | ACK, 1400),
        ]
    for i in range(12000):  # a 1-second, MTU-sized download: v1 called each packet "DDoS"
        ts = t0 + 20 + i / 12000
        pkts.append(tcp(ts, "151.101.1.1", CLIENT, 443, 45000, ACK, 1460))
        if i % 2 == 0:
            pkts.append(tcp(ts, CLIENT, "151.101.1.1", 45000, 443, ACK))
    for i in range(9000):  # QUIC video: fast UDP, but two-way
        ts = t0 + 25 + i / 9000
        pkts.append(udp(ts, "142.250.1.1", CLIENT, 443, 51000, 1200))
        if i % 4 == 0:
            pkts.append(udp(ts, CLIENT, "142.250.1.1", 51000, 443, 40))
    for i in range(30):  # mDNS to multicast from many LAN hosts
        pkts.append(udp(t0 + i * 0.1, f"10.0.0.{100 + i}", "224.0.0.251", 5353, 5353))
    pkts.append(meta(t0 + 1, src=CLIENT, dst="224.0.0.22", sport=0, dport=0, proto=2))  # IGMP
    return pkts


def syn_scan(
    src: str, dst: str, ports: Iterable[int], t0: float, rate: float = 100.0
) -> list[PacketMeta]:
    pkts = []
    for i, port in enumerate(ports):
        ts = t0 + i / rate
        pkts += [
            tcp(ts, src, dst, 60000, port, SYN),
            tcp(ts + 0.001, dst, src, port, 60000, RST | ACK),
        ]
    return pkts


def test_normal_traffic_raises_no_alerts() -> None:
    alerts = Harness().feed(normal_office_traffic()).finish()

    assert alerts == [], [(a.type, a.src, a.dst, a.evidence) for a in alerts]


def test_port_scan_is_one_alert_with_growing_evidence() -> None:
    h = Harness().feed(syn_scan(ATTACKER, VICTIM, range(1, 301), t0=1000.0, rate=50))
    h.finish()

    (scan,) = h.of_type("port_scan")
    assert h.of_type("syn_flood") == []  # 100 SYNs/s over many ports is a scan, not a flood
    assert (scan.src, scan.dst) == (ATTACKER, VICTIM)
    assert scan.evidence["distinct_ports"] >= 200
    assert scan.evidence["unanswered_ratio"] == 1.0  # every probe was answered with RST
    assert scan.occurrences > 1  # 25, 50, 100, 200 ports: merged, not four alerts
    assert scan.severity is Severity.HIGH
    assert scan.mitre_technique and scan.mitre_technique.startswith("T1046")
    assert ATTACKER in scan.explanation and "ports" in scan.explanation


def test_two_scanners_get_two_alerts() -> None:
    """v1's per-type cooldown hid the second attacker for 60 s (audit DET-04)."""
    packets = syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0) + syn_scan(
        "10.0.0.77", VICTIM, range(1, 60), 1000.2
    )
    h = Harness().feed(packets)
    h.finish()

    assert sorted(a.src for a in h.of_type("port_scan")) == [ATTACKER, "10.0.0.77"]


def test_slow_scan_below_threshold_is_ignored() -> None:
    h = Harness().feed(syn_scan(ATTACKER, VICTIM, range(1, 20), 1000.0))

    assert h.finish() == []


def test_host_sweep_on_one_subnet() -> None:
    packets = [tcp(1000 + i * 0.05, ATTACKER, f"10.0.0.{i}", 61000, 445, SYN) for i in range(1, 61)]
    h = Harness().feed(packets)
    h.finish()

    (sweep,) = h.of_type("host_sweep")
    assert sweep.dst == "10.0.0.0/24"
    assert sweep.evidence["service"] == "TCP port 445"
    assert sweep.evidence["distinct_hosts"] >= 20


def _baseline(t0: float, seconds: int) -> list[PacketMeta]:
    """A web server with a few normal connections a second."""
    pkts = []
    for s in range(seconds):
        for j in range(3):
            ts, sport = t0 + s + j * 0.3, 30000 + s * 3 + j
            pkts += [
                tcp(ts, CLIENT, VICTIM, sport, 80, SYN),
                tcp(ts + 0.01, VICTIM, CLIENT, 80, sport, SYN | ACK),
            ]
    return pkts


def test_spoofed_syn_flood_is_ddos() -> None:
    t0 = 1000.0
    flood = [
        tcp(t0 + 60 + i / 3000, f"198.51.{i // 250}.{i % 250}", VICTIM, 1024 + i % 60000, 80, SYN)
        for i in range(3000)
    ]
    h = Harness().feed(_baseline(t0, 60) + flood)
    h.finish()

    (ddos,) = h.of_type("ddos")
    assert ddos.dst == VICTIM and ddos.src is None
    assert ddos.severity is Severity.CRITICAL
    assert ddos.evidence["metric"] == "SYNs" and ddos.evidence["rate"] >= 2000
    assert isinstance(ddos.evidence["baseline"], float)  # learned from the 60 normal seconds


def test_single_source_syn_flood() -> None:
    t0 = 1000.0
    flood = [tcp(t0 + 60 + i / 800, ATTACKER, VICTIM, 1024 + i, 80, SYN) for i in range(800)]
    h = Harness().feed(_baseline(t0, 60) + flood)
    h.finish()

    (syn,) = h.of_type("syn_flood")
    assert syn.src == ATTACKER and syn.evidence["distinct_sources"] <= 2


def test_one_way_udp_flood() -> None:
    t0 = 1000.0
    flood = [udp(t0 + 60 + i / 20000, ATTACKER, "10.0.0.9", 40000, 9999, 512) for i in range(20000)]
    h = Harness().feed(_baseline(t0, 60) + flood)
    h.finish()

    (flood_alert,) = h.of_type("flood")
    assert flood_alert.dst == "10.0.0.9" and flood_alert.evidence["reply_ratio"] == 0.0


def test_unusual_protocol_but_not_igmp_or_multicast() -> None:
    gre = meta(1000.0, src=CLIENT, dst="203.0.113.7", sport=0, dport=0, proto=47)
    igmp = meta(1000.1, src=CLIENT, dst="224.0.0.22", sport=0, dport=0, proto=2)
    ospf_multicast = meta(1000.2, src=CLIENT, dst="224.0.0.5", sport=0, dport=0, proto=89)
    h = Harness().feed([gre, igmp, ospf_multicast])
    h.finish()

    (alert,) = h.alerts.values()
    assert alert.type == "unusual_protocol" and alert.protocol == 47
    assert alert.severity is Severity.LOW and "GRE" in alert.explanation


def test_false_positive_feedback_suppresses_repeats() -> None:
    h = Harness().feed(syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0))
    (alert,) = h.of_type("port_scan")
    h.engine.correlator.mark_false_positive(alert)

    h.feed(syn_scan(ATTACKER, VICTIM, range(100, 200), 1100.0))
    h.finish()

    assert alert.status is AlertStatus.FALSE_POSITIVE
    assert len(h.of_type("port_scan")) == 1  # no new alert
    assert h.engine.correlator.suppressed["port_scan"] > 0


def test_suppression_rule_matches_cidr() -> None:
    h = Harness()
    h.engine.correlator.add_rule(
        SuppressionRule(type="port_scan", src="10.0.0.0/24", reason="IT scanner")
    )
    h.feed(syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0))

    assert h.finish() == []


def test_alert_after_dedup_window_is_new() -> None:
    h = Harness()
    h.feed(syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0))
    h.feed(syn_scan(ATTACKER, VICTIM, range(1, 40), 3000.0))  # 2000 s later, window is 900 s
    h.finish()

    assert len(h.of_type("port_scan")) == 2


def test_flow_level_backends_still_detect_scans() -> None:
    """NFStream gives no packets, only finished flows."""
    source = Harness()
    source.feed(syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0))
    source.table.flush()

    alerts: list[Alert] = []
    engine = DetectionEngine(lambda a, new: alerts.append(a) if new else None)
    for flow in source.flows:
        engine.on_flow(flow)

    assert [a.type for a in alerts] == ["port_scan"]


class StubBundle:
    """Stands in for a trained model: flags flows with more than 5 packets."""

    attack_threshold = 0.5

    def score(self, features: pd.DataFrame) -> pd.DataFrame:
        big = features["fwd_packets"] + features["bwd_packets"] > 5
        return pd.DataFrame(
            {
                "family": ["brute_force" if b else "benign" for b in big],
                "attack_prob": [0.9 if b else 0.1 for b in big],
                "novelty": [0.5] * len(features),
                "fused": [0.9 if b else 0.5 for b in big],
                "alert": big.to_numpy(),
            }
        )


def test_ml_detector_turns_model_verdicts_into_alerts() -> None:
    h = Harness()
    h.engine.ml = MlDetector(StubBundle(), "stub-v1", h.engine._detect, batch_size=2)
    long_flow = [tcp(1000 + i * 0.1, ATTACKER, VICTIM, 50000, 22, ACK, 50) for i in range(8)]
    short_flow = [tcp(1000.0, CLIENT, VICTIM, 50001, 22, SYN)]
    h.feed(long_flow + short_flow)
    h.finish()

    (alert,) = h.alerts.values()
    assert alert.type == "ml_known_attack" and alert.family == "brute_force"
    assert alert.title == "Looks like password brute-force"
    assert alert.mitre_technique == "T1110 Brute Force"
    assert alert.model_version == "stub-v1" and alert.flow_ids


def test_replaying_a_scan_pcap_raises_the_alert(tmp_path: Path) -> None:
    packets = []
    for i, port in enumerate(range(1, 101)):
        ts = 1000 + i * 0.01
        packets.append(
            stamp(
                eth() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=60000, dport=port, flags="S"), ts
            )
        )
        packets.append(
            stamp(
                eth() / IP(src=VICTIM, dst=ATTACKER) / TCP(sport=port, dport=60000, flags="RA"),
                ts + 0.001,
            )
        )
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), packets)

    alerts: list[Alert] = []
    engine = DetectionEngine(lambda a, new: alerts.append(a) if new else None)
    source = PcapReplaySource(path, observer=engine)
    source.run(engine.on_flow, threading.Event())

    assert [a.type for a in alerts] == ["port_scan"]
    assert "unanswered_ratio" in alerts[0].evidence


@pytest.mark.parametrize(
    "kind",
    [
        "port_scan",
        "host_sweep",
        "syn_flood",
        "ddos",
        "flood",
        "unusual_protocol",
        "ml_known_attack",
        "ml_anomaly",
    ],
)
def test_every_alert_type_has_wording(kind: str) -> None:
    from nids.core.schemas.alert import AlertSource, Detection
    from nids.sensor.detect.knowledge import describe

    d = Detection(
        ts=0,
        type=kind,
        source=AlertSource.HEURISTIC,
        severity=Severity.LOW,
        confidence=0.5,
        src="a",
        dst="b",
        evidence={},
        family="dos",
    )
    title, _, explanation, recommendation = describe(d)

    assert title and explanation and recommendation

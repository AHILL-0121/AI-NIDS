"""The detection engine: feeds packets, new flows and finished flows to every detector, and their
detections through the correlator into alerts."""

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from nids.core.schemas.alert import AlertSource, Detection, Severity
from nids.core.schemas.flow import FlowRecord
from nids.sensor.detect.base import PROTOCOL_NAMES, is_unicast_target
from nids.sensor.detect.correlator import AlertCorrelator, AlertSink
from nids.sensor.detect.flood import FloodConfig, FloodDetector
from nids.sensor.detect.ml import MlDetector
from nids.sensor.detect.scan import ScanConfig, ScanDetector
from nids.sensor.packets import ACK, SYN, TCP, PacketMeta

log = logging.getLogger(__name__)

# ICMP, IGMP (multicast group membership, on every LAN), TCP, UDP, ICMPv6. Audit DET-03: v1
# alerted on IGMP constantly. mDNS, SSDP and LLMNR ride on UDP to multicast, so they're allowed.
DEFAULT_ALLOWED_PROTOCOLS = frozenset({1, 2, 6, 17, 58})


@dataclass(frozen=True)
class DetectionConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    flood: FloodConfig = field(default_factory=FloodConfig)
    allowed_protocols: frozenset[int] = DEFAULT_ALLOWED_PROTOCOLS
    dedup_window_s: float = 900.0


class DetectionEngine:
    """Implements PacketObserver. Not thread-safe: call it from the capture thread."""

    def __init__(self, on_alert: AlertSink, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self.correlator = AlertCorrelator(on_alert, self.config.dedup_window_s)
        self.scan = ScanDetector(self._detect, self.config.scan)
        self.flood = FloodDetector(self._detect, self.config.flood)
        self.ml: MlDetector | None = None
        self.packet_level = False  # True once a source feeds packets (Scapy backends)
        self.detections: Counter[str] = Counter()
        self._reported_protocols: set[tuple[str, str, int]] = set()

    def load_model(self, artifact_dir: Path) -> None:
        from nids.ml import registry  # needs the ml extra; only imported when a model is used

        bundle, manifest = registry.load(artifact_dir)
        self.ml = MlDetector(bundle, manifest["version"], self._detect)
        log.info("Loaded model %s", manifest["version"])

    # --- PacketObserver ---

    def on_packet(self, pkt: PacketMeta) -> None:
        self.packet_level = True
        self.flood.on_packet(pkt)

    def on_new_flow(self, pkt: PacketMeta, flow_id: str) -> None:
        opens = pkt.protocol != TCP or (pkt.tcp_flags & SYN and not pkt.tcp_flags & ACK)
        if opens:
            self.scan.on_attempt(
                pkt.ts, pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.dst_port, flow_id
            )
        self._check_protocol(pkt.ts, pkt.src_ip, pkt.dst_ip, pkt.protocol)

    def tick(self, now: float) -> None:
        self.flood.tick(now)
        self.scan.tick(now)
        if self.ml is not None:
            self.ml.flush()
        self.correlator.expire(now)

    def flush(self) -> None:
        self.flood.flush()
        if self.ml is not None:
            self.ml.flush()

    # --- finished flows (called by the flow sink) ---

    def on_flow(self, flow: FlowRecord) -> None:
        if not self.packet_level:
            # NFStream: no per-packet events, so treat the finished flow as the attempt.
            opens = flow.protocol != TCP or flow.fwd.syn > 0
            if opens:
                self.scan.on_attempt(
                    flow.first_seen,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.protocol,
                    flow.dst_port,
                    flow.flow_id,
                )
            self._check_protocol(flow.first_seen, flow.src_ip, flow.dst_ip, flow.protocol)
        self.scan.on_flow_end(flow)
        if self.ml is not None:
            self.ml.on_flow(flow)

    def _check_protocol(self, ts: float, src: str, dst: str, protocol: int) -> None:
        if protocol in self.config.allowed_protocols or not is_unicast_target(dst):
            return
        key = (src, dst, protocol)
        if key in self._reported_protocols:
            return
        if len(self._reported_protocols) > 100_000:
            self._reported_protocols.clear()
        self._reported_protocols.add(key)
        self._detect(
            Detection(
                ts=ts,
                type="unusual_protocol",
                source=AlertSource.HEURISTIC,
                severity=Severity.LOW,
                confidence=0.5,
                src=src,
                dst=dst,
                protocol=protocol,
                evidence={"protocol_name": PROTOCOL_NAMES.get(protocol, "unknown")},
            )
        )

    def _detect(self, detection: Detection) -> None:
        self.detections[detection.type] += 1
        self.correlator.add(detection)

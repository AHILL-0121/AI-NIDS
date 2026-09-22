"""The flow record every capture backend produces.

A flow is a bidirectional conversation keyed by its 5-tuple. "Forward" means the direction of the
first packet seen (the initiator); "backward" is the reply direction. Lengths are IP-level (IP
header included, link layer excluded), so values don't depend on Ethernet vs. Wi-Fi vs. loopback
capture. Times are seconds (float, Unix epoch).

Phase 2's feature schema (features_v1) is computed from these fields, so any field added here must
be filled by every backend, or be optional and documented as such.
"""

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class EndReason(StrEnum):
    IDLE_TIMEOUT = "idle_timeout"
    ACTIVE_TIMEOUT = "active_timeout"
    TCP_FIN = "tcp_fin"
    TCP_RST = "tcp_rst"
    EVICTED = "evicted"  # flow table full; least recently active flow dropped
    FLUSH = "flush"  # capture stopped / end of PCAP


@dataclass(frozen=True, slots=True)
class DirectionStats:
    packets: int
    bytes: int
    payload_bytes: int | None  # None when the backend can't measure it (NFStream)
    pkt_len_min: float
    pkt_len_max: float
    pkt_len_mean: float
    pkt_len_std: float
    iat_mean: float  # seconds between packets in this direction
    syn: int
    fin: int
    rst: int
    psh: int
    ack: int
    urg: int


@dataclass(frozen=True, slots=True)
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # IANA protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6)
    ip_version: int
    first_seen: float
    last_seen: float
    iat_mean: float  # seconds between consecutive packets, both directions
    iat_std: float
    iat_min: float
    iat_max: float
    fwd: DirectionStats
    bwd: DirectionStats
    end_reason: EndReason
    app_protocol: str | None = None  # nDPI label when available

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def packets(self) -> int:
        return self.fwd.packets + self.bwd.packets

    @property
    def bytes(self) -> int:
        return self.fwd.bytes + self.bwd.bytes

    def to_dict(self) -> dict[str, Any]:
        """Flat JSON-ready dict: nested direction stats become fwd_* / bwd_* keys."""
        data = asdict(self)
        for direction in ("fwd", "bwd"):
            for key, value in data.pop(direction).items():
                data[f"{direction}_{key}"] = value
        data["end_reason"] = self.end_reason.value
        data["duration"] = self.duration
        return data

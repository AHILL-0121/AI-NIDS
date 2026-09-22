"""The flow record every capture backend produces.

A flow is a bidirectional conversation keyed by its 5-tuple. "Forward" means the direction of the
first packet seen (the initiator); "backward" is the reply direction. Times are seconds (float,
Unix epoch).

Length statistics follow CICFlowMeter, the tool that produced the CIC-IDS2017 training data:
"packet length" means **transport payload** bytes, and standard deviations are **sample** (n-1)
deviations. IP-level sizes (headers included) are kept too, because UNSW-NB15 measures traffic
that way, but some backends can't provide them (they're None then).

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
    payload_bytes: int
    payload_len_min: float
    payload_len_max: float
    payload_len_mean: float
    payload_len_std: float
    iat_mean: float  # seconds between packets in this direction
    iat_std: float
    iat_min: float
    iat_max: float
    syn: int
    fin: int
    rst: int
    psh: int
    ack: int
    urg: int
    ip_bytes: int | None = None  # IP header + payload; None if the backend can't measure it
    ip_len_mean: float | None = None


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
    def payload_bytes(self) -> int:
        return self.fwd.payload_bytes + self.bwd.payload_bytes

    @property
    def ip_bytes(self) -> int | None:
        if self.fwd.ip_bytes is None or self.bwd.ip_bytes is None:
            return None
        return self.fwd.ip_bytes + self.bwd.ip_bytes

    def to_dict(self) -> dict[str, Any]:
        """Flat JSON-ready dict: nested direction stats become fwd_* / bwd_* keys."""
        data = asdict(self)
        for direction in ("fwd", "bwd"):
            for key, value in data.pop(direction).items():
                data[f"{direction}_{key}"] = value
        data["end_reason"] = self.end_reason.value
        data["duration"] = self.duration
        return data

"""Bidirectional flow table: packets in, finished FlowRecords out.

Replaces v1's global 100-packet window (audit ML-08) and its never-evicted per-IP dictionaries
(audit CAP-05).

How a flow ends:
- active timeout: the flow has lasted `active_timeout` seconds (long flows are split);
- idle timeout: no packet for `idle_timeout` seconds;
- TCP close: after a FIN has been seen in *both* directions, or after an RST. The flow lingers for
  `tcp_close_linger` seconds so the trailing ACKs are counted in it instead of starting a tiny new
  flow. Closing on the first FIN is the CICFlowMeter bug documented by Engelen et al. (2021);
- eviction: the table is full, so the least recently active flow is emitted early;
- flush: capture stopped.

All timing uses packet timestamps, so replaying a PCAP gives the same flows every time.

The defaults match CICFlowMeter, which produced the CIC-IDS2017 training data: flows end after
120 s, with no separate shorter idle timeout. Live flows must be cut the same way as training
flows, or features like duration and packet counts mean different things at inference time.
"""

import itertools
import math
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from nids.core.schemas.flow import DirectionStats, EndReason, FlowRecord
from nids.sensor.packets import ACK, FIN, PSH, RST, SYN, TCP, URG, PacketMeta

FlowKey = tuple[int, str, int, str, int]


@dataclass(frozen=True, slots=True)
class FlowTableConfig:
    idle_timeout: float = 120.0
    active_timeout: float = 120.0
    tcp_close_linger: float = 1.0
    max_flows: int = 100_000

    def __post_init__(self) -> None:
        if self.idle_timeout <= 0 or self.active_timeout <= 0 or self.max_flows <= 0:
            raise ValueError("timeouts and max_flows must be positive")
        if not 0 <= self.tcp_close_linger < self.idle_timeout:
            raise ValueError("tcp_close_linger must be >= 0 and shorter than idle_timeout")


@dataclass(slots=True)
class FlowTableStats:
    packets: int = 0
    flows_created: int = 0
    flows_emitted: Counter[str] = field(default_factory=Counter)


class _RunningStats:
    """Welford's online mean/variance, plus min and max.

    `std` is the sample standard deviation (n-1), as in CICFlowMeter (Apache Commons Math).
    """

    __slots__ = ("m2", "max", "mean", "min", "n")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min = math.inf
        self.max = -math.inf

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        self.min = min(self.min, x)
        self.max = max(self.max, x)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def summary(self) -> tuple[float, float, float, float]:
        if not self.n:
            return 0.0, 0.0, 0.0, 0.0
        return self.min, self.max, self.mean, self.std


class _Direction:
    __slots__ = (
        "ack",
        "fin",
        "iat",
        "ip_bytes",
        "last_ts",
        "payload",
        "payload_total",
        "psh",
        "rst",
        "syn",
        "urg",
    )

    def __init__(self) -> None:
        self.ip_bytes = self.payload_total = 0
        self.syn = self.fin = self.rst = self.psh = self.ack = self.urg = 0
        self.payload = _RunningStats()
        self.iat = _RunningStats()
        self.last_ts: float | None = None

    def add(self, pkt: PacketMeta) -> None:
        if self.last_ts is not None:
            self.iat.add(max(0.0, pkt.ts - self.last_ts))
        self.last_ts = pkt.ts
        self.ip_bytes += pkt.length
        self.payload.add(pkt.payload_len)
        self.payload_total += pkt.payload_len
        f = pkt.tcp_flags
        self.syn += bool(f & SYN)
        self.fin += bool(f & FIN)
        self.rst += bool(f & RST)
        self.psh += bool(f & PSH)
        self.ack += bool(f & ACK)
        self.urg += bool(f & URG)

    def to_stats(self) -> DirectionStats:
        lo, hi, mean, std = self.payload.summary()
        iat_min, iat_max, iat_mean, iat_std = self.iat.summary()
        packets = self.payload.n
        return DirectionStats(
            packets=packets,
            payload_bytes=self.payload_total,
            payload_len_min=lo,
            payload_len_max=hi,
            payload_len_mean=mean,
            payload_len_std=std,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            ip_bytes=self.ip_bytes,
            ip_len_mean=self.ip_bytes / packets if packets else 0.0,
            syn=self.syn,
            fin=self.fin,
            rst=self.rst,
            psh=self.psh,
            ack=self.ack,
            urg=self.urg,
        )


class _Flow:
    __slots__ = (
        "bwd",
        "closing",
        "dst",
        "first_seen",
        "flow_id",
        "fwd",
        "iat",
        "ip_version",
        "last_seen",
        "protocol",
        "src",
    )

    def __init__(self, flow_id: str, pkt: PacketMeta) -> None:
        self.flow_id = flow_id
        self.src = (pkt.src_ip, pkt.src_port)  # initiator = sender of the first packet seen
        self.dst = (pkt.dst_ip, pkt.dst_port)
        self.protocol = pkt.protocol
        self.ip_version = pkt.ip_version
        self.first_seen = self.last_seen = pkt.ts
        self.fwd = _Direction()
        self.bwd = _Direction()
        self.iat = _RunningStats()
        self.closing: EndReason | None = None

    def add(self, pkt: PacketMeta, first: bool) -> None:
        if not first:
            self.iat.add(max(0.0, pkt.ts - self.last_seen))
        self.last_seen = max(self.last_seen, pkt.ts)
        forward = (pkt.src_ip, pkt.src_port) == self.src
        (self.fwd if forward else self.bwd).add(pkt)

        if self.protocol == TCP and self.closing is None:
            if pkt.tcp_flags & RST:
                self.closing = EndReason.TCP_RST
            elif self.fwd.fin and self.bwd.fin:
                self.closing = EndReason.TCP_FIN

    def to_record(self, reason: EndReason) -> FlowRecord:
        iat_min, iat_max, iat_mean, iat_std = self.iat.summary()
        return FlowRecord(
            flow_id=self.flow_id,
            src_ip=self.src[0],
            dst_ip=self.dst[0],
            src_port=self.src[1],
            dst_port=self.dst[1],
            protocol=self.protocol,
            ip_version=self.ip_version,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            fwd=self.fwd.to_stats(),
            bwd=self.bwd.to_stats(),
            end_reason=reason,
        )


def flow_key(pkt: PacketMeta) -> FlowKey:
    """Direction-independent key: both directions of a conversation map to the same key."""
    a, b = (pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port)
    if b < a:
        a, b = b, a
    return (pkt.protocol, a[0], a[1], b[0], b[1])


def _opens_new_connection(pkt: PacketMeta) -> bool:
    return pkt.protocol == TCP and bool(pkt.tcp_flags & SYN) and not pkt.tcp_flags & ACK


class FlowTable:
    """Not thread-safe: feed it from a single thread."""

    def __init__(
        self,
        on_flow: Callable[[FlowRecord], None],
        config: FlowTableConfig | None = None,
        on_new_flow: Callable[[PacketMeta, str], None] | None = None,
    ) -> None:
        self.config = config or FlowTableConfig()
        self.stats = FlowTableStats()
        self._on_flow = on_flow
        self._on_new_flow = on_new_flow  # sees each flow's first packet (scan detection)
        self._flows: OrderedDict[FlowKey, _Flow] = OrderedDict()  # least recently active first
        self._ids = itertools.count(1)

    def __len__(self) -> int:
        return len(self._flows)

    def add(self, pkt: PacketMeta) -> None:
        self.stats.packets += 1
        key = flow_key(pkt)
        flow = self._flows.get(key)

        if flow is not None:
            reason: EndReason | None = None
            if flow.closing is not None and _opens_new_connection(pkt):
                reason = flow.closing  # port reuse: a new connection on a closed 5-tuple
            elif pkt.ts - flow.last_seen >= self.config.idle_timeout:
                reason = flow.closing or EndReason.IDLE_TIMEOUT
            elif pkt.ts - flow.first_seen >= self.config.active_timeout:
                reason = EndReason.ACTIVE_TIMEOUT
            if reason is not None:
                self._emit(key, reason)
                flow = None

        if flow is None:
            if len(self._flows) >= self.config.max_flows:
                self._emit(next(iter(self._flows)), EndReason.EVICTED)
            flow = _Flow(f"flow-{next(self._ids)}", pkt)
            self._flows[key] = flow
            self.stats.flows_created += 1
            flow.add(pkt, first=True)
            if self._on_new_flow is not None:
                self._on_new_flow(pkt, flow.flow_id)
        else:
            self._flows.move_to_end(key)
            flow.add(pkt, first=False)

    def expire(self, now: float) -> None:
        """Emit flows that have timed out as of `now` (packet time for replay, wall time live)."""
        linger, idle = self.config.tcp_close_linger, self.config.idle_timeout
        closed = [
            k
            for k, f in self._flows.items()
            if f.closing is not None and now - f.last_seen >= linger
        ]
        for key in closed:
            self._emit(key, self._flows[key].closing or EndReason.FLUSH)
        # Flows are ordered by last activity, so stop at the first one that's still fresh.
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if now - flow.last_seen < idle:
                break
            self._emit(key, flow.closing or EndReason.IDLE_TIMEOUT)

    def flush(self) -> None:
        """Emit every flow still open (end of capture)."""
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            self._emit(key, flow.closing or EndReason.FLUSH)

    def _emit(self, key: FlowKey, reason: EndReason) -> None:
        flow = self._flows.pop(key)
        self.stats.flows_emitted[reason.value] += 1
        self._on_flow(flow.to_record(reason))

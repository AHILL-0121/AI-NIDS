"""SYN floods, packet floods and DDoS (audit DET-02).

v1 called any packet over 1400 bytes "DDoS", so every download raised an alert. Here each host's
traffic is counted per second and compared with that host's own recent normal (an exponentially
weighted mean and variance). An alert needs all of:

- an absolute floor (`min_syn_rate` SYNs/s or `min_pps` UDP/ICMP packets/s), so quiet hosts don't
  alert on small bumps;
- a big jump over the host's baseline: at least `z` standard deviations and `ratio` times the mean
  (during the first `warmup_s` seconds of a host, the floor alone decides);
- for UDP/ICMP floods: the host answers almost none of it (`max_reply_ratio`). A download, a video
  call or a QUIC stream is two-way traffic, so it never qualifies, however fast it is.

TCP floods are measured by SYNs without ACK (half-open connections), not by packet size or count.
A burst of SYNs spread over many ports is a port scan, not a flood, and is left to the scan
detector (`max_flood_ports`).
Many distinct sources turn the alert into a DDoS. Needs packet-level capture (the Scapy backend);
with NFStream, flood detection is off (only finished flows are visible there).
"""

import math
from collections import OrderedDict
from dataclasses import dataclass

from nids.core.schemas.alert import AlertSource, Detection, Severity
from nids.sensor.detect.base import Emit
from nids.sensor.packets import ACK, SYN, TCP, PacketMeta


@dataclass(frozen=True)
class FloodConfig:
    min_syn_rate: float = 100.0
    min_pps: float = 5000.0
    z: float = 6.0
    ratio: float = 3.0
    warmup_s: int = 30
    alpha: float = 0.02  # EWMA weight: roughly the last 50 active seconds
    ddos_min_sources: int = 50
    max_reply_ratio: float = 0.05
    max_flood_ports: int = 10  # more distinct destination ports in one second = a scan
    max_sources_tracked: int = 4096
    max_hosts: int = 20_000
    host_idle_s: float = 600.0


class _Ewma:
    __slots__ = ("mean", "n", "var")

    def __init__(self) -> None:
        self.mean = self.var = 0.0
        self.n = 0

    def update(self, x: float, alpha: float) -> None:
        self.n += 1
        if self.n == 1:
            self.mean = x
            return
        diff = x - self.mean
        incr = alpha * diff
        self.mean += incr
        self.var = (1 - alpha) * (self.var + diff * incr)


class _Host:
    __slots__ = (
        "inbound",
        "last_active",
        "other",
        "outbound",
        "ports",
        "pps_base",
        "second",
        "sources",
        "syn",
        "syn_base",
    )

    def __init__(self, second: int) -> None:
        self.second = second
        self.inbound = self.outbound = self.syn = self.other = 0
        self.sources: set[str] = set()
        self.ports: set[int] = set()
        self.syn_base = _Ewma()
        self.pps_base = _Ewma()
        self.last_active = float(second)

    def reset(self, second: int) -> None:
        self.second = second
        self.inbound = self.outbound = self.syn = self.other = 0
        self.sources = set()
        self.ports = set()


class FloodDetector:
    def __init__(self, emit: Emit, config: FloodConfig | None = None) -> None:
        self.config = config or FloodConfig()
        self._emit = emit
        self._hosts: OrderedDict[str, _Host] = OrderedDict()

    def on_packet(self, pkt: PacketMeta) -> None:
        second = int(pkt.ts)
        dst = self._host(pkt.dst_ip, second)
        dst.inbound += 1
        if pkt.protocol == TCP:
            if pkt.tcp_flags & SYN and not pkt.tcp_flags & ACK:
                dst.syn += 1
                if len(dst.ports) <= self.config.max_flood_ports:
                    dst.ports.add(pkt.dst_port)
        else:
            dst.other += 1
        if len(dst.sources) < self.config.max_sources_tracked:
            dst.sources.add(pkt.src_ip)
        self._host(pkt.src_ip, second).outbound += 1

    def tick(self, now: float) -> None:
        current = int(now)
        for address, host in list(self._hosts.items()):
            if host.second < current:
                self._finish_second(address, host)
                host.reset(current)
            if now - host.last_active > self.config.host_idle_s:
                del self._hosts[address]

    def flush(self) -> None:
        for address, host in self._hosts.items():
            self._finish_second(address, host)
            host.reset(host.second + 1)

    def _host(self, address: str, second: int) -> _Host:
        host = self._hosts.get(address)
        if host is None:
            if len(self._hosts) >= self.config.max_hosts:
                self._hosts.popitem(last=False)
            host = self._hosts[address] = _Host(second)
        elif host.second != second:
            self._finish_second(address, host)
            host.reset(second)
        self._hosts.move_to_end(address)
        host.last_active = float(second)
        return host

    def _anomalous(self, base: _Ewma, value: float, floor: float) -> bool:
        c = self.config
        if value < floor:
            return False
        if base.n < c.warmup_s:
            return True
        return value >= base.mean + c.z * math.sqrt(base.var) and value >= c.ratio * base.mean

    def _finish_second(self, address: str, host: _Host) -> None:
        c = self.config
        if host.inbound == 0 and host.outbound == 0:
            return
        reply_ratio = host.outbound / host.inbound if host.inbound else 1.0
        scan_like = len(host.ports) > c.max_flood_ports
        syn_flood = not scan_like and self._anomalous(host.syn_base, host.syn, c.min_syn_rate)
        packet_flood = (
            not syn_flood
            and reply_ratio <= c.max_reply_ratio
            and self._anomalous(host.pps_base, host.other, c.min_pps)
        )
        if syn_flood:
            self._report(address, host, "SYNs", host.syn, host.syn_base, reply_ratio)
        elif packet_flood:
            self._report(address, host, "UDP/ICMP packets", host.other, host.pps_base, reply_ratio)
        # Learn only from normal seconds, so an ongoing flood doesn't become the new normal.
        if not syn_flood:
            host.syn_base.update(host.syn, c.alpha)
        if not packet_flood:
            host.pps_base.update(host.other, c.alpha)

    def _report(
        self, address: str, host: _Host, metric: str, rate: int, base: _Ewma, reply_ratio: float
    ) -> None:
        c = self.config
        sources = len(host.sources)
        distributed = sources >= c.ddos_min_sources
        kind = "ddos" if distributed else ("syn_flood" if metric == "SYNs" else "flood")
        baseline = round(base.mean, 1) if base.n >= c.warmup_s else None
        excess = (
            rate / max(base.mean, 1.0)
            if baseline is not None
            else rate / (c.min_syn_rate if metric == "SYNs" else c.min_pps)
        )
        self._emit(
            Detection(
                ts=float(host.second),
                type=kind,
                source=AlertSource.HEURISTIC,
                severity=Severity.CRITICAL if distributed else Severity.HIGH,
                confidence=min(1.0, 0.5 + 0.1 * excess),
                src=None if distributed else next(iter(host.sources), None),
                dst=address,
                evidence={
                    "metric": metric,
                    "rate": rate,
                    "baseline": baseline if baseline is not None else "not learned yet",
                    "distinct_sources": sources
                    if sources < c.max_sources_tracked
                    else f">={sources}",
                    "reply_ratio": round(reply_ratio, 3),
                    "second": host.second,
                },
            )
        )

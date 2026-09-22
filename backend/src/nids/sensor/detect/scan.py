"""Port scans and host sweeps (audit DET-01).

v1 flagged *every packet* to a common port (22, 53, 80, 443...) as a port scan, so every DNS
lookup and web request raised an alert. Here a scan is a behaviour over time:

- port scan: one source opens connections to many different ports (>= `min_ports`) of one host
  within `window_s` seconds;
- host sweep: one source contacts many different hosts (>= `min_hosts`) of the same subnet on
  the same service within `window_s`. Limiting it to one subnet keeps a browser that talks to
  dozens of CDN servers on 443 from looking like a worm.

Only connection *attempts* count: the first packet of a new flow (a TCP SYN without ACK, or a
new UDP/ICMP conversation). Multicast/broadcast destinations never count.
"""

from collections import OrderedDict
from dataclasses import dataclass

from nids.core.schemas.alert import AlertSource, Detection, Severity
from nids.core.schemas.flow import FlowRecord
from nids.sensor.detect.base import PROTOCOL_NAMES, Emit, is_unicast_target, subnet_of

Target = tuple[str, int, int]  # (dst ip, protocol, dst port)
Service = tuple[int, int, str]  # (protocol, port, subnet)


@dataclass(frozen=True)
class ScanConfig:
    window_s: float = 30.0
    min_ports: int = 25
    min_hosts: int = 20
    max_targets_per_source: int = 4096
    max_sources: int = 50_000


def service_name(protocol: int, port: int) -> str:
    name = PROTOCOL_NAMES.get(protocol, f"protocol {protocol}")
    return f"{name} port {port}" if protocol in (6, 17) else name


class _Source:
    __slots__ = ("attempts", "ended", "fired", "hosts_by_service", "ports_by_host", "unanswered")

    def __init__(self) -> None:
        self.attempts: OrderedDict[Target, float] = OrderedDict()
        self.ports_by_host: dict[str, set[tuple[int, int]]] = {}
        self.hosts_by_service: dict[Service, set[str]] = {}
        self.fired: dict[object, tuple[int, float]] = {}  # key -> (count, ts) at last detection
        self.ended = 0
        self.unanswered = 0

    def add(self, target: Target, ts: float) -> None:
        dst, proto, port = target
        if target in self.attempts:
            self.attempts.move_to_end(target)
        else:
            self.ports_by_host.setdefault(dst, set()).add((proto, port))
            self.hosts_by_service.setdefault((proto, port, subnet_of(dst)), set()).add(dst)
        self.attempts[target] = ts

    def prune(self, before: float, cap: int) -> None:
        while self.attempts:
            target, ts = next(iter(self.attempts.items()))
            if ts >= before and len(self.attempts) <= cap:
                break
            self.attempts.popitem(last=False)
            dst, proto, port = target
            ports = self.ports_by_host.get(dst)
            if ports is not None:
                ports.discard((proto, port))
                if not ports:
                    del self.ports_by_host[dst]
            service = (proto, port, subnet_of(dst))
            hosts = self.hosts_by_service.get(service)
            if hosts is not None:
                hosts.discard(dst)
                if not hosts:
                    del self.hosts_by_service[service]


class ScanDetector:
    def __init__(self, emit: Emit, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._emit = emit
        self._sources: OrderedDict[str, _Source] = OrderedDict()

    def on_attempt(
        self, ts: float, src: str, dst: str, protocol: int, port: int, flow_id: str
    ) -> None:
        if not is_unicast_target(dst):
            return
        state = self._sources.get(src)
        if state is None:
            if len(self._sources) >= self.config.max_sources:
                self._sources.popitem(last=False)
            state = self._sources[src] = _Source()
        else:
            self._sources.move_to_end(src)
        state.add((dst, protocol, port), ts)
        state.prune(ts - self.config.window_s, self.config.max_targets_per_source)

        ports = state.ports_by_host.get(dst, set())
        if len(ports) >= self.config.min_ports and self._should_fire(
            state, ("scan", dst), len(ports), ts
        ):
            self._emit_scan(ts, src, dst, ports, state, flow_id)

        service = (protocol, port, subnet_of(dst))
        hosts = state.hosts_by_service.get(service, set())
        if len(hosts) >= self.config.min_hosts and self._should_fire(
            state, service, len(hosts), ts
        ):
            self._emit_sweep(ts, src, service, hosts, state, flow_id)

    def on_flow_end(self, flow: FlowRecord) -> None:
        """Track how many of a source's connections went unanswered (evidence for scans)."""
        state = self._sources.get(flow.src_ip)
        if state is None:
            return
        state.ended += 1
        if flow.bwd.packets == 0 or flow.bwd.rst > 0:
            state.unanswered += 1

    def tick(self, now: float) -> None:
        before = now - self.config.window_s
        while self._sources:
            src, state = next(iter(self._sources.items()))
            last = next(reversed(state.attempts.values()), None) if state.attempts else None
            if last is not None and last >= before:
                break
            del self._sources[src]

    def _should_fire(self, state: _Source, key: object, count: int, ts: float) -> bool:
        previous = state.fired.get(key)
        if previous is None or count >= 2 * previous[0] or ts - previous[1] >= self.config.window_s:
            state.fired[key] = (count, ts)
            return True
        return False

    def _unanswered_ratio(self, state: _Source) -> float | None:
        return round(state.unanswered / state.ended, 3) if state.ended else None

    def _emit_scan(
        self,
        ts: float,
        src: str,
        dst: str,
        ports: set[tuple[int, int]],
        state: _Source,
        flow_id: str,
    ) -> None:
        count = len(ports)
        port_numbers = sorted(p for _, p in ports)
        confidence = min(1.0, 0.6 + 0.4 * count / (4 * self.config.min_ports))
        self._emit(
            Detection(
                ts=ts,
                type="port_scan",
                source=AlertSource.HEURISTIC,
                severity=Severity.HIGH if count >= 8 * self.config.min_ports else Severity.MEDIUM,
                confidence=confidence,
                src=src,
                dst=dst,
                ports=tuple(port_numbers[:50]),
                evidence={
                    "distinct_ports": count,
                    "window_s": self.config.window_s,
                    "sample_ports": port_numbers[:20],
                    "protocols": sorted({PROTOCOL_NAMES.get(p, str(p)) for p, _ in ports}),
                    "unanswered_ratio": self._unanswered_ratio(state),
                },
                flow_ids=(flow_id,),
            )
        )

    def _emit_sweep(
        self, ts: float, src: str, service: Service, hosts: set[str], state: _Source, flow_id: str
    ) -> None:
        protocol, port, subnet = service
        count = len(hosts)
        self._emit(
            Detection(
                ts=ts,
                type="host_sweep",
                source=AlertSource.HEURISTIC,
                severity=Severity.MEDIUM,
                confidence=min(1.0, 0.6 + 0.4 * count / (4 * self.config.min_hosts)),
                src=src,
                dst=subnet,
                ports=(port,) if protocol in (6, 17) else (),
                protocol=protocol,
                evidence={
                    "distinct_hosts": count,
                    "service": service_name(protocol, port),
                    "subnet": subnet,
                    "window_s": self.config.window_s,
                    "sample_hosts": sorted(hosts)[:10],
                    "unanswered_ratio": self._unanswered_ratio(state),
                },
                flow_ids=(flow_id,),
            )
        )

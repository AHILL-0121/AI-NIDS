"""The sensor pipeline: capture source -> flow table -> detection engine -> storage.

`Pipeline` is the PacketObserver a capture source feeds, the sink for finished flows, and the
sink for alerts. It keeps per-second traffic counters (audit CAP-07), writes flows, alerts and
traffic to the database, and periodically pulls analyst decisions back in (suppression rules and
alert statuses set through the API), since the API and the sensor are separate processes.
"""

import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from nids.core.schemas.alert import Alert, AlertStatus
from nids.core.schemas.flow import FlowRecord
from nids.sensor.detect import DetectionEngine
from nids.sensor.packets import PacketMeta
from nids.store import repo
from nids.store.db import Database
from nids.store.models import Traffic

log = logging.getLogger(__name__)

SYNC_EVERY_S = 30.0


@dataclass
class _Second:
    packets: int = 0
    bytes: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    other: int = 0
    flows_started: int = 0
    flows_ended: int = 0
    alerts: int = 0

    def count_protocol(self, protocol: int, n: int = 1) -> None:
        if protocol == 6:
            self.tcp += n
        elif protocol == 17:
            self.udp += n
        elif protocol in (1, 58):
            self.icmp += n
        else:
            self.other += n


@dataclass
class Pipeline:
    engine: DetectionEngine
    db: Database | None = None
    session_id: str | None = None
    flow_sample_rate: float = 1.0
    pseudonymizer: repo.Pseudonymizer | None = None
    extra_flow_sinks: list[Callable[[FlowRecord], None]] = field(default_factory=list)
    alert_listeners: list[Callable[[Alert, bool], None]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.alerts: dict[str, Alert] = {}
        self._seconds: dict[int, _Second] = {}
        self._packet_level = False
        self._last_sync = 0.0
        self.written: Counter[str] = Counter()
        self.flow_writer = (
            repo.FlowWriter(
                self.db, self.session_id, self.flow_sample_rate, pseudonymizer=self.pseudonymizer
            )
            if self.db is not None and self.session_id is not None
            else None
        )
        self.engine.correlator.sink = self.on_alert
        if self.db is not None:
            self.engine.correlator.replace_rules(repo.load_suppression_rules(self.db))

    # --- alert sink (the engine's correlator calls this) ---

    def on_alert(self, alert: Alert, is_new: bool) -> None:
        self.alerts[alert.id] = alert
        if is_new:
            self._second(alert.last_seen).alerts += 1
        if self.flow_writer is not None:
            self.flow_writer.keep(alert.flow_ids)
        if self.db is not None:
            repo.upsert_alert(self.db, alert, self.session_id, self.pseudonymizer)
            self.written["alerts"] += 1
        for listener in self.alert_listeners:
            listener(alert, is_new)

    # --- PacketObserver ---

    def on_packet(self, pkt: PacketMeta) -> None:
        self._packet_level = True
        bucket = self._second(pkt.ts)
        bucket.packets += 1
        bucket.bytes += pkt.length
        bucket.count_protocol(pkt.protocol)
        self.engine.on_packet(pkt)

    def on_new_flow(self, pkt: PacketMeta, flow_id: str) -> None:
        self._second(pkt.ts).flows_started += 1
        self.engine.on_new_flow(pkt, flow_id)

    def tick(self, now: float) -> None:
        self.engine.tick(now)
        self._write_traffic(before=int(now))
        if self.flow_writer is not None:
            self.flow_writer.flush()
        if self.db is not None and time.monotonic() - self._last_sync >= SYNC_EVERY_S:
            self._sync_from_db()

    def flush(self) -> None:
        self.engine.flush()
        self._write_traffic(before=None)
        if self.flow_writer is not None:
            self.flow_writer.flush()

    # --- flow sink ---

    def on_flow(self, flow: FlowRecord) -> None:
        bucket = self._second(flow.last_seen)
        bucket.flows_ended += 1
        if not self._packet_level:  # NFStream: count traffic from finished flows
            start = self._second(flow.first_seen)
            start.flows_started += 1
            start.packets += flow.packets
            start.bytes += flow.ip_bytes if flow.ip_bytes is not None else flow.payload_bytes
            start.count_protocol(flow.protocol, flow.packets)
        for sink in self.extra_flow_sinks:
            sink(flow)
        if self.flow_writer is not None:
            self.flow_writer.add(flow)
        self.engine.on_flow(flow)

    # --- internals ---

    def _second(self, ts: float) -> _Second:
        second = int(ts)
        bucket = self._seconds.get(second)
        if bucket is None:
            bucket = self._seconds[second] = _Second()
        return bucket

    def _write_traffic(self, before: int | None) -> None:
        done = sorted(s for s in self._seconds if before is None or s < before)
        if not done:
            return
        buckets = {s: self._seconds.pop(s) for s in done}
        if self.db is None or self.session_id is None:
            return
        with self.db.session() as s:
            for second, c in buckets.items():
                key = {"resolution": 1, "ts": second, "session_id": self.session_id}
                row = s.get(Traffic, key)
                values = c.__dict__
                if row is None:
                    s.add(Traffic(**key, **values))
                else:
                    for name, value in values.items():
                        setattr(row, name, getattr(row, name) + value)
        self.written["traffic_seconds"] += len(buckets)

    def _sync_from_db(self) -> None:
        """Pick up analyst decisions made through the API since the last sync."""
        assert self.db is not None
        self._last_sync = time.monotonic()
        self.engine.correlator.replace_rules(repo.load_suppression_rules(self.db))
        statuses = repo.alert_statuses(self.db, self.engine.correlator.open_alert_ids())
        self.engine.correlator.sync_statuses({k: AlertStatus(v) for k, v in statuses.items()})

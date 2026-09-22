"""Scapy capture backends: PCAP replay (any OS) and live capture (the Windows fallback)."""

import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any, Literal

from nids.sensor.capture.base import CaptureError, FlowSink
from nids.sensor.flows import FlowTable, FlowTableConfig
from nids.sensor.packets import load_protocol_layers, parse_packet

log = logging.getLogger(__name__)

EXPIRE_EVERY = 1.0  # seconds between timeout sweeps


class _Counters:
    def __init__(self) -> None:
        self.packets_seen = 0
        self.packets_non_ip = 0
        self.packets_malformed = 0
        self.packets_dropped = 0


def _metrics(counters: _Counters, table: FlowTable | None) -> dict[str, int | float]:
    data: dict[str, int | float] = {
        "packets_seen": counters.packets_seen,
        "packets_non_ip": counters.packets_non_ip,
        "packets_malformed": counters.packets_malformed,
        "packets_dropped": counters.packets_dropped,
    }
    if table is not None:
        data["flows_open"] = len(table)
        data["flows_created"] = table.stats.flows_created
        for reason, count in table.stats.flows_emitted.items():
            data[f"flows_ended_{reason}"] = count
    return data


def _feed(table: FlowTable, counters: _Counters, packet: Any) -> float | None:
    """Parse one packet into the table. Returns its timestamp, or None if it was skipped."""
    counters.packets_seen += 1
    try:
        meta = parse_packet(packet)
    except Exception:  # Scapy can raise on truncated or odd packets
        counters.packets_malformed += 1
        return None
    if meta is None:
        counters.packets_non_ip += 1
        return None
    table.add(meta)
    return meta.ts


class PcapReplaySource:
    """Stream a pcap/pcapng file through the flow table.

    speed="max" processes as fast as possible; "realtime" sleeps to match the original packet
    timing (for demos). Streams with PcapReader instead of loading the file (audit CAP-09).
    """

    name = "pcap"

    def __init__(
        self,
        path: str | Path,
        config: FlowTableConfig | None = None,
        speed: Literal["max", "realtime"] = "max",
    ) -> None:
        self.path = Path(path)
        self.config = config or FlowTableConfig()
        self.speed = speed
        self._counters = _Counters()
        self._table: FlowTable | None = None

    def metrics(self) -> dict[str, int | float]:
        return _metrics(self._counters, self._table)

    def run(self, emit: FlowSink, stop: threading.Event) -> None:
        from scapy.utils import PcapReader

        load_protocol_layers()
        if not self.path.is_file():
            raise CaptureError(f"PCAP file not found: {self.path}")
        table = self._table = FlowTable(emit, self.config)
        last_sweep: float | None = None
        previous_ts: float | None = None
        try:
            reader = PcapReader(str(self.path))
        except Exception as exc:
            raise CaptureError(f"Can't read {self.path} as pcap/pcapng: {exc}") from exc

        with reader:
            for packet in reader:
                if stop.is_set():
                    break
                if self.speed == "realtime" and previous_ts is not None:
                    delay = float(packet.time) - previous_ts
                    if delay > 0 and stop.wait(delay):
                        break
                previous_ts = float(packet.time)

                ts = _feed(table, self._counters, packet)
                if ts is None:
                    continue
                if last_sweep is None:
                    last_sweep = ts
                elif ts - last_sweep >= EXPIRE_EVERY:
                    table.expire(ts)
                    last_sweep = ts
        table.flush()
        log.info("Replay of %s finished: %s", self.path.name, self.metrics())


class LiveScapySource:
    """Live capture with Scapy's AsyncSniffer. Needs Npcap (Windows) or libpcap + privileges.

    The sniffer thread only enqueues packets; parsing and flow tracking happen in `run`'s thread.
    When the queue is full, packets are dropped and counted rather than logged one by one
    (audit CAP-06).
    """

    name = "scapy"
    START_TIMEOUT = 5.0  # seconds to wait for the sniffer thread to come up

    def __init__(
        self,
        interface: str,
        config: FlowTableConfig | None = None,
        bpf_filter: str | None = None,
        queue_size: int = 50_000,
    ) -> None:
        self.interface = interface
        self.config = config or FlowTableConfig()
        self.bpf_filter = bpf_filter
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=queue_size)
        self._counters = _Counters()
        self._table: FlowTable | None = None

    def metrics(self) -> dict[str, int | float]:
        data = _metrics(self._counters, self._table)
        data["queue_depth"] = self._queue.qsize()
        return data

    def _enqueue(self, packet: Any) -> None:
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            self._counters.packets_dropped += 1

    def run(self, emit: FlowSink, stop: threading.Event) -> None:
        from scapy.sendrecv import AsyncSniffer

        load_protocol_layers()
        table = self._table = FlowTable(emit, self.config)
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._enqueue,
            store=False,
            filter=self.bpf_filter,
            started_callback=started.set,
        )
        sniffer.start()
        if not started.wait(timeout=self.START_TIMEOUT):
            self._join_quietly(sniffer)
            raise CaptureError(self._describe_failure(sniffer.exception))
        log.info("Live capture started on %s", self.interface)

        last_sweep = time.time()
        try:
            while not stop.is_set():
                if sniffer.exception is not None:
                    raise CaptureError(self._describe_failure(sniffer.exception))
                try:
                    packet = self._queue.get(timeout=0.25)
                except queue.Empty:
                    packet = None
                if packet is not None:
                    _feed(table, self._counters, packet)
                now = time.time()
                if now - last_sweep >= EXPIRE_EVERY:
                    table.expire(now)
                    last_sweep = now
        finally:
            if sniffer.running:
                try:
                    sniffer.stop(join=True)
                except Exception:
                    log.exception("Error while stopping the sniffer")
            while not self._queue.empty():
                _feed(table, self._counters, self._queue.get_nowait())
            table.flush()
            log.info("Live capture on %s stopped: %s", self.interface, self.metrics())

    @staticmethod
    def _join_quietly(sniffer: Any) -> None:
        try:
            sniffer.join(timeout=2)
        except Exception:  # the failure is reported from sniffer.exception instead
            log.debug("Sniffer thread ended with an error", exc_info=True)

    def _describe_failure(self, exc: BaseException | None) -> str:
        detail = (
            f"{type(exc).__name__}: {exc}"
            if exc
            else f"the sniffer did not start within {self.START_TIMEOUT:g} s"
        )
        return (
            f"Capture on '{self.interface}' failed ({detail}). "
            "Run `nids doctor` to check the capture driver, privileges and interface name."
        )

"""Pick a capture backend and run it until stopped."""

import json
import logging
import platform
import threading
from pathlib import Path
from typing import IO, Literal

from nids.core.schemas.flow import FlowRecord
from nids.sensor.capture import (
    FlowSink,
    FlowSource,
    LiveScapySource,
    NfstreamSource,
    PcapReplaySource,
    nfstream_available,
)
from nids.sensor.detect.base import PacketObserver
from nids.sensor.flows import FlowTableConfig

log = logging.getLogger(__name__)

Backend = Literal["auto", "nfstream", "scapy"]


def build_live_source(
    interface: str,
    backend: Backend = "auto",
    config: FlowTableConfig | None = None,
    bpf_filter: str | None = None,
    observer: PacketObserver | None = None,
) -> FlowSource:
    if backend == "auto":
        use_nfstream = platform.system() == "Linux" and nfstream_available()
        backend = "nfstream" if use_nfstream else "scapy"
    if backend == "nfstream":
        return NfstreamSource(interface, config, bpf_filter, observer=observer)
    return LiveScapySource(interface, config, bpf_filter, observer=observer)


def build_replay_source(
    pcap: str | Path,
    backend: Literal["nfstream", "scapy"] = "scapy",
    config: FlowTableConfig | None = None,
    speed: Literal["max", "realtime"] = "max",
    observer: PacketObserver | None = None,
    shift_to_now: bool = False,
) -> FlowSource:
    if backend == "nfstream":
        if shift_to_now:
            raise ValueError("Shifting timestamps to now needs the scapy replay backend.")
        return NfstreamSource(pcap, config, observer=observer)
    return PcapReplaySource(pcap, config, speed, observer=observer, shift_to_now=shift_to_now)


class JsonlSink:
    """Write one JSON object per flow. Thread-safe."""

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self.count = 0

    def __call__(self, record: FlowRecord) -> None:
        line = json.dumps(record.to_dict(), separators=(",", ":"))
        with self._lock:
            self._stream.write(line + "\n")
            self.count += 1


def run_in_background(
    source: FlowSource, sink: FlowSink
) -> tuple[threading.Thread, threading.Event, list[BaseException]]:
    """Start `source` on a worker thread. Set the returned event to stop it.

    Errors raised by the source are collected in the returned list, so the caller's thread
    (e.g. the CLI, which needs to handle Ctrl+C) can report them after joining.
    """
    stop = threading.Event()
    errors: list[BaseException] = []

    def target() -> None:
        try:
            source.run(sink, stop)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=target, name=f"capture-{source.name}", daemon=True)
    thread.start()
    return thread, stop, errors

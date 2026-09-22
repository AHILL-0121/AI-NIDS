import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from scapy.utils import wrpcapng

from nids.core.schemas.flow import EndReason, FlowRecord
from nids.sensor.capture import CaptureError, LiveScapySource, PcapReplaySource
from nids.sensor.capture.nfstream_source import flow_from_nfstream

from .helpers import CLIENT, SERVER, dns_exchange, tcp_session


def replay(
    path: Path, stop: threading.Event | None = None
) -> tuple[list[FlowRecord], PcapReplaySource]:
    flows: list[FlowRecord] = []
    source = PcapReplaySource(path)
    source.run(flows.append, stop or threading.Event())
    return flows, source


def test_replay_builds_expected_flows(sample_pcap: Path) -> None:
    flows, source = replay(sample_pcap)

    by_proto = {(f.protocol, f.dst_port): f for f in flows}
    web = by_proto[(6, 80)]
    assert (web.src_ip, web.dst_ip) == (CLIENT, SERVER)
    assert (web.fwd.packets, web.bwd.packets) == (6, 3)
    assert web.end_reason is EndReason.TCP_FIN
    assert web.bwd.payload_bytes == 500

    dns = by_proto[(17, 53)]
    assert (dns.fwd.packets, dns.bwd.packets) == (1, 1)

    assert len(flows) == 4  # TCP, DNS, IPv6 mDNS, ICMP
    metrics = source.metrics()
    assert metrics["packets_seen"] == 14
    assert metrics["packets_non_ip"] == 1  # the ARP packet


def test_replay_is_deterministic(sample_pcap: Path) -> None:
    first, _ = replay(sample_pcap)
    second, _ = replay(sample_pcap)

    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]


def test_replay_reads_pcapng(tmp_path: Path) -> None:
    path = tmp_path / "sample.pcapng"
    wrpcapng(str(path), tcp_session() + dns_exchange())

    flows, _ = replay(path)

    assert len(flows) == 2


def test_replay_stops_when_asked(sample_pcap: Path) -> None:
    stop = threading.Event()
    stop.set()

    flows, source = replay(sample_pcap, stop)

    assert flows == [] and source.metrics()["packets_seen"] == 0


def test_replay_reports_missing_and_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(CaptureError, match="not found"):
        replay(tmp_path / "missing.pcap")
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"definitely not a pcap")
    with pytest.raises(CaptureError, match="pcap"):
        replay(bad)


class FakeSniffer:
    """Stands in for scapy's AsyncSniffer: feeds packets to `prn` from its own thread."""

    packets: ClassVar[list[Any]] = []
    fail_with: Exception | None = None

    def __init__(self, prn: Any, started_callback: Any, **_: Any) -> None:
        self.prn, self.started_callback = prn, started_callback
        self.running = False
        self.exception: Exception | None = None
        self._halt = threading.Event()

    def start(self) -> None:
        def run() -> None:
            if self.fail_with is not None:
                self.exception = self.fail_with
                return
            self.running = True
            self.started_callback()
            for p in self.packets:
                self.prn(p)
            self._halt.wait()
            self.running = False

        threading.Thread(target=run, daemon=True).start()

    def stop(self, join: bool = True) -> None:
        self._halt.set()

    def join(self, timeout: float | None = None) -> None:
        pass


@pytest.fixture
def fake_sniffer(monkeypatch: pytest.MonkeyPatch) -> type[FakeSniffer]:
    import scapy.sendrecv

    FakeSniffer.packets = tcp_session(t0=time.time()) + dns_exchange(t0=time.time())
    FakeSniffer.fail_with = None
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", FakeSniffer)
    return FakeSniffer


def test_live_source_flushes_open_flows_on_stop(fake_sniffer: type[FakeSniffer]) -> None:
    flows: list[FlowRecord] = []
    stop = threading.Event()
    source = LiveScapySource("eth-test")
    worker = threading.Thread(target=source.run, args=(flows.append, stop))
    worker.start()
    deadline = time.time() + 5
    while source.metrics()["packets_seen"] < len(fake_sniffer.packets) and time.time() < deadline:
        time.sleep(0.02)

    stop.set()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert sorted(f.protocol for f in flows) == [6, 17]


def test_live_source_reports_capture_failure(
    fake_sniffer: type[FakeSniffer], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_sniffer.fail_with = PermissionError("Operation not permitted")
    monkeypatch.setattr(LiveScapySource, "START_TIMEOUT", 0.2)

    with pytest.raises(CaptureError, match="Operation not permitted"):
        LiveScapySource("eth-test").run(lambda _: None, threading.Event())


def test_live_source_drops_when_queue_is_full() -> None:
    source = LiveScapySource("eth-test", queue_size=1)
    source._enqueue(object())
    source._enqueue(object())

    assert source.metrics()["packets_dropped"] == 1


def _nf_flow(**overrides: Any) -> SimpleNamespace:
    fields: dict[str, Any] = {
        "id": 7,
        "src_ip": CLIENT,
        "dst_ip": SERVER,
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 6,
        "ip_version": 4,
        "bidirectional_first_seen_ms": 1_000_000,
        "bidirectional_last_seen_ms": 1_002_500,
        "bidirectional_mean_piat_ms": 250.0,
        "bidirectional_stddev_piat_ms": 10.0,
        "bidirectional_min_piat_ms": 5.0,
        "bidirectional_max_piat_ms": 900.0,
        "expiration_id": 0,
        "application_name": "TLS.Google",
    }
    for d, packets in (("src2dst", 6), ("dst2src", 4)):
        fields |= {
            f"{d}_packets": packets,
            f"{d}_bytes": packets * 100,
            f"{d}_min_ps": 40,
            f"{d}_max_ps": 1500,
            f"{d}_mean_ps": 100.0,
            f"{d}_stddev_ps": 3.0,
            f"{d}_mean_piat_ms": 400.0,
            f"{d}_stddev_piat_ms": 20.0,
            f"{d}_min_piat_ms": 1.0,
            f"{d}_max_piat_ms": 800.0,
            f"{d}_syn_packets": 1,
            f"{d}_fin_packets": 1,
            f"{d}_rst_packets": 0,
            f"{d}_psh_packets": 2,
            f"{d}_ack_packets": packets - 1,
            f"{d}_urg_packets": 0,
        }
    return SimpleNamespace(**(fields | overrides))


def test_nfstream_flow_maps_to_flow_record() -> None:
    record = flow_from_nfstream(_nf_flow())

    assert record.flow_id == "nfs-7"
    assert record.duration == pytest.approx(2.5)  # milliseconds converted to seconds
    assert record.iat_max == pytest.approx(0.9)
    assert (record.fwd.packets, record.bwd.payload_bytes) == (6, 400)
    assert record.fwd.ip_bytes is None  # NFStream runs in payload accounting mode
    assert record.fwd.iat_mean == pytest.approx(0.4) and record.fwd.iat_max == pytest.approx(0.8)
    assert record.end_reason is EndReason.IDLE_TIMEOUT
    assert record.app_protocol == "TLS.Google"


@pytest.mark.parametrize(
    ("expiration_id", "reason"),
    [(1, EndReason.ACTIVE_TIMEOUT), (-1, EndReason.FLUSH)],
)
def test_nfstream_expiration_codes(expiration_id: int, reason: EndReason) -> None:
    record = flow_from_nfstream(_nf_flow(expiration_id=expiration_id, application_name="Unknown"))

    assert record.end_reason is reason and record.app_protocol is None

"""NFStream capture backend (Linux). NFStream assembles flows in C (libpcap + nDPI).

Sizes use `accounting_mode=3` (transport payload), matching CICFlowMeter and the Scapy flow table's
payload statistics. NFStream can't also report IP-level sizes in the same pass, so `ip_bytes` and
`ip_len_mean` are None for these flows.
"""

import logging
import threading
from pathlib import Path
from typing import Any

from nids.core.schemas.flow import DirectionStats, EndReason, FlowRecord
from nids.sensor.capture.base import CaptureError, FlowSink
from nids.sensor.flows import FlowTableConfig

log = logging.getLogger(__name__)

_EXPIRATION = {0: EndReason.IDLE_TIMEOUT, 1: EndReason.ACTIVE_TIMEOUT}


def nfstream_available() -> bool:
    try:
        import nfstream  # noqa: F401
    except ImportError:
        return False
    return True


def _direction(f: Any, prefix: str) -> DirectionStats:
    def g(name: str) -> Any:
        return getattr(f, f"{prefix}_{name}")

    return DirectionStats(
        packets=int(g("packets")),
        payload_bytes=int(g("bytes")),
        payload_len_min=float(g("min_ps")),
        payload_len_max=float(g("max_ps")),
        payload_len_mean=float(g("mean_ps")),
        payload_len_std=float(g("stddev_ps")),
        iat_mean=float(g("mean_piat_ms")) / 1000.0,
        iat_std=float(g("stddev_piat_ms")) / 1000.0,
        iat_min=float(g("min_piat_ms")) / 1000.0,
        iat_max=float(g("max_piat_ms")) / 1000.0,
        syn=int(g("syn_packets")),
        fin=int(g("fin_packets")),
        rst=int(g("rst_packets")),
        psh=int(g("psh_packets")),
        ack=int(g("ack_packets")),
        urg=int(g("urg_packets")),
    )


def flow_from_nfstream(f: Any) -> FlowRecord:
    """Map an NFStream NFlow (created with statistical_analysis=True) to a FlowRecord."""
    app = getattr(f, "application_name", None) or None
    return FlowRecord(
        flow_id=f"nfs-{f.id}",
        src_ip=str(f.src_ip),
        dst_ip=str(f.dst_ip),
        src_port=int(f.src_port),
        dst_port=int(f.dst_port),
        protocol=int(f.protocol),
        ip_version=int(f.ip_version),
        first_seen=f.bidirectional_first_seen_ms / 1000.0,
        last_seen=f.bidirectional_last_seen_ms / 1000.0,
        iat_mean=f.bidirectional_mean_piat_ms / 1000.0,
        iat_std=f.bidirectional_stddev_piat_ms / 1000.0,
        iat_min=f.bidirectional_min_piat_ms / 1000.0,
        iat_max=f.bidirectional_max_piat_ms / 1000.0,
        fwd=_direction(f, "src2dst"),
        bwd=_direction(f, "dst2src"),
        end_reason=_EXPIRATION.get(int(f.expiration_id), EndReason.FLUSH),
        app_protocol=app if app != "Unknown" else None,
    )


class NfstreamSource:
    """Live interface or PCAP file through NFStream.

    NFStream's iterator blocks until its next flow is ready, so a stop request takes effect when
    the next flow arrives (at most `idle_timeout` seconds on a quiet interface).
    """

    name = "nfstream"

    def __init__(
        self,
        source: str | Path,
        config: FlowTableConfig | None = None,
        bpf_filter: str | None = None,
    ) -> None:
        self.source = str(source)
        self.config = config or FlowTableConfig()
        self.bpf_filter = bpf_filter
        self._flows = 0

    def metrics(self) -> dict[str, int | float]:
        return {"flows_created": self._flows}

    def run(self, emit: FlowSink, stop: threading.Event) -> None:
        try:
            from nfstream import NFStreamer
        except ImportError as exc:
            raise CaptureError(
                "NFStream is not installed. On Linux: `uv sync --extra capture`. "
                "Elsewhere, use the scapy backend."
            ) from exc

        try:
            streamer = NFStreamer(
                source=self.source,
                bpf_filter=self.bpf_filter,
                idle_timeout=max(1, round(self.config.idle_timeout)),
                active_timeout=max(1, round(self.config.active_timeout)),
                accounting_mode=3,  # payload sizes, as in CICFlowMeter
                statistical_analysis=True,
                n_dissections=20,
            )
            for flow in streamer:
                emit(flow_from_nfstream(flow))
                self._flows += 1
                if stop.is_set():
                    break
        except CaptureError:
            raise
        except Exception as exc:
            raise CaptureError(
                f"NFStream failed on '{self.source}' ({type(exc).__name__}: {exc}). "
                "Run `nids doctor`."
            ) from exc

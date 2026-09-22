"""Capture backends. Each one turns packets (live or from a PCAP) into FlowRecords."""

from nids.sensor.capture.base import CaptureError, FlowSink, FlowSource
from nids.sensor.capture.nfstream_source import NfstreamSource, nfstream_available
from nids.sensor.capture.scapy_source import LiveScapySource, PcapReplaySource

__all__ = [
    "CaptureError",
    "FlowSink",
    "FlowSource",
    "LiveScapySource",
    "NfstreamSource",
    "PcapReplaySource",
    "nfstream_available",
]

"""Detection: heuristics (scans, sweeps, floods, unusual protocols), the ML model, and the
correlator that turns detections into alerts (Phase 3)."""

from nids.sensor.detect.base import PacketObserver
from nids.sensor.detect.correlator import AlertCorrelator, SuppressionRule
from nids.sensor.detect.engine import DetectionConfig, DetectionEngine

__all__ = [
    "AlertCorrelator",
    "DetectionConfig",
    "DetectionEngine",
    "PacketObserver",
    "SuppressionRule",
]

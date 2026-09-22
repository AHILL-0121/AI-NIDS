"""Run the trained model (Phase 2 bundle) on finished flows; turn its verdicts into detections."""

from typing import Any

from nids.core.schemas.alert import AlertSource, Detection, Severity
from nids.core.schemas.features_v1 import features_from_flow
from nids.core.schemas.flow import FlowRecord
from nids.sensor.detect.base import Emit
from nids.sensor.detect.knowledge import ML_FAMILIES

_FAMILY_SEVERITY = {
    "ddos": Severity.CRITICAL,
    "dos": Severity.HIGH,
    "brute_force": Severity.HIGH,
    "web_attack": Severity.HIGH,
    "botnet": Severity.HIGH,
    "infiltration": Severity.HIGH,
    "exploit": Severity.HIGH,
    "recon": Severity.MEDIUM,
}


class MlDetector:
    """Scores flows in batches (scoring one flow at a time costs a DataFrame per flow)."""

    def __init__(self, bundle: Any, model_version: str, emit: Emit, batch_size: int = 256) -> None:
        self.bundle = bundle
        self.model_version = model_version
        self._emit = emit
        self.batch_size = batch_size
        self._pending: list[FlowRecord] = []
        self.scored = 0

    def on_flow(self, flow: FlowRecord) -> None:
        self._pending.append(flow)
        if len(self._pending) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._pending:
            return
        import pandas as pd  # the ml extra is only needed when a model is loaded

        flows, self._pending = self._pending, []
        frame = pd.DataFrame([features_from_flow(f) for f in flows])
        scores = self.bundle.score(frame)
        self.scored += len(flows)
        alerting = scores["alert"].to_numpy()
        reasons = (
            self.bundle.novelty_reasons(frame[alerting])
            if alerting.any() and hasattr(self.bundle, "novelty_reasons")
            else []
        )
        reason_iter = iter(reasons)
        for flow, row in zip(flows, scores.itertuples(index=False), strict=True):
            if row.alert:
                self._emit(self._detection(flow, row, next(reason_iter, [])))

    def _detection(self, flow: FlowRecord, row: Any, unusual: list[str]) -> Detection:
        known = row.attack_prob >= self.bundle.attack_threshold and row.family != "benign"
        family = str(row.family) if known else None
        if known:
            severity = _FAMILY_SEVERITY.get(family or "", Severity.MEDIUM)
            confidence = float(row.attack_prob)
        else:
            severity = Severity.MEDIUM if row.novelty >= 0.999 else Severity.LOW
            confidence = float(row.novelty)
        return Detection(
            ts=flow.last_seen,
            type="ml_known_attack" if known else "ml_anomaly",
            source=AlertSource.ML,
            severity=severity,
            confidence=confidence,
            src=flow.src_ip,
            dst=flow.dst_ip,
            ports=(flow.dst_port,) if flow.protocol in (6, 17) else (),
            protocol=flow.protocol,
            flow_ids=(flow.flow_id,),
            family=family,
            model_version=self.model_version,
            evidence={
                "attack_prob": round(float(row.attack_prob), 3),
                "novelty": round(float(row.novelty), 4),
                "novelty_pct": f"{float(row.novelty):.1%}",
                "family_label": ML_FAMILIES.get(family, (family, None))[0] if family else None,
                "duration_s": round(flow.duration, 3),
                "packets": flow.packets,
                "payload_bytes": flow.payload_bytes,
                "dst_port": flow.dst_port,
                "most_unusual_features": unusual,
            },
        )

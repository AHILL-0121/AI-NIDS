"""Alerts: what the analyst sees (audit DET-05).

A detector produces a `Detection` (one observation). The correlator folds repeated detections of
the same thing (same type, source and destination) into one `Alert` whose `occurrences` and
`last_seen` grow, instead of dropping them or flooding the list (audit DET-04).
"""

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class AlertSource(StrEnum):
    HEURISTIC = "heuristic"
    ML = "ml"


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True, slots=True)
class Detection:
    ts: float
    type: str  # e.g. "port_scan", "syn_flood", "ml_known_attack"
    source: AlertSource
    severity: Severity
    confidence: float  # 0..1
    src: str | None
    dst: str | None
    evidence: dict[str, Any]
    ports: tuple[int, ...] = ()
    protocol: int | None = None
    flow_ids: tuple[str, ...] = ()
    family: str | None = None  # ML: predicted attack family
    model_version: str | None = None


@dataclass(slots=True)
class Alert:
    id: str
    created_at: float
    last_seen: float
    type: str
    title: str
    source: AlertSource
    severity: Severity
    confidence: float
    src: str | None
    dst: str | None
    ports: list[int]
    protocol: int | None
    mitre_technique: str | None
    explanation: str
    recommendation: str
    evidence: dict[str, Any]
    occurrences: int = 1
    flow_ids: list[str] = field(default_factory=list)
    family: str | None = None
    model_version: str | None = None
    status: AlertStatus = AlertStatus.NEW
    note: str = ""

    @staticmethod
    def new_id() -> str:
        return f"A-{uuid.uuid4().hex[:10]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "type": self.type,
            "title": self.title,
            "source": self.source.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "src": self.src,
            "dst": self.dst,
            "ports": self.ports,
            "protocol": self.protocol,
            "mitre_technique": self.mitre_technique,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "occurrences": self.occurrences,
            "flow_ids": self.flow_ids,
            "family": self.family,
            "model_version": self.model_version,
            "status": self.status.value,
            "note": self.note,
        }

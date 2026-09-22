"""Fold detections into alerts, and apply analyst suppressions (audit DET-04, DET-05).

v1 had one cooldown per alert *type*: after one port-scan alert, every other attacker's scan was
silently dropped for 60 s. Here the key is (type, src, dst): a repeat of the same thing updates the
open alert (occurrences, last_seen, strongest evidence), and a different source is a new alert.
"""

import ipaddress
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from nids.core.schemas.alert import Alert, AlertStatus, Detection, Severity
from nids.sensor.detect.knowledge import describe

AlertSink = Callable[[Alert, bool], None]  # (alert, is_new)


@dataclass(frozen=True)
class SuppressionRule:
    """Drop matching detections, e.g. after an analyst marks an alert as a false positive.
    Fields left as None match anything; `src`/`dst` may be an address or a CIDR range."""

    type: str | None = None
    src: str | None = None
    dst: str | None = None
    dst_port: int | None = None
    until: float | None = None  # epoch seconds; None = no expiry
    reason: str = ""

    def matches(self, d: Detection) -> bool:
        if self.until is not None and d.ts > self.until:
            return False
        if self.type is not None and d.type != self.type:
            return False
        if self.dst_port is not None and self.dst_port not in d.ports:
            return False
        return _in(d.src, self.src) and _in(d.dst, self.dst)


def _in(address: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if address is None:
        return False
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return address == pattern


class AlertCorrelator:
    def __init__(
        self, sink: AlertSink, dedup_window: float = 900.0, max_flow_ids: int = 50
    ) -> None:
        self._sink = sink
        self.dedup_window = dedup_window
        self.max_flow_ids = max_flow_ids
        self._open: dict[tuple[str, str | None, str | None], Alert] = {}
        self._rules: list[SuppressionRule] = []
        self._lock = threading.Lock()
        self.suppressed: Counter[str] = Counter()  # per type, for the evaluation log

    def add_rule(self, rule: SuppressionRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def mark_false_positive(self, alert: Alert, until: float | None = None) -> SuppressionRule:
        """Record the analyst's verdict and stop the same (type, src, dst) from alerting again."""
        alert.status = AlertStatus.FALSE_POSITIVE
        rule = SuppressionRule(
            type=alert.type,
            src=alert.src,
            dst=alert.dst,
            until=until,
            reason=f"false positive {alert.id}",
        )
        self.add_rule(rule)
        return rule

    def add(self, d: Detection) -> Alert | None:
        with self._lock:
            if any(rule.matches(d) for rule in self._rules):
                self.suppressed[d.type] += 1
                return None
            key = (d.type, d.src, d.dst)
            alert = self._open.get(key)
            if (
                alert is not None
                and d.ts - alert.last_seen <= self.dedup_window
                and alert.status
                in (
                    AlertStatus.NEW,
                    AlertStatus.ACKNOWLEDGED,
                )
            ):
                self._merge(alert, d)
                is_new = False
            else:
                alert = self._create(d)
                self._open[key] = alert
                is_new = True
        self._sink(alert, is_new)
        return alert

    def expire(self, now: float) -> None:
        """Forget alerts idle for longer than the dedup window (a later repeat becomes new)."""
        with self._lock:
            stale = [k for k, a in self._open.items() if now - a.last_seen > self.dedup_window]
            for key in stale:
                del self._open[key]

    def _create(self, d: Detection) -> Alert:
        title, mitre, explanation, recommendation = describe(d)
        return Alert(
            id=Alert.new_id(),
            created_at=d.ts,
            last_seen=d.ts,
            type=d.type,
            title=title,
            source=d.source,
            severity=d.severity,
            confidence=d.confidence,
            src=d.src,
            dst=d.dst,
            ports=sorted(d.ports)[:50],
            protocol=d.protocol,
            mitre_technique=mitre,
            explanation=explanation,
            recommendation=recommendation,
            evidence=dict(d.evidence),
            flow_ids=list(d.flow_ids[: self.max_flow_ids]),
            family=d.family,
            model_version=d.model_version,
        )

    def _merge(self, alert: Alert, d: Detection) -> None:
        alert.occurrences += 1
        alert.last_seen = max(alert.last_seen, d.ts)
        if d.severity.rank > Severity(alert.severity).rank:
            alert.severity = d.severity
        if d.confidence >= alert.confidence:
            # Keep the strongest evidence and the explanation that matches it.
            alert.confidence = d.confidence
            alert.evidence = dict(d.evidence)
            _, _, alert.explanation, _ = describe(d)
        alert.ports = sorted(set(alert.ports) | set(d.ports))[:50]
        room = self.max_flow_ids - len(alert.flow_ids)
        if room > 0:
            alert.flow_ids.extend(f for f in d.flow_ids[:room] if f not in alert.flow_ids)

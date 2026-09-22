"""Decide which alerts to announce, and send them (audit OPS-04).

Every few seconds the API looks at alerts changed since its last look. An alert is announced on a
channel the first time its severity reaches that channel's minimum, so a new high alert is sent
once and a medium alert that escalates to critical is sent when it crosses the line. The highest
severity handled is stored on the alert (`notified_severity`), so restarts don't repeat messages.

Alerts found in one pass go out as one message per channel. Each channel sends at most
`max_per_hour` messages; alerts over the limit are counted and mentioned in the next message.
Delivery is at most once: a message that fails is logged and shown in Settings, not retried.
"""

import logging
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from nids.core.schemas.alert import Severity
from nids.notify import config
from nids.notify.channels import SENDERS, DeliveryError, Message, alert_link, alerts_message
from nids.store.db import Database
from nids.store.models import AlertRow, CaptureSession
from nids.store.repo import get_setting, set_setting

log = logging.getLogger(__name__)

CHANNELS = ("email", "webhook")
OVERLAP_S = 10  # re-read this far back: another process may commit rows slightly out of order
MAX_IN_MESSAGE = 10

Sender = Callable[[config.NotificationSettings, Message], None]


def rank(severity: str | None) -> int:
    if severity is None or severity not in Severity._value2member_map_:
        return -1
    return Severity(severity).rank


class Notifier:
    def __init__(
        self,
        db: Database,
        senders: dict[str, Sender] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db = db
        self.senders = senders or dict(SENDERS)
        self.clock = clock
        self._cursor = 0.0  # updated_at of the newest alert looked at
        self._sent: dict[str, deque[float]] = {c: deque() for c in CHANNELS}
        self._held_back: dict[str, int] = dict.fromkeys(CHANNELS, 0)

    # --- one pass --------------------------------------------------------------------------

    def run_once(self) -> dict[str, int]:
        """Look at changed alerts and send what's due. Returns alerts sent per channel."""
        settings = config.load(self.db)
        now = self.clock()
        due = self._due_alerts(settings)
        sent = {}
        for channel, alerts in due.items():
            if alerts:
                sent[channel] = self._deliver(settings, channel, alerts, now)
        if settings.digest_enabled:
            self._maybe_digest(settings, now)
        return sent

    def _enabled(self, settings: config.NotificationSettings) -> dict[str, int]:
        """Enabled channels and the minimum severity rank each wants."""
        channels = {}
        if settings.email_enabled:
            channels["email"] = rank(settings.email_min_severity)
        if settings.webhook_enabled:
            channels["webhook"] = rank(settings.webhook_min_severity)
        return channels

    def _due_alerts(self, settings: config.NotificationSettings) -> dict[str, list[dict[str, Any]]]:
        channels = self._enabled(settings)
        due: dict[str, list[dict[str, Any]]] = {c: [] for c in channels}
        with self.db.session() as s:
            rows = s.execute(
                select(AlertRow, CaptureSession.kind)
                .outerjoin(CaptureSession, CaptureSession.id == AlertRow.session_id)
                .where(AlertRow.updated_at > self._cursor - OVERLAP_S)
                .order_by(AlertRow.updated_at)
                .limit(2000)
            ).all()
            for row, session_kind in rows:
                self._cursor = max(self._cursor, row.updated_at)
                current, previous = rank(row.severity), rank(row.notified_severity)
                if current <= previous:
                    continue  # nothing new about this alert (or it was already announced)
                row.notified_severity = row.severity
                if session_kind == "replay" and not settings.include_replays:
                    continue
                if row.status in ("resolved", "false_positive"):
                    continue
                for channel, minimum in channels.items():
                    if current >= minimum > previous:
                        due[channel].append(_alert_data(row, escalated=previous >= 0))
        return due

    def _deliver(
        self,
        settings: config.NotificationSettings,
        channel: str,
        alerts: list[dict[str, Any]],
        now: float,
    ) -> int:
        window = self._sent[channel]
        while window and now - window[0] > 3600:
            window.popleft()
        if len(window) >= settings.max_per_hour:
            self._held_back[channel] += len(alerts)
            return 0
        alerts.sort(key=lambda a: (-rank(a["severity"]), -a["occurrences"]))
        shown, extra = alerts[:MAX_IN_MESSAGE], len(alerts) - MAX_IN_MESSAGE
        held = self._held_back[channel] + max(extra, 0)
        message = alerts_message(shown, settings.link_base_url, held_back=held)
        window.append(now)
        if self._send(settings, channel, message, now):
            self._held_back[channel] = 0
            return len(shown)
        return 0

    def _send(
        self, settings: config.NotificationSettings, channel: str, message: Message, now: float
    ) -> bool:
        try:
            self.senders[channel](settings, message)
        except DeliveryError as exc:
            log.warning("%s notification failed: %s", channel, exc)
            config.record(self.db, channel, ok=False, now=now, error=str(exc))
            return False
        except Exception as exc:  # a bug in a sender must not stop the loop
            log.exception("%s notification failed", channel)
            config.record(self.db, channel, ok=False, now=now, error=f"Unexpected error: {exc}")
            return False
        config.record(self.db, channel, ok=True, now=now)
        return True

    def send_test(self, settings: config.NotificationSettings, channel: str) -> None:
        """Send a test message now (raises DeliveryError)."""
        from nids.notify.channels import test_message

        now = self.clock()
        try:
            self.senders[channel](settings, test_message(channel, settings.link_base_url))
        except DeliveryError as exc:
            config.record(self.db, channel, ok=False, now=now, error=str(exc))
            raise
        config.record(self.db, channel, ok=True, now=now)

    # --- daily digest ------------------------------------------------------------------------

    def _maybe_digest(self, settings: config.NotificationSettings, now: float) -> None:
        local = datetime.fromtimestamp(now, UTC).astimezone()
        today = local.date().isoformat()
        if local.hour != settings.digest_hour:
            return
        with self.db.session() as s:
            if get_setting(s, config.DIGEST_KEY) == today:
                return
            set_setting(s, config.DIGEST_KEY, today)
        channels = list(self._enabled(settings))
        if not channels:
            return
        message = digest_message(self.db, settings.link_base_url, now)
        for channel in channels:
            self._send(settings, channel, message, now)


def _alert_data(row: AlertRow, escalated: bool) -> dict[str, Any]:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "severity": row.severity,
        "title": row.title,
        "type": row.type,
        "src": row.src,
        "dst": row.dst,
        "ports": list(row.ports or []),
        "protocol": row.protocol,
        "occurrences": row.occurrences,
        "confidence": row.confidence,
        "mitre_technique": row.mitre_technique,
        "explanation": row.explanation,
        "recommendation": row.recommendation,
        "created_at": row.created_at,
        "last_seen": row.last_seen,
        "escalated": escalated,
    }


def digest_message(db: Database, base_url: str, now: float) -> Message:
    """Summary of the last 24 hours."""
    since = now - 86400
    with db.session() as s:
        by_severity: dict[str, int] = {
            str(severity): int(n)
            for severity, n in s.execute(
                select(AlertRow.severity, func.count())
                .where(AlertRow.created_at >= since)
                .group_by(AlertRow.severity)
            )
        }
        open_count = (
            s.scalar(
                select(func.count())
                .select_from(AlertRow)
                .where(AlertRow.status.in_(("new", "acknowledged")))
            )
            or 0
        )
        recent = s.scalars(select(AlertRow).where(AlertRow.created_at >= since).limit(500)).all()
        top = sorted(recent, key=lambda r: (-rank(r.severity), -r.occurrences))[:5]
        top_data = [_alert_data(r, escalated=False) for r in top]
    total = sum(by_severity.values())
    counts = {sev.value: int(by_severity.get(sev.value, 0)) for sev in reversed(Severity)}
    lines = [
        f"Last 24 hours: {total} new alert(s). Open now: {open_count}.",
        "  " + " · ".join(f"{sev} {n}" for sev, n in counts.items()),
    ]
    if top_data:
        lines += ["", "Most important:"]
        lines += [
            f"  {a['severity'].upper()} · {a['title']} · {a['src'] or '*'} → {a['dst'] or '*'}"
            f" · {alert_link(base_url, a['id'])}"
            for a in top_data
        ]
    else:
        lines += ["", "Nothing was flagged."]
    day = datetime.fromtimestamp(now, UTC).astimezone().strftime("%Y-%m-%d")
    return Message(
        "digest",
        f"[AI-NIDS] Daily digest {day}: {total} alert(s), {open_count} open",
        "\n".join(lines),
        {"counts": counts, "open": open_count, "total": total, "top": top_data},
    )

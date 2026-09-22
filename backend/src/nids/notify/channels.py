"""Message formatting and delivery: SMTP email and HTTP webhooks.

Webhook requests are signed when a secret is set: `X-NIDS-Signature: sha256=<hex>` is the
HMAC-SHA256 of `<X-NIDS-Timestamp>.<body>` with the secret, so the receiver can check both origin
and freshness. Redirects are not followed (a redirect could send alert data somewhere else).
"""

import hashlib
import hmac
import json
import smtplib
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

from nids import __version__
from nids.notify.config import NotificationSettings

TIMEOUT_S = 15
_MARKS = {"critical": "◆", "high": "▲", "medium": "●", "low": "▼", "info": "○"}


class DeliveryError(RuntimeError):
    pass


@dataclass
class Message:
    """One notification: a subject line, a plain-text body and structured data for webhooks."""

    kind: str  # "alerts" | "digest" | "test"
    subject: str
    text: str
    data: dict[str, Any] = field(default_factory=dict)


def _endpoint(alert: dict[str, Any]) -> str:
    dst = alert.get("dst") or "*"
    ports = alert.get("ports") or []
    if len(ports) == 1:
        return f"{dst}:{ports[0]}"
    if len(ports) > 1:
        return f"{dst} ({len(ports)} ports)"
    return dst


def alert_link(base: str, alert_id: str) -> str:
    return f"{base.rstrip('/')}/alerts/?id={alert_id}"


def alerts_message(alerts: list[dict[str, Any]], base_url: str, held_back: int = 0) -> Message:
    """A message for one or more alerts (most severe first)."""
    first = alerts[0]
    if len(alerts) == 1:
        subject = (
            f"[AI-NIDS] {first['severity'].upper()} · {first['title']} · "
            f"{first.get('src') or '*'} → {_endpoint(first)}"
        )
    else:
        counts: dict[str, int] = {}
        for a in alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
        breakdown = ", ".join(f"{n} {sev}" for sev, n in counts.items())
        subject = f"[AI-NIDS] {len(alerts)} alerts ({breakdown})"
    blocks = []
    for a in alerts:
        escalated = " (escalated)" if a.get("escalated") else ""
        blocks.append(
            "\n".join(
                [
                    f"{_MARKS.get(a['severity'], '')} {a['severity'].upper()}{escalated} · "
                    f"{a['title']} · {a.get('src') or '*'} → {_endpoint(a)}",
                    f"  {a['occurrences']:,} hit(s), confidence {a['confidence'] * 100:.0f} %"
                    + (
                        f", MITRE ATT&CK {a['mitre_technique']}" if a.get("mitre_technique") else ""
                    ),
                    f"  What happened: {a['explanation']}",
                    f"  What to do: {a['recommendation']}",
                    f"  Open: {alert_link(base_url, a['id'])}",
                ]
            )
        )
    text = "\n\n".join(blocks)
    if held_back:
        text += (
            f"\n\n{held_back} more alert(s) were held back by the hourly message limit. "
            f"See {base_url.rstrip('/')}/alerts/"
        )
    items = [
        {
            key: a.get(key)
            for key in (
                "id",
                "severity",
                "title",
                "type",
                "src",
                "dst",
                "ports",
                "protocol",
                "occurrences",
                "confidence",
                "mitre_technique",
                "explanation",
                "recommendation",
                "created_at",
                "last_seen",
                "session_id",
                "escalated",
            )
        }
        | {"url": alert_link(base_url, a["id"])}
        for a in alerts
    ]
    return Message("alerts", subject, text, {"alerts": items, "held_back": held_back})


def test_message(channel: str, base_url: str) -> Message:
    return Message(
        "test",
        "[AI-NIDS] Test notification",
        f"This is a test from AI-NIDS. {channel.capitalize()} notifications work.\n"
        f"Alerts: {base_url.rstrip('/')}/alerts/",
        {"channel": channel},
    )


# --- delivery ----------------------------------------------------------------------------------


def send_email(settings: NotificationSettings, message: Message) -> None:
    email = EmailMessage()
    email["Subject"] = message.subject
    email["From"] = settings.email_from
    email["To"] = ", ".join(settings.email_to)
    email["X-Mailer"] = f"AI-NIDS {__version__}"
    email.set_content(
        message.text + "\n\n-- \nSent by AI-NIDS. Change this in Settings > Notifications.\n"
    )
    context = ssl.create_default_context()
    try:
        smtp: smtplib.SMTP
        if settings.smtp_security == "tls":
            smtp = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=TIMEOUT_S, context=context
            )
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=TIMEOUT_S)
        with smtp:
            if settings.smtp_security == "starttls":
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(email)
    except (smtplib.SMTPException, OSError) as exc:
        raise DeliveryError(f"Email failed: {exc}") from exc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # urllib then raises HTTPError for the 3xx response


_opener = urllib.request.build_opener(_NoRedirect)


def webhook_body(settings: NotificationSettings, message: Message) -> bytes:
    if settings.webhook_format == "slack":
        payload: dict[str, Any] = {"text": f"*{message.subject}*\n{message.text}"[:39_000]}
    elif settings.webhook_format == "discord":
        payload = {"content": f"**{message.subject}**\n{message.text}"[:1_990]}
    else:
        payload = {
            "event": message.kind,
            "subject": message.subject,
            "text": message.text,
            "sent_at": time.time(),
            "source": f"AI-NIDS {__version__}",
            **message.data,
        }
    return json.dumps(payload).encode()


def sign(secret: str, timestamp: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + digest.hexdigest()


def send_webhook(settings: NotificationSettings, message: Message) -> None:
    body = webhook_body(settings, message)
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"AI-NIDS/{__version__}",
        "X-NIDS-Event": message.kind,
        "X-NIDS-Timestamp": timestamp,
    }
    if settings.webhook_secret:
        headers["X-NIDS-Signature"] = sign(settings.webhook_secret, timestamp, body)
    request = urllib.request.Request(  # noqa: S310 - the URL is validated as http(s)
        settings.webhook_url, data=body, headers=headers, method="POST"
    )
    try:
        with _opener.open(request, timeout=TIMEOUT_S) as response:
            if not 200 <= response.status < 300:
                raise DeliveryError(f"Webhook answered {response.status}.")
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"Webhook answered {exc.code} {exc.reason}.") from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"Webhook unreachable: {reason}") from exc


SENDERS = {"email": send_email, "webhook": send_webhook}

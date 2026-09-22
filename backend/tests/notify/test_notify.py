import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from nids.notify import config
from nids.notify.channels import DeliveryError, Message, send_webhook, sign
from nids.notify.dispatcher import Notifier, digest_message
from nids.store.db import Database
from nids.store.models import AlertRow, AuditLog, utcnow

from ..sensor.test_detect import ATTACKER, VICTIM, syn_scan
from ..store.test_store import run_pipeline


@pytest.fixture
def db(isolated_database: str) -> Database:
    return Database(isolated_database)


class Outbox:
    """Fake senders that record what would have been sent."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, Message]] = []
        self.fail: str | None = None

    def sender(self, channel: str) -> Any:
        def send(_settings: config.NotificationSettings, message: Message) -> None:
            if self.fail:
                raise DeliveryError(self.fail)
            self.messages.append((channel, message))

        return send


def notifier(db: Database, outbox: Outbox, now: float = 1_000_000.0) -> Notifier:
    return Notifier(
        db,
        senders={"email": outbox.sender("email"), "webhook": outbox.sender("webhook")},
        clock=lambda: now,
    )


def two_scans(db: Database, kind: str = "live") -> None:
    run_pipeline(
        db,
        syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0)
        + syn_scan("10.0.0.77", VICTIM, range(1, 60), 1000.2),
        kind=kind,
    )


WEBHOOK = {"webhook_enabled": True, "webhook_url": "http://127.0.0.1:9/hook"}


def test_new_alerts_are_sent_once_per_channel_in_one_message(db: Database) -> None:
    config.update(db, WEBHOOK | {"webhook_min_severity": "medium"}, "admin")
    outbox = Outbox()
    sender = notifier(db, outbox)
    two_scans(db)

    first = sender.run_once()
    again = sender.run_once()

    assert first == {"webhook": 2} and again == {}
    [(channel, message)] = outbox.messages
    assert channel == "webhook" and message.subject.startswith("[AI-NIDS] 2 alerts (2 medium)")
    assert {a["src"] for a in message.data["alerts"]} == {ATTACKER, "10.0.0.77"}
    assert "/alerts/?id=A-" in message.text
    assert config.status(db)["webhook"].last_ok_at is not None


def test_alerts_below_the_threshold_or_from_replays_are_not_sent(db: Database) -> None:
    config.update(db, WEBHOOK, "admin")  # minimum: high; scans are medium
    outbox = Outbox()
    two_scans(db)
    notifier(db, outbox).run_once()
    assert outbox.messages == []

    config.update(db, {"webhook_min_severity": "medium"}, "admin")
    two_scans(db, kind="replay")
    notifier(db, outbox).run_once()
    assert outbox.messages == []  # replays are off by default, and the live ones were handled


def test_escalation_past_the_threshold_is_announced(db: Database) -> None:
    config.update(db, WEBHOOK, "admin")
    outbox = Outbox()
    sender = notifier(db, outbox)
    two_scans(db)
    sender.run_once()
    with db.session() as s:
        alert = s.scalars(select(AlertRow).where(AlertRow.src == ATTACKER)).one()
        alert.severity, alert.updated_at = "critical", utcnow()

    sender.run_once()

    [(_, message)] = outbox.messages
    [sent] = message.data["alerts"]
    assert sent["src"] == ATTACKER and sent["escalated"] is True
    assert "CRITICAL (escalated)" in message.text


def test_hourly_limit_holds_alerts_back_and_says_so(db: Database) -> None:
    config.update(db, WEBHOOK | {"webhook_min_severity": "medium", "max_per_hour": 1}, "admin")
    outbox = Outbox()
    clock = [1_000_000.0]
    sender = Notifier(db, senders={"webhook": outbox.sender("webhook")}, clock=lambda: clock[0])
    two_scans(db)
    sender.run_once()
    two_scans(db)
    sender.run_once()  # over the limit
    assert len(outbox.messages) == 1

    clock[0] += 3601
    two_scans(db)
    sender.run_once()

    assert len(outbox.messages) == 2
    assert "2 more alert(s) were held back" in outbox.messages[1][1].text


def test_failed_delivery_is_recorded(db: Database) -> None:
    config.update(db, WEBHOOK | {"webhook_min_severity": "medium"}, "admin")
    outbox = Outbox()
    outbox.fail = "Webhook unreachable: connection refused"
    two_scans(db)

    notifier(db, outbox).run_once()

    status = config.status(db)["webhook"]
    assert status.last_error == "Webhook unreachable: connection refused"
    assert status.last_ok_at is None


def test_settings_validation_and_secret_handling(db: Database) -> None:
    with pytest.raises(ValidationError):
        config.update(db, {"email_enabled": True}, "admin")  # no server or recipients
    with pytest.raises(ValidationError):
        config.update(db, {"webhook_url": "file:///etc/passwd"}, "admin")
    with pytest.raises(ValidationError):
        config.update(db, {"email_to": ["not-an-address"]}, "admin")

    config.update(
        db,
        {
            "email_enabled": True,
            "smtp_host": "smtp.example.com",
            "email_from": "nids@example.com",
            "email_to": ["me@example.com"],
            "smtp_password": "hunter2hunter2",
        },
        "admin",
    )
    config.update(db, {"email_min_severity": "critical"}, "admin")  # password kept

    public = config.public(db)
    assert public.smtp_password_set is True and public.values.smtp_password == ""
    assert config.load(db).smtp_password == "hunter2hunter2"
    with db.session() as s:
        details = [a.details for a in s.scalars(select(AuditLog))]
    assert "hunter2hunter2" not in json.dumps(details)
    assert any(d["changes"].get("smtp_password") == "(changed)" for d in details)


def test_digest_summarises_the_last_day(db: Database) -> None:
    two_scans(db)  # replayed at packet time ~1000 s

    message = digest_message(db, "http://127.0.0.1:8000", now=1000.0 + 3600)

    assert "2 alert(s), 2 open" in message.subject
    assert message.data["counts"]["medium"] == 2 and len(message.data["top"]) == 2


# --- a real HTTP round trip ------------------------------------------------------------------


@pytest.fixture
def receiver() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"path": self.path, "headers": dict(self.headers), "body": body})
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            else:
                self.send_response(204)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()


def test_webhook_is_signed_and_does_not_follow_redirects(
    receiver: tuple[str, list[dict[str, Any]]],
) -> None:
    base, received = receiver
    settings = config.NotificationSettings(
        webhook_enabled=True, webhook_url=f"{base}/hook", webhook_secret="s3cret"
    )
    message = Message("test", "subject", "text", {"channel": "webhook"})

    send_webhook(settings, message)
    with pytest.raises(DeliveryError, match="307"):
        send_webhook(settings.model_copy(update={"webhook_url": f"{base}/redirect"}), message)

    request = received[0]
    headers = {k.lower(): v for k, v in request["headers"].items()}
    expected = sign("s3cret", headers["x-nids-timestamp"], request["body"])
    assert headers["x-nids-signature"] == expected
    assert json.loads(request["body"])["event"] == "test"
    assert [r["path"] for r in received] == ["/hook", "/redirect"]  # nothing sent to /elsewhere


def test_slack_and_discord_formats() -> None:
    from nids.notify.channels import webhook_body

    message = Message("alerts", "subject", "x" * 5000)
    slack = json.loads(webhook_body(config.NotificationSettings(webhook_format="slack"), message))
    discord = json.loads(
        webhook_body(config.NotificationSettings(webhook_format="discord"), message)
    )

    assert slack["text"].startswith("*subject*")
    assert len(discord["content"]) <= 2000  # Discord's message limit

"""Notification settings, stored in the database and edited from the UI.

The SMTP password and webhook secret are write-only: the API reports whether they are set, never
their value, and the audit log records that they changed, not what to.
"""

import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from nids.store.db import Database
from nids.store.repo import audit, get_setting, set_setting

SETTING_KEY = "notifications"
STATUS_KEY = "notifications.status"
DIGEST_KEY = "notifications.digest_last"
SECRETS = ("smtp_password", "webhook_secret")

NotifySeverity = Literal["info", "low", "medium", "high", "critical"]
_EMAIL = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+\.[^@\s<>,;\"]+$")
_HOST = re.compile(r"^[A-Za-z0-9.\-:\[\]]*$")


class NotificationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    # Email (SMTP)
    email_enabled: bool = False
    email_min_severity: NotifySeverity = "high"
    smtp_host: str = Field(default="", max_length=253)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: str = Field(default="", max_length=256)
    smtp_password: str = Field(default="", max_length=256)
    email_from: str = Field(default="", max_length=254)
    email_to: list[str] = Field(default=[], max_length=10)

    # Webhook (generic JSON, or Slack / Discord incoming-webhook format)
    webhook_enabled: bool = False
    webhook_min_severity: NotifySeverity = "high"
    webhook_url: str = Field(default="", max_length=2048)
    webhook_format: Literal["json", "slack", "discord"] = "json"
    webhook_secret: str = Field(default="", max_length=256)

    # Routing and volume
    include_replays: bool = False  # replays of old captures don't page anyone by default
    max_per_hour: int = Field(default=12, ge=1, le=600)  # messages per channel
    digest_enabled: bool = False
    digest_hour: int = Field(default=8, ge=0, le=23)  # local time on the server
    link_base_url: str = Field(default="http://127.0.0.1:8000", max_length=512)

    @field_validator("smtp_host")
    @classmethod
    def _host(cls, value: str) -> str:
        if not _HOST.match(value):
            raise ValueError("a host name or IP address")
        return value

    @field_validator("email_from")
    @classmethod
    def _sender(cls, value: str) -> str:
        if value and not _EMAIL.match(value):
            raise ValueError("an email address like nids@example.com")
        return value

    @field_validator("email_to")
    @classmethod
    def _recipients(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip() for v in value if v.strip()]
        bad = [v for v in cleaned if not _EMAIL.match(v)]
        if bad:
            raise ValueError(f"not an email address: {', '.join(bad)}")
        return cleaned

    @field_validator("webhook_url", "link_base_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if value:
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError("an http:// or https:// URL")
        return value

    @model_validator(mode="after")
    def _complete(self) -> "NotificationSettings":
        if self.email_enabled and not (self.smtp_host and self.email_from and self.email_to):
            raise ValueError("email needs an SMTP server, a sender and at least one recipient")
        if self.webhook_enabled and not self.webhook_url:
            raise ValueError("the webhook needs a URL")
        return self


class ChannelStatus(BaseModel):
    last_ok_at: float | None = None
    last_error: str | None = None
    last_error_at: float | None = None


class NotificationSettingsOut(BaseModel):
    """What the API returns: the settings with secrets blanked, plus delivery status."""

    values: NotificationSettings
    smtp_password_set: bool
    webhook_secret_set: bool
    status: dict[str, ChannelStatus]


def load(db: Database) -> NotificationSettings:
    with db.session() as s:
        stored = get_setting(s, SETTING_KEY, {}) or {}
    known = set(NotificationSettings.model_fields)
    try:
        return NotificationSettings(**{k: v for k, v in stored.items() if k in known})
    except ValueError:
        return NotificationSettings()  # stored values no longer valid: start from defaults


def update(db: Database, changes: dict[str, Any], actor: str) -> NotificationSettings:
    """Validate and store a partial update (pydantic.ValidationError on bad values). Secrets are
    only changed when sent; send "" to clear one."""
    current = load(db)
    updated = NotificationSettings(**(current.model_dump() | changes))
    changed = sorted(k for k in changes if getattr(current, k) != getattr(updated, k))
    with db.session() as s:
        set_setting(s, SETTING_KEY, updated.model_dump())
        if changed:
            audit(
                s,
                actor,
                "notifications.update",
                None,
                changes={
                    k: "(changed)"
                    if k in SECRETS
                    else {
                        "from": getattr(current, k),
                        "to": getattr(updated, k),
                    }
                    for k in changed
                },
            )
    return updated


def status(db: Database) -> dict[str, ChannelStatus]:
    with db.session() as s:
        stored = get_setting(s, STATUS_KEY, {}) or {}
    return {c: ChannelStatus(**stored.get(c, {})) for c in ("email", "webhook")}


def record(db: Database, channel: str, ok: bool, now: float, error: str | None = None) -> None:
    with db.session() as s:
        stored = get_setting(s, STATUS_KEY, {}) or {}
        entry = dict(stored.get(channel, {}))
        if ok:
            entry["last_ok_at"] = now
        else:
            entry["last_error"], entry["last_error_at"] = error, now
        set_setting(s, STATUS_KEY, {**stored, channel: entry})


def public(db: Database) -> NotificationSettingsOut:
    settings = load(db)
    return NotificationSettingsOut(
        values=settings.model_copy(update=dict.fromkeys(SECRETS, "")),
        smtp_password_set=bool(settings.smtp_password),
        webhook_secret_set=bool(settings.webhook_secret),
        status=status(db),
    )

"""Notification settings and test messages (audit OPS-04)."""

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, ValidationError

from nids.api.auth import Principal, RateLimiter, get_db, require_user
from nids.api.errors import ApiError
from nids.notify import config
from nids.notify.channels import DeliveryError
from nids.store.db import Database

router = APIRouter(prefix="/api/notifications", tags=["notifications"])
test_limiter = RateLimiter(limit=5, window_s=60)


@router.get("")
def get_notifications(
    _: Principal = Depends(require_user), db: Database = Depends(get_db)
) -> config.NotificationSettingsOut:
    """Current settings (the SMTP password and webhook secret are never returned) and the
    result of the last delivery per channel."""
    return config.public(db)


@router.patch("")
def update_notifications(
    changes: dict[str, Any],
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> config.NotificationSettingsOut:
    """Change some settings. Leave out `smtp_password` / `webhook_secret` to keep them; send ""
    to clear one."""
    unknown = sorted(set(changes) - set(config.NotificationSettings.model_fields))
    if unknown:
        raise ApiError(
            422, f"Unknown setting(s): {', '.join(unknown)}.", details={"unknown": unknown}
        )
    try:
        config.update(db, changes, principal.username)
    except ValidationError as exc:
        details = [
            {"field": ".".join(map(str, e["loc"])) or "settings", "message": e["msg"]}
            for e in exc.errors()
        ]
        raise ApiError(422, "Some values are invalid.", details=details) from exc
    return config.public(db)


class TestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["email", "webhook"]


class TestResult(BaseModel):
    ok: bool
    message: str


@router.post("/test")
async def send_test(
    body: TestRequest,
    request: Request,
    principal: Principal = Depends(require_user),
    db: Database = Depends(get_db),
) -> TestResult:
    """Send a test message on one channel with the saved settings, even if it's turned off."""
    test_limiter.check(principal.username)
    settings = config.load(db)
    if body.channel == "email" and not (
        settings.smtp_host and settings.email_from and settings.email_to
    ):
        raise ApiError(422, "Save an SMTP server, a sender and a recipient first.")
    if body.channel == "webhook" and not settings.webhook_url:
        raise ApiError(422, "Save a webhook URL first.")
    try:
        await asyncio.to_thread(request.app.state.notifier.send_test, settings, body.channel)
    except DeliveryError as exc:
        raise ApiError(502, str(exc), code="delivery_failed") from exc
    return TestResult(ok=True, message=f"Test {body.channel} sent.")

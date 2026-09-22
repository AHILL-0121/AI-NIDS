"""Live updates over one WebSocket: `/api/ws`.

The sensor runs in another process, so the broadcaster watches the shared database once a second
and pushes what changed. Events: `alert.new`, `alert.updated`, `stats.tick` (one per completed
second of traffic), `sensor.state`, `job.progress`. The browser never polls (audit UI-01).

Security: the socket needs the same session cookie as the REST API, and the Origin header must be
this site (or one listed in `allowed_origins`), which blocks cross-site WebSocket hijacking.
"""

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, FastAPI, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from nids.api.auth import COOKIE, resolve_session
from nids.store.db import Database
from nids.store.models import AlertRow, Job, Traffic

log = logging.getLogger(__name__)

_COUNTERS = (
    "packets",
    "bytes",
    "tcp",
    "udp",
    "icmp",
    "other",
    "flows_started",
    "flows_ended",
    "alerts",
)


class Broadcaster:
    def __init__(self, app: FastAPI) -> None:
        self.app = app
        self.clients: set[WebSocket] = set()
        now = time.time()
        self._alert_cursor = now
        self._traffic_cursor = int(now)
        self._seen_alerts: OrderedDict[str, None] = OrderedDict()
        self._jobs: dict[str, str] = {}
        self._sensor: dict[str, Any] | None = None

    @property
    def db(self) -> Database:
        db: Database = self.app.state.db
        return db

    async def run(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                events = await asyncio.to_thread(self.collect)
            except Exception:
                log.exception("Broadcaster poll failed")
                continue
            if events and self.clients:
                await self.send(events)

    async def send(self, events: list[dict[str, Any]]) -> None:
        for client in list(self.clients):
            try:
                for event in events:
                    await client.send_json(event)
            except Exception:  # disconnected mid-send
                self.clients.discard(client)

    def collect(self) -> list[dict[str, Any]]:
        from nids.api.routes.data import AlertOut

        supervisor = self.app.state.supervisor
        supervisor.poll()
        events: list[dict[str, Any]] = []
        with self.db.session() as s:
            alerts = s.scalars(
                select(AlertRow)
                .where(AlertRow.updated_at > self._alert_cursor)
                .order_by(AlertRow.updated_at)
                .limit(500)
            ).all()
            for row in alerts:
                self._alert_cursor = max(self._alert_cursor, row.updated_at)
                kind = "alert.updated" if row.id in self._seen_alerts else "alert.new"
                self._seen_alerts[row.id] = None
                if len(self._seen_alerts) > 10_000:
                    self._seen_alerts.popitem(last=False)
                events.append({"type": kind, "data": AlertOut.model_validate(row).model_dump()})

            complete = int(time.time()) - 1  # the current second is still being counted
            ticks = s.execute(
                select(Traffic.ts, *(func.sum(getattr(Traffic, c)).label(c) for c in _COUNTERS))
                .where(
                    Traffic.resolution == 1,
                    Traffic.ts > self._traffic_cursor,
                    Traffic.ts <= complete,
                )
                .group_by(Traffic.ts)
                .order_by(Traffic.ts)
            ).all()
            for tick in ticks:
                self._traffic_cursor = max(self._traffic_cursor, tick.ts)
                events.append(
                    {
                        "type": "stats.tick",
                        "data": {"ts": tick.ts, **{c: int(getattr(tick, c)) for c in _COUNTERS}},
                    }
                )

            for job in s.scalars(select(Job).order_by(Job.created_at.desc()).limit(50)):
                if self._jobs.get(job.id) != job.status:
                    self._jobs[job.id] = job.status
                    events.append(
                        {
                            "type": "job.progress",
                            "data": {
                                "id": job.id,
                                "kind": job.kind,
                                "status": job.status,
                                "result": job.result,
                            },
                        }
                    )

        sensor = supervisor.sensor_status().__dict__
        if sensor != self._sensor:
            self._sensor = sensor
            events.append({"type": "sensor.state", "data": sensor})
        return events


def _origin_allowed(websocket: WebSocket, allowed: list[str]) -> bool:
    origin = websocket.headers.get("origin")
    if origin is None:
        return True  # non-browser clients send no Origin; the cookie is still required
    host = websocket.headers.get("host", "")
    parsed = urlsplit(origin)
    return parsed.netloc == host or origin in allowed


router = APIRouter()


@router.websocket("/api/ws")
async def live(websocket: WebSocket) -> None:
    app = websocket.app
    settings = app.state.settings
    if not _origin_allowed(websocket, settings.allowed_origins):
        await websocket.close(code=4403, reason="origin not allowed")
        return
    principal = await asyncio.to_thread(
        resolve_session,
        app.state.db,
        websocket.cookies.get(COOKIE),
        settings.session_ttl_hours * 3600,
    )
    if principal is None:
        await websocket.close(code=4401, reason="sign in first")
        return
    await websocket.accept()
    broadcaster: Broadcaster = app.state.broadcaster
    broadcaster.clients.add(websocket)
    await websocket.send_json(
        {"type": "hello", "data": {"user": principal.username, "server_time": time.time()}}
    )
    try:
        while True:
            await websocket.receive_text()  # the client may send pings; nothing else is expected
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.clients.discard(websocket)

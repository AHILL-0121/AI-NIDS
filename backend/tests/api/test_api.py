import base64
import hashlib
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from sqlalchemy import select

from nids.api import auth
from nids.api.app import create_app
from nids.api.routes import sensor as sensor_routes
from nids.core.settings import get_settings
from nids.sensor.capability import CapabilityReport, Check
from nids.sensor.interfaces import InterfaceInfo
from nids.store.models import AuditLog

from ..sensor.helpers import eth, stamp
from ..sensor.test_detect import ATTACKER, VICTIM, syn_scan
from ..store.test_store import run_pipeline

PASSWORD = "correct horse battery staple"


def make_client(**overrides: object) -> TestClient:
    settings = get_settings().model_copy(update=overrides) if overrides else get_settings()
    return TestClient(create_app(settings, background=False))


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as c:
        yield c


def sign_in(client: TestClient) -> str:
    """Create the admin and return the CSRF token (the session cookie stays in the client)."""
    response = client.post("/api/auth/setup", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 201, response.text
    token: str = response.json()["csrf_token"]
    return token


def csrf(token: str) -> dict[str, str]:
    return {"X-CSRF-Token": token}


# --- auth ----------------------------------------------------------------------------------


def test_everything_needs_a_session_except_health(client: TestClient) -> None:
    denied = client.get("/api/alerts")

    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "unauthenticated"
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").json() == {"status": "ready"}


def test_first_run_setup(client: TestClient) -> None:
    assert client.get("/api/auth/status").json()["setup_required"] is True
    short = client.post("/api/auth/setup", json={"username": "admin", "password": "short"})
    assert short.status_code == 422 and short.json()["error"]["details"][0]["field"] == "password"

    ok = client.post("/api/auth/setup", json={"username": "admin", "password": PASSWORD})
    cookie = ok.headers["set-cookie"].lower()

    assert ok.status_code == 201
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert (
        client.post("/api/auth/setup", json={"username": "x", "password": PASSWORD}).status_code
        == 409
    )
    status = client.get("/api/auth/status").json()
    assert status["authenticated"] is True and status["csrf_token"]


def test_password_is_stored_as_argon2id(client: TestClient) -> None:
    sign_in(client)
    from nids.store.models import User

    with client.app.state.db.session() as s:  # type: ignore[attr-defined]
        user = s.scalars(select(User)).one()
    assert user.password_hash.startswith("$argon2id$") and PASSWORD not in user.password_hash


def test_writes_need_the_csrf_token(client: TestClient) -> None:
    token = sign_in(client)

    missing = client.patch("/api/settings", json={"scan_min_ports": 30})
    wrong = client.patch("/api/settings", json={"scan_min_ports": 30}, headers=csrf("nope"))
    right = client.patch("/api/settings", json={"scan_min_ports": 30}, headers=csrf(token))

    assert missing.status_code == wrong.status_code == 403
    assert missing.json()["error"]["code"] == "csrf"
    assert right.status_code == 200


def test_login_logout_and_rate_limit(client: TestClient) -> None:
    token = sign_in(client)
    auth.login_limiter._events.clear()  # setup counted as an attempt
    assert client.post("/api/auth/logout", headers=csrf(token)).status_code == 204
    assert client.get("/api/alerts").status_code == 401

    wrong = [
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        for _ in range(5)
    ]
    assert {r.status_code for r in wrong} == {401}
    assert wrong[0].json()["error"]["message"] == "Wrong username or password."
    limited = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert limited.status_code == 429

    auth.login_limiter._events.clear()
    ok = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert ok.status_code == 200 and client.get("/api/alerts").status_code == 200


# --- data ----------------------------------------------------------------------------------


def seed_alerts(client: TestClient) -> None:
    db = client.app.state.db  # type: ignore[attr-defined]
    run_pipeline(
        db,
        syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0)
        + syn_scan("10.0.0.77", VICTIM, range(1, 60), 1000.2),
    )


def test_alerts_list_filter_and_detail(client: TestClient) -> None:
    sign_in(client)
    seed_alerts(client)

    page = client.get("/api/alerts", params={"severity": ["medium"], "limit": 1}).json()
    one = client.get("/api/alerts", params={"src": ATTACKER}).json()
    detail = client.get(f"/api/alerts/{one['items'][0]['id']}").json()

    assert page["total"] == 2 and len(page["items"]) == 1
    assert one["total"] == 1 and detail["src"] == ATTACKER and detail["type"] == "port_scan"
    assert client.get("/api/alerts/A-missing").status_code == 404


def test_marking_false_positive_creates_a_suppression_rule(client: TestClient) -> None:
    token = sign_in(client)
    seed_alerts(client)
    alert_id = client.get("/api/alerts", params={"src": ATTACKER}).json()["items"][0]["id"]

    updated = client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "false_positive", "note": "our scanner"},
        headers=csrf(token),
    )
    rejected = client.patch(
        f"/api/alerts/{alert_id}", json={"severity": "low"}, headers=csrf(token)
    )

    assert updated.status_code == 200 and updated.json()["status"] == "false_positive"
    assert rejected.status_code == 422  # analysts can't rewrite detection fields
    rules = client.get("/api/suppressions").json()
    assert rules[0]["src"] == ATTACKER and rules[0]["alert_id"] == alert_id


def test_flows_sessions_and_stats(client: TestClient) -> None:
    sign_in(client)
    seed_alerts(client)

    sessions = client.get("/api/sessions").json()
    session_id = sessions["items"][0]["id"]
    flows = client.get("/api/flows", params={"ip": ATTACKER, "limit": 5}).json()
    series = client.get(
        "/api/stats/timeseries", params={"since": 0, "session_id": session_id}
    ).json()
    summary = client.get("/api/stats/summary").json()

    assert sessions["total"] == 1 and flows["total"] == 59 and len(flows["items"]) == 5
    assert sum(b["packets"] for b in series) == 236
    assert summary["open_alerts"] == {"medium": 2}


def test_minute_series_covers_seconds_not_yet_rolled_up(client: TestClient) -> None:
    from nids.store.retention import rollup_traffic

    sign_in(client)
    seed_alerts(client)
    params = {"since": 0, "resolution": 60}

    before = client.get("/api/stats/timeseries", params=params).json()
    # A replay is rolled up once it finished more than two minutes ago.
    rolled = rollup_traffic(client.app.state.db, now=time.time() + 600)  # type: ignore[attr-defined]
    after = client.get("/api/stats/timeseries", params=params).json()

    assert rolled > 0
    assert all(b["ts"] % 60 == 0 for b in before)
    assert sum(b["packets"] for b in before) == sum(b["packets"] for b in after) == 236


# --- settings ------------------------------------------------------------------------------


def test_settings_are_allow_listed_and_validated(client: TestClient) -> None:
    token = sign_in(client)

    unknown = client.patch(
        "/api/settings", json={"model_path": "/tmp/evil.pkl"}, headers=csrf(token)
    )
    out_of_range = client.patch("/api/settings", json={"scan_min_ports": 1}, headers=csrf(token))
    ok = client.patch(
        "/api/settings",
        json={"scan_min_ports": 40, "allowed_protocols": [6, 17, 47]},
        headers=csrf(token),
    )

    assert unknown.status_code == 422 and unknown.json()["error"]["details"] == {
        "unknown": ["model_path"]
    }
    assert out_of_range.status_code == 422
    assert ok.json()["values"]["scan_min_ports"] == 40
    assert ok.json()["apply"]["scan_min_ports"] == "restart"
    with client.app.state.db.session() as s:  # type: ignore[attr-defined]
        actions = s.scalars(select(AuditLog.action)).all()
    assert "settings.update" in actions


# --- uploads, jobs, models -----------------------------------------------------------------


def write_scan_pcap(path: Path) -> Path:
    packets = [
        stamp(
            eth() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=60000, dport=port, flags="S"),
            1000 + i * 0.02,
        )
        for i, port in enumerate(range(1, 61))
    ]
    wrpcap(str(path), packets)
    return path


def test_upload_checks_the_file_signature(client: TestClient, tmp_path: Path) -> None:
    token = sign_in(client)
    pcap = write_scan_pcap(tmp_path / "scan.pcap")

    fake = client.post(
        "/api/uploads", files={"file": ("x.pcap", b"not a capture")}, headers=csrf(token)
    )
    real = client.post(
        "/api/uploads", files={"file": ("../../evil.pcap", pcap.read_bytes())}, headers=csrf(token)
    )

    assert fake.status_code == 415
    assert real.status_code == 201
    body = real.json()
    assert body["format"] == "pcap" and body["filename"] == "evil.pcap"  # path parts stripped
    assert body["sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()


def test_upload_size_limit(tmp_path: Path) -> None:
    with make_client(upload_max_mb=1) as client:
        token = sign_in(client)
        big = b"\xd4\xc3\xb2\xa1" + b"\0" * (2 * 1024 * 1024)
        response = client.post(
            "/api/uploads", files={"file": ("big.pcap", big)}, headers=csrf(token)
        )
    assert response.status_code == 413


def test_replay_job_runs_in_a_subprocess_and_stores_results(
    client: TestClient, tmp_path: Path
) -> None:
    token = sign_in(client)
    pcap = write_scan_pcap(tmp_path / "scan.pcap")
    upload = client.post(
        "/api/uploads", files={"file": ("scan.pcap", pcap.read_bytes())}, headers=csrf(token)
    ).json()

    job = client.post(
        "/api/jobs", json={"kind": "replay", "upload_id": upload["id"]}, headers=csrf(token)
    ).json()
    deadline = time.time() + 120
    while (current := client.get(f"/api/jobs/{job['id']}").json())[
        "status"
    ] == "running" and time.time() < deadline:
        time.sleep(0.5)

    assert current["status"] == "done", client.get(
        "/api/logs", params={"source": f"job:{job['id']}"}
    ).json()
    assert current["result"]["session_id"]
    alerts = client.get(
        "/api/alerts", params={"session_id": current["result"]["session_id"]}
    ).json()
    assert alerts["total"] == 1 and alerts["items"][0]["type"] == "port_scan"
    log = client.get("/api/logs", params={"source": f"job:{job['id']}"}).json()["lines"]
    assert any("Port scan" in line for line in log)


def test_job_requests_are_validated(client: TestClient) -> None:
    token = sign_in(client)

    bad_dataset = client.post(
        "/api/jobs", json={"kind": "train", "dataset": "../etc"}, headers=csrf(token)
    )
    bad_upload = client.post(
        "/api/jobs", json={"kind": "replay", "upload_id": "0" * 16}, headers=csrf(token)
    )
    extra = client.post(
        "/api/jobs",
        json={"kind": "prepare", "dataset": "cicids2017", "src": "/"},
        headers=csrf(token),
    )

    assert bad_dataset.status_code == 422
    assert bad_upload.status_code == 404
    assert extra.status_code == 422  # no way to pass a source path


def test_models_are_activated_by_registered_version_only(client: TestClient) -> None:
    from nids.ml import registry
    from nids.ml.train import TrainConfig, train

    from ..ml.synth import cic_like_frame
    from ..ml.test_train import WEEK

    token = sign_in(client)
    result = train(
        cic_like_frame(WEEK), "cicids2017", TrainConfig(n_estimators=30, early_stopping_rounds=5)
    )
    registry.save(result.bundle, result.report, Path(get_settings().artifacts_dir))

    models = client.get("/api/models").json()
    version = models[0]["version"]
    activated = client.post(f"/api/models/{version}/activate", headers=csrf(token))
    traversal = client.post("/api/models/..%2F..%2Fetc/activate", headers=csrf(token))

    assert len(models) == 1 and models[0]["active"] is False
    assert activated.json() == {"active": version}
    assert client.get("/api/models").json()[0]["active"] is True
    assert traversal.status_code == 404
    assert client.get("/api/sensor/status").json()["model_version"] == version
    report = client.get(f"/api/models/{version}/report").json()
    assert "per_family" in report and "confusion_matrix" in report["multiclass"]


def test_sensor_start_checks_capability_and_interface(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = sign_in(client)
    monkeypatch.setattr(
        sensor_routes,
        "check_capture",
        lambda: CapabilityReport(
            platform="Windows",
            backend=None,
            checks=[Check(name="npcap", status="error", detail="missing", fix="install")],
        ),
    )
    blocked = client.post("/api/sensor/start", json={"interface": "eth0"}, headers=csrf(token))

    monkeypatch.setattr(
        sensor_routes,
        "check_capture",
        lambda: CapabilityReport(platform="Linux", backend="scapy", checks=[]),
    )
    monkeypatch.setattr(
        sensor_routes,
        "list_interfaces",
        lambda: [
            InterfaceInfo(
                name="eth0",
                label="eth0",
                description="",
                ipv4=[],
                ipv6=[],
                mac=None,
                loopback=False,
            )
        ],
    )
    unknown = client.post(
        "/api/sensor/start", json={"interface": "eth0; rm -rf /"}, headers=csrf(token)
    )

    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "capture_unavailable"
    assert blocked.json()["error"]["details"][0]["fix"] == "install"
    assert unknown.status_code == 422
    assert client.post("/api/sensor/stop", headers=csrf(token)).status_code == 409
    assert client.get("/api/sensor/status").json()["running"] is False


# --- hardening -----------------------------------------------------------------------------


def test_security_headers_and_body_limit(client: TestClient) -> None:
    token = sign_in(client)
    response = client.get("/api/auth/status")

    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.headers["cache-control"] == "no-store"
    big = client.patch(
        "/api/settings",
        content=b"{" + b" " * (2 * 1024 * 1024) + b"}",
        headers={**csrf(token), "content-type": "application/json"},
    )
    assert big.status_code == 413


def test_frontend_is_served_with_script_hashes(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "alerts").mkdir(parents=True)
    script = b"document.documentElement.dataset.theme='light'"
    (out / "index.html").write_bytes(b"<html><head><script>" + script + b"</script></head></html>")
    (out / "alerts" / "index.html").write_bytes(b"<html>alerts</html>")
    (out / "404.html").write_bytes(b"<html>not found</html>")
    (out / "alerts" / "__next.!KGFwcCk" / "alerts").mkdir(parents=True)
    (out / "alerts" / "__next.!KGFwcCk" / "alerts" / "__PAGE__.txt").write_text("segment")
    with make_client(frontend_dir=str(out)) as client:
        home = client.get("/")
        page = client.get("/alerts/")
        probe = client.head("/alerts/")  # the Next.js router probes pages with HEAD
        segment = client.get("/alerts/__next.!KGFwcCk.alerts.__PAGE__.txt?_rsc=abc")
        escape = client.get("/..%2F..%2Fsecret")
        api_miss = client.get("/api/nothing")

    expected = "'sha256-" + base64.b64encode(hashlib.sha256(script).digest()).decode() + "'"
    assert home.status_code == 200 and expected in home.headers["content-security-policy"]
    assert (
        "unsafe-inline"
        not in home.headers["content-security-policy"].split("script-src")[1].split(";")[0]
    )
    assert page.text == "<html>alerts</html>"
    assert probe.status_code == 200 and probe.text == ""
    assert segment.status_code == 200 and segment.text == "segment"
    assert escape.status_code == 404
    assert api_miss.status_code == 404 and api_miss.json()["error"]["code"] == "not_found"


def test_websocket_requires_session_and_same_origin(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    with (
        pytest.raises(WebSocketDisconnect) as no_session,
        client.websocket_connect("/api/ws") as ws,
    ):
        ws.receive_json()
    assert no_session.value.code == 4401

    sign_in(client)
    with (
        pytest.raises(WebSocketDisconnect) as bad_origin,
        client.websocket_connect("/api/ws", headers={"origin": "https://evil.example"}) as ws,
    ):
        ws.receive_json()
    assert bad_origin.value.code == 4403

    with client.websocket_connect("/api/ws", headers={"origin": "http://testserver"}) as ws:
        assert ws.receive_json()["type"] == "hello"


def test_broadcaster_reports_new_and_updated_alerts(client: TestClient) -> None:
    token = sign_in(client)
    broadcaster = client.app.state.broadcaster  # type: ignore[attr-defined]
    broadcaster._alert_cursor = 0.0
    seed_alerts(client)

    first = broadcaster.collect()
    alert_id = next(e["data"]["id"] for e in first if e["type"] == "alert.new")
    client.patch(f"/api/alerts/{alert_id}", json={"status": "acknowledged"}, headers=csrf(token))
    second = broadcaster.collect()

    assert sum(e["type"] == "alert.new" for e in first) == 2
    assert any(e["type"] == "sensor.state" for e in first)
    assert [e["data"]["status"] for e in second if e["type"] == "alert.updated"] == ["acknowledged"]


def test_openapi_metrics_and_logs(client: TestClient) -> None:
    sign_in(client)

    schema = client.get("/api/openapi.json").json()
    metrics = client.get("/metrics").text
    logs = client.get("/api/logs", params={"source": "api", "lines": 5})
    bad = client.get("/api/logs", params={"source": "../../etc/passwd"})

    assert "/api/alerts/{alert_id}" in schema["paths"]
    assert "nids_up 1" in metrics and "nids_sensor_running 0" in metrics
    assert logs.status_code == 200
    assert bad.status_code == 422


def test_api_restart_marks_orphaned_work_as_interrupted(isolated_database: str) -> None:
    from nids.store import repo
    from nids.store.db import Database
    from nids.store.models import CaptureSession

    db = Database(isolated_database)
    session_id = repo.start_session(db, "live", "eth0", "scapy")

    with make_client():
        pass  # startup runs recovery

    with db.session() as s:
        row = s.get(CaptureSession, session_id)
    assert row is not None and row.status == "failed" and "restarted" in (row.error or "")

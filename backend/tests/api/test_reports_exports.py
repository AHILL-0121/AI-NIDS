import csv
import io
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from nids.notify.channels import DeliveryError

from ..sensor.test_detect import ATTACKER
from .test_api import csrf, make_client, seed_alerts, sign_in


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as c:
        yield c


def wait_for(client: TestClient, job_id: str) -> dict:  # type: ignore[type-arg]
    deadline = time.time() + 120
    while (job := client.get(f"/api/jobs/{job_id}").json())["status"] == "running":
        assert time.time() < deadline, "job took too long"
        time.sleep(0.3)
    return job  # type: ignore[no-any-return]


# --- reports --------------------------------------------------------------------------------


def test_report_job_writes_a_downloadable_report(client: TestClient) -> None:
    token = sign_in(client)
    seed_alerts(client)
    session_id = client.get("/api/sessions").json()["items"][0]["id"]

    job = client.post(
        "/api/jobs",
        json={"kind": "report", "session_id": session_id, "pdf": False},
        headers=csrf(token),
    ).json()
    finished = wait_for(client, job["id"])
    reports = client.get("/api/reports", params={"session_id": session_id}).json()
    view = client.get(f"/api/reports/{job['id']}/html")
    saved = client.get(f"/api/reports/{job['id']}/html", params={"download": True})
    no_pdf = client.get(f"/api/reports/{job['id']}/pdf")

    assert finished["status"] == "done", client.get(
        "/api/logs", params={"source": f"job:{job['id']}"}
    ).json()
    assert finished["result"]["html"] is True and finished["result"]["session_id"] == session_id
    assert [(r["id"], r["html"], r["pdf"]) for r in reports] == [(job["id"], True, False)]
    assert view.status_code == 200 and "Session report" in view.text
    csp = view.headers["content-security-policy"]
    assert "sandbox" in csp and "script-src" not in csp and "default-src 'none'" in csp
    assert view.headers["content-disposition"].startswith("inline")
    assert saved.headers["content-disposition"].startswith("attachment")
    assert f"nids-report-{session_id}-" in saved.headers["content-disposition"]
    assert no_pdf.status_code == 404

    deleted = client.delete(f"/api/reports/{job['id']}", headers=csrf(token))
    assert deleted.status_code == 204
    assert client.get("/api/reports").json() == []
    assert client.get(f"/api/reports/{job['id']}/html").status_code == 404


def test_report_requests_are_validated(client: TestClient) -> None:
    token = sign_in(client)

    unknown = client.post(
        "/api/jobs", json={"kind": "report", "session_id": "0" * 16}, headers=csrf(token)
    )
    traversal = client.post(
        "/api/jobs", json={"kind": "report", "session_id": "../../etc"}, headers=csrf(token)
    )
    bad_id = client.get("/api/reports/..%2F..%2Fnids/html")
    bad_format = client.get(f"/api/reports/{'a' * 16}/exe")

    assert unknown.status_code == 404
    assert traversal.status_code == 422
    assert bad_id.status_code in (404, 422)
    assert bad_format.status_code == 422


# --- exports --------------------------------------------------------------------------------


def test_alert_export_covers_every_match_and_is_formula_safe(client: TestClient) -> None:
    token = sign_in(client)
    seed_alerts(client)
    alert_id = client.get("/api/alerts", params={"src": ATTACKER}).json()["items"][0]["id"]
    client.patch(
        f"/api/alerts/{alert_id}", json={"note": '=HYPERLINK("http://x")'}, headers=csrf(token)
    )

    as_csv = client.get("/api/alerts/export", params={"format": "csv"})
    as_json = client.get("/api/alerts/export", params={"format": "json", "src": ATTACKER})

    rows = list(csv.DictReader(io.StringIO(as_csv.text)))
    assert as_csv.headers["content-type"].startswith("text/csv")
    assert as_csv.headers["content-disposition"].startswith('attachment; filename="alerts-')
    assert len(rows) == 2 and {r["type"] for r in rows} == {"port_scan"}
    noted = next(r for r in rows if r["id"] == alert_id)
    assert noted["note"] == '\'=HYPERLINK("http://x")'
    assert noted["created_at"].endswith("Z")
    [one] = as_json.json()
    assert one["src"] == ATTACKER and isinstance(one["ports"], list)


def test_flow_export(client: TestClient) -> None:
    sign_in(client)
    seed_alerts(client)

    rows = list(
        csv.DictReader(io.StringIO(client.get("/api/flows/export", params={"ip": ATTACKER}).text))
    )
    flows = client.get("/api/flows/export", params={"format": "json", "port": 22}).json()

    assert len(rows) == 59 and all(ATTACKER in (r["src_ip"], r["dst_ip"]) for r in rows)
    assert len(flows) == 2 and "stats" in flows[0]


def test_exports_need_a_session(client: TestClient) -> None:
    assert client.get("/api/alerts/export").status_code == 401
    assert client.get("/api/flows/export").status_code == 401


# --- notifications --------------------------------------------------------------------------


def test_notification_settings_api(client: TestClient) -> None:
    token = sign_in(client)

    unknown = client.patch("/api/notifications", json={"smtp_cmd": "x"}, headers=csrf(token))
    incomplete = client.patch(
        "/api/notifications", json={"email_enabled": True}, headers=csrf(token)
    )
    ok = client.patch(
        "/api/notifications",
        json={
            "webhook_enabled": True,
            "webhook_url": "https://hooks.example.com/nids",
            "webhook_secret": "abc",
        },
        headers=csrf(token),
    )

    assert unknown.status_code == 422 and unknown.json()["error"]["details"] == {
        "unknown": ["smtp_cmd"]
    }
    assert incomplete.status_code == 422
    body = ok.json()
    assert body["values"]["webhook_enabled"] is True and body["values"]["webhook_secret"] == ""
    assert body["webhook_secret_set"] is True and body["smtp_password_set"] is False
    assert "abc" not in client.get("/api/notifications").text


def test_notification_test_endpoint(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = sign_in(client)
    unsaved = client.post("/api/notifications/test", json={"channel": "email"}, headers=csrf(token))
    client.patch(
        "/api/notifications",
        json={"webhook_url": "http://127.0.0.1:9/hook"},
        headers=csrf(token),
    )
    notifier = client.app.state.notifier  # type: ignore[attr-defined]

    def refuse(*_: object) -> None:
        raise DeliveryError("Webhook unreachable: connection refused")

    monkeypatch.setitem(notifier.senders, "webhook", refuse)
    failed = client.post(
        "/api/notifications/test", json={"channel": "webhook"}, headers=csrf(token)
    )
    monkeypatch.setitem(notifier.senders, "webhook", lambda *_: None)
    sent = client.post("/api/notifications/test", json={"channel": "webhook"}, headers=csrf(token))

    assert unsaved.status_code == 422
    assert failed.status_code == 502 and failed.json()["error"]["code"] == "delivery_failed"
    assert sent.json() == {"ok": True, "message": "Test webhook sent."}
    status = client.get("/api/notifications").json()["status"]["webhook"]
    assert status["last_ok_at"] and "refused" in status["last_error"]

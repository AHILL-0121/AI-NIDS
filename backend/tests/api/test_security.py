"""Security sweep over the whole API (audit SEC-01…04).

Rather than testing a few routes by hand, walk every operation in the OpenAPI schema: a route
added later without `require_user` fails here immediately.
"""

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nids.core.settings import get_settings

from .test_api import csrf, make_client, sign_in

# Routes that must work without a session, and why.
PUBLIC = {
    ("get", "/healthz"),  # liveness probe
    ("get", "/readyz"),  # readiness probe
    ("get", "/metrics"),  # Prometheus scrape: counts only, no addresses; loopback by default
    ("get", "/api/auth/status"),  # tells the UI whether to show setup or login
    ("post", "/api/auth/setup"),  # first run only; refuses once an admin exists
    ("post", "/api/auth/login"),
}
WRITE = {"post", "put", "patch", "delete"}


def operations() -> list[tuple[str, str]]:
    with make_client() as client:
        schema = client.get("/api/openapi.json").json()
    return sorted(
        (method, path)
        for path, item in schema["paths"].items()
        for method in item
        if method in {"get", "post", "put", "patch", "delete"}
    )


def concrete(path: str) -> str:
    """Fill path parameters with well-formed values (16-hex ids pass every id pattern)."""
    return re.sub(
        r"\{(\w+)\}", lambda m: "html" if m.group(1) == "fmt" else "0123456789abcdef", path
    )


OPERATIONS = operations()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as c:
        yield c


def test_the_sweep_sees_every_route() -> None:
    assert len(OPERATIONS) >= 40
    assert set(OPERATIONS) >= PUBLIC, "a public route was renamed; update PUBLIC"


@pytest.mark.parametrize(("method", "path"), [op for op in OPERATIONS if op not in PUBLIC])
def test_every_route_needs_a_session(client: TestClient, method: str, path: str) -> None:
    sign_in(client)  # an admin exists, so setup is closed...
    client.cookies.clear()  # ...but this client has no session

    response = client.request(method.upper(), concrete(path), json={})

    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "unauthenticated"


@pytest.mark.parametrize(
    ("method", "path"), [op for op in OPERATIONS if op[0] in WRITE and op not in PUBLIC]
)
def test_every_write_needs_the_csrf_token(client: TestClient, method: str, path: str) -> None:
    sign_in(client)

    response = client.request(method.upper(), concrete(path), json={})

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "csrf"


def test_setup_cannot_be_rerun_to_take_over(client: TestClient) -> None:
    sign_in(client)
    client.cookies.clear()

    again = client.post("/api/auth/setup", json={"username": "mallory", "password": "x" * 20})

    assert again.status_code == 409


def test_a_tampered_model_is_refused(client: TestClient) -> None:
    from nids.ml import registry
    from nids.ml.train import TrainConfig, train

    from ..ml.synth import cic_like_frame
    from ..ml.test_train import WEEK

    token = sign_in(client)
    result = train(
        cic_like_frame(WEEK), "cicids2017", TrainConfig(n_estimators=20, early_stopping_rounds=5)
    )
    artifact = registry.save(result.bundle, result.report, Path(get_settings().artifacts_dir))
    version = client.get("/api/models").json()[0]["version"]

    model_file = next(p for p in Path(artifact).iterdir() if p.suffix in (".joblib", ".pkl"))
    data = bytearray(model_file.read_bytes())
    data[len(data) // 2] ^= 0xFF  # one flipped byte
    model_file.write_bytes(bytes(data))
    activated = client.post(f"/api/models/{version}/activate", headers=csrf(token))

    assert activated.status_code == 409
    assert "hash" in activated.json()["error"]["message"].lower()
    assert client.get("/api/sensor/status").json()["model_version"] is None

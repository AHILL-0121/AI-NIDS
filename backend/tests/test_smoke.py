import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from nids import __version__
from nids.api.app import create_app
from nids.core.settings import Settings


def test_healthz_reports_ok_and_version() -> None:
    client = TestClient(create_app())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_api_binds_to_loopback_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NIDS_HOST", raising=False)

    assert Settings(_env_file=None).host == "127.0.0.1"


def test_settings_reject_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, model_path="models/evil.pkl")  # type: ignore[call-arg]

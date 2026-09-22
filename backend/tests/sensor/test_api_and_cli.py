import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from nids.api.app import create_app
from nids.api.routes import sensor as sensor_routes
from nids.cli import app as cli
from nids.sensor.capability import CapabilityReport, Check
from nids.sensor.interfaces import InterfaceInfo


def test_interfaces_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = [
        InterfaceInfo(
            name="eth0",
            label="eth0",
            description="eth0",
            ipv4=["10.0.0.2"],
            ipv6=[],
            mac=None,
            loopback=False,
        )
    ]
    monkeypatch.setattr(sensor_routes, "list_interfaces", lambda: fake)

    response = TestClient(create_app()).get("/api/sensor/interfaces")

    assert response.status_code == 200
    assert response.json()[0]["ipv4"] == ["10.0.0.2"]


def test_interfaces_endpoint_without_capture_support(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing() -> list[InterfaceInfo]:
        raise ImportError("scapy")

    monkeypatch.setattr(sensor_routes, "list_interfaces", missing)

    response = TestClient(create_app()).get("/api/sensor/interfaces")

    assert response.status_code == 503


def test_capabilities_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    report = CapabilityReport(
        platform="Windows",
        backend=None,
        checks=[Check(name="npcap", status="error", detail="missing", fix="install npcap")],
    )
    monkeypatch.setattr(sensor_routes, "check_capture", lambda: report)

    body = TestClient(create_app()).get("/api/sensor/capabilities").json()

    assert body["ok"] is False and body["checks"][0]["fix"] == "install npcap"


def test_cli_replay_writes_json_lines(sample_pcap: Path, tmp_path: Path) -> None:
    out = tmp_path / "flows.jsonl"

    result = CliRunner().invoke(cli, ["replay", str(sample_pcap), "--out", str(out)])

    assert result.exit_code == 0, result.output
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 4
    assert {"src_ip", "fwd_packets", "bwd_bytes", "end_reason", "duration"} <= rows[0].keys()


def test_cli_replay_rejects_bad_speed(sample_pcap: Path) -> None:
    result = CliRunner().invoke(cli, ["replay", str(sample_pcap), "--speed", "warp"])

    assert result.exit_code != 0


def test_cli_replay_in_a_fresh_interpreter(sample_pcap: Path, tmp_path: Path) -> None:
    """Regression: in a new process Scapy hasn't loaded its IP layers yet, so every frame was
    decoded as Ether + raw bytes and no flows came out. The in-process tests couldn't see it."""
    out = tmp_path / "flows.jsonl"

    subprocess.run(
        [sys.executable, "-m", "nids.cli", "replay", str(sample_pcap), "--out", str(out)],
        check=True,
        capture_output=True,
        timeout=120,
    )

    assert len(out.read_text().splitlines()) == 4

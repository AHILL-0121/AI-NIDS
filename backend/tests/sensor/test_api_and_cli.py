import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from nids.cli import app as cli


def test_cli_replay_writes_json_lines(sample_pcap: Path, tmp_path: Path) -> None:
    out = tmp_path / "flows.jsonl"

    result = CliRunner().invoke(cli, ["replay", str(sample_pcap), "--out", str(out)])

    assert result.exit_code == 0, result.output
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 4
    assert {"src_ip", "fwd_packets", "bwd_payload_bytes", "end_reason", "duration"} <= rows[
        0
    ].keys()


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

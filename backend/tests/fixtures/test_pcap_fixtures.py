"""Labelled captures replayed through the real `nids replay` path (audit QA-02, DET-01, DET-02).

Each fixture states exactly which alerts it must raise, and the benign one must raise none: a
detector that fires on ordinary browsing is as broken as one that misses a scan.
"""

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nids.cli import app

from .pcaps.make_fixtures import ATTACKER, BUILDERS, HERE, SERVER

# fixture -> the (type, src, dst) of every alert it must raise, and nothing else
EXPECTED: dict[str, set[tuple[str, str | None, str | None]]] = {
    "benign_browsing.pcap": set(),
    "nmap_syn_scan.pcap": {("port_scan", ATTACKER, SERVER)},
    "hping3_syn_flood.pcap": {("syn_flood", ATTACKER, SERVER)},
    "host_sweep_445.pcap": {("host_sweep", ATTACKER, "192.168.1.0/24")},
}


def replay(pcap: Path, tmp_path: Path) -> list[dict]:  # type: ignore[type-arg]
    out = tmp_path / f"{pcap.stem}.alerts.jsonl"
    result = CliRunner().invoke(app, ["replay", str(pcap), "--no-db", "--alerts", str(out)])
    assert result.exit_code == 0, result.output
    return [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_raises_exactly_the_expected_alerts(name: str, tmp_path: Path) -> None:
    alerts = replay(HERE / name, tmp_path)

    assert {(a["type"], a["src"], a["dst"]) for a in alerts} == EXPECTED[name]
    assert len(alerts) == len(EXPECTED[name])  # one alert per attack, not one per packet


def test_scan_evidence_matches_what_nmap_did(tmp_path: Path) -> None:
    [scan] = replay(HERE / "nmap_syn_scan.pcap", tmp_path)

    assert scan["severity"] in ("medium", "high")
    assert scan["mitre_technique"].startswith("T1046")
    assert scan["evidence"]["distinct_ports"] >= 25


def test_flood_names_the_flooder_not_a_bystander(tmp_path: Path) -> None:
    """The server has normal web clients during the flood; none of them may be blamed."""
    [flood] = replay(HERE / "hping3_syn_flood.pcap", tmp_path)

    assert flood["src"] == ATTACKER
    assert flood["evidence"]["top_source_share"] > 0.9
    assert flood["evidence"]["distinct_sources"] < 10  # clients present, but it's not a DDoS


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_committed_fixtures_match_the_generator(name: str, tmp_path: Path) -> None:
    """The .pcap files are reproducible from make_fixtures.py, so they can be reviewed."""
    rebuilt = BUILDERS[name](tmp_path)

    committed = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
    assert hashlib.sha256(rebuilt.read_bytes()).hexdigest() == committed, (
        f"{name} differs from make_fixtures.py: run `uv run python -m "
        "tests.fixtures.pcaps.make_fixtures` and commit the result"
    )

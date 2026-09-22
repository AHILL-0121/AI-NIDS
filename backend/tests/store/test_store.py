import json
import sqlite3
import time
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, select
from typer.testing import CliRunner

from nids.cli import app as cli
from nids.core.schemas.alert import AlertStatus
from nids.sensor.detect import DetectionEngine
from nids.sensor.flows import FlowTable
from nids.sensor.pipeline import Pipeline
from nids.store import repo
from nids.store.db import Database
from nids.store.models import AlertRow, AuditLog, Base, CaptureSession, Flow, Traffic
from nids.store.retention import RetentionPolicy, purge, rollup_traffic

from ..sensor.test_detect import ATTACKER, VICTIM, syn_scan


@pytest.fixture
def db(isolated_database: str) -> Database:
    return Database(isolated_database)


def run_pipeline(
    db: Database, packets: list, kind: str = "replay", sample_rate: float = 1.0
) -> Pipeline:  # type: ignore[type-arg]
    session_id = repo.start_session(db, kind, "test.pcap", "scapy")
    pipeline = Pipeline(
        DetectionEngine(), db=db, session_id=session_id, flow_sample_rate=sample_rate
    )
    table = FlowTable(pipeline.on_flow, on_new_flow=pipeline.on_new_flow)
    second = None
    for pkt in sorted(packets, key=lambda p: p.ts):
        if second is not None and int(pkt.ts) != second:
            table.expire(pkt.ts)
            pipeline.tick(pkt.ts)
        second = int(pkt.ts)
        pipeline.on_packet(pkt)
        table.add(pkt)
    table.flush()
    pipeline.flush()
    repo.finish_session(db, session_id, {"flows_created": table.stats.flows_created})
    return pipeline


def count(db: Database, model: type) -> int:  # type: ignore[type-arg]
    with db.session() as s:
        return s.scalar(select(func.count()).select_from(model)) or 0


def test_migrations_match_the_models(db: Database) -> None:
    with db.engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], "models changed without a migration: run `alembic revision --autogenerate`"


def test_sqlite_runs_in_wal_mode(db: Database) -> None:
    with db.engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_pipeline_stores_session_flows_alerts_and_traffic(db: Database) -> None:
    pipeline = run_pipeline(db, syn_scan(ATTACKER, VICTIM, range(1, 101), t0=1000.0, rate=50))

    with db.session() as s:
        session = s.scalars(select(CaptureSession)).one()
        alert = s.scalars(select(AlertRow)).one()
        seconds = s.scalars(select(Traffic).where(Traffic.resolution == 1)).all()
    assert session.status == "stopped" and session.stopped_at is not None
    assert count(db, Flow) == 100
    assert alert.type == "port_scan" and alert.session_id == session.id
    assert alert.occurrences == pipeline.alerts[alert.id].occurrences > 1
    assert sum(t.packets for t in seconds) == 200 and sum(t.flows_started for t in seconds) == 100
    assert sum(t.alerts for t in seconds) == 1


def test_sampling_still_keeps_flows_that_alerts_refer_to(db: Database) -> None:
    pipeline = run_pipeline(
        db, syn_scan(ATTACKER, VICTIM, range(1, 101), 1000.0, rate=50), sample_rate=0.0
    )

    (alert,) = pipeline.alerts.values()
    with db.session() as s:
        stored = set(s.scalars(select(Flow.flow_id)))
    assert stored and stored == set(alert.flow_ids)


def test_analyst_status_survives_sensor_updates_and_false_positive_suppresses(db: Database) -> None:
    first = run_pipeline(db, syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0))
    (alert_id,) = first.alerts

    repo.set_alert_status(
        db, alert_id, AlertStatus.FALSE_POSITIVE, actor="admin", note="IT scanner"
    )
    second = run_pipeline(db, syn_scan(ATTACKER, VICTIM, range(1, 60), 5000.0))

    with db.session() as s:
        row = s.get(AlertRow, alert_id)
        actions = list(s.scalars(select(AuditLog.action)))
    assert row is not None and row.status == "false_positive" and row.note == "IT scanner"
    assert second.alerts == {}  # the new sensor run loaded the suppression rule
    assert second.engine.correlator.suppressed["port_scan"] > 0
    assert {"alert.status", "suppression.add"} <= set(actions)


def test_upsert_never_overwrites_analyst_fields(db: Database) -> None:
    pipeline = run_pipeline(db, syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0))
    (alert,) = pipeline.alerts.values()
    repo.set_alert_status(db, alert.id, AlertStatus.ACKNOWLEDGED, actor="admin", note="looking")

    alert.occurrences += 5
    repo.upsert_alert(db, alert, session_id=None)

    with db.session() as s:
        row = s.get(AlertRow, alert.id)
    assert row is not None and row.status == "acknowledged" and row.note == "looking"
    assert row.occurrences == alert.occurrences


def test_list_alerts_filters_and_counts(db: Database) -> None:
    run_pipeline(
        db,
        syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0)
        + syn_scan("10.0.0.77", VICTIM, range(1, 40), 1000.1),
    )

    rows, total = repo.list_alerts(db, repo.AlertQuery(src=ATTACKER))
    assert total == 1 and rows[0].src == ATTACKER
    rows, total = repo.list_alerts(db, repo.AlertQuery(type=("port_scan",), limit=1))
    assert total == 2 and len(rows) == 1


def test_rollup_and_retention(db: Database) -> None:
    now = time.time()
    live = repo.start_session(db, "live", "eth0", "scapy")
    old_replay = repo.start_session(db, "replay", "old.pcap", "scapy")
    with db.session() as s:
        for second in range(60):  # one full minute of live traffic, two days ago
            s.add(
                Traffic(
                    resolution=1,
                    ts=int(now - 2 * 86400) // 60 * 60 + second,
                    session_id=live,
                    packets=10,
                )
            )
        s.add(
            Traffic(resolution=1, ts=1_499_000_000, session_id=old_replay, packets=5)
        )  # 2017 replay
        s.get(CaptureSession, old_replay).stopped_at = now - 3600  # replayed an hour ago
    rollup_traffic(db, now)

    with db.session() as s:
        minutes = s.scalars(select(Traffic).where(Traffic.resolution == 60)).all()
    assert {m.session_id: m.packets for m in minutes} == {live: 600, old_replay: 5}

    deleted = purge(db, RetentionPolicy(), now)

    assert deleted["traffic_1s"] == 60  # live 1 s buckets older than 24 h; the recent replay stays
    with db.session() as s:
        assert s.scalars(select(Traffic.session_id).where(Traffic.resolution == 1)).all() == [
            old_replay
        ]


def test_pseudonymized_storage(db: Database) -> None:
    session_id = repo.start_session(db, "replay", "x", "scapy")
    pseudo = repo.Pseudonymizer.from_db(db)
    pipeline = Pipeline(DetectionEngine(), db=db, session_id=session_id, pseudonymizer=pseudo)
    pipeline.flow_writer = repo.FlowWriter(db, session_id, pseudonymizer=pseudo)
    table = FlowTable(pipeline.on_flow, on_new_flow=pipeline.on_new_flow)
    for pkt in syn_scan(ATTACKER, VICTIM, range(1, 40), 1000.0):
        pipeline.on_packet(pkt)
        table.add(pkt)
    table.flush()
    pipeline.flush()

    with db.session() as s:
        alert = s.scalars(select(AlertRow)).one()
        flow = s.scalars(select(Flow)).first()
    assert alert.src == pseudo.token(ATTACKER) and ATTACKER not in alert.explanation
    assert pseudo.token(ATTACKER) in alert.explanation
    assert (
        flow is not None
        and flow.src_ip.startswith("ip-")
        and ATTACKER not in json.dumps(flow.stats)
    )
    assert repo.Pseudonymizer.from_db(db).token(ATTACKER) == pseudo.token(ATTACKER)  # stable key


def test_cli_replay_and_db_commands(tmp_path: Path, isolated_database: str) -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap

    from ..sensor.helpers import eth, stamp

    packets = []
    for i, port in enumerate(range(1, 61)):
        packets.append(
            stamp(
                eth() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=60000, dport=port, flags="S"),
                1000 + i * 0.02,
            )
        )
    pcap = tmp_path / "scan.pcap"
    wrpcap(str(pcap), packets)
    runner = CliRunner()

    replayed = runner.invoke(cli, ["replay", str(pcap)])
    status = runner.invoke(cli, ["db", "status"])
    backup = runner.invoke(cli, ["db", "backup", str(tmp_path / "backup.db")])

    assert replayed.exit_code == 0, replayed.output
    assert "alerts                        1" in status.output.replace("\r", "")
    assert backup.exit_code == 0
    with sqlite3.connect(tmp_path / "backup.db") as copy:
        assert copy.execute("select count(*) from alerts").fetchone() == (1,)

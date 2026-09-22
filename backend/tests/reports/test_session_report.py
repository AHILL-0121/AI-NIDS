from pathlib import Path

import pytest
from sqlalchemy import select

from nids.core.settings import Settings
from nids.reports.pdf import find_browser
from nids.reports.session import ReportError, collect, render, write_report
from nids.store.db import Database
from nids.store.models import AlertRow

from ..sensor.test_detect import ATTACKER, VICTIM, syn_scan
from ..store.test_store import run_pipeline


@pytest.fixture
def db(isolated_database: str) -> Database:
    return Database(isolated_database)


def scanned_session(db: Database) -> str:
    pipeline = run_pipeline(
        db,
        syn_scan(ATTACKER, VICTIM, range(1, 60), 1000.0)
        + syn_scan("10.0.0.77", VICTIM, range(1, 60), 1000.2),
    )
    assert pipeline.session_id is not None
    return pipeline.session_id


def test_report_summarises_the_session(db: Database) -> None:
    session_id = scanned_session(db)

    data = collect(db, session_id)
    html = render(data)

    assert data.alert_total == 2 and data.severity_counts["medium"] == 2
    assert data.totals["flows"] == 118 and data.totals["packets"] == 236
    assert [a["type"] for a in data.actions] == ["port_scan"]
    assert data.buckets and sum(b["alerts"] for b in data.buckets) == 2
    for section in ("Summary", "What should I do?", "Timeline", "Top alerts", "Glossary"):
        assert section in html
    assert ATTACKER in html and "Port scan" in html
    assert "original packet times" in html  # replays say their clock is the capture's


def test_report_escapes_captured_text(db: Database) -> None:
    session_id = scanned_session(db)
    with db.session() as s:
        alert = s.scalars(select(AlertRow)).first()
        assert alert is not None
        alert.note = '<script>alert("x")</script>'
        alert.src = "<img src=x onerror=alert(1)>"

    html = render(collect(db, session_id))

    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "<script" not in html.lower()  # the report never contains scripts


def test_report_for_an_empty_session_says_so(db: Database) -> None:
    session_id = run_pipeline(db, []).session_id
    assert session_id is not None

    html = render(collect(db, session_id))

    assert "No alerts were raised" in html and "not that the traffic is proven safe" in html
    assert "No traffic was recorded" in html


def test_unknown_session(db: Database) -> None:
    with pytest.raises(ReportError):
        collect(db, "0" * 16)


def test_pdf_is_skipped_with_a_reason_when_no_browser(db: Database, tmp_path: Path) -> None:
    session_id = scanned_session(db)

    result = write_report(db, session_id, tmp_path / "r", browser=str(tmp_path / "missing.exe"))

    assert result["html"] is True and result["pdf"] is False
    assert "NIDS_PDF_BROWSER" in result["pdf_error"]
    assert (tmp_path / "r.html").is_file() and not (tmp_path / "r.pdf").exists()


@pytest.mark.skipif(find_browser() is None, reason="no Edge/Chrome/Chromium on this machine")
def test_pdf_is_printed_by_a_local_browser(db: Database, tmp_path: Path) -> None:
    session_id = scanned_session(db)

    settings = Settings()  # CI names its browser and turns the sandbox off (as the Docker image)
    result = write_report(
        db,
        session_id,
        tmp_path / "r",
        browser=settings.pdf_browser,
        no_sandbox=settings.pdf_no_sandbox,
    )

    assert result["pdf"] is True, result.get("pdf_error")  # a message, so pytest won't cut it
    assert (tmp_path / "r.pdf").read_bytes().startswith(b"%PDF")

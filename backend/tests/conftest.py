"""Test-wide fixtures."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from nids.core.settings import get_settings


@pytest.fixture(autouse=True)
def isolated_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Every test gets its own SQLite file, so nothing touches data/nids.db. Also applies to
    CLI runs in a subprocess, which inherit the environment."""
    url = f"sqlite:///{(tmp_path / 'nids-test.db').as_posix()}"
    monkeypatch.setenv("NIDS_DATABASE_URL", url)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()

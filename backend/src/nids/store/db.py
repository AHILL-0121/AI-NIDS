"""Database connection and migrations.

SQLite runs in WAL mode so the sensor can write while the API reads, with a busy timeout instead
of "database is locked" errors. Other SQLAlchemy URLs (e.g. PostgreSQL) work too, given a driver.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        path = url.removeprefix("sqlite:///")
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False})
        event.listen(engine, "connect", _sqlite_pragmas)
        return engine
    return create_engine(url, pool_pre_ping=True)


def upgrade(url: str, revision: str = "head") -> None:
    """Apply migrations up to `revision` (idempotent)."""
    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, revision)


class Database:
    def __init__(self, url: str, migrate: bool = True) -> None:
        self.url = url
        if migrate:
            upgrade(url)
        self.engine = make_engine(url)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """A unit of work: committed on success, rolled back on error."""
        with self._sessions() as session:
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def dispose(self) -> None:
        self.engine.dispose()

"""Physical schema-version migration behavior for durable SQLite stores."""

import sqlite3
from pathlib import Path

import pytest

from olympus.athena.adapters.sqlite import SCHEMA_VERSION as ATHENA_VERSION
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.core.migrations import (
    SqliteSchemaVersionError,
    initialize_sqlite_schema,
)
from olympus.engagements.store import SCHEMA_VERSION as ENGAGEMENTS_VERSION
from olympus.engagements.store import SqliteEngagementStore
from olympus.findings.store import SCHEMA_VERSION as FINDINGS_VERSION
from olympus.findings.store import SqliteFindingTransitionStore

STORES = (
    (SqliteAssessmentRepository, ATHENA_VERSION),
    (SqliteEngagementStore, ENGAGEMENTS_VERSION),
    (SqliteFindingTransitionStore, FINDINGS_VERSION),
)


@pytest.mark.parametrize(("store_type", "version"), STORES)
def test_legacy_store_is_migrated_without_losing_rows(
    tmp_path: Path, store_type, version: int
) -> None:
    database = tmp_path / f"{store_type.__name__}.sqlite3"
    store = store_type(database)
    store._conn.execute("CREATE TABLE migration_fixture (value TEXT NOT NULL)")
    store._conn.execute("INSERT INTO migration_fixture VALUES ('preserved')")
    store._conn.execute("PRAGMA user_version = 0")
    store._conn.commit()
    store.close()

    migrated = store_type(database)
    try:
        assert migrated._conn.execute("PRAGMA user_version").fetchone()[0] == version
        assert (
            migrated._conn.execute("SELECT value FROM migration_fixture").fetchone()[0]
            == "preserved"
        )
    finally:
        migrated.close()


@pytest.mark.parametrize(("store_type", "version"), STORES)
def test_future_store_version_is_rejected(tmp_path: Path, store_type, version: int) -> None:
    database = tmp_path / f"{store_type.__name__}.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {version + 1}")
    with pytest.raises(SqliteSchemaVersionError, match="newer than supported"):
        store_type(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == version + 1


def test_failed_migration_rolls_back_schema_and_version(tmp_path: Path) -> None:
    database = tmp_path / "rollback.sqlite3"
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.OperationalError):
            initialize_sqlite_schema(
                connection,
                "CREATE TABLE created_before_failure (value TEXT); THIS IS NOT VALID SQL;",
                current_version=1,
            )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='created_before_failure'"
            ).fetchone()
            is None
        )

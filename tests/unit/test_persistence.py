"""Persistence backend selection for Themis jobs (ROADMAP DATA-2).

The factory is the single seam that chooses a storage backend from a location/DSN.
These tests pin the contract: a path or sqlite/file URL yields a working local SQLite
store, a Postgres DSN (or any unknown scheme) fails closed with a clear message, and the
SQLite store satisfies the structural :class:`JobStore` port a future adapter must match.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.themis.jobs import JobState, ThemisJobStore
from olympus.themis.persistence import (
    JobStore,
    UnsupportedBackendError,
    describe_backend,
    resolve_job_store,
)


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_a_filesystem_path_selects_the_local_sqlite_store(tmp_path: Path) -> None:
    db = tmp_path / "jobs.sqlite3"
    store = resolve_job_store(db)
    assert isinstance(store, ThemisJobStore)
    assert store.path == db
    # Not a stub: the resolved store really persists and reads back a job.
    store.initialize()
    job = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=_scope(tmp_path),
        authorized=True,
    )
    assert store.get(job.job_id).state is JobState.QUEUED


def test_a_string_path_and_sqlite_and_file_urls_all_resolve_to_that_file(tmp_path: Path) -> None:
    target = tmp_path / "state" / "jobs.sqlite3"
    assert resolve_job_store(str(target)).path == target
    assert resolve_job_store(f"sqlite://{target}").path == target
    assert resolve_job_store(f"file:{target}").path == target


def test_a_postgres_dsn_is_refused_fail_closed() -> None:
    for dsn in ("postgresql://user:pw@db.internal/olympus", "postgres://db/olympus"):
        with pytest.raises(UnsupportedBackendError, match="DATA-2"):
            resolve_job_store(dsn)


def test_an_unknown_backend_scheme_is_refused() -> None:
    with pytest.raises(UnsupportedBackendError, match="unknown persistence backend"):
        resolve_job_store("mysql://db/olympus")


def test_describe_backend_names_the_backend_without_leaking_credentials() -> None:
    # Only the scheme is reported, never the user/password/host of a DSN.
    assert describe_backend(Path("/var/lib/olympus/jobs.sqlite3")) == "sqlite"
    assert describe_backend("jobs.sqlite3") == "sqlite"
    label = describe_backend("postgresql://user:secret@db.internal/olympus")
    assert "planned" in label and "secret" not in label and "db.internal" not in label
    assert describe_backend("mysql://x") == "mysql (unsupported)"


def test_sqlite_store_satisfies_the_jobstore_port(tmp_path: Path) -> None:
    # The structural contract a Postgres adapter would also have to implement.
    store = resolve_job_store(tmp_path / "jobs.sqlite3")
    assert isinstance(store, JobStore)

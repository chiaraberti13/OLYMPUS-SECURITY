"""Failure-injection tests for the durable AEGIS control plane."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import olympus.aegis.jobs as jobs_module
from olympus.aegis.jobs import AegisJobStore, JobState

_LEGACY_SCHEMA = """
CREATE TABLE aegis_jobs (
    job_id TEXT PRIMARY KEY,
    scanner TEXT NOT NULL,
    target TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    scope_path TEXT NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    result_json TEXT,
    error TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0
);
"""


def _scope(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.aegis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _submit(
    store: AegisJobStore,
    scope: Path,
    *,
    idempotency_key: str | None = None,
    max_attempts: int = 1,
):
    return store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
        idempotency_key=idempotency_key,
        max_attempts=max_attempts,
    )


def _expire_lease(database: Path, job_id: str) -> None:
    expired = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE aegis_jobs SET lease_expires_at = ? WHERE job_id = ?",
            (expired, job_id),
        )


def test_restart_recovers_one_job_without_duplication_or_terminal_state_loss(
    tmp_path: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    scope = _scope(tmp_path / "scope.json")
    before_crash = AegisJobStore(database, backoff_seconds=0.0)
    submitted = _submit(before_crash, scope, idempotency_key="restart-1", max_attempts=2)
    claimed = before_crash.claim_next("worker-before-crash")
    assert claimed is not None and claimed.job_id == submitted.job_id
    _expire_lease(database, submitted.job_id)

    after_restart = AegisJobStore(database, backoff_seconds=0.0)
    recovered = after_restart.recover_expired_leases()
    assert [job.job_id for job in recovered] == [submitted.job_id]
    replacement = after_restart.claim_next("worker-after-restart")
    assert replacement is not None and replacement.attempts == 2
    finished = after_restart.complete(
        submitted.job_id,
        worker_id="worker-after-restart",
        state=JobState.SUCCEEDED,
        result={"state": "live"},
    )

    final_restart = AegisJobStore(database, backoff_seconds=0.0)
    assert final_restart.recover_expired_leases() == []
    assert final_restart.get(submitted.job_id) == finished
    assert final_restart.get(submitted.job_id).state is JobState.SUCCEEDED
    assert [job.job_id for job in final_restart.list()] == [submitted.job_id]


def test_concurrent_idempotent_retries_create_exactly_one_job(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    scope = _scope(tmp_path / "scope.json")
    AegisJobStore(database).initialize()
    callers = 8
    start = threading.Barrier(callers)

    def submit_retry() -> str:
        start.wait(timeout=10)
        return _submit(AegisJobStore(database), scope, idempotency_key="request-retry-4711").job_id

    with ThreadPoolExecutor(max_workers=callers) as pool:
        job_ids = list(pool.map(lambda _: submit_retry(), range(callers)))

    assert len(set(job_ids)) == 1
    jobs = AegisJobStore(database).list()
    assert len(jobs) == 1 and jobs[0].job_id == job_ids[0]


def test_sqlite_writer_lock_serializes_a_claim_instead_of_losing_it(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    store = AegisJobStore(database)
    submitted = _submit(store, _scope(tmp_path / "scope.json"))

    locker = sqlite3.connect(database)
    locker.execute("BEGIN IMMEDIATE")
    locker.execute("UPDATE aegis_jobs SET updated_at = updated_at")
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            waiting_claim = pool.submit(store.claim_next, "waiting-worker")
            time.sleep(0.1)
            assert not waiting_claim.done(), "the competing writer did not wait for the lock"
            locker.commit()
            claimed = waiting_claim.result(timeout=5)
    finally:
        locker.close()

    assert claimed is not None and claimed.job_id == submitted.job_id
    assert claimed.worker_id == "waiting-worker" and claimed.attempts == 1
    assert store.claim_next("second-worker") is None


def test_interrupted_legacy_migration_rolls_back_and_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "legacy.sqlite3"
    stamp = datetime.now(UTC).isoformat()
    job_id = f"AEGIS-{'A' * 32}"
    with sqlite3.connect(database) as db:
        db.executescript(_LEGACY_SCHEMA)
        db.execute(
            """INSERT INTO aegis_jobs
            (job_id, scanner, target, target_kind, scope_path, authorized, state,
             created_at, updated_at)
            VALUES (?, 'test-engine', '127.0.0.1', 'host', ?, 1, 'queued', ?, ?)""",
            (job_id, str(tmp_path / "scope.json"), stamp, stamp),
        )

    original = jobs_module._execute_schema_statements

    def interrupt_after_first_ddl(db: sqlite3.Connection, statements: tuple[str, ...]) -> None:
        db.execute(statements[0])
        raise RuntimeError("simulated migration interruption")

    monkeypatch.setattr(jobs_module, "_execute_schema_statements", interrupt_after_first_ddl)
    store = AegisJobStore(database)
    with pytest.raises(RuntimeError, match="simulated migration interruption"):
        store.initialize()

    with sqlite3.connect(database) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(aegis_jobs)")}
        assert "idempotency_key" not in columns
        assert int(db.execute("PRAGMA user_version").fetchone()[0]) == 0
        assert db.execute("SELECT job_id FROM aegis_jobs").fetchone()[0] == job_id

    monkeypatch.setattr(jobs_module, "_execute_schema_statements", original)
    store.initialize()
    assert store.get(job_id).state is JobState.QUEUED
    with sqlite3.connect(database) as db:
        assert int(db.execute("PRAGMA user_version").fetchone()[0]) == jobs_module.SCHEMA_VERSION

"""SEC-E-01: durable audit survives restart, duplicates and competing writers."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from olympus.athena.adapters.audit import SqliteAuditSink
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.domain.assessment import Job, JobState
from olympus.athena.domain.audit import AuditEvent


def test_explicit_duplicate_cannot_replace_history(tmp_path: Path) -> None:
    repo = SqliteAssessmentRepository(tmp_path / "audit.db")
    try:
        repo.append_audit("A", 0, "t", "created", "planned", None, "{}")
        original = repo.audit_events("A")
        with pytest.raises(sqlite3.IntegrityError):
            repo.append_audit("A", 0, "t2", "recovered", "failed", None, "{}")
        assert repo.audit_events("A") == original
        SqliteAuditSink(repo).append(AuditEvent("A", 0, "t3", "cancelled", "cancelled"))
        assert [e["sequence"] for e in repo.audit_events("A")] == [0, 1]
    finally:
        repo.close()


def test_independent_writers_allocate_durable_sequences(tmp_path: Path) -> None:
    path = tmp_path / "audit.db"
    seed = SqliteAssessmentRepository(path)
    seed.append_audit("A", 7, "t", "original", "planned", None, "{}")
    original = seed.audit_events("A")
    seed.close()
    barrier = Barrier(2)

    def writer(name: str) -> None:
        repo = SqliteAssessmentRepository(path)
        try:
            barrier.wait(timeout=10)
            for _ in range(20):
                # A fresh producer may start its local sequence at zero.
                SqliteAuditSink(repo).append(AuditEvent("A", 0, "t", name, "ok"))
        finally:
            repo.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, name) for name in ("one", "two")]
        for future in futures:
            future.result(timeout=30)
    repo = SqliteAssessmentRepository(path)
    try:
        events = repo.audit_events("A")
        assert events[:1] == original
        assert [e["sequence"] for e in events] == list(range(7, 48))
        assert sum(e["action"] == "one" for e in events) == 20
        assert sum(e["action"] == "two" for e in events) == 20
        SqliteAuditSink(repo).append(AuditEvent("B", 99, "t", "new", "ok"))
        assert repo.audit_events("B")[0]["sequence"] == 0
    finally:
        repo.close()


def test_job_transition_and_audit_rollback_together_on_audit_failure(tmp_path: Path) -> None:
    repo = SqliteAssessmentRepository(tmp_path / "atomic.db")
    repo._conn.executescript(
        "INSERT INTO plans VALUES ('P', '{}');"
        "INSERT INTO assessments VALUES ('A', 'P', 'running');"
        "INSERT INTO jobs VALUES ('J', 'A', 0, 'dns', 'domain', 'example.test', "
        "'queued', NULL, NULL);"
        "CREATE TRIGGER reject_audit BEFORE INSERT ON audit "
        "BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;"
    )
    job = Job(job_id="J", adapter="dns", target_kind="domain", target_value="example.test")
    event = AuditEvent("A", 0, "t", "job_started", "running", "J", {"adapter": "dns"})
    try:
        with pytest.raises(sqlite3.IntegrityError, match="injected audit failure"):
            repo.transition_job_with_audit("A", job, JobState.RUNNING, event)
        row = repo._conn.execute("SELECT state FROM jobs WHERE job_id = 'J'").fetchone()
        assert row["state"] == "queued"
        assert repo.audit_events("A") == []

        repo._conn.execute("DROP TRIGGER reject_audit")
        repo.transition_job_with_audit("A", job, JobState.RUNNING, event)
        row = repo._conn.execute("SELECT state FROM jobs WHERE job_id = 'J'").fetchone()
        assert row["state"] == "running"
        assert repo.audit_events("A")[0]["action"] == "job_started"
    finally:
        repo.close()

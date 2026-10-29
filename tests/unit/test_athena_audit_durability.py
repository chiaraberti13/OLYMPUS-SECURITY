"""SEC-E-01: durable audit survives restart, duplicates and competing writers."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from olympus.athena.adapters.audit import SqliteAuditSink
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
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

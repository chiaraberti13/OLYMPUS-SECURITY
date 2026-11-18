"""Deterministic coverage for the offline concurrency benchmark's diagnostics.

Real write contention is timing-dependent and may not reproduce on every run, so
these tests exercise the *diagnostic* machinery on temporary data rather than
racing processes: the per-failure detail (synthetic request id, writer, and the
SQLite error code/name when present) and the submitted-vs-present reconciliation
that must flag any missing or duplicate request. A benign single-process run is
also checked end to end so the healthy path reports ``ok`` with no discrepancy.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path

from scripts.benchmark_themis_concurrency import (
    _failure_detail,
    _present_key_counts,
    _reconcile,
    run,
)

from olympus.themis.jobs import ThemisJobStore


def _busy_error(tmp_path: Path) -> sqlite3.OperationalError:
    """Trigger a real SQLITE_BUSY by contending for the single writer lock."""
    database = tmp_path / "busy.sqlite3"
    holder = sqlite3.connect(database, isolation_level=None)
    holder.execute("CREATE TABLE t(x)")
    holder.execute("BEGIN IMMEDIATE")
    other = sqlite3.connect(database, isolation_level=None)
    other.execute("PRAGMA busy_timeout = 0")
    try:
        other.execute("BEGIN IMMEDIATE")
        raise AssertionError("expected SQLITE_BUSY but the lock was not contended")
    except sqlite3.OperationalError as exc:
        return exc
    finally:
        holder.close()
        other.close()


def test_failure_detail_captures_the_sqlite_busy_code_and_name(tmp_path: Path) -> None:
    detail = _failure_detail("bench:3:7", 3, _busy_error(tmp_path))
    assert detail["request_id"] == "bench:3:7"
    assert detail["writer"] == 3
    assert detail["error_type"] == "OperationalError"
    assert detail["sqlite_errorcode"] == 5
    assert detail["sqlite_errorname"] == "SQLITE_BUSY"


def test_failure_detail_reads_a_wrapped_sqlite_cause(tmp_path: Path) -> None:
    wrapper = RuntimeError("submission failed")
    wrapper.__cause__ = _busy_error(tmp_path)
    detail = _failure_detail("bench:0:0", 0, wrapper)
    assert detail["error_type"] == "RuntimeError"
    assert detail["sqlite_errorcode"] == 5
    assert detail["sqlite_errorname"] == "SQLITE_BUSY"


def test_failure_detail_without_sqlite_codes_stays_honest() -> None:
    detail = _failure_detail("bench:1:2", 1, ValueError("not a sqlite error"))
    assert detail["error_type"] == "ValueError"
    assert detail["sqlite_errorcode"] is None
    assert detail["sqlite_errorname"] is None


def test_reconcile_flags_missing_duplicate_and_unexpected() -> None:
    submitted = {"bench:0:0", "bench:0:1", "bench:0:2"}
    present = Counter({"bench:0:0": 1, "bench:0:1": 2, "bench:9:9": 1})
    report = _reconcile(submitted, present)

    assert report["submitted"] == 3
    assert report["present"] == 4  # 1 + 2 + 1
    assert report["distinct_present"] == 3
    assert report["missing"] == ["bench:0:2"]
    assert report["missing_count"] == 1
    assert report["duplicate"] == [{"request_id": "bench:0:1", "count": 2}]
    assert report["duplicate_count"] == 1
    assert report["unexpected"] == ["bench:9:9"]
    assert report["unexpected_count"] == 1


def test_reconcile_is_clean_when_every_request_landed_once() -> None:
    submitted = {"bench:0:0", "bench:0:1"}
    report = _reconcile(submitted, Counter({"bench:0:0": 1, "bench:0:1": 1}))
    assert report["missing_count"] == 0
    assert report["duplicate_count"] == 0
    assert report["unexpected_count"] == 0


def _scope_file(tmp_path: Path) -> Path:
    scope = tmp_path / "scope.json"
    scope.write_text(
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
    return scope


def test_present_key_counts_reads_stored_idempotency_keys(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    store = ThemisJobStore(database)
    scope = _scope_file(tmp_path)
    for index in range(2):
        store.submit(
            scanner="benchmark",
            target="127.0.0.1",
            target_kind="host",
            scope_path=scope,
            authorized=True,
            idempotency_key=f"bench:0:{index}",
        )

    present = _present_key_counts(database)
    assert present == Counter({"bench:0:0": 1, "bench:0:1": 1})

    # A request that was submitted but is absent from the store is reported missing.
    reconciliation = _reconcile({"bench:0:0", "bench:0:1", "bench:0:2"}, present)
    assert reconciliation["missing"] == ["bench:0:2"]


def test_benign_single_process_run_reports_ok_without_discrepancy() -> None:
    report = run(processes=1, jobs_per_process=5, migrate_first=True)
    assert report["ok"] is True
    assert report["jobs_requested"] == 5
    assert report["jobs_persisted"] == 5
    assert report["errors"] == {}
    assert report["submission_failures"] == []
    assert report["reconciliation"]["missing_count"] == 0
    assert report["reconciliation"]["duplicate_count"] == 0
    assert report["reconciliation"]["unexpected_count"] == 0
    assert report["migrated_before_writers"] is True

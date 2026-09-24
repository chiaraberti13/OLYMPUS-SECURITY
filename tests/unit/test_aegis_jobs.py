from __future__ import annotations

import json
import socket
import sqlite3
import stat
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.aegis.application import AegisApplicationService
from olympus.aegis.base import ScannerAdapter
from olympus.aegis.jobs import (
    ACTIVE_STATES,
    SCHEMA_VERSION,
    TERMINAL_STATES,
    AegisJob,
    AegisJobStore,
    AegisWorker,
    IdempotencyConflict,
    JobState,
    LeaseLostError,
    SchemaVersionError,
    classify_result,
    redact_error,
)
from olympus.aegis.model import ScanRequest, ScanResult
from olympus.aegis.runner import CommandOutput, TerminationCause, TerminationReport
from olympus.aegis.states import ExecutionState
from olympus.cli import app
from olympus.core.execution import CancellationRequested

runner = CliRunner()


class _Adapter(ScannerAdapter):
    name = "test-engine"
    binary = "true"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        return ["true"]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list:
        return []


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


def test_durable_job_lifecycle(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "state" / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"),
        authorized=True,
    )
    assert job.state is JobState.QUEUED
    worker = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Adapter()),
        live_scans=True,
    )
    completed = worker.run_next(audit_path=tmp_path / "audit.ndjson")
    assert completed is not None and completed.state is JobState.SUCCEEDED
    assert completed.result is not None and completed.result["state"] == "live"
    assert store.get(job.job_id) == completed
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_atomic_claim_and_queue_order(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    scope = _scope(tmp_path / "scope.json")
    first = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
    )
    store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
    )
    claimed = store.claim_next()
    assert claimed is not None and claimed.job_id == first.job_id
    assert store.list(state=JobState.RUNNING) == [claimed]


def test_queued_cancel_is_terminal_and_idempotent(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"),
        authorized=True,
    )
    cancelled = store.cancel(job.job_id)
    assert cancelled.state is JobState.CANCELLED
    assert store.cancel(job.job_id) == cancelled
    assert store.claim_next() is None


def test_failure_is_persisted_without_secret_fields(tmp_path: Path) -> None:
    class _Broken(_Adapter):
        def run(self, request: ScanRequest):
            raise RuntimeError("controlled failure")

    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine",
        target="127.0.0.1",
        target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"),
        authorized=True,
    )
    result = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Broken()),
        live_scans=True,
    ).run_next()
    assert result is not None and result.state is JobState.FAILED
    assert result.error == "RuntimeError: controlled failure"
    assert job.job_id == result.job_id


def test_store_rejects_symlink_database(tmp_path: Path) -> None:
    target = tmp_path / "real.sqlite3"
    target.touch()
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(OSError, match="non-symlink"):
        AegisJobStore(link).initialize()


def test_job_cli_submit_list_status_cancel(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    scope = _scope(tmp_path / "scope.json")
    submitted = runner.invoke(
        app,
        [
            "aegis",
            "jobs",
            "submit",
            "nmap",
            "--target",
            "127.0.0.1",
            "--scope",
            str(scope),
            "--database",
            str(database),
            "--i-am-authorized",
        ],
    )
    assert submitted.exit_code == 0, submitted.output
    job_id = json.loads(submitted.output)["job_id"]
    listed = runner.invoke(app, ["aegis", "jobs", "list", "-d", str(database)])
    assert listed.exit_code == 0 and json.loads(listed.output)["count"] == 1
    status = runner.invoke(app, ["aegis", "jobs", "status", job_id, "-d", str(database)])
    assert status.exit_code == 0 and json.loads(status.output)["state"] == "queued"
    cancelled = runner.invoke(app, ["aegis", "jobs", "cancel", job_id, "-d", str(database)])
    assert cancelled.exit_code == 0 and json.loads(cancelled.output)["state"] == "cancelled"


def test_job_cli_refuses_unconfirmed_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "aegis",
            "jobs",
            "submit",
            "nmap",
            "--target",
            "127.0.0.1",
            "--scope",
            str(_scope(tmp_path / "scope.json")),
            "--database",
            str(tmp_path / "jobs.sqlite3"),
        ],
    )
    assert result.exit_code == 4
    assert "requires --i-am-authorized" in result.output


# --------------------------------------------------------------------------- #
# Leases, ownership and orphan recovery
# --------------------------------------------------------------------------- #
def _submit(store: AegisJobStore, tmp_path: Path, **overrides: object) -> AegisJob:
    arguments: dict[str, object] = {
        "scanner": "test-engine",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_path": _scope(tmp_path / "scope.json"),
        "authorized": True,
    }
    arguments.update(overrides)
    return store.submit(**arguments)  # type: ignore[arg-type]


def _expire_lease(store: AegisJobStore, job_id: str) -> None:
    """Age a lease out, exactly as a worker that stopped reporting would."""
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE aegis_jobs SET lease_expires_at = ? WHERE job_id = ?", (past, job_id))


def test_claim_leases_the_job_to_exactly_one_worker(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    claimed = store.claim_next("worker-a")
    assert claimed is not None
    assert claimed.worker_id == "worker-a"
    assert claimed.attempts == 1
    assert claimed.lease_expires_at is not None
    assert store.claim_next("worker-b") is None


def test_heartbeat_extends_a_lease_only_for_its_owner(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    claimed = store.claim_next("worker-a")
    assert claimed is not None and claimed.lease_expires_at is not None
    renewed = store.heartbeat(claimed.job_id, "worker-a")
    assert renewed.lease_expires_at is not None
    assert renewed.lease_expires_at >= claimed.lease_expires_at
    assert renewed.heartbeat_at is not None
    with pytest.raises(LeaseLostError):
        store.heartbeat(claimed.job_id, "worker-b")


def test_a_terminal_transition_requires_the_current_lease(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    claimed = store.claim_next("worker-a")
    assert claimed is not None
    with pytest.raises(LeaseLostError):
        store.fail(claimed.job_id, worker_id="worker-b", error="not mine to fail")
    assert store.get(claimed.job_id).state is JobState.RUNNING


def test_worker_id_is_validated(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    with pytest.raises(ValueError, match="worker_id"):
        store.claim_next("worker id with spaces")


def test_an_abandoned_lease_is_requeued_while_attempts_remain(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=0.0)
    job = _submit(store, tmp_path, max_attempts=2)
    claimed = store.claim_next("worker-a")
    assert claimed is not None
    _expire_lease(store, job.job_id)

    recovered = store.recover_expired_leases()
    assert [item.job_id for item in recovered] == [job.job_id]
    requeued = store.get(job.job_id)
    assert requeued.state is JobState.QUEUED
    assert requeued.worker_id is None
    assert requeued.error is not None and "lease expired" in requeued.error
    # The recovered job is claimable again, and the attempt counter advances.
    second = store.claim_next("worker-b")
    assert second is not None and second.job_id == job.job_id and second.attempts == 2


def test_an_abandoned_lease_fails_when_the_attempt_budget_is_spent(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = _submit(store, tmp_path)  # max_attempts defaults to 1
    store.claim_next("worker-a")
    _expire_lease(store, job.job_id)

    recovered = store.recover_expired_leases()
    assert recovered and recovered[0].state is JobState.FAILED
    assert "lease expired" in (recovered[0].error or "")
    assert store.get(job.job_id).finished_at is not None


def test_claiming_recovers_abandoned_work_before_taking_new_work(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=0.0)
    job = _submit(store, tmp_path, max_attempts=2)
    store.claim_next("worker-a")
    _expire_lease(store, job.job_id)

    reclaimed = store.claim_next("worker-b")
    assert reclaimed is not None and reclaimed.job_id == job.job_id
    assert reclaimed.worker_id == "worker-b"


def test_worker_renews_its_lease_while_a_scan_runs(tmp_path: Path) -> None:
    class _Slow(_Adapter):
        def run(self, request: ScanRequest) -> ScanResult:
            time.sleep(0.3)
            return ScanResult(scanner=self.name, state=ExecutionState.LIVE, target=request.target)

    store = AegisJobStore(tmp_path / "jobs.sqlite3", lease_seconds=1.0)
    _submit(store, tmp_path)
    finished = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Slow()),
        live_scans=True,
        heartbeat_seconds=0.05,
    ).run_next()
    assert finished is not None and finished.state is JobState.SUCCEEDED
    assert finished.started_at is not None and finished.heartbeat_at is not None
    assert finished.heartbeat_at > finished.started_at, "the lease was never renewed"


def test_a_worker_that_loses_its_lease_stops_and_reports_the_new_owner(
    tmp_path: Path,
) -> None:
    started = threading.Event()

    class _Blocking(_Adapter):
        def run(self, request: ScanRequest) -> ScanResult:
            started.set()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if request.cancellation.is_cancelled():
                    raise CancellationRequested("lease lost")
                time.sleep(0.02)
            raise AssertionError("the worker was never told to stop")

    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=0.0)
    job = _submit(store, tmp_path, max_attempts=2)
    worker = AegisWorker(
        store,
        AegisApplicationService(lambda name: _Blocking()),
        live_scans=True,
        worker_id="worker-a",
        heartbeat_seconds=0.05,
    )
    outcome: list[AegisJob | None] = []
    thread = threading.Thread(target=lambda: outcome.append(worker.run_next()))
    thread.start()
    assert started.wait(timeout=5)

    # The job is taken over exactly as an orphan-recovery run would take it.
    _expire_lease(store, job.job_id)
    stolen = store.claim_next("worker-b")
    assert stolen is not None and stolen.worker_id == "worker-b"

    thread.join(timeout=10)
    assert not thread.is_alive(), "the worker kept scanning after losing its lease"
    # The first worker must not overwrite the new owner's state.
    assert store.get(job.job_id).worker_id == "worker-b"
    assert store.get(job.job_id).state is JobState.RUNNING
    assert outcome and outcome[0] is not None and outcome[0].worker_id == "worker-b"


# --------------------------------------------------------------------------- #
# Retry budget, backoff and idempotency
# --------------------------------------------------------------------------- #
def test_a_timed_out_job_is_retried_until_its_budget_is_spent(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=0.0)
    job = _submit(store, tmp_path, max_attempts=2)
    first = store.claim_next("worker-a")
    assert first is not None
    retried = store.complete(
        job.job_id, worker_id="worker-a", state=JobState.TIMED_OUT, error="deadline exceeded"
    )
    assert retried.state is JobState.QUEUED
    assert retried.attempts == 1 and retried.error == "deadline exceeded"

    store.claim_next("worker-a")
    final = store.complete(
        job.job_id, worker_id="worker-a", state=JobState.TIMED_OUT, error="deadline exceeded"
    )
    assert final.state is JobState.TIMED_OUT
    assert final.attempts == 2 and final.finished_at is not None


def test_outcomes_that_will_not_change_are_never_retried(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=0.0)
    for state in (JobState.FAILED, JobState.POLICY_DENIED, JobState.PARTIAL):
        job = _submit(store, tmp_path, max_attempts=3, idempotency_key=f"key-{state.value}")
        store.claim_next("worker-a")
        settled = store.complete(job.job_id, worker_id="worker-a", state=state, error="no")
        assert settled.state is state
        assert settled.attempts == 1, f"{state} must not consume more than one attempt"


def test_retry_backoff_grows_and_stays_capped() -> None:
    store = AegisJobStore(Path("unused.sqlite3"), backoff_seconds=1.0, max_backoff_seconds=10.0)
    assert 1.0 <= store.backoff_for(1) < 1.3
    assert store.backoff_for(1) < store.backoff_for(4)
    assert store.backoff_for(9) <= 10.0 * 1.25


def test_a_requeued_job_waits_for_its_backoff_before_being_claimed(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3", backoff_seconds=60.0)
    job = _submit(store, tmp_path, max_attempts=2)
    store.claim_next("worker-a")
    requeued = store.complete(job.job_id, worker_id="worker-a", state=JobState.TIMED_OUT)
    assert requeued.state is JobState.QUEUED
    assert requeued.available_at > requeued.updated_at
    assert store.claim_next("worker-b") is None, "backoff must be respected"


def test_an_idempotency_key_makes_resubmission_safe(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    first = _submit(store, tmp_path, idempotency_key="ticket-4711")
    second = _submit(store, tmp_path, idempotency_key="ticket-4711")
    assert first.job_id == second.job_id
    assert len(store.list()) == 1


def test_reusing_a_key_for_a_different_request_is_refused(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path, idempotency_key="ticket-4711")
    with pytest.raises(IdempotencyConflict, match="ticket-4711"):
        _submit(store, tmp_path, target="127.0.0.2", idempotency_key="ticket-4711")


def test_malformed_idempotency_keys_and_budgets_are_rejected(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    with pytest.raises(ValueError, match="idempotency_key"):
        _submit(store, tmp_path, idempotency_key="not a key")
    with pytest.raises(ValueError, match="max_attempts"):
        _submit(store, tmp_path, max_attempts=99)


# --------------------------------------------------------------------------- #
# Schema versioning and migration
# --------------------------------------------------------------------------- #
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


def test_a_pre_versioning_database_is_migrated_without_losing_jobs(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"
    stamp = datetime.now(UTC).isoformat()
    with sqlite3.connect(database) as db:
        db.executescript(_LEGACY_SCHEMA)
        db.execute(
            """INSERT INTO aegis_jobs
            (job_id, scanner, target, target_kind, scope_path, authorized, state,
             created_at, updated_at)
            VALUES (?, 'test-engine', '127.0.0.1', 'host', ?, 1, 'queued', ?, ?)""",
            (f"AEGIS-{'A' * 32}", str(tmp_path / "scope.json"), stamp, stamp),
        )

    store = AegisJobStore(database)
    store.initialize()
    with sqlite3.connect(database) as db:
        assert int(db.execute("PRAGMA user_version").fetchone()[0]) == SCHEMA_VERSION

    migrated = store.get(f"AEGIS-{'A' * 32}")
    assert migrated.state is JobState.QUEUED
    assert migrated.attempts == 0 and migrated.max_attempts == 1
    assert migrated.available_at is not None
    # A migrated job is immediately claimable: its backfilled availability is
    # its creation time, not the epoch default used to satisfy NOT NULL.
    claimed = store.claim_next("worker-a")
    assert claimed is not None and claimed.job_id == migrated.job_id


def test_a_database_from_a_newer_release_is_refused(tmp_path: Path) -> None:
    database = tmp_path / "future.sqlite3"
    store = AegisJobStore(database)
    store.initialize()
    with sqlite3.connect(database) as db:
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(SchemaVersionError, match="upgrade Olympus"):
        store.get("AEGIS-" + "A" * 32)


def test_the_store_uses_write_ahead_logging_and_a_busy_timeout(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    store.initialize()
    with sqlite3.connect(store.path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    # A reader must not be blocked out while a writer holds a transaction.
    _submit(store, tmp_path)
    with sqlite3.connect(store.path) as writer:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE aegis_jobs SET updated_at = updated_at")
        assert len(store.list()) == 1
        writer.rollback()


# --------------------------------------------------------------------------- #
# One state means one thing
# --------------------------------------------------------------------------- #
def test_scan_outcomes_map_onto_distinct_job_states() -> None:
    def result(state: ExecutionState, **kw: object) -> ScanResult:
        return ScanResult(scanner="test-engine", state=state, target="127.0.0.1", **kw)  # type: ignore[arg-type]

    assert classify_result(result(ExecutionState.LIVE))[0] is JobState.SUCCEEDED
    assert classify_result(result(ExecutionState.SIMULATION))[0] is JobState.SUCCEEDED
    assert classify_result(result(ExecutionState.UNAVAILABLE))[0] is JobState.PARTIAL
    assert classify_result(result(ExecutionState.DISABLED))[0] is JobState.PARTIAL
    assert classify_result(result(ExecutionState.FAILED))[0] is JobState.FAILED
    timed_out = result(
        ExecutionState.FAILED,
        termination=TerminationReport(cause=TerminationCause.TIMEOUT, detail="slow"),
    )
    assert classify_result(timed_out)[0] is JobState.TIMED_OUT


def test_out_of_scope_work_is_denied_not_failed(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path, target="10.11.12.13")
    outcome = AegisWorker(
        store, AegisApplicationService(lambda name: _Adapter()), live_scans=True
    ).run_next()
    assert outcome is not None and outcome.state is JobState.POLICY_DENIED
    assert outcome.result is None


def test_a_missing_scanner_is_partial_not_failed(tmp_path: Path) -> None:
    class _Missing(_Adapter):
        binary = "definitely-not-a-real-binary-xyz"

    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    outcome = AegisWorker(
        store, AegisApplicationService(lambda name: _Missing()), live_scans=True
    ).run_next()
    assert outcome is not None and outcome.state is JobState.PARTIAL
    assert outcome.error is not None and "not installed" in outcome.error


def test_disabled_live_scanning_is_partial_not_success(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    outcome = AegisWorker(
        store, AegisApplicationService(lambda name: _Adapter()), live_scans=False
    ).run_next()
    assert outcome is not None and outcome.state is JobState.PARTIAL


def test_cancelled_running_work_is_cancelled_not_failed(tmp_path: Path) -> None:
    class _Cancelling(_Adapter):
        def run(self, request: ScanRequest) -> ScanResult:
            raise CancellationRequested("operation cancelled")

    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    outcome = AegisWorker(
        store, AegisApplicationService(lambda name: _Cancelling()), live_scans=True
    ).run_next()
    assert outcome is not None and outcome.state is JobState.CANCELLED


# --------------------------------------------------------------------------- #
# What gets persisted and published
# --------------------------------------------------------------------------- #
def test_persisted_errors_drop_secrets_and_server_paths() -> None:
    redacted = redact_error(
        "could not read /srv/olympus/engagements/acme/scope.json while fetching "
        "https://api.test/scan?api_key=super-secret"
    )
    assert "/srv/olympus/engagements/acme" not in redacted
    assert "[path]/scope.json" in redacted
    assert "super-secret" not in redacted
    assert "[REDACTED]" in redacted


def test_a_url_is_not_mistaken_for_a_filesystem_path() -> None:
    assert "https://example.test/a/b" in redact_error("fetch failed: https://example.test/a/b")


def test_the_job_document_never_publishes_the_scope_path(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = _submit(store, tmp_path)
    document = job.model_dump(mode="json")
    assert document["schema_version"] == "2.0.0"
    assert "scope_path" not in document
    assert document["scope_name"] == "scope.json"
    assert str(tmp_path) not in json.dumps(document)
    # The worker still gets the real path it needs to load the scope.
    assert store.execution_record(job.job_id).scope_path == (tmp_path / "scope.json").resolve()


def test_credentials_in_a_target_url_are_not_republished(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = _submit(
        store,
        tmp_path,
        target="https://app.example.test/status?api_key=super-secret",
        target_kind="url",
    )
    assert "super-secret" not in job.target
    assert "[REDACTED]" in job.target
    # The scanner is still run against the target exactly as submitted.
    assert store.execution_record(job.job_id).target.endswith("api_key=super-secret")


def test_worker_identity_does_not_leak_the_host(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    _submit(store, tmp_path)
    claimed = store.claim_next()
    assert claimed is not None and claimed.worker_id is not None
    assert claimed.worker_id.startswith("aegis-")
    assert socket.gethostname().lower() not in claimed.worker_id.lower()


def test_recover_cli_reports_what_it_requeued(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    store = AegisJobStore(database)
    job = _submit(store, tmp_path)
    store.claim_next("worker-a")
    _expire_lease(store, job.job_id)

    recovered = runner.invoke(app, ["aegis", "jobs", "recover", "-d", str(database)])
    assert recovered.exit_code == 0, recovered.output
    payload = json.loads(recovered.output)
    assert payload["recovered"] == 1
    assert payload["jobs"][0]["state"] == "failed"


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #
def test_every_job_state_is_either_active_or_terminal() -> None:
    """A new state must be classified, or retention and recovery would skip it."""
    assert set(JobState) == ACTIVE_STATES | TERMINAL_STATES
    assert not ACTIVE_STATES & TERMINAL_STATES


def _finish(store: AegisJobStore, tmp_path: Path, *, key: str) -> AegisJob:
    job = _submit(store, tmp_path, idempotency_key=key)
    store.claim_next("worker-a")
    return store.complete(
        job.job_id, worker_id="worker-a", state=JobState.SUCCEEDED, result={"state": "live"}
    )


def _age_job(store: AegisJobStore, job_id: str, days: int) -> None:
    stamp = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with sqlite3.connect(store.path) as db:
        db.execute(
            "UPDATE aegis_jobs SET finished_at = ?, updated_at = ? WHERE job_id = ?",
            (stamp, stamp, job_id),
        )


def test_finished_jobs_are_pruned_past_the_retention_window(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    old = _finish(store, tmp_path, key="old")
    recent = _finish(store, tmp_path, key="recent")
    _age_job(store, old.job_id, 90)

    count, pruned = store.prune(older_than_days=30)

    assert count == 1 and pruned == (old.job_id,)
    with pytest.raises(KeyError):
        store.get(old.job_id)
    assert store.get(recent.job_id).state is JobState.SUCCEEDED


def test_pruning_never_removes_queued_or_running_work(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    queued = _submit(store, tmp_path, idempotency_key="queued")
    running = _submit(store, tmp_path, idempotency_key="running")
    store.claim_next("worker-a")
    for job_id in (queued.job_id, running.job_id):
        _age_job(store, job_id, 400)

    count, _ = store.prune(older_than_days=1)

    assert count == 0
    assert {job.job_id for job in store.list()} == {queued.job_id, running.job_id}


def test_a_pruning_dry_run_changes_nothing(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    old = _finish(store, tmp_path, key="old")
    _age_job(store, old.job_id, 90)

    count, pruned = store.prune(older_than_days=30, dry_run=True)

    assert count == 1 and pruned == (old.job_id,)
    assert store.get(old.job_id).job_id == old.job_id


def test_pruned_content_does_not_linger_in_the_database_file(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="test-engine",
        target="secret-host.internal.example",
        target_kind="host",
        scope_path=_scope(tmp_path / "scope.json"),
        authorized=True,
    )
    store.claim_next("worker-a")
    store.complete(job.job_id, worker_id="worker-a", state=JobState.SUCCEEDED, result={})
    _age_job(store, job.job_id, 90)
    assert b"secret-host.internal.example" in store.path.read_bytes()

    store.prune(older_than_days=30)

    assert b"secret-host.internal.example" not in store.path.read_bytes()


def test_prune_validates_its_window(tmp_path: Path) -> None:
    store = AegisJobStore(tmp_path / "jobs.sqlite3")
    with pytest.raises(ValueError, match="older_than_days"):
        store.prune(older_than_days=99_999)


def test_prune_cli_reports_what_it_removed(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    store = AegisJobStore(database)
    old = _finish(store, tmp_path, key="old")
    _age_job(store, old.job_id, 90)

    result = runner.invoke(
        app,
        ["aegis", "jobs", "prune", "-d", str(database), "--older-than-days", "30"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["pruned"] == 1 and payload["job_ids"] == [old.job_id]

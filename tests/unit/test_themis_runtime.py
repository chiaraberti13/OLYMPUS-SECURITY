from __future__ import annotations

import json
import signal
import sqlite3
from pathlib import Path

import pytest

from olympus.core.execution import Cancellation, CancellationRequested
from olympus.themis.jobs import SCHEMA_VERSION, JobState, SchemaVersionError, ThemisJobStore
from olympus.themis.model import ScanResult
from olympus.themis.runtime import WorkerStop, migrate_jobs, work_queue, worker_signals
from olympus.themis.states import ExecutionState


def test_native_migration_is_idempotent_and_retains_jobs(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    assert migrate_jobs(database).to_dict() == {
        "previous_version": None,
        "schema_version": SCHEMA_VERSION,
        "migrated": True,
    }
    store = ThemisJobStore(database)
    job = store.submit(
        scanner="nmap",
        target="127.0.0.1",
        target_kind="host",
        scope_path=tmp_path / "scope.json",
        authorized=True,
    )
    assert migrate_jobs(database).to_dict()["migrated"] is False
    assert store.get(job.job_id) == job


def test_migration_refuses_foreign_database_without_changing_it(tmp_path: Path) -> None:
    database = tmp_path / "vap.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE scans (evidence TEXT)")
        db.execute("INSERT INTO scans VALUES ('preserve this evidence')")
    original = database.read_bytes()
    with pytest.raises(SchemaVersionError, match="legacy database"):
        migrate_jobs(database)
    assert database.read_bytes() == original


@pytest.mark.parametrize("version", [1, SCHEMA_VERSION + 1])
def test_unknown_versions_are_not_relabelled(tmp_path: Path, version: int) -> None:
    database = tmp_path / "jobs.sqlite3"
    ThemisJobStore(database).initialize()
    with sqlite3.connect(database) as db:
        db.execute(f"PRAGMA user_version = {version}")
    with pytest.raises(SchemaVersionError):
        migrate_jobs(database)
    with sqlite3.connect(database) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == version


def test_missing_current_schema_and_symlinks_are_refused(tmp_path: Path) -> None:
    database = tmp_path / "invalid.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    with pytest.raises(SchemaVersionError, match="missing"):
        migrate_jobs(database)
    link = tmp_path / "link.sqlite3"
    try:
        link.symlink_to(database)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError, match="symlink"):
        migrate_jobs(link)


def test_worker_shutdown_leaves_unclaimed_work_queued(tmp_path: Path) -> None:
    from olympus.themis.jobs import ThemisWorker

    store = ThemisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="nmap",
        target="127.0.0.1",
        target_kind="host",
        scope_path=tmp_path / "scope.json",
        authorized=True,
    )
    stop = WorkerStop()
    stop.cancel()
    worker = ThemisWorker(store, live_scans=False)
    assert worker.run_next(cancellation=stop) is None
    assert store.get(job.job_id).state is JobState.QUEUED
    assert store.get(job.job_id).attempts == 0


@pytest.mark.parametrize("raises", [False, True])
def test_worker_propagates_shutdown_to_active_execution(tmp_path: Path, raises: bool) -> None:
    from olympus.themis.application import ThemisRunRequest
    from olympus.themis.jobs import ThemisWorker

    store = ThemisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="nmap",
        target="127.0.0.1",
        target_kind="host",
        scope_path=tmp_path / "scope.json",
        authorized=True,
    )
    stop = WorkerStop()

    class Application:
        def run(self, request: ThemisRunRequest) -> ScanResult:
            assert request.cancellation is not None
            assert not request.cancellation.is_cancelled()
            stop.cancel()
            assert request.cancellation.is_cancelled()
            if raises:
                raise CancellationRequested("worker shutdown")
            return ScanResult(scanner="nmap", target="127.0.0.1", state=ExecutionState.LIVE)

    worker = ThemisWorker(store, application=Application())  # type: ignore[arg-type]
    final = worker.run_next(cancellation=stop)
    assert final is not None and final.state is JobState.CANCELLED
    assert store.get(job.job_id).state is JobState.CANCELLED


def test_queue_wait_is_interruptible_and_does_not_busy_spin() -> None:
    stop = WorkerStop()

    class EmptyWorker:
        calls = 0

        def run_next(self, **kwargs: object) -> None:
            self.calls += 1
            stop.cancel()

    worker = EmptyWorker()
    result = work_queue(worker, stop, audit_path=None, poll_seconds=30, on_job=lambda job: None)
    assert worker.calls == 1 and result.stopped and result.processed == 0


def test_queue_continues_after_failed_job(tmp_path: Path) -> None:
    from olympus.themis.jobs import ThemisJob

    store = ThemisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="nmap",
        target="127.0.0.1",
        target_kind="host",
        scope_path=tmp_path / "scope.json",
        authorized=True,
    ).model_copy(update={"state": JobState.FAILED})
    stop = WorkerStop()
    observed: list[ThemisJob] = []

    class Worker:
        calls = 0

        def run_next(
            self, *, audit_path: Path | None = None, cancellation: Cancellation | None = None
        ) -> ThemisJob | None:
            self.calls += 1
            if self.calls == 1:
                return job
            stop.cancel()
            return None

    worker = Worker()
    result = work_queue(worker, stop, audit_path=None, on_job=observed.append)
    assert worker.calls == 2 and observed == [job]
    assert result.processed == 1 and result.stopped


@pytest.mark.parametrize("interval", [0, 31, float("nan")])
def test_queue_refuses_unbounded_polling(interval: float) -> None:
    from olympus.themis.jobs import ThemisWorker

    with pytest.raises(ValueError, match="poll_seconds"):
        work_queue(
            ThemisWorker(ThemisJobStore(Path("unused"))),
            WorkerStop(),
            audit_path=None,
            poll_seconds=interval,
            on_job=lambda job: None,
        )


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM])
def test_signal_handlers_cancel_and_are_restored(number: signal.Signals) -> None:
    previous = signal.getsignal(number)
    stop = WorkerStop()
    with worker_signals(stop):
        handler = signal.getsignal(number)
        assert callable(handler)
        handler(number, None)
        assert stop.is_cancelled()
    assert signal.getsignal(number) is previous


def test_default_worker_never_generates_live_traffic(tmp_path: Path) -> None:
    from olympus.themis.jobs import ThemisWorker

    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
            }
        )
    )
    store = ThemisJobStore(tmp_path / "jobs.sqlite3")
    store.submit(
        scanner="nmap",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
    )
    final = ThemisWorker(store, live_scans=False).run_next()
    assert final is not None and final.state is JobState.PARTIAL
    assert final.result is not None and final.result["findings"] == []

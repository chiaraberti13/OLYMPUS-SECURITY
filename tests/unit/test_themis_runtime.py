from __future__ import annotations

import json
import signal
import sqlite3
from pathlib import Path

import pytest

from olympus.core.enums import Severity, Source
from olympus.core.execution import Cancellation, CancellationRequested
from olympus.core.models import Finding
from olympus.core.notifications import NotificationKind
from olympus.themis.jobs import (
    SCHEMA_VERSION,
    JobState,
    SchemaVersionError,
    ThemisJob,
    ThemisJobStore,
)
from olympus.themis.model import ScanResult
from olympus.themis.runtime import (
    MAX_FINDING_NOTIFICATIONS,
    WorkerStop,
    finding_notifications,
    job_notifier,
    migrate_jobs,
    notification_from_themis_job,
    work_queue,
    worker_signals,
)
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


def _terminal_job(state: JobState = JobState.SUCCEEDED, *, error: str | None = None) -> ThemisJob:
    from datetime import UTC, datetime

    moment = datetime(2026, 1, 1, tzinfo=UTC)
    return ThemisJob(
        job_id="THEMIS-" + "A" * 32,
        scanner="nmap",
        target="10.0.0.1",
        target_kind="host",
        scope_name="lab",
        state=state,
        authorized=True,
        attempts=1,
        max_attempts=3,
        created_at=moment,
        updated_at=moment,
        available_at=moment,
        error=error,
    )


def test_notification_from_themis_job_is_redacted_and_control_safe() -> None:
    job = _terminal_job().model_copy(update={"target": "10.0.0.1\x1b[31m\nInjected"})
    notification = notification_from_themis_job(job)
    assert notification.kind is NotificationKind.JOB
    assert "succeeded" in notification.title
    # Control bytes from a target-controlled field never reach the payload.
    assert "\x1b" not in notification.summary and "\n" not in notification.summary
    assert notification.labels["scanner"] == "nmap"
    assert notification.labels["state"] == "succeeded"


def test_notification_redacts_url_secret_in_error() -> None:
    # The error redaction contract covers URL query secrets and filesystem paths.
    job = _terminal_job(
        JobState.FAILED, error="callback failed https://hook.example/p?token=SECRETVALUE123456"
    )
    notification = notification_from_themis_job(job)
    assert "SECRETVALUE123456" not in notification.summary


def test_job_notifier_dispatches_only_on_terminal_states() -> None:
    sent: list[object] = []
    seen: list[ThemisJob] = []

    class _Dispatcher:
        def dispatch(self, notification: object) -> tuple[object, ...]:
            sent.append(notification)
            return ()

    on_job = job_notifier(_Dispatcher(), also=seen.append)  # type: ignore[arg-type]
    terminal = _terminal_job()
    on_job(terminal)
    on_job(terminal.model_copy(update={"state": JobState.QUEUED}))  # a requeued retry

    assert len(sent) == 1  # only the terminal job produced a notification
    assert len(seen) == 2  # the wrapped callback always runs


def test_job_notifier_never_lets_a_delivery_error_crash_the_worker() -> None:
    class _Boom:
        def dispatch(self, notification: object) -> tuple[object, ...]:
            raise RuntimeError("sink exploded")

    on_job = job_notifier(_Boom())  # type: ignore[arg-type]
    on_job(_terminal_job())  # must not raise


def _finding_dict(severity: Severity, index: int) -> dict[str, object]:
    return Finding(
        asset_id="AST-X",
        source=Source.THEMIS,
        title=f"issue {index}",
        severity=severity,
        finding_id=f"FND-2026-{index:05d}",
    ).model_dump(mode="json")


def _job_with_findings(*findings: dict[str, object]) -> ThemisJob:
    return _terminal_job(JobState.PARTIAL).model_copy(
        update={"result": {"findings": list(findings)}}
    )


def test_finding_notifications_filters_sorts_and_skips_malformed() -> None:
    job = _job_with_findings(
        _finding_dict(Severity.INFO, 1),
        _finding_dict(Severity.HIGH, 2),
        _finding_dict(Severity.CRITICAL, 3),
        {"not": "a finding"},  # malformed entry is skipped, never raised
    )
    notes = finding_notifications(job, minimum_severity=Severity.HIGH)
    # INFO is below the floor and the malformed entry is dropped; most-severe first.
    assert [n.severity for n in notes] == [Severity.CRITICAL, Severity.HIGH]


def test_finding_notifications_are_capped() -> None:
    many = [_finding_dict(Severity.CRITICAL, i) for i in range(1, MAX_FINDING_NOTIFICATIONS + 10)]
    job = _job_with_findings(*many)
    notes = finding_notifications(job, minimum_severity=Severity.INFO)
    assert len(notes) == MAX_FINDING_NOTIFICATIONS  # a noisy scan cannot flood the sink


def test_finding_notifications_empty_without_result() -> None:
    assert finding_notifications(_terminal_job(), minimum_severity=Severity.INFO) == []


def test_job_notifier_emits_job_and_findings_when_severity_set() -> None:
    sent: list[object] = []

    class _Dispatcher:
        def dispatch(self, notification: object) -> tuple[object, ...]:
            sent.append(notification)
            return ()

    job = _job_with_findings(_finding_dict(Severity.HIGH, 1), _finding_dict(Severity.CRITICAL, 2))
    job_notifier(_Dispatcher(), finding_min_severity=Severity.HIGH)(job)  # type: ignore[arg-type]
    assert len(sent) == 3  # one job notification plus two finding notifications

    only_job: list[object] = []

    class _JobOnly:
        def dispatch(self, notification: object) -> tuple[object, ...]:
            only_job.append(notification)
            return ()

    job_notifier(_JobOnly())(job)  # type: ignore[arg-type]
    assert len(only_job) == 1  # no per-finding emission unless a severity floor is set

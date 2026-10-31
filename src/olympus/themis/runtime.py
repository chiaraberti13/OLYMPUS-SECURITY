"""Native migration and worker services; no vendored imports or broker required."""

from __future__ import annotations

import contextlib
import signal
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Protocol

from pydantic import ValidationError

from olympus.core.enums import Severity
from olympus.core.execution import Cancellation, redact_mapping, redact_text, safe_terminal_text
from olympus.core.models import Finding
from olympus.core.notifications import (
    Notification,
    NotificationDispatcher,
    NotificationKind,
    notification_from_finding,
)
from olympus.themis.jobs import (
    SCHEMA_VERSION,
    TERMINAL_STATES,
    SchemaVersionError,
    ThemisJob,
    ThemisJobStore,
    redact_error,
)

#: Ascending severity rank, so a per-finding notification floor can be applied
#: without importing the reporting layer (vulcan) into the engine.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Hard cap on per-job finding notifications, so a noisy scan cannot flood a sink.
MAX_FINDING_NOTIFICATIONS = 50


@dataclass(frozen=True)
class MigrationResult:
    previous_version: int | None
    schema_version: int

    def to_dict(self) -> dict[str, object]:
        return {
            "previous_version": self.previous_version,
            "schema_version": self.schema_version,
            "migrated": self.previous_version != self.schema_version,
        }


def migrate_jobs(database: Path) -> MigrationResult:
    """Migrate only the native job database; never adopt a VAP/foreign database.

    Inspection is read-only. The store applies DDL and the version bump in one
    serialized transaction, retaining jobs and refusing newer/unknown versions.
    """
    if database.is_symlink():
        raise ValueError("Themis job database must not be a symlink")
    previous: int | None = None
    if database.exists():
        with sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True) as db:
            previous = int(db.execute("PRAGMA user_version").fetchone()[0])
            tables = {
                str(row[0])
                for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
                if not str(row[0]).startswith("sqlite_")
            }
        if tables and tables != {"themis_jobs"}:
            raise SchemaVersionError(
                "not a native Themis job database; keep the legacy database and use a new file"
            )
    ThemisJobStore(database).initialize()
    return MigrationResult(previous, SCHEMA_VERSION)


class WorkerPort(Protocol):
    def run_next(
        self, *, audit_path: Path | None = None, cancellation: Cancellation | None = None
    ) -> ThemisJob | None: ...


class WorkerStop:
    """Interruptible shutdown token shared with the executing scanner."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        return self._event.wait(seconds)


@contextmanager
def worker_signals(stop: WorkerStop) -> Iterator[None]:
    """Handle SIGINT/SIGTERM cooperatively and restore the caller's handlers."""
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def shutdown(number: int, frame: FrameType | None) -> None:
        del number, frame
        stop.cancel()

    try:
        for number in previous:
            signal.signal(number, shutdown)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@dataclass(frozen=True)
class WorkerResult:
    processed: int
    last_job: ThemisJob | None
    stopped: bool


def work_queue(
    worker: WorkerPort,
    stop: WorkerStop,
    *,
    audit_path: Path | None,
    poll_seconds: float = 1.0,
    once: bool = False,
    on_job: Callable[[ThemisJob], None],
) -> WorkerResult:
    """Consume serially; individual job failures do not kill the service.

    Scale with separate processes sharing the native store's atomic leases.
    Polling is interruptible, and shutdown never claims another queued job.
    """
    if not 0.05 <= poll_seconds <= 30.0:
        raise ValueError("poll_seconds must be between 0.05 and 30")
    processed = 0
    last_job: ThemisJob | None = None
    while not stop.is_cancelled():
        job = worker.run_next(audit_path=audit_path, cancellation=stop)
        if job is not None:
            processed += 1
            last_job = job
            on_job(job)
        if once:
            break
        if job is None:
            stop.wait(poll_seconds)
    return WorkerResult(processed, last_job, stop.is_cancelled())


def notification_from_themis_job(job: ThemisJob) -> Notification:
    """Build a redacted notification announcing a Themis job's terminal state.

    The Iris output port (:mod:`olympus.core.notifications`) owns the contract and
    redaction; this adapter maps the themis-native :class:`ThemisJob` onto it so a
    worker can emit on job completion. Every text goes through
    :func:`safe_terminal_text` and labels through :func:`redact_mapping`, so a
    target-controlled scanner name or error can neither forge terminal lines nor
    leak a secret into the delivered payload.
    """
    summary = f"scanner {job.scanner} on {job.target_kind} {job.target} is {job.state.value}"
    if job.error:
        # The store already redacts errors on completion; redact again here so a
        # directly built or imported job cannot leak a secret into the payload.
        summary += f" ({redact_error(job.error)})"
    labels = redact_mapping(
        {
            "job_id": job.job_id,
            "scanner": job.scanner,
            "state": job.state.value,
            "target_kind": job.target_kind,
            "scope": job.scope_name,
        }
    )
    return Notification(
        kind=NotificationKind.JOB,
        title=safe_terminal_text(f"job {job.job_id}: {job.state.value}"),
        summary=safe_terminal_text(redact_text(summary)),
        labels={key: safe_terminal_text(str(value)) for key, value in labels.items()},
    )


def finding_notifications(
    job: ThemisJob,
    *,
    minimum_severity: Severity,
    cap: int = MAX_FINDING_NOTIFICATIONS,
) -> list[Notification]:
    """Build bounded, redacted per-finding notifications from a job's result.

    Reads the findings a job carried in its result document, keeps those at or
    above ``minimum_severity``, orders them most-severe first and caps the count
    so a noisy scan cannot flood a sink. Parsing is defensive: a malformed finding
    entry is skipped, never raised, so one bad record cannot suppress the rest.
    """
    raw = job.result.get("findings") if job.result else None
    if not isinstance(raw, list):
        return []
    floor = _SEVERITY_RANK[minimum_severity]
    kept: list[Finding] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        try:
            finding = Finding.model_validate(dict(item))
        except ValidationError:
            continue
        if _SEVERITY_RANK.get(finding.severity, 0) >= floor:
            kept.append(finding)
    kept.sort(key=lambda finding: _SEVERITY_RANK.get(finding.severity, 0), reverse=True)
    return [notification_from_finding(finding) for finding in kept[:cap]]


def job_notifier(
    dispatcher: NotificationDispatcher,
    *,
    also: Callable[[ThemisJob], None] | None = None,
    finding_min_severity: Severity | None = None,
) -> Callable[[ThemisJob], None]:
    """Return an ``on_job`` callback that emits notifications on terminal jobs.

    Wraps an existing callback (``also``) so the worker keeps its current output
    and additionally dispatches a redacted :class:`Notification` once a job
    reaches a terminal state (a requeued retry, still ``QUEUED``, is skipped).
    When ``finding_min_severity`` is set, it also emits one bounded, redacted
    notification per finding at or above that severity (see
    :func:`finding_notifications`); left unset, only the job-level notification is
    sent. The dispatcher is off by default — with no channels it is a no-op — and
    every dispatch is guarded so a notification problem can never crash the loop.
    """

    def _on_job(job: ThemisJob) -> None:
        if also is not None:
            also(job)
        if job.state not in TERMINAL_STATES:
            return
        with contextlib.suppress(Exception):
            dispatcher.dispatch(notification_from_themis_job(job))
        if finding_min_severity is not None:
            for notification in finding_notifications(job, minimum_severity=finding_min_severity):
                with contextlib.suppress(Exception):
                    dispatcher.dispatch(notification)

    return _on_job

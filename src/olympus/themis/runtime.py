"""Native migration and worker services; no vendored imports or broker required."""

from __future__ import annotations

import signal
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Protocol

from olympus.core.execution import Cancellation
from olympus.themis.jobs import SCHEMA_VERSION, SchemaVersionError, ThemisJob, ThemisJobStore


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
        raise ValueError("THEMIS job database must not be a symlink")
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
                "not a native THEMIS job database; keep the legacy database and use a new file"
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

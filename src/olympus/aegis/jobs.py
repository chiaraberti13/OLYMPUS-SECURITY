"""Durable, dependency-light AEGIS job control plane.

This module replaces the legacy VAP/Celery ownership boundary for local and
single-node deployments. SQLite owns job lifecycle, leases and cancellation
intent; the existing AEGIS application service remains the only path that may
execute an adapter, so authorization, scope, SSRF controls, audit and output
limits are not bypassed by queued work.

Three properties matter beyond "it stores rows":

* **Nothing is lost when a worker dies.** A claim is a *lease*, renewed by a
  heartbeat. When renewal stops, the job is requeued (or failed, if its attempt
  budget is spent) instead of sitting in ``running`` forever, and the worker
  that lost the lease is told to stop.
* **A state means one thing.** ``failed`` is a scanner that ran and failed;
  ``timed_out``, ``cancelled``, ``policy_denied`` and ``partial`` are not
  folded into it, so an operator can tell a broken scan from a refused one.
* **Persisted text is not a leak.** Errors are redacted before they are stored,
  and the job document exposes a scope *name*, never the server's filesystem
  layout.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from olympus.aegis.application import AegisApplicationService, AegisRunRequest
from olympus.aegis.config import live_enabled
from olympus.aegis.model import ScanResult
from olympus.aegis.runner import TerminationCause
from olympus.aegis.states import ExecutionState
from olympus.core.execution import (
    Cancellation,
    CancellationRequested,
    redact_text,
    redact_url,
)

#: Bumped whenever the SQLite layout changes; ``initialize`` migrates forward.
SCHEMA_VERSION = 2

DEFAULT_LEASE_SECONDS = 300.0
DEFAULT_HEARTBEAT_SECONDS = 60.0
MAX_ATTEMPTS_LIMIT = 10

WORKER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class JobState(StrEnum):
    """Lifecycle state of one durable job.

    The terminal states are deliberately distinct: collapsing them into
    ``failed`` hides whether a scan broke, was refused, ran out of time, or
    never ran at all.
    """

    #: Waiting for a worker (including a job awaiting its retry backoff).
    QUEUED = "queued"
    #: Leased by a worker that is renewing its heartbeat.
    RUNNING = "running"
    #: The scanner ran and produced a result.
    SUCCEEDED = "succeeded"
    #: Nothing ran, for a reason that is not a failure: the dependency is
    #: missing, or live scanning is switched off.
    PARTIAL = "partial"
    #: The scanner ran and failed, or the worker raised.
    FAILED = "failed"
    #: A timeout or deadline stopped the work.
    TIMED_OUT = "timed_out"
    #: Cancellation was requested and honoured.
    CANCELLED = "cancelled"
    #: Authorization, scope or SSRF policy refused the work before traffic.
    POLICY_DENIED = "policy_denied"


TERMINAL_STATES = frozenset(
    {
        JobState.SUCCEEDED,
        JobState.PARTIAL,
        JobState.FAILED,
        JobState.TIMED_OUT,
        JobState.CANCELLED,
        JobState.POLICY_DENIED,
    }
)

#: The states a job can still leave on its own. Together with
#: ``TERMINAL_STATES`` this partitions ``JobState`` — a test pins that, so a new
#: state cannot quietly fall outside retention or recovery.
ACTIVE_STATES = frozenset({JobState.QUEUED, JobState.RUNNING})

#: Only transient outcomes are retried. A refused policy, a cancellation or a
#: scanner that ran and failed will fail again; retrying them wastes a budget
#: and re-sends traffic to a target for no reason.
RETRYABLE_STATES = frozenset({JobState.TIMED_OUT})


class JobStoreError(RuntimeError):
    """Raised when a job transition is not valid for the store's current state."""


class LeaseLostError(JobStoreError):
    """Raised when a worker acts on a job it no longer owns."""


class SchemaVersionError(JobStoreError):
    """Raised when the database was written by a newer Olympus release."""


class IdempotencyConflict(ValueError):
    """Raised when an idempotency key is reused for a different request."""


class AegisJob(BaseModel):
    """Versioned job document returned consistently by CLI, API and workers.

    ``2.0.0`` replaces ``scope_path`` with ``scope_name``: the absolute path is
    server-side state and never leaves the store.
    """

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-job"] = "olympus.aegis-job"
    schema_version: Literal["2.0.0"] = "2.0.0"
    job_id: str = Field(pattern=r"^AEGIS-[A-F0-9]{32}$")
    idempotency_key: str | None = Field(default=None, max_length=128)
    scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    target: str = Field(min_length=1, max_length=2_048)
    target_kind: Literal["host", "domain", "url"]
    scope_name: str = Field(min_length=1, max_length=255)
    state: JobState
    authorized: bool
    attempts: int = Field(ge=0, le=MAX_ATTEMPTS_LIMIT)
    max_attempts: int = Field(ge=1, le=MAX_ATTEMPTS_LIMIT)
    worker_id: str | None = Field(default=None, max_length=64)
    created_at: datetime
    updated_at: datetime
    available_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    lease_expires_at: datetime | None = None
    heartbeat_at: datetime | None = None
    result: dict[str, object] | None = None
    error: str | None = Field(default=None, max_length=2_000)


@dataclass(frozen=True)
class JobExecution:
    """Server-side execution record: the parts a worker needs but no API shows."""

    job_id: str
    scanner: str
    target: str
    target_kind: str
    scope_path: Path
    authorized: bool
    attempts: int
    max_attempts: int


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _at(offset_seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


def generate_worker_id() -> str:
    """Return an opaque worker identity.

    Deliberately not hostname/PID based: worker identity is published through
    the API, and the control plane's internal topology is not the caller's
    business.
    """
    return f"aegis-{uuid4().hex[:12]}"


#: ``AegisJobStore.list`` shadows the builtin inside the class body, so the
#: methods that return several jobs name this alias instead.
JobRecords = list[AegisJob]


@dataclass(frozen=True)
class AegisJobStore:
    """SQLite repository with atomic claims, leases and explicit transitions."""

    path: Path
    lease_seconds: float = DEFAULT_LEASE_SECONDS
    backoff_seconds: float = 5.0
    max_backoff_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not 1.0 <= self.lease_seconds <= 86_400.0:
            raise ValueError("lease_seconds must be between 1 and 86400")
        if not 0.0 <= self.backoff_seconds <= self.max_backoff_seconds <= 3_600.0:
            raise ValueError("backoff must be between 0 and max_backoff (<= 3600)")

    # -- schema ------------------------------------------------------------- #
    def initialize(self) -> None:
        """Create or migrate the schema; safe to call before every operation."""
        self._validate_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise SchemaVersionError(
                    f"AEGIS job database is at schema {version}, but this release understands "
                    f"{SCHEMA_VERSION}: upgrade Olympus rather than downgrading the database"
                )
            if version < SCHEMA_VERSION:
                self._migrate(db, version)
                db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.path.chmod(0o600)

    def _migrate(self, db: sqlite3.Connection, version: int) -> None:
        legacy = db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'aegis_jobs'"
        ).fetchone()
        if version == 0 and legacy is None:
            db.executescript(_SCHEMA_V2)
            return
        if version == 0:
            # A pre-versioning database: add what v2 introduced, keeping rows.
            for column, definition in (
                ("idempotency_key", "TEXT"),
                ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("max_attempts", "INTEGER NOT NULL DEFAULT 1"),
                ("available_at", "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'"),
                ("worker_id", "TEXT"),
                ("lease_expires_at", "TEXT"),
                ("heartbeat_at", "TEXT"),
            ):
                db.execute(f"ALTER TABLE aegis_jobs ADD COLUMN {column} {definition}")
            db.execute("UPDATE aegis_jobs SET available_at = created_at")
            db.executescript(_INDEXES_V2)

    # -- submission --------------------------------------------------------- #
    def submit(
        self,
        *,
        scanner: str,
        target: str,
        target_kind: str,
        scope_path: Path,
        authorized: bool,
        idempotency_key: str | None = None,
        max_attempts: int = 1,
    ) -> AegisJob:
        """Persist one authorized job; an idempotency key makes retries safe."""
        self.initialize()
        if not 1 <= max_attempts <= MAX_ATTEMPTS_LIMIT:
            raise ValueError(f"max_attempts must be between 1 and {MAX_ATTEMPTS_LIMIT}")
        if idempotency_key is not None and not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
            raise ValueError(
                "idempotency_key must be 1-128 characters of letters, digits, '_', '.', ':' or '-'"
            )
        # Reuse the strict request validation before persisting untrusted data.
        AegisRunRequest(
            scanner=scanner,
            target=target,
            target_kind=target_kind,
            scope_path=scope_path,
            authorized=authorized,
            live_enabled=False,
        )
        resolved_scope = str(scope_path.resolve())
        if idempotency_key is not None:
            existing = self._by_idempotency_key(idempotency_key)
            if existing is not None:
                self._require_same_request(
                    existing, scanner, target, target_kind, resolved_scope, authorized
                )
                return self.get(existing["job_id"])
        timestamp = _now()
        job_id = f"AEGIS-{uuid4().hex.upper()}"
        try:
            with self._transaction() as db:
                db.execute(
                    """INSERT INTO aegis_jobs
                    (job_id, idempotency_key, scanner, target, target_kind, scope_path,
                     authorized, state, attempts, max_attempts, available_at,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
                    (
                        job_id,
                        idempotency_key,
                        scanner,
                        target,
                        target_kind,
                        resolved_scope,
                        int(authorized),
                        JobState.QUEUED.value,
                        max_attempts,
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError:  # concurrent submit with the same key
            if idempotency_key is None:
                raise
            existing = self._by_idempotency_key(idempotency_key)
            if existing is None:
                raise
            self._require_same_request(
                existing, scanner, target, target_kind, resolved_scope, authorized
            )
            return self.get(existing["job_id"])
        return self.get(job_id)

    @staticmethod
    def _require_same_request(
        row: sqlite3.Row,
        scanner: str,
        target: str,
        target_kind: str,
        scope_path: str,
        authorized: bool,
    ) -> None:
        recorded = (
            row["scanner"],
            row["target"],
            row["target_kind"],
            row["scope_path"],
            bool(row["authorized"]),
        )
        if recorded != (scanner, target, target_kind, scope_path, authorized):
            raise IdempotencyConflict(
                f"idempotency key {row['idempotency_key']!r} was already used for a "
                "different request"
            )

    def _by_idempotency_key(self, key: str) -> sqlite3.Row | None:
        with self._reading() as db:
            row: sqlite3.Row | None = db.execute(
                "SELECT * FROM aegis_jobs WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return row

    # -- reads -------------------------------------------------------------- #
    def get(self, job_id: str) -> AegisJob:
        self.initialize()
        with self._reading() as db:
            row = db.execute("SELECT * FROM aegis_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown AEGIS job: {job_id}")
        return _job(row)

    def execution_record(self, job_id: str) -> JobExecution:
        """Return the server-side record a worker needs, including the scope path."""
        self.initialize()
        with self._reading() as db:
            row = db.execute("SELECT * FROM aegis_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown AEGIS job: {job_id}")
        return JobExecution(
            job_id=row["job_id"],
            scanner=row["scanner"],
            target=row["target"],
            target_kind=row["target_kind"],
            scope_path=Path(row["scope_path"]),
            authorized=bool(row["authorized"]),
            attempts=int(row["attempts"]),
            max_attempts=int(row["max_attempts"]),
        )

    def list(self, *, limit: int = 100, state: JobState | None = None) -> JobRecords:
        self.initialize()
        if not 1 <= limit <= 1_000:
            raise ValueError("job list limit must be between 1 and 1000")
        query = "SELECT * FROM aegis_jobs"
        params: tuple[object, ...]
        if state is None:
            params = (limit,)
        else:
            query += " WHERE state = ?"
            params = (state.value, limit)
        query += " ORDER BY created_at DESC LIMIT ?"
        with self._reading() as db:
            return [_job(row) for row in db.execute(query, params).fetchall()]

    # -- leases ------------------------------------------------------------- #
    def claim_next(self, worker_id: str | None = None) -> AegisJob | None:
        """Lease the oldest due job, after recovering any abandoned lease."""
        owner = _validated_worker_id(worker_id)
        self.recover_expired_leases()
        timestamp = _now()
        with self._transaction(immediate=True) as db:
            row = db.execute(
                """SELECT job_id FROM aegis_jobs
                WHERE state = ? AND cancel_requested = 0 AND available_at <= ?
                ORDER BY available_at ASC, created_at ASC LIMIT 1""",
                (JobState.QUEUED.value, timestamp),
            ).fetchone()
            if row is None:
                return None
            changed = db.execute(
                """UPDATE aegis_jobs
                SET state = ?, worker_id = ?, attempts = attempts + 1,
                    lease_expires_at = ?, heartbeat_at = ?,
                    started_at = COALESCE(started_at, ?), updated_at = ?
                WHERE job_id = ? AND state = ?""",
                (
                    JobState.RUNNING.value,
                    owner,
                    _at(self.lease_seconds),
                    timestamp,
                    timestamp,
                    timestamp,
                    row["job_id"],
                    JobState.QUEUED.value,
                ),
            ).rowcount
        return self.get(row["job_id"]) if changed == 1 else None

    def heartbeat(self, job_id: str, worker_id: str) -> AegisJob:
        """Extend the lease of a job this worker still owns."""
        timestamp = _now()
        with self._transaction() as db:
            changed = db.execute(
                """UPDATE aegis_jobs SET lease_expires_at = ?, heartbeat_at = ?, updated_at = ?
                WHERE job_id = ? AND state = ? AND worker_id = ?""",
                (
                    _at(self.lease_seconds),
                    timestamp,
                    timestamp,
                    job_id,
                    JobState.RUNNING.value,
                    worker_id,
                ),
            ).rowcount
        if changed != 1:
            raise LeaseLostError(f"job {job_id} is no longer leased by worker {worker_id}")
        return self.get(job_id)

    def recover_expired_leases(self) -> JobRecords:
        """Requeue (or fail) running jobs whose worker stopped renewing its lease."""
        self.initialize()
        timestamp = _now()
        with self._transaction(immediate=True) as db:
            rows = db.execute(
                """SELECT job_id, worker_id, attempts, max_attempts FROM aegis_jobs
                WHERE state = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?""",
                (JobState.RUNNING.value, timestamp),
            ).fetchall()
            recovered: list[str] = []
            for row in rows:
                reason = (
                    f"lease expired: worker {row['worker_id']} stopped reporting after "
                    f"attempt {row['attempts']}"
                )
                if int(row["attempts"]) < int(row["max_attempts"]):
                    self._requeue_row(db, row["job_id"], int(row["attempts"]), reason)
                else:
                    db.execute(
                        """UPDATE aegis_jobs SET state = ?, error = ?, worker_id = NULL,
                        lease_expires_at = NULL, finished_at = ?, updated_at = ?
                        WHERE job_id = ?""",
                        (JobState.FAILED.value, reason, timestamp, timestamp, row["job_id"]),
                    )
                recovered.append(row["job_id"])
        return [self.get(job_id) for job_id in recovered]

    # -- transitions -------------------------------------------------------- #
    def cancel(self, job_id: str) -> AegisJob:
        """Record operator cancellation intent; running work stops cooperatively."""
        job = self.get(job_id)
        if job.state in TERMINAL_STATES:
            return job
        timestamp = _now()
        with self._transaction() as db:
            if job.state is JobState.QUEUED:
                db.execute(
                    """UPDATE aegis_jobs SET state = ?, cancel_requested = 1,
                    finished_at = ?, updated_at = ? WHERE job_id = ?""",
                    (JobState.CANCELLED.value, timestamp, timestamp, job_id),
                )
            else:
                db.execute(
                    "UPDATE aegis_jobs SET cancel_requested = 1, updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
        return self.get(job_id)

    def cancellation_requested(self, job_id: str) -> bool:
        with self._reading() as db:
            row = db.execute(
                "SELECT cancel_requested FROM aegis_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def finish(self, job_id: str, *, worker_id: str, result: dict[str, object]) -> AegisJob:
        return self.complete(job_id, worker_id=worker_id, state=JobState.SUCCEEDED, result=result)

    def fail(self, job_id: str, *, worker_id: str, error: str) -> AegisJob:
        return self.complete(job_id, worker_id=worker_id, state=JobState.FAILED, error=error)

    def mark_cancelled(self, job_id: str, *, worker_id: str) -> AegisJob:
        return self.complete(job_id, worker_id=worker_id, state=JobState.CANCELLED)

    def complete(
        self,
        job_id: str,
        *,
        worker_id: str,
        state: JobState,
        result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> AegisJob:
        """Finish a leased job, requeueing it instead when a retry is allowed."""
        if state not in TERMINAL_STATES:
            raise ValueError(f"{state} is not a terminal job state")
        record = self.execution_record(job_id)
        redacted = redact_error(error) if error is not None else None
        if state in RETRYABLE_STATES and record.attempts < record.max_attempts:
            return self._retry(job_id, worker_id, record.attempts, redacted)
        timestamp = _now()
        with self._transaction() as db:
            changed = db.execute(
                """UPDATE aegis_jobs SET state = ?, result_json = ?, error = ?,
                worker_id = NULL, lease_expires_at = NULL, finished_at = ?, updated_at = ?
                WHERE job_id = ? AND state = ? AND worker_id = ?""",
                (
                    state.value,
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    redacted,
                    timestamp,
                    timestamp,
                    job_id,
                    JobState.RUNNING.value,
                    worker_id,
                ),
            ).rowcount
        if changed != 1:
            raise LeaseLostError(f"job {job_id} is not running under worker {worker_id}")
        return self.get(job_id)

    def _retry(self, job_id: str, worker_id: str, attempts: int, error: str | None) -> AegisJob:
        with self._transaction() as db:
            changed = self._requeue_row(db, job_id, attempts, error, worker_id=worker_id)
        if changed != 1:
            raise LeaseLostError(f"job {job_id} is not running under worker {worker_id}")
        return self.get(job_id)

    def _requeue_row(
        self,
        db: sqlite3.Connection,
        job_id: str,
        attempts: int,
        error: str | None,
        *,
        worker_id: str | None = None,
    ) -> int:
        timestamp = _now()
        query = """UPDATE aegis_jobs SET state = ?, error = ?, worker_id = NULL,
            lease_expires_at = NULL, available_at = ?, updated_at = ?
            WHERE job_id = ? AND state = ?"""
        params = [
            JobState.QUEUED.value,
            error,
            _at(self.backoff_for(attempts)),
            timestamp,
            job_id,
            JobState.RUNNING.value,
        ]
        if worker_id is not None:
            query += " AND worker_id = ?"
            params.append(worker_id)
        return int(db.execute(query, params).rowcount)

    def backoff_for(self, attempts: int) -> float:
        """Return the exponential backoff, capped, with up to 25% jitter.

        Jitter keeps a fleet of workers from retrying a shared dependency in
        lockstep. ``secrets`` is used simply because it is the randomness source
        already imported here; nothing about this value is a secret.
        """
        exponent = max(0, min(attempts - 1, 16))
        base = min(self.backoff_seconds * float(2**exponent), self.max_backoff_seconds)
        if base <= 0:
            return 0.0
        return base + base * 0.25 * (secrets.randbelow(1_000) / 1_000.0)

    def prune(
        self, *, older_than_days: int, dry_run: bool = False, now: datetime | None = None
    ) -> tuple[int, tuple[str, ...]]:
        """Delete finished jobs older than the retention window.

        Only terminal jobs are removed: queued and running work is never pruned
        out from under a worker, however old it is. Deletion runs with
        ``secure_delete`` on and is followed by a VACUUM, so the removed
        targets, errors and results do not linger in the database file.
        """
        if not 0 <= older_than_days <= 3_650:
            raise ValueError("older_than_days must be between 0 and 3650")
        self.initialize()
        cutoff = ((now or datetime.now(UTC)) - timedelta(days=older_than_days)).isoformat()
        query = (
            "SELECT job_id FROM aegis_jobs WHERE state NOT IN (?, ?) "
            "AND COALESCE(finished_at, updated_at) < ?"
        )
        parameters = (JobState.QUEUED.value, JobState.RUNNING.value, cutoff)
        with self._reading() as db:
            doomed = [row["job_id"] for row in db.execute(query, parameters).fetchall()]
        if dry_run or not doomed:
            return len(doomed), tuple(doomed)
        with self._transaction(immediate=True) as db:
            db.executemany(
                "DELETE FROM aegis_jobs WHERE job_id = ?", [(job_id,) for job_id in doomed]
            )
        # VACUUM cannot run inside a transaction; it rebuilds the file so the
        # freed pages are released rather than kept for reuse. Truncating the
        # write-ahead log afterwards drops the pre-deletion page images that
        # would otherwise stay readable in the -wal file.
        vacuum = self._connect()
        try:
            vacuum.execute("VACUUM")
            vacuum.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            vacuum.close()
        return len(doomed), tuple(doomed)

    # -- connections -------------------------------------------------------- #
    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 10000")
        # WAL lets a reader (status, list) run while a worker holds a write
        # transaction; FULL keeps a committed transition on disk before the
        # caller is told it happened.
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = FULL")
        # Deleted rows carry targets, errors and results. secure_delete zeroes
        # the freed pages instead of leaving that content in the file.
        db.execute("PRAGMA secure_delete = ON")
        return db

    @contextmanager
    def _reading(self) -> Iterator[sqlite3.Connection]:
        """Run one read and always close the handle.

        ``with sqlite3.connect(...)`` manages a *transaction*, not the
        connection: using it alone leaks the handle, and in WAL mode a leaked
        reader also keeps the write-ahead log from ever being checkpointed away.
        """
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Run one write transaction, committing on success and closing always."""
        db = self._connect()
        try:
            if immediate:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _validate_path(self) -> None:
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise OSError("AEGIS job database must be a regular non-symlink file")


_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS aegis_jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT,
    scanner TEXT NOT NULL,
    target TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    scope_path TEXT NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 1,
    available_at TEXT NOT NULL,
    worker_id TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    result_json TEXT,
    error TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0
        CHECK (cancel_requested IN (0, 1))
);
"""

_INDEXES_V2 = """
CREATE INDEX IF NOT EXISTS idx_aegis_jobs_state_created
    ON aegis_jobs(state, created_at);
CREATE INDEX IF NOT EXISTS idx_aegis_jobs_claim
    ON aegis_jobs(state, available_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_aegis_jobs_idempotency
    ON aegis_jobs(idempotency_key) WHERE idempotency_key IS NOT NULL;
"""

_SCHEMA_V2 = _SCHEMA_V2 + _INDEXES_V2

#: An absolute path in an error message tells a caller how the server is laid
#: out. Matches POSIX and Windows roots but never the ``//host/path`` part of a
#: URL, which ``redact_url`` has already handled.
_ABSOLUTE_PATH = re.compile(r"(?<![\w:/\\])(?:[A-Za-z]:)?[/\\](?:[\w.\-]+[/\\])+[\w.\-]*")


def redact_error(text: str) -> str:
    """Return persisted error text without secrets or server filesystem layout."""
    value = _ABSOLUTE_PATH.sub(_replace_path, redact_text(text))
    return value[:2_000]


def _replace_path(match: re.Match[str]) -> str:
    raw = match.group(0).rstrip("/\\")
    name = re.split(r"[/\\]", raw)[-1]
    return f"[path]/{name}" if name else "[path]"


def _validated_worker_id(worker_id: str | None) -> str:
    if worker_id is None:
        return generate_worker_id()
    if not WORKER_ID_PATTERN.fullmatch(worker_id):
        raise ValueError(
            "worker_id must be 1-64 characters of letters, digits, '_', '.', ':' or '-'"
        )
    return worker_id


@dataclass
class _JobCancellation(Cancellation):
    """Cooperative cancellation: operator intent, or a lease this worker lost."""

    store: AegisJobStore
    job_id: str
    lease_lost: threading.Event = field(default_factory=threading.Event)

    def is_cancelled(self) -> bool:
        return self.lease_lost.is_set() or self.store.cancellation_requested(self.job_id)


class _Heartbeat:
    """Renew a lease in the background for as long as a job is being executed."""

    def __init__(
        self,
        store: AegisJobStore,
        job_id: str,
        worker_id: str,
        cancellation: _JobCancellation,
        interval: float,
    ) -> None:
        self._store = store
        self._job_id = job_id
        self._worker_id = worker_id
        self._cancellation = cancellation
        self._interval = max(0.05, interval)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="aegis-heartbeat", daemon=True)

    def __enter__(self) -> _Heartbeat:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._store.heartbeat(self._job_id, self._worker_id)
            except LeaseLostError:
                # Another worker owns this job now. Stop the local execution
                # instead of racing it to the same terminal transition.
                self._cancellation.lease_lost.set()
                return
            except (sqlite3.Error, OSError, JobStoreError):
                # A transient database problem must not kill the scan; the
                # lease simply expires if it keeps failing.
                continue


@dataclass(frozen=True)
class AegisWorker:
    """Claim and execute one durable job through the canonical application service."""

    store: AegisJobStore
    application: AegisApplicationService = field(default_factory=AegisApplicationService)
    live_scans: bool | None = None
    worker_id: str = field(default_factory=generate_worker_id)
    heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS

    def run_next(self, *, audit_path: Path | None = None) -> AegisJob | None:
        """Claim one job, execute it under a renewed lease, and record its outcome."""
        job = self.store.claim_next(self.worker_id)
        if job is None:
            return None
        if self.store.cancellation_requested(job.job_id):
            return self._settle(job.job_id, JobState.CANCELLED)
        record = self.store.execution_record(job.job_id)
        cancellation = _JobCancellation(self.store, job.job_id)
        try:
            with _Heartbeat(
                self.store, job.job_id, self.worker_id, cancellation, self.heartbeat_seconds
            ):
                result = self.application.run(
                    AegisRunRequest(
                        scanner=record.scanner,
                        target=record.target,
                        target_kind=record.target_kind,
                        scope_path=record.scope_path,
                        authorized=record.authorized,
                        live_enabled=(
                            live_enabled() if self.live_scans is None else self.live_scans
                        ),
                        audit_path=audit_path,
                        cancellation=cancellation,
                    )
                )
        except BaseException as exc:
            return self._record_exception(job.job_id, exc)
        if self.store.cancellation_requested(job.job_id):
            return self._settle(job.job_id, JobState.CANCELLED)
        state, error = classify_result(result)
        return self._settle(job.job_id, state, result=result.to_dict(), error=error)

    def _record_exception(self, job_id: str, exc: BaseException) -> AegisJob:
        if self.store.cancellation_requested(job_id) or isinstance(exc, CancellationRequested):
            return self._settle(job_id, JobState.CANCELLED)
        return self._settle(job_id, classify_exception(exc), error=f"{type(exc).__name__}: {exc}")

    def _settle(
        self,
        job_id: str,
        state: JobState,
        *,
        result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> AegisJob:
        """Record the outcome, unless this worker no longer owns the job.

        Losing a lease mid-scan means another worker has taken the job over.
        Overwriting its state from here would undo that recovery, so the job is
        reported exactly as its current owner left it.
        """
        try:
            return self.store.complete(
                job_id, worker_id=self.worker_id, state=state, result=result, error=error
            )
        except LeaseLostError:
            return self.store.get(job_id)


def classify_result(result: ScanResult) -> tuple[JobState, str | None]:
    """Map one scan outcome onto a job state that means exactly one thing."""
    if result.state in {ExecutionState.LIVE, ExecutionState.SIMULATION}:
        return JobState.SUCCEEDED, None
    if result.state in {ExecutionState.UNAVAILABLE, ExecutionState.DISABLED}:
        return JobState.PARTIAL, result.error
    termination = result.termination
    if termination is not None and termination.cause is TerminationCause.TIMEOUT:
        return JobState.TIMED_OUT, result.error
    return JobState.FAILED, result.error


def classify_exception(exc: BaseException) -> JobState:
    """Map a worker exception onto a job state, keeping policy refusals distinct."""
    from olympus.aegis.base import NotAuthorizedError
    from olympus.aegis.scope import OutOfScopeError, SsrfBlockedError, TargetValidationError
    from olympus.core.execution import AuthorizationRequiredError

    if isinstance(
        exc,
        NotAuthorizedError
        | AuthorizationRequiredError
        | OutOfScopeError
        | SsrfBlockedError
        | TargetValidationError,
    ):
        return JobState.POLICY_DENIED
    if isinstance(exc, TimeoutError):
        return JobState.TIMED_OUT
    return JobState.FAILED


def _job(row: sqlite3.Row) -> AegisJob:
    return AegisJob(
        job_id=row["job_id"],
        idempotency_key=row["idempotency_key"],
        scanner=row["scanner"],
        # The stored target is what a scanner is run against; the published one
        # never carries a credential someone put in a URL query.
        target=redact_url(row["target"]),
        target_kind=row["target_kind"],
        scope_name=Path(row["scope_path"]).name or "scope",
        state=row["state"],
        authorized=bool(row["authorized"]),
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        worker_id=row["worker_id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        available_at=row["available_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        lease_expires_at=row["lease_expires_at"],
        heartbeat_at=row["heartbeat_at"],
        result=json.loads(row["result_json"]) if row["result_json"] else None,
        error=row["error"],
    )

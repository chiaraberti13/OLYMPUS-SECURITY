"""Durable SQLite repository for Athena assessments.

Implements :class:`~olympus.athena.ports.AssessmentRepository` on Python's
``sqlite3`` with foreign keys, WAL mode, a busy timeout, and a transaction per
state transition. The database file and its parent directory are created with
owner-only permissions. Every transition is validated by the domain state
machine before it is written, so an illegal move fails closed.

Result documents are bounded and stored inline with their SHA-256 digest and
byte length; the storage root is derived from validated identifiers only.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from olympus.athena.domain.assessment import (
    Assessment,
    AssessmentState,
    Job,
    JobState,
    advance_assessment,
    advance_job,
)
from olympus.athena.domain.audit import AuditEvent
from olympus.athena.domain.contracts import AssessmentPlan, load_plan, load_result
from olympus.core.migrations import initialize_sqlite_schema

#: Maximum bytes accepted for a single stored result document.
MAX_RESULT_BYTES = 1_000_000
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AthenaBackupInfo:
    """Verification facts for one Athena SQLite snapshot."""

    schema_version: int
    plan_count: int
    assessment_count: int
    job_count: int
    result_count: int
    audit_event_count: int
    size_bytes: int
    sha256: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    document TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES plans(plan_id),
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id),
    ordinal INTEGER NOT NULL,
    adapter TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_value TEXT NOT NULL,
    state TEXT NOT NULL,
    error_code TEXT,
    result_id TEXT
);
CREATE TABLE IF NOT EXISTS results (
    result_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id),
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    document TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    length INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    assessment_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    job_id TEXT,
    metadata TEXT NOT NULL,
    PRIMARY KEY (assessment_id, sequence)
);
"""


class ResultTooLargeError(ValueError):
    """Raised when a result document exceeds the configured storage cap."""


class TransitionConflictError(RuntimeError):
    """Raised when another writer changed the persisted state first."""


class SqliteAssessmentRepository:
    """SQLite-backed :class:`~olympus.athena.ports.AssessmentRepository`."""

    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            path.parent.chmod(0o700)
        first_time = not path.exists()
        self._conn = sqlite3.connect(str(path))
        if first_time:
            with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
                path.chmod(0o600)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        initialize_sqlite_schema(self._conn, _SCHEMA, current_version=SCHEMA_VERSION)

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def backup(self, destination: Path) -> AthenaBackupInfo:
        """Atomically publish a verified, standalone snapshot of this store only."""
        source = self._path
        if source.is_symlink() or not source.is_file():
            raise OSError("Athena database must be an existing regular file")
        if destination.is_symlink():
            raise OSError("backup destination must not be a symlink")
        if _same_file(source, destination):
            raise ValueError("backup destination must differ from the live database")
        temporary: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            os.close(descriptor)
            temporary = Path(name)
            target = sqlite3.connect(temporary)
            try:
                self._conn.backup(target)
                target.execute("PRAGMA journal_mode = DELETE")
            finally:
                target.close()
            temporary.chmod(0o600)
            info = self.verify_backup(temporary)
            temporary.replace(destination)
            destination.chmod(0o600)
            return info
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def verify_backup(backup: Path) -> AthenaBackupInfo:
        """Verify one standalone snapshot's schema, data contracts and SQLite state."""
        connection, info = _open_verified_athena_database(backup)
        connection.close()
        return info

    @staticmethod
    def restore_backup(backup: Path, destination: Path) -> AthenaBackupInfo:
        """Restore a verified snapshot to a new path without overwriting data."""
        source, _ = _open_verified_athena_database(backup)
        temporary: Path | None = None
        try:
            if destination.is_symlink():
                raise OSError("restore destination must not be a symlink")
            if _same_file(backup, destination):
                raise ValueError("restore destination must differ from the backup")
            sidecars = tuple(
                Path(f"{destination}{suffix}") for suffix in ("-wal", "-shm", "-journal")
            )
            if destination.exists() or any(p.exists() or p.is_symlink() for p in sidecars):
                raise FileExistsError("restore destination and SQLite sidecars must be absent")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".restore", dir=destination.parent
            )
            os.close(descriptor)
            temporary = Path(name)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.execute("PRAGMA journal_mode = DELETE")
            finally:
                target.close()
            temporary.chmod(0o600)
            info = SqliteAssessmentRepository.verify_backup(temporary)
            os.link(temporary, destination)
            temporary.unlink()
            return info
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
        finally:
            source.close()

    # -- plans ------------------------------------------------------------- #
    def save_plan(self, plan: AssessmentPlan) -> str:
        plan_id = f"PLAN-{plan.digest()[:16]}"
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO plans(plan_id, document) VALUES (?, ?)",
                (plan_id, plan.canonical_json()),
            )
        return plan_id

    def load_plan(self, plan_id: str) -> AssessmentPlan | None:
        row = self._conn.execute(
            "SELECT document FROM plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            return None
        return load_plan(json.loads(row["document"]))

    # -- assessments/jobs -------------------------------------------------- #
    def save_assessment(self, assessment: Assessment) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO assessments(assessment_id, plan_id, state) VALUES (?, ?, ?)",
                (assessment.assessment_id, assessment.plan_id, assessment.state.value),
            )
            self._conn.executemany(
                "INSERT INTO jobs(job_id, assessment_id, ordinal, adapter, target_kind, "
                "target_value, state, error_code, result_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        job.job_id,
                        assessment.assessment_id,
                        ordinal,
                        job.adapter,
                        job.target_kind,
                        job.target_value,
                        job.state.value,
                        job.error_code,
                        job.result_id,
                    )
                    for ordinal, job in enumerate(assessment.jobs)
                ],
            )

    def load_assessment(self, assessment_id: str) -> Assessment | None:
        row = self._conn.execute(
            "SELECT plan_id, state FROM assessments WHERE assessment_id = ?", (assessment_id,)
        ).fetchone()
        if row is None:
            return None
        job_rows = self._conn.execute(
            "SELECT * FROM jobs WHERE assessment_id = ? ORDER BY ordinal", (assessment_id,)
        ).fetchall()
        jobs = tuple(
            Job(
                job_id=jr["job_id"],
                adapter=jr["adapter"],
                target_kind=jr["target_kind"],
                target_value=jr["target_value"],
                state=JobState(jr["state"]),
                error_code=jr["error_code"],
                result_id=jr["result_id"],
            )
            for jr in job_rows
        )
        return Assessment(
            assessment_id=assessment_id,
            plan_id=row["plan_id"],
            state=AssessmentState(row["state"]),
            jobs=jobs,
        )

    def transition_assessment(self, assessment_id: str, target: AssessmentState) -> None:
        row = self._conn.execute(
            "SELECT state FROM assessments WHERE assessment_id = ?", (assessment_id,)
        ).fetchone()
        if row is None:
            raise LookupError(f"assessment not found: {assessment_id}")
        current = Assessment(
            assessment_id=assessment_id, plan_id="", state=AssessmentState(row["state"])
        )
        advance_assessment(current, target)  # validates or raises TransitionError
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE assessments SET state = ? WHERE assessment_id = ? AND state = ?",
                (target.value, assessment_id, current.state.value),
            )
            if cursor.rowcount != 1:
                raise TransitionConflictError(
                    f"assessment {assessment_id} state changed during transition"
                )

    def transition_assessment_with_audit(
        self, assessment_id: str, target: AssessmentState, event: AuditEvent
    ) -> None:
        """Persist an assessment state change and its audit event atomically."""
        if event.assessment_id != assessment_id or event.job_id is not None:
            raise ValueError("assessment audit event identity does not match transition")
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT state FROM assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
            if row is None:
                raise LookupError(f"assessment not found: {assessment_id}")
            current_state = AssessmentState(row["state"])
            current = Assessment(assessment_id=assessment_id, plan_id="", state=current_state)
            advance_assessment(current, target)
            cursor = self._conn.execute(
                "UPDATE assessments SET state = ? WHERE assessment_id = ? AND state = ?",
                (target.value, assessment_id, current_state.value),
            )
            if cursor.rowcount != 1:
                raise TransitionConflictError(
                    f"assessment {assessment_id} state changed during transition"
                )
            self._append_audit_event(event)

    def transition_job(
        self,
        job: Job,
        target: JobState,
        *,
        error_code: str | None = None,
        result_id: str | None = None,
    ) -> Job:
        updated = advance_job(job, target, error_code=error_code, result_id=result_id)
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE jobs SET state = ?, error_code = ?, result_id = ? "
                "WHERE job_id = ? AND state = ?",
                (
                    updated.state.value,
                    updated.error_code,
                    updated.result_id,
                    updated.job_id,
                    job.state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise TransitionConflictError(f"job {job.job_id} state changed during transition")
        return updated

    def transition_job_with_audit(
        self,
        assessment_id: str,
        job: Job,
        target: JobState,
        event: AuditEvent,
        *,
        error_code: str | None = None,
        result_id: str | None = None,
    ) -> Job:
        """Persist a job state change and its audit event atomically."""
        if event.assessment_id != assessment_id or event.job_id != job.job_id:
            raise ValueError("job audit event identity does not match transition")
        updated = advance_job(job, target, error_code=error_code, result_id=result_id)
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT assessment_id, state FROM jobs WHERE job_id = ?", (job.job_id,)
            ).fetchone()
            if row is None:
                raise LookupError(f"job not found: {job.job_id}")
            if row["assessment_id"] != assessment_id:
                raise ValueError("job assessment identity does not match transition")
            cursor = self._conn.execute(
                "UPDATE jobs SET state = ?, error_code = ?, result_id = ? "
                "WHERE job_id = ? AND state = ?",
                (
                    updated.state.value,
                    updated.error_code,
                    updated.result_id,
                    updated.job_id,
                    job.state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise TransitionConflictError(f"job {job.job_id} state changed during transition")
            self._append_audit_event(event)
        return updated

    # -- results ----------------------------------------------------------- #
    def save_result(self, assessment_id: str, job_id: str, document: str) -> str:
        encoded = document.encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise ResultTooLargeError(
                f"result document for job {job_id} exceeds {MAX_RESULT_BYTES} bytes"
            )
        try:
            result = load_result(json.loads(document))
        except json.JSONDecodeError as exc:
            raise ValueError("result document must be valid JSON") from exc
        if result.assessment_id != assessment_id:
            raise ValueError("result assessment_id does not match storage key")
        if result.job.assessment_id != assessment_id or result.job.job_id != job_id:
            raise ValueError("result job identity does not match storage key")
        canonical = result.canonical_json()
        encoded = canonical.encode("utf-8")
        sha256 = hashlib.sha256(encoded).hexdigest()
        result_id = f"RES-{sha256[:16]}-{job_id}"
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO results(result_id, assessment_id, job_id, document, "
                "sha256, length) VALUES (?, ?, ?, ?, ?, ?)",
                (result_id, assessment_id, job_id, canonical, sha256, len(encoded)),
            )
        return result_id

    def load_result(self, result_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT assessment_id, job_id, document, sha256, length FROM results "
            "WHERE result_id = ?",
            (result_id,),
        ).fetchone()
        if row is None:
            return None
        document = str(row["document"])
        encoded = document.encode("utf-8")
        if len(encoded) > MAX_RESULT_BYTES:
            raise ResultTooLargeError(f"stored result {result_id} exceeds {MAX_RESULT_BYTES} bytes")
        if len(encoded) != int(row["length"]):
            raise ValueError(f"stored result {result_id} length does not match its metadata")
        digest = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(digest, str(row["sha256"])):
            raise ValueError(f"stored result {result_id} digest does not match its metadata")
        expected_id = f"RES-{digest[:16]}-{row['job_id']}"
        if result_id != expected_id:
            raise ValueError(f"stored result {result_id} identity does not match its metadata")
        try:
            result = load_result(json.loads(document))
        except json.JSONDecodeError as exc:
            raise ValueError(f"stored result {result_id} is not valid JSON") from exc
        if result.assessment_id != row["assessment_id"] or result.job.job_id != row["job_id"]:
            raise ValueError(
                f"stored result {result_id} document identity does not match its metadata"
            )
        return result.canonical_json()

    # -- recovery ---------------------------------------------------------- #
    def running_jobs(self) -> list[tuple[str, Job]]:
        rows = self._conn.execute(
            "SELECT * FROM jobs WHERE state = ?", (JobState.RUNNING.value,)
        ).fetchall()
        return [
            (
                jr["assessment_id"],
                Job(
                    job_id=jr["job_id"],
                    adapter=jr["adapter"],
                    target_kind=jr["target_kind"],
                    target_value=jr["target_value"],
                    state=JobState.RUNNING,
                    error_code=jr["error_code"],
                    result_id=jr["result_id"],
                ),
            )
            for jr in rows
        ]

    # -- audit ------------------------------------------------------------- #
    def append_audit(
        self,
        assessment_id: str,
        sequence: int | None,
        timestamp: str,
        action: str,
        outcome: str,
        job_id: str | None,
        metadata: str,
    ) -> None:
        """Append without replacement; ``None`` allocates a durable sequence.

        Explicit sequences are preserved and duplicates raise IntegrityError.
        The persistent sink requests allocation because producer counters reset
        after a restart. Acquire the write lock before reading MAX so independent
        connections cannot allocate the same sequence. Failure rolls back both
        allocation and insertion; existing rows are never rewritten.
        """
        with self._conn:
            if sequence is None:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute(
                    "SELECT COALESCE(MAX(sequence), -1) + 1 FROM audit WHERE assessment_id = ?",
                    (assessment_id,),
                ).fetchone()
                sequence = int(row[0])
            self._conn.execute(
                "INSERT INTO audit(assessment_id, sequence, timestamp, action, "
                "outcome, job_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (assessment_id, sequence, timestamp, action, outcome, job_id, metadata),
            )

    def _append_audit_event(self, event: AuditEvent) -> None:
        """Append one event inside the caller's transaction with a durable sequence."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(sequence), -1) + 1 FROM audit WHERE assessment_id = ?",
            (event.assessment_id,),
        ).fetchone()
        sequence = int(row[0])
        self._conn.execute(
            "INSERT INTO audit(assessment_id, sequence, timestamp, action, outcome, job_id, "
            "metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.assessment_id,
                sequence,
                event.timestamp,
                event.action,
                event.outcome,
                event.job_id,
                json.dumps(event.metadata, sort_keys=True),
            ),
        )

    def audit_events(self, assessment_id: str) -> list[dict[str, object]]:
        """Return the ordered audit rows for an assessment."""
        rows = self._conn.execute(
            "SELECT * FROM audit WHERE assessment_id = ? ORDER BY sequence", (assessment_id,)
        ).fetchall()
        return [dict(row) for row in rows]


def _same_file(source: Path, destination: Path) -> bool:
    try:
        return source.samefile(destination)
    except FileNotFoundError:
        return False


def _open_verified_athena_database(path: Path) -> tuple[sqlite3.Connection, AthenaBackupInfo]:
    if path.is_symlink() or not path.is_file():
        raise OSError("Athena backup must be a regular non-symlink file")
    sidecars = tuple(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal"))
    if any(sidecar.exists() or sidecar.is_symlink() for sidecar in sidecars):
        raise ValueError("Athena backup must be a self-contained SQLite file")
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            raise ValueError(f"unsupported Athena backup schema version: {version}")
        expected = {
            "plans": ("plan_id", "document"),
            "assessments": ("assessment_id", "plan_id", "state"),
            "jobs": (
                "job_id",
                "assessment_id",
                "ordinal",
                "adapter",
                "target_kind",
                "target_value",
                "state",
                "error_code",
                "result_id",
            ),
            "results": ("result_id", "assessment_id", "job_id", "document", "sha256", "length"),
            "audit": (
                "assessment_id",
                "sequence",
                "timestamp",
                "action",
                "outcome",
                "job_id",
                "metadata",
            ),
        }
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        objects = {
            str(row[0])
            for row in connection.execute(
                "SELECT type FROM sqlite_master WHERE type IN ('view', 'trigger')"
            )
        }
        actual = {
            table: tuple(str(col[1]) for col in connection.execute(f'PRAGMA table_info("{table}")'))
            for table in expected
            if table in tables
        }
        if tables != set(expected) or actual != expected or objects:
            raise ValueError("Athena backup schema does not match this release")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise ValueError("Athena backup failed SQLite integrity_check")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Athena backup contains foreign-key violations")

        for row in connection.execute("SELECT plan_id, document FROM plans"):
            plan = load_plan(json.loads(str(row["document"])))
            if str(row["plan_id"]) != f"PLAN-{plan.digest()[:16]}":
                raise ValueError("Athena backup contains a plan with an invalid identity")
        for row in connection.execute("SELECT assessment_id, state FROM assessments"):
            if not str(row["assessment_id"]) or str(row["state"]) not in {
                state.value for state in AssessmentState
            }:
                raise ValueError("Athena backup contains an invalid assessment")
        for row in connection.execute("SELECT state FROM jobs"):
            if str(row["state"]) not in {state.value for state in JobState}:
                raise ValueError("Athena backup contains an invalid job state")

        # Reuse the repository's bounded parser, digest, length and identity checks.
        for row in connection.execute("SELECT result_id FROM results"):
            result_id = str(row["result_id"])
            result_row = connection.execute(
                "SELECT assessment_id, job_id, document, sha256, length FROM results "
                "WHERE result_id = ?",
                (result_id,),
            ).fetchone()
            if result_row is None:
                raise ValueError("Athena backup result disappeared during verification")
            document = str(result_row["document"])
            encoded = document.encode("utf-8")
            digest = hashlib.sha256(encoded).hexdigest()
            if (
                len(encoded) > MAX_RESULT_BYTES
                or len(encoded) != int(result_row["length"])
                or not hmac.compare_digest(digest, str(result_row["sha256"]))
                or result_id != f"RES-{digest[:16]}-{result_row['job_id']}"
            ):
                raise ValueError(f"Athena backup result {result_id} failed integrity validation")
            result = load_result(json.loads(document))
            if (
                result.assessment_id != result_row["assessment_id"]
                or result.job.job_id != result_row["job_id"]
            ):
                raise ValueError(f"Athena backup result {result_id} has invalid identity")

        counts = [
            int(connection.execute("SELECT count(*) FROM plans").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM assessments").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM jobs").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM results").fetchone()[0]),
            int(connection.execute("SELECT count(*) FROM audit").fetchone()[0]),
        ]
        file_digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                file_digest.update(chunk)
        info = AthenaBackupInfo(
            schema_version=version,
            plan_count=counts[0],
            assessment_count=counts[1],
            job_count=counts[2],
            result_count=counts[3],
            audit_event_count=counts[4],
            size_bytes=path.stat().st_size,
            sha256=file_digest.hexdigest(),
        )
        return connection, info
    except BaseException:
        connection.close()
        raise

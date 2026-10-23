"""Read-only, privacy-minimized snapshots of the archived VAP database.

The legacy database is evidence, not an executable queue.  This module never
mutates it and deliberately does not turn historical ``queued``/``running``
rows into native jobs: doing so would invent current scope and authorization.
It creates a consistent SQLite backup plus a versioned inventory that a later,
reviewed converter can consume.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Collection
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from olympus.core.execution import redact_url
from olympus.core.fileio import (
    UnsafeWriteTarget,
    atomic_write_text,
    ensure_write_target,
    read_regular_text,
)
from olympus.core.models import OlympusModel
from olympus.engagements.manifest import SignedEngagementManifest
from olympus.themis.jobs import HistoricalJobImport, JobState, ThemisJobStore
from olympus.themis.scope import host_of

MAX_LEGACY_DATABASE_BYTES = 1_000_000_000
MAX_LEGACY_MANIFEST_BYTES = 100_000_000
MAX_SIGNED_MANIFEST_BYTES = 1_000_000
MAX_LEGACY_SCANS = 100_000
_SHA256 = r"^[a-f0-9]{64}$"
_SAFE_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_REQUIRED_SCAN_COLUMNS = frozenset({"id", "target", "scan_type", "status", "created_at"})
_KNOWN_EXCLUDED_TABLES = {
    "audit_events": "requires a separate audit-provenance review",
    "consent_records": "requires a separate privacy and purpose review",
    "learning_feedback": "product analytics are outside the migration purpose",
    "learning_path_progress": "product analytics are outside the migration purpose",
    "scan_configuration_presets": "no native persisted preset contract exists",
}
_KNOWN_TABLE_COUNT_QUERIES = {
    "audit_events": 'SELECT COUNT(*) FROM "audit_events"',
    "consent_records": 'SELECT COUNT(*) FROM "consent_records"',
    "learning_feedback": 'SELECT COUNT(*) FROM "learning_feedback"',
    "learning_path_progress": 'SELECT COUNT(*) FROM "learning_path_progress"',
    "scan_configuration_presets": 'SELECT COUNT(*) FROM "scan_configuration_presets"',
}
NativeLegacyState = Literal["succeeded", "failed", "cancelled"]
ImportedJobState = Literal["partial", "failed", "cancelled"]
LegacyConversionDecision = Literal["convertible_terminal", "blocked_active", "unmapped"]
LegacyPlanDisposition = Literal[
    "review_terminal",
    "retain_deleted",
    "retain_active",
    "retain_unmapped_state",
    "retain_unmapped_scanner",
]

_STATE_MAP: dict[str, NativeLegacyState] = {
    "completed": "succeeded",
    "failed": "failed",
    "canceled": "cancelled",
}
_ACTIVE_STATES = frozenset({"queued", "running"})


class LegacyVapSnapshotError(ValueError):
    """Raised when a legacy database cannot be snapshotted unambiguously."""


class LegacyVapScan(BaseModel):
    """One privacy-minimized legacy scan inventory record."""

    model_config = ConfigDict(extra="forbid")

    legacy_scan_id: int = Field(ge=1)
    migration_key: str = Field(pattern=_SHA256)
    target_sha256: str = Field(pattern=_SHA256)
    scan_type: str = Field(min_length=1, max_length=50)
    legacy_state: str = Field(min_length=1, max_length=30)
    native_state: NativeLegacyState | None = None
    conversion_decision: LegacyConversionDecision
    created_at: str = Field(min_length=1, max_length=64)
    completed_at: str | None = Field(default=None, max_length=64)
    deleted_at: str | None = Field(default=None, max_length=64)
    findings_sha256: str | None = Field(default=None, pattern=_SHA256)
    configuration_sha256: str | None = Field(default=None, pattern=_SHA256)


class LegacyVapExcludedTable(BaseModel):
    """A legacy table intentionally kept only inside the SQLite backup."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    row_count: int | None = Field(default=None, ge=0)
    reason: str = Field(min_length=1, max_length=160)


class LegacyVapSnapshot(OlympusModel):
    """Versioned migration inventory tied to an immutable backup digest."""

    schema_name: Literal["olympus.legacy-vap-snapshot"] = "olympus.legacy-vap-snapshot"
    schema_version: Literal["1.0.0"] = "1.0.0"
    source_sha256: str = Field(pattern=_SHA256)
    backup_sha256: str = Field(pattern=_SHA256)
    source_size_bytes: int = Field(ge=1, le=MAX_LEGACY_DATABASE_BYTES)
    scan_count: int = Field(ge=0, le=MAX_LEGACY_SCANS)
    scans: list[LegacyVapScan] = Field(max_length=MAX_LEGACY_SCANS)
    excluded_tables: list[LegacyVapExcludedTable]
    rollback: Literal["retain-source-and-restore-backup"] = "retain-source-and-restore-backup"


class LegacyVapPlanEntry(BaseModel):
    """One non-executable, privacy-minimized conversion recommendation."""

    model_config = ConfigDict(extra="forbid")

    migration_key: str = Field(pattern=_SHA256)
    target_sha256: str = Field(pattern=_SHA256)
    legacy_scan_type: str = Field(min_length=1, max_length=50)
    native_scanner: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    legacy_state: str = Field(min_length=1, max_length=30)
    native_state: NativeLegacyState | None = None
    disposition: LegacyPlanDisposition
    requires_operator_review: Literal[True] = True


class LegacyVapConversionPlan(OlympusModel):
    """Review boundary between an immutable snapshot and any future import."""

    schema_name: Literal["olympus.legacy-vap-conversion-plan"] = (
        "olympus.legacy-vap-conversion-plan"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    snapshot_manifest_sha256: str = Field(pattern=_SHA256)
    backup_sha256: str = Field(pattern=_SHA256)
    entry_count: int = Field(ge=0, le=MAX_LEGACY_SCANS)
    entries: list[LegacyVapPlanEntry] = Field(max_length=MAX_LEGACY_SCANS)
    executable_jobs_created: Literal[0] = 0
    authorization_inherited: Literal[False] = False


class LegacyVapImportApprovalEntry(BaseModel):
    """One terminal legacy record explicitly approved for later archival import."""

    model_config = ConfigDict(extra="forbid")

    migration_key: str = Field(pattern=_SHA256)
    target_sha256: str = Field(pattern=_SHA256)
    native_scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    native_state: NativeLegacyState
    disposition: Literal["approved_historical_import"] = "approved_historical_import"
    historical_execution_authorized: Literal[False] = False


class LegacyVapImportApproval(OlympusModel):
    """Signed, current approval boundary for a later non-executable import."""

    schema_name: Literal["olympus.legacy-vap-import-approval"] = (
        "olympus.legacy-vap-import-approval"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    plan_sha256: str = Field(pattern=_SHA256)
    snapshot_manifest_sha256: str = Field(pattern=_SHA256)
    backup_sha256: str = Field(pattern=_SHA256)
    signed_manifest_sha256: str = Field(pattern=_SHA256)
    engagement_id: str = Field(pattern=r"^ENG-[0-9]{4}-[0-9]{5}$")
    approved_count: int = Field(ge=1, le=MAX_LEGACY_SCANS)
    approvals: list[LegacyVapImportApprovalEntry] = Field(min_length=1, max_length=MAX_LEGACY_SCANS)
    historical_execution_authorized: Literal[False] = False
    executable_jobs_created: Literal[0] = 0


class LegacyVapImportReceiptEntry(BaseModel):
    """One idempotently imported terminal record with minimized provenance."""

    model_config = ConfigDict(extra="forbid")

    migration_key: str = Field(pattern=_SHA256)
    job_id: str = Field(pattern=r"^THEMIS-[A-F0-9]{32}$")
    target_sha256: str = Field(pattern=_SHA256)
    native_scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    native_job_state: ImportedJobState
    findings_sha256: str | None = Field(default=None, pattern=_SHA256)
    configuration_sha256: str | None = Field(default=None, pattern=_SHA256)


class LegacyVapImportReceipt(OlympusModel):
    """Create-only receipt for a non-executable historical import."""

    schema_name: Literal["olympus.legacy-vap-import-receipt"] = "olympus.legacy-vap-import-receipt"
    schema_version: Literal["1.0.0"] = "1.0.0"
    approval_sha256: str = Field(pattern=_SHA256)
    backup_sha256: str = Field(pattern=_SHA256)
    signed_manifest_sha256: str = Field(pattern=_SHA256)
    engagement_id: str = Field(pattern=r"^ENG-[0-9]{4}-[0-9]{5}$")
    imported_count: int = Field(ge=1, le=MAX_LEGACY_SCANS)
    imports: list[LegacyVapImportReceiptEntry] = Field(min_length=1, max_length=MAX_LEGACY_SCANS)
    historical_execution_authorized: Literal[False] = False
    executable_jobs_created: Literal[0] = 0


def _hash_regular_file(path: Path, *, label: str) -> tuple[str, int]:
    if path.is_symlink():
        raise OSError(f"{label} must not be a symlink: {path}")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"{label} must be a regular file: {path}")
        if not 1 <= metadata.st_size <= MAX_LEGACY_DATABASE_BYTES:
            raise LegacyVapSnapshotError(
                f"{label} must be between 1 and {MAX_LEGACY_DATABASE_BYTES} bytes"
            )
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), metadata.st_size
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _optional_digest(value: object) -> str | None:
    if value is None or value == "":
        return None
    return hashlib.sha256(str(value).encode("utf-8", errors="strict")).hexdigest()


def _decision(state: str) -> tuple[NativeLegacyState | None, LegacyConversionDecision]:
    if state in _STATE_MAP:
        return _STATE_MAP[state], "convertible_terminal"
    if state in _ACTIVE_STATES:
        return None, "blocked_active"
    return None, "unmapped"


def _validated_tables(db: sqlite3.Connection) -> tuple[str, ...]:
    names = tuple(
        str(row[0])
        for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
        if not str(row[0]).startswith("sqlite_")
    )
    if "scans" not in names:
        raise LegacyVapSnapshotError("legacy database has no scans table")
    unsafe = [name for name in names if _SAFE_TABLE.fullmatch(name) is None]
    if unsafe:
        raise LegacyVapSnapshotError("legacy database contains an unsafe table identifier")
    columns = {str(row[1]) for row in db.execute('PRAGMA table_info("scans")').fetchall()}
    missing = sorted(_REQUIRED_SCAN_COLUMNS - columns)
    if missing:
        raise LegacyVapSnapshotError(
            "legacy scans table is missing required columns: " + ", ".join(missing)
        )
    return names


def _scan_inventory(db: sqlite3.Connection, source_sha256: str) -> list[LegacyVapScan]:
    count = int(db.execute('SELECT COUNT(*) FROM "scans"').fetchone()[0])
    if count > MAX_LEGACY_SCANS:
        raise LegacyVapSnapshotError(f"legacy scans table exceeds the {MAX_LEGACY_SCANS} row limit")
    records: list[LegacyVapScan] = []
    for row in db.execute('SELECT * FROM "scans" ORDER BY id'):
        row_columns = set(row.keys())
        raw_target = str(row["target"])
        raw_state = str(row["status"]).strip().lower()
        native_state, conversion = _decision(raw_state)
        records.append(
            LegacyVapScan(
                legacy_scan_id=int(row["id"]),
                migration_key=hashlib.sha256(
                    f"{source_sha256}:scans:{int(row['id'])}".encode()
                ).hexdigest(),
                target_sha256=hashlib.sha256(raw_target.encode()).hexdigest(),
                scan_type=str(row["scan_type"]),
                legacy_state=raw_state,
                native_state=native_state,
                conversion_decision=conversion,
                created_at=str(row["created_at"]),
                completed_at=(
                    str(row["completed_at"])
                    if "completed_at" in row_columns and row["completed_at"] is not None
                    else None
                ),
                deleted_at=(
                    str(row["deleted_at"])
                    if "deleted_at" in row_columns and row["deleted_at"] is not None
                    else None
                ),
                findings_sha256=(
                    _optional_digest(row["findings_json"])
                    if "findings_json" in row_columns
                    else None
                ),
                configuration_sha256=(
                    _optional_digest(row["scan_configuration_json"])
                    if "scan_configuration_json" in row_columns
                    else None
                ),
            )
        )
    return records


def _excluded_inventory(
    db: sqlite3.Connection, tables: tuple[str, ...]
) -> list[LegacyVapExcludedTable]:
    excluded: list[LegacyVapExcludedTable] = []
    for name in tables:
        if name == "scans":
            continue
        reason = _KNOWN_EXCLUDED_TABLES.get(
            name, "unrecognized legacy data requires an explicit migration decision"
        )
        query = _KNOWN_TABLE_COUNT_QUERIES.get(name)
        count = int(db.execute(query).fetchone()[0]) if query is not None else None
        excluded.append(LegacyVapExcludedTable(name=name, row_count=count, reason=reason))
    return excluded


def _publish_backup(source: sqlite3.Connection, destination: Path) -> None:
    ensure_write_target(destination, overwrite=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        with sqlite3.connect(temporary) as backup:
            source.backup(backup)
            integrity = str(backup.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise LegacyVapSnapshotError(f"legacy backup integrity check failed: {integrity}")
        temporary.chmod(0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise UnsafeWriteTarget(
                f"refusing to overwrite an existing file: {destination}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def create_legacy_vap_snapshot(source: Path, *, backup: Path, manifest: Path) -> LegacyVapSnapshot:
    """Create a consistent backup and deterministic, non-executable inventory."""
    ensure_write_target(backup, overwrite=False)
    ensure_write_target(manifest, overwrite=False)
    resolved = {source.resolve(), backup.resolve(), manifest.resolve()}
    if len(resolved) != 3:
        raise LegacyVapSnapshotError("source, backup and manifest must be different files")
    source_sha256, source_size = _hash_regular_file(source, label="legacy database")
    uri = source.resolve().as_uri() + "?mode=ro"
    backup_created = False
    try:
        with sqlite3.connect(uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            _validated_tables(db)
            _publish_backup(db, backup)
            backup_created = True
        current_sha256, current_size = _hash_regular_file(source, label="legacy database")
        if (current_sha256, current_size) != (source_sha256, source_size):
            raise LegacyVapSnapshotError("legacy database changed while the snapshot was created")
        backup_sha256, _ = _hash_regular_file(backup, label="legacy backup")
        backup_uri = backup.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(backup_uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            tables = _validated_tables(db)
            scans = _scan_inventory(db, backup_sha256)
            excluded = _excluded_inventory(db, tables)
        document = LegacyVapSnapshot(
            source_sha256=source_sha256,
            backup_sha256=backup_sha256,
            source_size_bytes=source_size,
            scan_count=len(scans),
            scans=scans,
            excluded_tables=excluded,
        )
        atomic_write_text(
            manifest,
            json.dumps(document.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            mode=0o600,
            overwrite=False,
        )
    except sqlite3.DatabaseError as exc:
        if backup_created:
            backup.unlink(missing_ok=True)
        raise LegacyVapSnapshotError(f"legacy database is not readable SQLite: {exc}") from exc
    except BaseException:
        if backup_created:
            backup.unlink(missing_ok=True)
        raise
    return document


def verify_legacy_vap_snapshot(source: Path, *, backup: Path, manifest: Path) -> LegacyVapSnapshot:
    """Fail closed unless all snapshot artifacts still describe the same data.

    The source is mandatory because its digest and size cannot be recovered from
    the backup.  Verification never repairs or rewrites an artifact and never
    promotes legacy rows into the native job store.
    """
    if len({source.resolve(), backup.resolve(), manifest.resolve()}) != 3:
        raise LegacyVapSnapshotError("source, backup and manifest must be different files")
    manifest_text = read_regular_text(
        manifest,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy snapshot manifest",
    )
    document = LegacyVapSnapshot.model_validate_json(manifest_text)
    source_sha256, source_size = _hash_regular_file(source, label="legacy database")
    backup_sha256, _ = _hash_regular_file(backup, label="legacy backup")
    if (source_sha256, source_size) != (document.source_sha256, document.source_size_bytes):
        raise LegacyVapSnapshotError("legacy source does not match the snapshot manifest")
    if backup_sha256 != document.backup_sha256:
        raise LegacyVapSnapshotError("legacy backup does not match the snapshot manifest")

    try:
        backup_uri = backup.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(backup_uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity != "ok":
                raise LegacyVapSnapshotError(f"legacy backup integrity check failed: {integrity}")
            tables = _validated_tables(db)
            scans = _scan_inventory(db, backup_sha256)
            excluded = _excluded_inventory(db, tables)
    except sqlite3.DatabaseError as exc:
        raise LegacyVapSnapshotError(f"legacy backup is not readable SQLite: {exc}") from exc

    expected = LegacyVapSnapshot(
        source_sha256=source_sha256,
        backup_sha256=backup_sha256,
        source_size_bytes=source_size,
        scan_count=len(scans),
        scans=scans,
        excluded_tables=excluded,
    )
    if document != expected:
        raise LegacyVapSnapshotError("legacy snapshot manifest inventory does not match the backup")

    current_source = _hash_regular_file(source, label="legacy database")
    current_backup = _hash_regular_file(backup, label="legacy backup")
    current_manifest = read_regular_text(
        manifest,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy snapshot manifest",
    )
    if (
        current_source != (source_sha256, source_size)
        or current_backup[0] != backup_sha256
        or current_manifest != manifest_text
    ):
        raise LegacyVapSnapshotError("legacy snapshot artifacts changed during verification")
    return document


def create_legacy_vap_conversion_plan(
    source: Path,
    *,
    backup: Path,
    manifest: Path,
    output: Path,
    native_scanners: frozenset[str],
) -> LegacyVapConversionPlan:
    """Create a review plan without reading targets or creating native jobs.

    Verification is deliberately repeated immediately before planning.  A
    terminal row with a native adapter is only recommended for review: legacy
    consent is never interpreted as current Olympus authorization.
    """
    if output.resolve() in {source.resolve(), backup.resolve(), manifest.resolve()}:
        raise LegacyVapSnapshotError("conversion plan must be a different file")
    ensure_write_target(output, overwrite=False)
    snapshot = verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    entries = [_plan_entry(scan, native_scanners) for scan in snapshot.scans]
    manifest_text = read_regular_text(
        manifest,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy snapshot manifest",
    )
    if LegacyVapSnapshot.model_validate_json(manifest_text) != snapshot:
        raise LegacyVapSnapshotError("legacy snapshot manifest changed while planning")
    plan = LegacyVapConversionPlan(
        snapshot_manifest_sha256=hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
        backup_sha256=snapshot.backup_sha256,
        entry_count=len(entries),
        entries=entries,
    )
    atomic_write_text(
        output,
        json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        mode=0o600,
        overwrite=False,
    )
    return plan


def _plan_entry(scan: LegacyVapScan, native_scanners: frozenset[str]) -> LegacyVapPlanEntry:
    normalized_scanner = scan.scan_type.strip().lower()
    native_scanner = normalized_scanner if normalized_scanner in native_scanners else None
    if scan.deleted_at is not None:
        disposition: LegacyPlanDisposition = "retain_deleted"
    elif scan.conversion_decision == "blocked_active":
        disposition = "retain_active"
    elif scan.conversion_decision == "unmapped":
        disposition = "retain_unmapped_state"
    elif native_scanner is None:
        disposition = "retain_unmapped_scanner"
    else:
        disposition = "review_terminal"
    return LegacyVapPlanEntry(
        migration_key=scan.migration_key,
        target_sha256=scan.target_sha256,
        legacy_scan_type=scan.scan_type,
        native_scanner=native_scanner,
        legacy_state=scan.legacy_state,
        native_state=scan.native_state,
        disposition=disposition,
    )


def approve_legacy_vap_import(
    source: Path,
    *,
    backup: Path,
    manifest: Path,
    plan_path: Path,
    signed_manifest_path: Path,
    trusted_public_key_path: Path,
    output: Path,
    migration_keys: Collection[str],
    native_scanners: frozenset[str],
    revoked: Collection[str] = (),
    now: datetime | None = None,
) -> LegacyVapImportApproval:
    """Approve selected terminal records without importing or executing them.

    The current signed engagement manifest authorizes the *present import
    review*.  It cannot prove that a historical scan was authorized, so the
    resulting contract records that distinction explicitly and creates no job.
    """
    artifact_paths = {
        source.resolve(),
        backup.resolve(),
        manifest.resolve(),
        plan_path.resolve(),
        signed_manifest_path.resolve(),
        trusted_public_key_path.resolve(),
        output.resolve(),
    }
    if len(artifact_paths) != 7:
        raise LegacyVapSnapshotError("legacy approval artifacts must be different files")
    ensure_write_target(output, overwrite=False)
    selected = tuple(migration_keys)
    if not selected:
        raise LegacyVapSnapshotError("at least one migration key must be explicitly selected")
    if len(selected) != len(set(selected)):
        raise LegacyVapSnapshotError("migration keys must be unique")
    if any(re.fullmatch(_SHA256, key) is None for key in selected):
        raise LegacyVapSnapshotError("migration keys must be lowercase SHA-256 digests")

    snapshot = verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    manifest_text = read_regular_text(
        manifest,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy snapshot manifest",
    )
    plan_text = read_regular_text(
        plan_path,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy conversion plan",
    )
    plan = LegacyVapConversionPlan.model_validate_json(plan_text)
    expected_plan_entries = [_plan_entry(scan, native_scanners) for scan in snapshot.scans]
    expected_plan = LegacyVapConversionPlan(
        snapshot_manifest_sha256=hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
        backup_sha256=snapshot.backup_sha256,
        entry_count=len(expected_plan_entries),
        entries=expected_plan_entries,
    )
    if plan != expected_plan:
        raise LegacyVapSnapshotError("legacy conversion plan does not match the verified snapshot")

    signed_text = read_regular_text(
        signed_manifest_path,
        max_bytes=MAX_SIGNED_MANIFEST_BYTES,
        label="signed engagement manifest",
    )
    signed_manifest = SignedEngagementManifest.model_validate_json(signed_text)
    public_key = read_regular_text(
        trusted_public_key_path,
        max_bytes=64 * 1024,
        label="trusted manifest public key",
    )
    selected_entries = {entry.migration_key: entry for entry in plan.entries}
    unknown = sorted(set(selected) - selected_entries.keys())
    if unknown:
        raise LegacyVapSnapshotError("selected migration key is not present in the conversion plan")

    scan_by_key = {scan.migration_key: scan for scan in snapshot.scans}
    id_by_key = {scan.migration_key: scan.legacy_scan_id for scan in snapshot.scans}
    approval_entries: list[LegacyVapImportApprovalEntry] = []
    targets: set[str] = set()
    backup_uri = backup.resolve().as_uri() + "?mode=ro"
    instant = now if now is not None else datetime.now(UTC)
    try:
        with sqlite3.connect(backup_uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            for migration_key in selected:
                entry = selected_entries[migration_key]
                scan = scan_by_key[migration_key]
                if (
                    entry.disposition != "review_terminal"
                    or entry.native_scanner is None
                    or entry.native_state is None
                ):
                    raise LegacyVapSnapshotError(
                        "only review_terminal records can be approved for historical import"
                    )
                row = db.execute(
                    'SELECT target FROM "scans" WHERE id = ?', (id_by_key[migration_key],)
                ).fetchone()
                if row is None:
                    raise LegacyVapSnapshotError("approved legacy row is missing from the backup")
                target = str(row["target"])
                if hashlib.sha256(target.encode()).hexdigest() != scan.target_sha256:
                    raise LegacyVapSnapshotError("approved legacy target does not match its digest")
                signed_manifest.authorize(
                    trusted_public_key_pem=public_key,
                    target=target,
                    technique=entry.native_scanner,
                    now=instant,
                    revoked=revoked,
                )
                targets.add(target)
                approval_entries.append(
                    LegacyVapImportApprovalEntry(
                        migration_key=migration_key,
                        target_sha256=entry.target_sha256,
                        native_scanner=entry.native_scanner,
                        native_state=entry.native_state,
                    )
                )
    except sqlite3.DatabaseError as exc:
        raise LegacyVapSnapshotError(f"legacy backup is not readable SQLite: {exc}") from exc
    if len(targets) > signed_manifest.manifest.max_targets:
        raise LegacyVapSnapshotError("selected legacy targets exceed the signed manifest limit")

    if verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest) != snapshot:
        raise LegacyVapSnapshotError("legacy snapshot changed while approval was created")
    if (
        read_regular_text(
            plan_path,
            max_bytes=MAX_LEGACY_MANIFEST_BYTES,
            label="legacy conversion plan",
        )
        != plan_text
    ):
        raise LegacyVapSnapshotError("legacy conversion plan changed while approval was created")
    approval = LegacyVapImportApproval(
        plan_sha256=hashlib.sha256(plan_text.encode("utf-8")).hexdigest(),
        snapshot_manifest_sha256=plan.snapshot_manifest_sha256,
        backup_sha256=plan.backup_sha256,
        signed_manifest_sha256=signed_manifest.manifest_sha256,
        engagement_id=signed_manifest.manifest.engagement_id,
        approved_count=len(approval_entries),
        approvals=approval_entries,
    )
    atomic_write_text(
        output,
        json.dumps(approval.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        mode=0o600,
        overwrite=False,
    )
    return approval


def _legacy_timestamp(value: str | None, *, fallback: datetime | None = None) -> datetime:
    if value is None:
        if fallback is None:
            raise LegacyVapSnapshotError("legacy terminal record has no completion timestamp")
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LegacyVapSnapshotError("legacy timestamp is not valid ISO 8601") from exc
    if parsed.tzinfo is None:
        raise LegacyVapSnapshotError("legacy timestamps must include a timezone")
    return parsed.astimezone(UTC)


def _legacy_target_kind(target: str) -> Literal["host", "domain", "url"]:
    parsed = urlsplit(target)
    if parsed.scheme:
        kind: Literal["host", "domain", "url"] = "url"
    else:
        try:
            ipaddress.ip_address(target.rstrip("."))
        except ValueError:
            kind = "domain"
        else:
            kind = "host"
    host_of(kind, target)
    return kind


def import_legacy_vap_history(
    source: Path,
    *,
    backup: Path,
    manifest: Path,
    plan_path: Path,
    approval_path: Path,
    signed_manifest_path: Path,
    trusted_public_key_path: Path,
    database: Path,
    output: Path,
    native_scanners: frozenset[str],
    revoked: Collection[str] = (),
    now: datetime | None = None,
) -> LegacyVapImportReceipt:
    """Import reviewed terminal history without creating executable work.

    The original target is used only for current signature/scope verification.
    Sensitive URL query values are redacted before persistence.  A historical
    ``completed`` row becomes ``partial`` because its untrusted finding body is
    retained in the immutable backup rather than being presented as exhaustive
    native evidence.
    """
    artifact_paths = {
        source.resolve(),
        backup.resolve(),
        manifest.resolve(),
        plan_path.resolve(),
        approval_path.resolve(),
        signed_manifest_path.resolve(),
        trusted_public_key_path.resolve(),
        database.resolve(),
        output.resolve(),
    }
    if len(artifact_paths) != 9:
        raise LegacyVapSnapshotError("legacy import artifacts and database must be different")
    ensure_write_target(output, overwrite=False)
    snapshot = verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    manifest_text = read_regular_text(
        manifest,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy snapshot manifest",
    )
    plan_text = read_regular_text(
        plan_path,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy conversion plan",
    )
    plan = LegacyVapConversionPlan.model_validate_json(plan_text)
    expected_entries = [_plan_entry(scan, native_scanners) for scan in snapshot.scans]
    expected_plan = LegacyVapConversionPlan(
        snapshot_manifest_sha256=hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
        backup_sha256=snapshot.backup_sha256,
        entry_count=len(expected_entries),
        entries=expected_entries,
    )
    if plan != expected_plan:
        raise LegacyVapSnapshotError("legacy conversion plan does not match the verified snapshot")

    approval_text = read_regular_text(
        approval_path,
        max_bytes=MAX_LEGACY_MANIFEST_BYTES,
        label="legacy import approval",
    )
    approval = LegacyVapImportApproval.model_validate_json(approval_text)
    if (
        approval.plan_sha256 != hashlib.sha256(plan_text.encode("utf-8")).hexdigest()
        or approval.snapshot_manifest_sha256 != plan.snapshot_manifest_sha256
        or approval.backup_sha256 != snapshot.backup_sha256
    ):
        raise LegacyVapSnapshotError("legacy import approval does not match the verified plan")

    signed_text = read_regular_text(
        signed_manifest_path,
        max_bytes=MAX_SIGNED_MANIFEST_BYTES,
        label="signed engagement manifest",
    )
    signed_manifest = SignedEngagementManifest.model_validate_json(signed_text)
    if (
        approval.signed_manifest_sha256 != signed_manifest.manifest_sha256
        or approval.engagement_id != signed_manifest.manifest.engagement_id
    ):
        raise LegacyVapSnapshotError("legacy approval does not match the signed manifest")
    public_key = read_regular_text(
        trusted_public_key_path,
        max_bytes=64 * 1024,
        label="trusted manifest public key",
    )
    approval_by_key = {item.migration_key: item for item in approval.approvals}
    if approval.approved_count != len(approval_by_key):
        raise LegacyVapSnapshotError("legacy approval contains duplicate migration keys")
    scan_by_key = {scan.migration_key: scan for scan in snapshot.scans}
    plan_by_key = {entry.migration_key: entry for entry in plan.entries}
    instant = now if now is not None else datetime.now(UTC)
    historical: list[HistoricalJobImport] = []
    receipt_source: list[tuple[LegacyVapScan, LegacyVapImportApprovalEntry, ImportedJobState]] = []
    backup_uri = backup.resolve().as_uri() + "?mode=ro"
    try:
        with sqlite3.connect(backup_uri, uri=True) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only = ON")
            for migration_key, approved in approval_by_key.items():
                scan = scan_by_key.get(migration_key)
                planned = plan_by_key.get(migration_key)
                if scan is None or planned is None:
                    raise LegacyVapSnapshotError(
                        "approved legacy record is absent from the snapshot"
                    )
                if (
                    planned.disposition != "review_terminal"
                    or approved.target_sha256 != scan.target_sha256
                    or approved.native_scanner != planned.native_scanner
                    or approved.native_state != planned.native_state
                ):
                    raise LegacyVapSnapshotError("legacy approval entry does not match the plan")
                row = db.execute(
                    'SELECT target FROM "scans" WHERE id = ?', (scan.legacy_scan_id,)
                ).fetchone()
                if row is None:
                    raise LegacyVapSnapshotError("approved legacy row is missing from the backup")
                target = str(row["target"])
                if hashlib.sha256(target.encode()).hexdigest() != scan.target_sha256:
                    raise LegacyVapSnapshotError("approved legacy target does not match its digest")
                signed_manifest.authorize(
                    trusted_public_key_pem=public_key,
                    target=target,
                    technique=approved.native_scanner,
                    now=instant,
                    revoked=revoked,
                )
                created_at = _legacy_timestamp(scan.created_at)
                finished_at = _legacy_timestamp(scan.completed_at, fallback=created_at)
                receipt_state = cast(
                    ImportedJobState,
                    {
                        "succeeded": "partial",
                        "failed": "failed",
                        "cancelled": "cancelled",
                    }[approved.native_state],
                )
                state = JobState(receipt_state)
                historical.append(
                    HistoricalJobImport(
                        idempotency_key=f"legacy-vap:{migration_key}",
                        scanner=approved.native_scanner,
                        target=redact_url(target),
                        target_kind=_legacy_target_kind(target),
                        scope_path=signed_manifest_path,
                        state=state,
                        created_at=created_at,
                        finished_at=finished_at,
                        result={
                            "schema_name": "olympus.legacy-vap-history",
                            "schema_version": "1.0.0",
                            "migration_key": migration_key,
                            "target_sha256": scan.target_sha256,
                            "findings_sha256": scan.findings_sha256,
                            "configuration_sha256": scan.configuration_sha256,
                            "import_manifest_sha256": signed_manifest.manifest_sha256,
                            "historical_execution_authorized": False,
                            "coverage_complete": False,
                        },
                    )
                )
                receipt_source.append((scan, approved, receipt_state))
    except sqlite3.DatabaseError as exc:
        raise LegacyVapSnapshotError(f"legacy backup is not readable SQLite: {exc}") from exc

    if (
        len({item.target_sha256 for item in approval.approvals})
        > signed_manifest.manifest.max_targets
    ):
        raise LegacyVapSnapshotError("approved legacy targets exceed the signed manifest limit")
    if verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest) != snapshot:
        raise LegacyVapSnapshotError("legacy snapshot changed while import was prepared")
    if (
        read_regular_text(
            approval_path,
            max_bytes=MAX_LEGACY_MANIFEST_BYTES,
            label="legacy import approval",
        )
        != approval_text
    ):
        raise LegacyVapSnapshotError("legacy approval changed while import was prepared")

    jobs = ThemisJobStore(database).import_historical_terminal(historical)
    imports = [
        LegacyVapImportReceiptEntry(
            migration_key=scan.migration_key,
            job_id=job.job_id,
            target_sha256=scan.target_sha256,
            native_scanner=approved.native_scanner,
            native_job_state=state,
            findings_sha256=scan.findings_sha256,
            configuration_sha256=scan.configuration_sha256,
        )
        for job, (scan, approved, state) in zip(jobs, receipt_source, strict=True)
    ]
    receipt = LegacyVapImportReceipt(
        approval_sha256=hashlib.sha256(approval_text.encode("utf-8")).hexdigest(),
        backup_sha256=snapshot.backup_sha256,
        signed_manifest_sha256=signed_manifest.manifest_sha256,
        engagement_id=signed_manifest.manifest.engagement_id,
        imported_count=len(imports),
        imports=imports,
    )
    atomic_write_text(
        output,
        json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        mode=0o600,
        overwrite=False,
    )
    return receipt

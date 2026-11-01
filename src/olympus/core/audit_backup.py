"""Backup, verify and restore of the structured audit log (ROADMAP WEB-J-01).

The structured audit log is an append-only JSON-Lines file written by
``append_structured_audit``. A snapshot is a byte-exact copy that is first
validated line by line against the redacted record shape, so a truncated tail
(a write caught mid-flight), a non-JSON line or an unredacted secret-bearing
key is refused instead of being preserved as a "good" backup. The SHA-256 is an
unauthenticated fingerprint: record it separately or sign it with ``olympus
core sign``. The log has no hash chain, so this verifies shape, not authorship.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from olympus.core.execution import redact_mapping
from olympus.core.fileio import UnsafeWriteTarget, atomic_write_bytes, read_regular_bytes

DEFAULT_MAX_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 5_000_000
MAX_LINE_BYTES = 1_000_001
_REQUIRED = frozenset({"timestamp", "execution_id", "action", "outcome", "target", "metadata"})


class AuditBackupError(ValueError):
    """Raised when an audit log or snapshot is unsafe, malformed or unredacted."""


@dataclass(frozen=True)
class AuditBackupInfo:
    """Verified facts about one audit log snapshot."""

    records: int
    size_bytes: int
    sha256: str
    first_timestamp: str | None
    last_timestamp: str | None


def _inspect(data: bytes, *, label: str) -> AuditBackupInfo:
    if data and not data.endswith(b"\n"):
        raise AuditBackupError(f"{label} ends with an incomplete record (torn write?)")
    first: str | None = None
    last: str | None = None
    count = 0
    for number, raw in enumerate(data.splitlines(), start=1):
        if len(raw) > MAX_LINE_BYTES:
            raise AuditBackupError(f"{label} line {number} exceeds the record size limit")
        count += 1
        if count > MAX_RECORDS:
            raise AuditBackupError(f"{label} has more than {MAX_RECORDS} records")
        try:
            record: Any = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise AuditBackupError(f"{label} line {number} is not valid JSON") from exc
        if not isinstance(record, dict) or set(record) != _REQUIRED:
            raise AuditBackupError(f"{label} line {number} does not match the audit record shape")
        for key in ("timestamp", "execution_id", "action", "outcome"):
            if not isinstance(record[key], str) or not record[key]:
                raise AuditBackupError(f"{label} line {number}: {key} must be a non-empty string")
        if record["target"] is not None and not isinstance(record["target"], str):
            raise AuditBackupError(f"{label} line {number}: target must be a string or null")
        metadata = record["metadata"]
        if not isinstance(metadata, dict) or redact_mapping(metadata) != metadata:
            raise AuditBackupError(f"{label} line {number} contains unredacted metadata")
        first = first or record["timestamp"]
        last = record["timestamp"]
    return AuditBackupInfo(
        records=count,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        first_timestamp=first,
        last_timestamp=last,
    )


def _read(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        return read_regular_bytes(path, max_bytes=max_bytes, label=label)
    except FileNotFoundError as exc:
        raise AuditBackupError(f"{label} does not exist: {path}") from exc
    except (OSError, ValueError) as exc:
        raise AuditBackupError(str(exc)) from exc


def verify_audit_backup(backup: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> AuditBackupInfo:
    """Validate every record of ``backup`` and fingerprint its bytes."""
    return _inspect(_read(backup, max_bytes=max_bytes, label="audit backup"), label="audit backup")


def _publish(source: Path, destination: Path, *, max_bytes: int, label: str) -> AuditBackupInfo:
    if destination.is_symlink() or destination.exists():
        raise AuditBackupError("destination already exists; refusing to overwrite")
    data = _read(source, max_bytes=max_bytes, label=label)
    _inspect(data, label=label)
    try:
        atomic_write_bytes(destination, data, mode=0o600, overwrite=False)
    except UnsafeWriteTarget as exc:
        raise AuditBackupError("destination already exists; refusing to overwrite") from exc
    return verify_audit_backup(destination, max_bytes=max_bytes)


def backup_audit_log(
    log: Path, destination: Path, *, max_bytes: int = DEFAULT_MAX_BYTES
) -> AuditBackupInfo:
    """Snapshot a validated audit log to a new ``0600`` path (create-only)."""
    return _publish(log, destination, max_bytes=max_bytes, label="audit log")


def restore_audit_backup(
    backup: Path, destination: Path, *, max_bytes: int = DEFAULT_MAX_BYTES
) -> AuditBackupInfo:
    """Restore a verified snapshot to an absent path; never overwrites a live log."""
    return _publish(backup, destination, max_bytes=max_bytes, label="audit backup")

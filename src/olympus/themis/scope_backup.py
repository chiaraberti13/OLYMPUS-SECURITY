"""Backup, verify and restore of the Themis engagement scope file (WEB-J-01).

The scope file is the authorisation perimeter for native scans, so a snapshot
must never preserve (or restore) a perimeter that the scanner itself would
refuse. Every operation therefore validates the document with the same
``load_scope`` used at scan time (strict contract, bounded size, non-empty), and
publishes an exact byte copy create-only with ``0600``. The SHA-256 is an
unauthenticated fingerprint: record it separately or sign it with ``olympus
core sign``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from olympus.core.fileio import UnsafeWriteTarget, atomic_write_bytes, read_regular_bytes
from olympus.themis.application import DEFAULT_MAX_SCOPE_BYTES, load_scope


class ScopeBackupError(ValueError):
    """Raised when a scope file or snapshot is unsafe, invalid or would be overwritten."""


@dataclass(frozen=True)
class ScopeBackupInfo:
    """Verified facts about one scope snapshot."""

    hosts: int
    domains: int
    cidrs: int
    size_bytes: int
    sha256: str


def verify_scope_backup(backup: Path) -> ScopeBackupInfo:
    """Validate ``backup`` with the scan-time scope loader and fingerprint its bytes."""
    try:
        data = read_regular_bytes(backup, max_bytes=DEFAULT_MAX_SCOPE_BYTES, label="scope backup")
        scope = load_scope(backup)
    except FileNotFoundError as exc:
        raise ScopeBackupError(f"scope backup does not exist: {backup}") from exc
    except (OSError, ValueError) as exc:
        raise ScopeBackupError(str(exc)) from exc
    return ScopeBackupInfo(
        hosts=len(scope.allowed_hosts),
        domains=len(scope.allowed_domains),
        cidrs=len(scope.allowed_cidrs),
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _publish(source: Path, destination: Path) -> ScopeBackupInfo:
    if destination.is_symlink() or destination.exists():
        raise ScopeBackupError("destination already exists; refusing to overwrite")
    info = verify_scope_backup(source)
    try:
        data = read_regular_bytes(source, max_bytes=DEFAULT_MAX_SCOPE_BYTES, label="scope")
    except OSError as exc:
        raise ScopeBackupError(str(exc)) from exc
    if hashlib.sha256(data).hexdigest() != info.sha256:
        raise ScopeBackupError("scope changed while it was being copied; retry")
    try:
        atomic_write_bytes(destination, data, mode=0o600, overwrite=False)
    except UnsafeWriteTarget as exc:
        raise ScopeBackupError("destination already exists; refusing to overwrite") from exc
    return verify_scope_backup(destination)


def backup_scope(scope: Path, destination: Path) -> ScopeBackupInfo:
    """Snapshot a valid scope file to a new ``0600`` path (create-only)."""
    return _publish(scope, destination)


def restore_scope(backup: Path, destination: Path) -> ScopeBackupInfo:
    """Restore a verified snapshot to an absent path; never overwrites a live scope."""
    return _publish(backup, destination)

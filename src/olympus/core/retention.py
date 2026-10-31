"""Retention and best-effort secure deletion for logs, artefacts and evidence.

An offensive-security tool accumulates the most sensitive material in an
engagement: scanner output, evidence exports, audit trails naming targets and
identities. Keeping it forever is a liability, and deleting it with ``unlink``
leaves the plaintext on disk until the blocks happen to be reused.

This module provides the two operations that answer that, and is deliberately
honest about the limits of the second one:

* :func:`prune_paths` enforces an age / count / size budget over a directory of
  artefacts, oldest first.
* :func:`secure_delete` overwrites a file's current contents before unlinking
  it, then :func:`rotate_log` uses both to keep an append-only log bounded.

**What overwriting can and cannot promise.** Writing over a file removes the
plaintext from the blocks the file currently occupies, which defeats
undelete-style recovery and casual inspection of free space. It does *not*
guarantee erasure: a copy-on-write or journalling filesystem (Btrfs, ZFS, APFS,
ext4 with data journalling), a snapshot, an SSD's wear-levelling layer, or a
backup may retain an older copy that no userspace write can reach. The
dependable control for data at rest is full-disk or filesystem encryption;
this is defence in depth on top of it, not a substitute.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

#: Overwriting is done in bounded chunks so a large artefact cannot be read
#: into memory in one go.
_CHUNK_BYTES = 1024 * 1024

#: A file larger than this is truncated rather than fully overwritten: writing
#: tens of gigabytes to "delete" one file is its own kind of outage.
MAX_OVERWRITE_BYTES = 512 * 1024 * 1024

MAX_AGE_DAYS = 3_650
MAX_KEPT_FILES = 10_000


class RetentionError(ValueError):
    """Raised when a retention policy or target is invalid or unsafe."""


@dataclass(frozen=True)
class RetentionPolicy:
    """How much history a directory of artefacts may keep."""

    #: Delete anything last modified longer ago than this. ``None`` keeps all ages.
    max_age_days: int | None = None
    #: Keep at most this many files, deleting the oldest first.
    max_files: int | None = None
    #: Keep at most this many bytes in total, deleting the oldest first.
    max_total_bytes: int | None = None
    #: Overwrite contents before unlinking (see the module docstring's caveats).
    secure: bool = True

    def __post_init__(self) -> None:
        if self.max_age_days is not None and not 0 <= self.max_age_days <= MAX_AGE_DAYS:
            raise RetentionError(f"max_age_days must be between 0 and {MAX_AGE_DAYS}")
        if self.max_files is not None and not 0 <= self.max_files <= MAX_KEPT_FILES:
            raise RetentionError(f"max_files must be between 0 and {MAX_KEPT_FILES}")
        if self.max_total_bytes is not None and self.max_total_bytes < 0:
            raise RetentionError("max_total_bytes must not be negative")
        if (self.max_age_days, self.max_files, self.max_total_bytes) == (None, None, None):
            raise RetentionError("a retention policy must bound age, count or total size")


@dataclass(frozen=True)
class RetentionReport:
    """What a retention pass looked at, what it removed, and what it kept."""

    examined: int
    removed: tuple[str, ...]
    freed_bytes: int
    kept: int
    dry_run: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "examined": self.examined,
            "removed": list(self.removed),
            "removed_count": len(self.removed),
            "freed_bytes": self.freed_bytes,
            "kept": self.kept,
            "dry_run": self.dry_run,
        }


def secure_delete(path: Path, *, overwrite: bool = True) -> int:
    """Overwrite a regular file's contents, then unlink it. Returns bytes freed.

    Refuses symlinks and anything that is not a regular file: following a link
    would overwrite whatever it points at, which is exactly the primitive an
    attacker wants from a cleanup job running with the server's privileges.
    """
    if path.is_symlink():
        raise RetentionError(f"refusing to delete through a symlink: {path}")
    try:
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RetentionError(f"refusing to delete a non-regular file: {path}")
        size = metadata.st_size
        if overwrite:
            _overwrite(descriptor, min(size, MAX_OVERWRITE_BYTES))
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.unlink(missing_ok=True)
    _fsync_directory(path.parent)
    return size


def _overwrite(descriptor: int, size: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = size
    while remaining > 0:
        block = min(remaining, _CHUNK_BYTES)
        os.write(descriptor, secrets.token_bytes(block))
        remaining -= block
    os.fsync(descriptor)


def prune_paths(
    directory: Path,
    *,
    policy: RetentionPolicy,
    pattern: str = "*",
    dry_run: bool = False,
    now: datetime | None = None,
) -> RetentionReport:
    """Apply ``policy`` to the files in ``directory``, oldest first.

    Only regular files directly inside the directory are considered; symlinks
    and subdirectories are left alone rather than followed.
    """
    if directory.is_symlink() or not directory.is_dir():
        raise RetentionError(f"retention target must be a non-symlink directory: {directory}")
    if "/" in pattern or "\\" in pattern or ".." in pattern:
        raise RetentionError("retention pattern must name files in one directory")
    moment = now or datetime.now(UTC)
    candidates = sorted(_regular_files(directory, pattern), key=lambda item: item[1])
    doomed: list[tuple[Path, float, int]] = []
    survivors = list(candidates)

    if policy.max_age_days is not None:
        cutoff = (moment - timedelta(days=policy.max_age_days)).timestamp()
        expired = [item for item in survivors if item[1] < cutoff]
        doomed.extend(expired)
        survivors = [item for item in survivors if item not in expired]
    if policy.max_files is not None:
        while len(survivors) > policy.max_files:
            doomed.append(survivors.pop(0))
    if policy.max_total_bytes is not None:
        total = sum(item[2] for item in survivors)
        while survivors and total > policy.max_total_bytes:
            oldest = survivors.pop(0)
            total -= oldest[2]
            doomed.append(oldest)

    freed = 0
    removed: list[str] = []
    for path, _, size in doomed:
        if not dry_run:
            freed += secure_delete(path, overwrite=policy.secure)
        else:
            freed += size
        removed.append(path.name)
    return RetentionReport(
        examined=len(candidates),
        removed=tuple(sorted(removed)),
        freed_bytes=freed,
        kept=len(survivors),
        dry_run=dry_run,
    )


def rotate_log(path: Path, *, max_bytes: int, keep: int, secure: bool = True) -> RetentionReport:
    """Roll an append-only log once it passes ``max_bytes``, keeping ``keep`` files.

    The live file becomes ``.1``, each older generation shifts up, and anything
    past ``keep`` is securely deleted. Rotating instead of truncating keeps the
    log append-only: no record is ever rewritten in place, it simply ages out.
    """
    if not 1 <= max_bytes <= 10_000_000_000:
        raise RetentionError("max_bytes must be between 1 and 10000000000")
    if not 0 <= keep <= 100:
        raise RetentionError("keep must be between 0 and 100")
    if path.is_symlink():
        raise RetentionError(f"refusing to rotate through a symlink: {path}")
    if not path.exists():
        return RetentionReport(0, (), 0, 0, False)
    if path.stat().st_size <= max_bytes:
        return RetentionReport(1, (), 0, 1, False)

    removed: list[str] = []
    freed = 0
    oldest = path.with_name(f"{path.name}.{keep}") if keep else path
    if keep and oldest.exists():
        freed += secure_delete(oldest, overwrite=secure)
        removed.append(oldest.name)
    for generation in range(keep - 1, 0, -1):
        source = path.with_name(f"{path.name}.{generation}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{generation + 1}"))
    if keep:
        path.replace(path.with_name(f"{path.name}.1"))
    else:  # no history kept: the live log is removed outright
        freed += secure_delete(path, overwrite=secure)
        removed.append(path.name)
    _fsync_directory(path.parent)
    return RetentionReport(
        examined=1, removed=tuple(removed), freed_bytes=freed, kept=min(keep, 1), dry_run=False
    )


def _regular_files(directory: Path, pattern: str) -> Iterable[tuple[Path, float, int]]:
    for entry in directory.glob(pattern):
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            metadata = entry.stat()
        except OSError:  # pragma: no cover - vanished between listing and stat
            continue
        yield entry, metadata.st_mtime, metadata.st_size


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:  # pragma: no cover - not every platform permits directory fsync
        return
    try:
        os.fsync(descriptor)
    except OSError:  # pragma: no cover - filesystem-dependent durability support
        pass
    finally:
        os.close(descriptor)

"""Coordinated backup manifest (ROADMAP WEB-J-01).

Each Olympus store produces its own verified snapshot. This module binds a set
of those already-published files into one deterministic manifest so an operator
can detect a missing, extra, swapped, truncated or modified snapshot before a
restore. It is pure, offline and store-agnostic: it hashes files and never opens
or interprets their contents, so per-store schema/integrity checks stay with the
store verifiers. The manifest is an *integrity fingerprint set*, not an
authenticated document; sign it with ``olympus core sign`` for provenance.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from olympus.core.fileio import UnsafeWriteTarget, atomic_write_bytes

SCHEMA_NAME = "olympus.backup-manifest"
SCHEMA_VERSION = "1.0.0"
MANIFEST_NAME = "backup-manifest.json"
MAX_COMPONENTS = 64
MAX_MANIFEST_BYTES = 1_000_000
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_CHUNK = 1024 * 1024


class BackupManifestError(ValueError):
    """Raised when a manifest or one of its components is unsafe or inconsistent."""


@dataclass(frozen=True)
class ComponentDigest:
    """Size and SHA-256 of one snapshot file."""

    name: str
    file: str
    size_bytes: int
    sha256: str


def _safe_file(directory: Path, relative: str) -> Path:
    pure = Path(relative)
    if pure.is_absolute() or len(pure.parts) != 1 or relative in {".", ".."}:
        raise BackupManifestError(f"component file must be a plain name: {relative!r}")
    path = directory / relative
    if path.is_symlink() or not path.is_file():
        raise BackupManifestError(f"component is not a regular file: {relative}")
    return path


def _digest(path: Path) -> tuple[int, str]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            size += len(chunk)
            hasher.update(chunk)
    return size, hasher.hexdigest()


def build_manifest(
    directory: Path, components: dict[str, str], *, created_at: datetime | None = None
) -> dict[str, object]:
    """Hash ``components`` (logical name -> file name inside ``directory``)."""
    if not components or len(components) > MAX_COMPONENTS:
        raise BackupManifestError(f"1 to {MAX_COMPONENTS} components are required")
    files = list(components.values())
    if len(set(files)) != len(files):
        raise BackupManifestError("two components must not share the same file")
    entries = []
    for name in sorted(components):
        if not _NAME.fullmatch(name):
            raise BackupManifestError(f"invalid component name: {name!r}")
        if components[name] == MANIFEST_NAME:
            raise BackupManifestError("a component must not be the manifest itself")
        size, sha = _digest(_safe_file(directory, components[name]))
        entries.append({"name": name, "file": components[name], "size_bytes": size, "sha256": sha})
    moment = (created_at or datetime.now(UTC)).astimezone(UTC)
    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "created_at": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "components": entries,
    }


def write_manifest(directory: Path, manifest: dict[str, object]) -> Path:
    """Publish ``manifest`` create-only as ``backup-manifest.json``."""
    path = directory / MANIFEST_NAME
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    try:
        atomic_write_bytes(path, text.encode("utf-8"), mode=0o600, overwrite=False)
    except (FileExistsError, UnsafeWriteTarget) as exc:
        raise BackupManifestError("manifest already exists; refusing to overwrite") from exc
    return path


def _parse(directory: Path) -> list[ComponentDigest]:
    path = directory / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        raise BackupManifestError("manifest is missing or not a regular file")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise BackupManifestError("manifest is too large")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupManifestError("manifest is not valid JSON") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema_name") != SCHEMA_NAME
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("components"), list)
        or not 1 <= len(data["components"]) <= MAX_COMPONENTS
    ):
        raise BackupManifestError("unsupported or malformed manifest")
    result: list[ComponentDigest] = []
    for raw in data["components"]:
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("name"), str)
            or not _NAME.fullmatch(raw["name"])
            or not isinstance(raw.get("file"), str)
            or not isinstance(raw.get("size_bytes"), int)
            or isinstance(raw.get("size_bytes"), bool)
            or not isinstance(raw.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", raw["sha256"])
        ):
            raise BackupManifestError("malformed manifest component")
        result.append(ComponentDigest(raw["name"], raw["file"], raw["size_bytes"], raw["sha256"]))
    names = [c.name for c in result]
    files = [c.file for c in result]
    if len(set(names)) != len(names) or len(set(files)) != len(files):
        raise BackupManifestError("duplicate component in manifest")
    return result


def verify_manifest(directory: Path) -> list[ComponentDigest]:
    """Re-hash every listed file; reject mismatches and unlisted extra files."""
    components = _parse(directory)
    for component in components:
        size, sha = _digest(_safe_file(directory, component.file))
        if size != component.size_bytes or sha != component.sha256:
            raise BackupManifestError(f"component {component.name} does not match the manifest")
    listed = {c.file for c in components} | {MANIFEST_NAME, MANIFEST_NAME + ".sig"}
    extra = sorted(p.name for p in directory.iterdir() if p.name not in listed)
    if extra:
        raise BackupManifestError(f"unlisted files in backup directory: {', '.join(extra)}")
    return components

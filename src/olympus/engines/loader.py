"""Load and validate ``engine.toml`` manifests, in the same form for CLI, CI and tests."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from olympus.core.errors import ValidationReport, format_validation_error
from olympus.core.fileio import read_regular_bytes
from olympus.engines.schema import DataManifest, EngineManifest

MANIFEST_NAME = "engine.toml"
#: A manifest is a few hundred bytes; anything near this cap is not a manifest.
MAX_MANIFEST_BYTES = 64 * 1024
ENGINES_ROOT = Path(__file__).resolve().parent
#: Data dependencies live apart from engines: ``_data/<name>.toml``.
DATA_ROOT = ENGINES_ROOT / "_data"


class ManifestError(ValueError):
    """A manifest is unreadable, malformed, or inconsistent with where it lives."""

    def __init__(self, message: str, report: ValidationReport | None = None) -> None:
        super().__init__(message)
        self.report = report


def parse_manifest(text: str, *, source: str = "<string>") -> EngineManifest:
    """Validate manifest ``text``; raise :class:`ManifestError` with a structured report."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{source}: invalid TOML: {exc}") from exc
    try:
        return EngineManifest.model_validate(raw)
    except ValidationError as exc:
        report = format_validation_error(exc, schema="olympus.engine-manifest", source=source)
        raise ManifestError(report.to_human(), report) from exc


def load_manifest(path: Path) -> EngineManifest:
    """Read one manifest file (bounded, no symlinks) and check the directory name matches."""
    try:
        data = read_regular_bytes(path, max_bytes=MAX_MANIFEST_BYTES, label="engine manifest")
        text = data.decode("utf-8")
    except (OSError, ValueError) as exc:  # ValueError: size cap, UnicodeDecodeError
        raise ManifestError(f"{path}: cannot read manifest: {exc}") from exc
    manifest = parse_manifest(text, source=str(path))
    if manifest.engine.name != path.parent.name:
        raise ManifestError(
            f"{path}: engine.name {manifest.engine.name!r} must equal its directory "
            f"{path.parent.name!r}"
        )
    return manifest


def load_all(root: Path = ENGINES_ROOT) -> dict[str, EngineManifest]:
    """Load every ``<root>/<name>/engine.toml``; names are unique by construction."""
    manifests: dict[str, EngineManifest] = {}
    for path in sorted(root.glob(f"*/{MANIFEST_NAME}")):
        manifest = load_manifest(path)
        manifests[manifest.engine.name] = manifest
    return manifests


def load_data_manifest(path: Path) -> DataManifest:
    """Read one ``_data/<name>.toml`` (bounded, no symlinks); the file stem is the name."""
    try:
        text = read_regular_bytes(path, max_bytes=MAX_MANIFEST_BYTES, label="data manifest").decode(
            "utf-8"
        )
    except (OSError, ValueError) as exc:
        raise ManifestError(f"{path}: cannot read data manifest: {exc}") from exc
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path}: invalid TOML: {exc}") from exc
    try:
        manifest = DataManifest.model_validate(raw)
    except ValidationError as exc:
        report = format_validation_error(exc, schema="olympus.data-manifest", source=str(path))
        raise ManifestError(report.to_human(), report) from exc
    if manifest.data.name != path.stem:
        raise ManifestError(
            f"{path}: data.name {manifest.data.name!r} must equal the file name {path.stem!r}"
        )
    return manifest


def load_all_data(root: Path = DATA_ROOT) -> dict[str, DataManifest]:
    """Load every ``<root>/*.toml`` data dependency."""
    return {
        manifest.data.name: manifest
        for manifest in (load_data_manifest(path) for path in sorted(root.glob("*.toml")))
    }


@lru_cache(maxsize=64)
def manifest_for(name: str) -> EngineManifest:
    """Return the validated manifest of one shipped engine (cached; manifests are static)."""
    if not name or not name.replace("-", "").isalnum() or name != name.lower():
        raise ManifestError(f"invalid engine name {name!r}")
    return load_manifest(ENGINES_ROOT / name / MANIFEST_NAME)


def reviewed_timeouts(
    name: str, *, default_timeout: float, default_deadline: float
) -> tuple[float, float]:
    """Return ``(timeout, deadline)`` defaults for ``name``.

    A manifest's ``timeout_seconds`` is used only when ``reviewed = true`` (measured, not
    estimated); every other engine keeps the legacy defaults. The overall deadline always
    leaves 300 s of room beyond the per-process timeout, otherwise it would cap it silently.
    """
    try:
        adapter = manifest_for(name).adapter
    except (ManifestError, OSError):
        adapter = None
    if adapter is None or not adapter.reviewed:
        return default_timeout, default_deadline
    timeout = float(adapter.timeout_seconds)
    return timeout, max(default_deadline, timeout + 300.0)

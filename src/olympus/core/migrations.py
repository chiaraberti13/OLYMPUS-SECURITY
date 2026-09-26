"""Explicit, deterministic migrations for persisted Olympus contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from olympus.core.contracts import ContractVersion

LEGACY = "legacy"
MigrationFunction = Callable[[dict[str, Any]], dict[str, Any]]


class ContractMigrationError(ValueError):
    """Raised when no safe, declared path reaches the current contract."""


@dataclass(frozen=True)
class ContractMigration:
    """One pure migration edge in a contract's version graph."""

    schema_name: str
    from_version: str
    to_version: str
    transform: MigrationFunction


def _headers(document: dict[str, Any], schema_name: str, version: str) -> dict[str, Any]:
    migrated = dict(document)
    migrated["schema_name"] = schema_name
    migrated["schema_version"] = version
    return migrated


def _legacy_aegis_scope(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    if "allowed" in migrated and "allowed_domains" in migrated:
        raise ContractMigrationError(
            "legacy AEGIS scope cannot contain both allowed and allowed_domains"
        )
    if "allowed" in migrated:
        migrated["allowed_domains"] = migrated.pop("allowed")
    return _headers(migrated, "olympus.aegis-scope", "1.0.0")


def _legacy_plan(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.athena.plan", "1.0.0")


def _integer_plan_v1(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    migrated["schema_version"] = "1.0.0"
    return migrated


def _legacy_job(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.aegis-job", "1.0.0")


def _job_v1_to_v2(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    if "scope_path" not in migrated:
        raise ContractMigrationError("AEGIS job 1.0.0 is missing scope_path")
    if "scope_name" in migrated:
        raise ContractMigrationError("AEGIS job contains both scope_path and scope_name")
    raw_path = migrated.pop("scope_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ContractMigrationError("AEGIS job scope_path must be a non-empty string")
    scope_name = raw_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if not scope_name:
        raise ContractMigrationError("AEGIS job scope_path has no file name")
    migrated["scope_name"] = scope_name
    migrated["schema_version"] = "2.0.0"
    return migrated


def _legacy_evidence(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.evidence", "1.0.0")


def _legacy_metis_case(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.metis-case", "1.0.0")


MIGRATIONS = (
    ContractMigration("olympus.aegis-scope", LEGACY, "1.0.0", _legacy_aegis_scope),
    ContractMigration("olympus.athena.plan", LEGACY, "1.0.0", _legacy_plan),
    ContractMigration("olympus.athena.plan", "1", "1.0.0", _integer_plan_v1),
    ContractMigration("olympus.aegis-job", LEGACY, "1.0.0", _legacy_job),
    ContractMigration("olympus.aegis-job", "1.0.0", "2.0.0", _job_v1_to_v2),
    ContractMigration("olympus.evidence", LEGACY, "1.0.0", _legacy_evidence),
    ContractMigration("olympus.metis-case", LEGACY, "1.0.0", _legacy_metis_case),
)


def migrate_document(document: object, *, schema_name: str, current_version: str) -> dict[str, Any]:
    """Migrate a mapping along declared edges, or fail without guessing."""
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise ContractMigrationError("contract document must be a JSON object with string keys")
    candidate = dict(cast(dict[str, Any], document))
    has_name = "schema_name" in candidate
    has_version = "schema_version" in candidate
    if has_name != has_version:
        raise ContractMigrationError("contract document has a partial header")
    if not has_name:
        source_version = LEGACY
    else:
        if candidate["schema_name"] != schema_name:
            raise ContractMigrationError(
                f"expected schema_name {schema_name!r}, got {candidate['schema_name']!r}"
            )
        raw_version = candidate["schema_version"]
        if isinstance(raw_version, bool):
            raise ContractMigrationError(f"invalid schema_version: {raw_version!r}")
        if isinstance(raw_version, int):
            source_version = str(raw_version)
        else:
            ContractVersion.parse(raw_version)
            source_version = cast(str, raw_version)

    ContractVersion.parse(current_version)
    visited: set[str] = set()
    while source_version != current_version:
        if source_version in visited:
            raise ContractMigrationError(
                f"migration cycle for {schema_name} at version {source_version}"
            )
        visited.add(source_version)
        matching = [
            migration
            for migration in MIGRATIONS
            if migration.schema_name == schema_name and migration.from_version == source_version
        ]
        if len(matching) != 1:
            raise ContractMigrationError(
                f"unsupported contract version: no unambiguous migration for {schema_name} "
                f"from {source_version} to {current_version}"
            )
        migration = matching[0]
        candidate = migration.transform(candidate)
        if candidate.get("schema_name") != schema_name:
            raise ContractMigrationError("migration changed the contract identity")
        if candidate.get("schema_version") != migration.to_version:
            raise ContractMigrationError("migration emitted the wrong target version")
        source_version = migration.to_version
    return candidate


def migration_manifest() -> tuple[dict[str, str], ...]:
    """Return the stable public list of supported migration edges."""
    return tuple(
        {
            "schema_name": migration.schema_name,
            "from_version": migration.from_version,
            "to_version": migration.to_version,
        }
        for migration in MIGRATIONS
    )

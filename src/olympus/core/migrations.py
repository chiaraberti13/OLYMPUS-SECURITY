"""Explicit, deterministic migrations for persisted Olympus contracts."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from olympus.core.contracts import ContractVersion, canonicalize_schema_name

LEGACY = "legacy"
MigrationFunction = Callable[[dict[str, Any]], dict[str, Any]]


class ContractMigrationError(ValueError):
    """Raised when no safe, declared path reaches the current contract."""


class SqliteSchemaVersionError(RuntimeError):
    """Raised when a SQLite store is newer than this application supports."""


def initialize_sqlite_schema(
    connection: sqlite3.Connection, schema_sql: str, *, current_version: int
) -> int:
    """Apply an unversioned legacy schema atomically and reject future versions.

    Existing version-zero databases are the legacy format. SQLite DDL and the
    ``user_version`` marker commit together, so an interrupted migration can be
    retried without claiming a partial schema is current.
    """
    if current_version < 1:
        raise ValueError("SQLite schema version must be positive")
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > current_version:
            raise SqliteSchemaVersionError(
                f"database schema {version} is newer than supported {current_version}"
            )
        if version == current_version:
            connection.commit()
            return version
        if version != 0:
            raise SqliteSchemaVersionError(f"unsupported database schema {version}")
        for statement in schema_sql.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {current_version}")
        connection.commit()
        return current_version
    except Exception:
        connection.rollback()
        raise


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


def _legacy_themis_scope(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    if "allowed" in migrated and "allowed_domains" in migrated:
        raise ContractMigrationError(
            "legacy Themis scope cannot contain both allowed and allowed_domains"
        )
    if "allowed" in migrated:
        migrated["allowed_domains"] = migrated.pop("allowed")
    return _headers(migrated, "olympus.themis-scope", "1.0.0")


def _legacy_plan(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.athena.plan", "1.0.0")


def _integer_plan_v1(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    migrated["schema_version"] = "1.0.0"
    return migrated


def _legacy_job(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.themis-job", "1.0.0")


def _job_v1_to_v2(document: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(document)
    if "scope_path" not in migrated:
        raise ContractMigrationError("Themis job 1.0.0 is missing scope_path")
    if "scope_name" in migrated:
        raise ContractMigrationError("Themis job contains both scope_path and scope_name")
    raw_path = migrated.pop("scope_path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ContractMigrationError("Themis job scope_path must be a non-empty string")
    scope_name = raw_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if not scope_name:
        raise ContractMigrationError("Themis job scope_path has no file name")
    migrated["scope_name"] = scope_name
    migrated["schema_version"] = "2.0.0"
    return migrated


def _job_v2_to_v3(document: dict[str, Any]) -> dict[str, Any]:
    """Add the optional signed-manifest binding without inventing provenance."""
    migrated = dict(document)
    migrated.setdefault("manifest_sha256", None)
    migrated["schema_version"] = "3.0.0"
    return migrated


def _legacy_evidence(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.evidence", "1.0.0")


def _legacy_metis_case(document: dict[str, Any]) -> dict[str, Any]:
    return _headers(document, "olympus.metis-case", "1.0.0")


MIGRATIONS = (
    ContractMigration("olympus.themis-scope", LEGACY, "1.0.0", _legacy_themis_scope),
    ContractMigration("olympus.athena.plan", LEGACY, "1.0.0", _legacy_plan),
    ContractMigration("olympus.athena.plan", "1", "1.0.0", _integer_plan_v1),
    ContractMigration("olympus.themis-job", LEGACY, "1.0.0", _legacy_job),
    ContractMigration("olympus.themis-job", "1.0.0", "2.0.0", _job_v1_to_v2),
    ContractMigration("olympus.themis-job", "2.0.0", "3.0.0", _job_v2_to_v3),
    ContractMigration("olympus.evidence", LEGACY, "1.0.0", _legacy_evidence),
    ContractMigration("olympus.metis-case", LEGACY, "1.0.0", _legacy_metis_case),
)


def migrate_document(document: object, *, schema_name: str, current_version: str) -> dict[str, Any]:
    """Migrate a mapping along declared edges, or fail without guessing."""
    if not isinstance(document, dict) or not all(isinstance(key, str) for key in document):
        raise ContractMigrationError("contract document must be a JSON object with string keys")
    candidate = canonicalize_schema_name(dict(cast(dict[str, Any], document)))
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

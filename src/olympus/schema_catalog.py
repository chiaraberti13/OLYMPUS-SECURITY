"""Deterministic publication of Olympus JSON Schema contracts.

The catalog is the public compatibility boundary for machine-readable inputs
and outputs. Every entry has a stable schema identity, an independent Semantic
Version, a direction, a content digest, and a versioned path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from olympus.argus.pipeline import PipelineDocument, PipelinePreset
from olympus.athena.domain.contracts import AssessmentPlan, AssessmentResult
from olympus.core.contracts import ContractVersion
from olympus.core.fileio import atomic_write_text, ensure_write_target
from olympus.core.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Finding,
    Incident,
    Observation,
    ScanJob,
    SecurityReport,
)
from olympus.metis.models import EngagementPlan, IntelCaseDocument

CATALOG_SCHEMA_NAME = "olympus.schema-catalog"
CATALOG_SCHEMA_VERSION = "1.0.0"
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_NAME = re.compile(r"^olympus\.[a-z0-9][a-z0-9.-]*$")

ContractDirection = Literal["input", "output", "shared"]


class SchemaCatalogError(ValueError):
    """Raised when a model cannot be published as an unambiguous contract."""


@dataclass(frozen=True)
class PublishedContract:
    """One public Pydantic contract and its use at the platform boundary."""

    name: str
    direction: ContractDirection
    model: type[BaseModel]


PUBLISHED_CONTRACTS = (
    PublishedContract("olympus.athena.plan", "input", AssessmentPlan),
    PublishedContract("olympus.athena.result", "output", AssessmentResult),
    PublishedContract("olympus.argus-pipeline-preset", "input", PipelinePreset),
    PublishedContract("olympus.argus-pipeline", "output", PipelineDocument),
    PublishedContract("olympus.metis-plan", "output", EngagementPlan),
    PublishedContract("olympus.metis-case", "output", IntelCaseDocument),
    PublishedContract("olympus.asset", "shared", Asset),
    PublishedContract("olympus.finding", "shared", Finding),
    PublishedContract("olympus.event", "shared", Event),
    PublishedContract("olympus.evidence", "shared", Evidence),
    PublishedContract("olympus.alert", "shared", Alert),
    PublishedContract("olympus.incident", "shared", Incident),
    PublishedContract("olympus.observation", "shared", Observation),
    PublishedContract("olympus.scan-job", "shared", ScanJob),
    PublishedContract("olympus.security-report", "output", SecurityReport),
)


def _constant(schema: dict[str, Any], field: str) -> str:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise SchemaCatalogError(f"schema has no properties mapping for {field}")
    descriptor = properties.get(field)
    if not isinstance(descriptor, dict):
        raise SchemaCatalogError(f"schema field {field} must declare one string Literal")
    value = descriptor.get("const")
    if not isinstance(value, str):
        raise SchemaCatalogError(f"schema field {field} must declare one string Literal")
    return value


def _validated_contracts(
    contracts: tuple[PublishedContract, ...] = PUBLISHED_CONTRACTS,
) -> tuple[tuple[PublishedContract, str, dict[str, Any]], ...]:
    validated: list[tuple[PublishedContract, str, dict[str, Any]]] = []
    names: set[str] = set()
    for contract in contracts:
        if _SCHEMA_NAME.fullmatch(contract.name) is None:
            raise SchemaCatalogError(f"invalid public schema name: {contract.name!r}")
        if contract.name in names:
            raise SchemaCatalogError(f"duplicate public schema name: {contract.name}")
        names.add(contract.name)
        schema = contract.model.model_json_schema(mode="validation")
        declared_name = _constant(schema, "schema_name")
        version = _constant(schema, "schema_version")
        if declared_name != contract.name:
            raise SchemaCatalogError(
                f"registry name {contract.name!r} does not match model identity {declared_name!r}"
            )
        ContractVersion.parse(version)
        validated.append((contract, version, schema))
    return tuple(sorted(validated, key=lambda item: item[0].name))


def legacy_schema_bundle() -> dict[str, dict[str, Any]]:
    """Return the original name-to-schema mapping kept for CLI compatibility."""
    return {contract.name: schema for contract, _version, schema in _validated_contracts()}


def catalog_files() -> dict[Path, str]:
    """Render every publishable file with deterministic formatting and hashes."""
    files: dict[Path, str] = {}
    entries: list[dict[str, str]] = []
    legacy: dict[str, dict[str, Any]] = {}
    for contract, version, raw_schema in _validated_contracts():
        legacy[contract.name] = raw_schema
        schema = {
            "$schema": JSON_SCHEMA_DIALECT,
            "$id": f"urn:olympus:schema:{contract.name}:{version}",
            **raw_schema,
        }
        content = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        relative_path = Path("contracts") / contract.name / f"{version}.schema.json"
        files[relative_path] = content
        entries.append(
            {
                "direction": contract.direction,
                "name": contract.name,
                "path": relative_path.as_posix(),
                "schema_version": version,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )

    catalog = {
        "schema_name": CATALOG_SCHEMA_NAME,
        "schema_version": CATALOG_SCHEMA_VERSION,
        "contracts": entries,
    }
    files[Path("catalog.json")] = json.dumps(catalog, indent=2, sort_keys=True) + "\n"
    files[Path("schemas.json")] = json.dumps(legacy, indent=2, sort_keys=True) + "\n"
    return files


def write_catalog(output_dir: Path) -> tuple[Path, ...]:
    """Atomically publish the versioned catalog below ``output_dir``."""
    written: list[Path] = []
    for relative_path, content in catalog_files().items():
        destination = ensure_write_target(output_dir / relative_path, base=output_dir)
        atomic_write_text(destination, content, mode=0o644)
        written.append(destination)
    return tuple(written)

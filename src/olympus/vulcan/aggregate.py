"""Bounded contract loading, exact deduplication and ranking for Vulcan."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from olympus.core.contracts import ContractCompatibilityError, validate_contract_header
from olympus.core.enums import Severity
from olympus.core.fileio import read_regular_text
from olympus.core.models import Alert, Asset, Finding, Observation, ScanJob, SecurityReport

DEFAULT_MAX_INPUT_BYTES = 50_000_000
DEFAULT_MAX_FILES = 100
DEFAULT_MAX_ITEMS_PER_FILE = 100_000
DEFAULT_MAX_TOTAL_ITEMS = 200_000

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _ArgusAssets(_Envelope):
    schema_name: Literal["olympus.argus-assets"]
    schema_version: Literal["1.0.0"]
    assets: list[Asset]


class _ArgusFronting(_Envelope):
    schema_name: Literal["olympus.argus-fronting"]
    schema_version: Literal["1.0.0"]
    domain: str = Field(min_length=1, max_length=253)
    fronted: bool
    cdn_providers: list[str]
    asset: Asset
    findings: list[Finding]


class _AthenaResult(_Envelope):
    schema_name: Literal["olympus.athena.result"]
    schema_version: Literal["1.0.0"]
    assessment_id: str = Field(min_length=1)
    job: ScanJob
    assets: list[Asset]
    findings: list[Finding]


class _HeliosFindings(_Envelope):
    schema_name: Literal["olympus.helios-findings"]
    schema_version: Literal["1.0.0"]
    findings: list[Finding]


class _HeliosResult(_Envelope):
    schema_name: Literal["olympus.helios-result"]
    schema_version: Literal["1.0.0"]
    observations: list[Observation]
    findings: list[Finding]


class _ApolloAlerts(_Envelope):
    schema_name: Literal["olympus.apollo-alerts"]
    schema_version: Literal["1.0.0"]
    alerts: list[Alert]


# schema -> (strict envelope model, payload key, singular payload)
_COLLECTION_SCHEMAS: dict[type[BaseModel], dict[str, tuple[type[BaseModel], str, bool]]] = {
    Asset: {
        "olympus.argus-assets": (_ArgusAssets, "assets", False),
        "olympus.argus-fronting": (_ArgusFronting, "asset", True),
        "olympus.athena.result": (_AthenaResult, "assets", False),
        "olympus.security-report": (SecurityReport, "assets", False),
    },
    Finding: {
        "olympus.argus-fronting": (_ArgusFronting, "findings", False),
        "olympus.athena.result": (_AthenaResult, "findings", False),
        "olympus.helios-findings": (_HeliosFindings, "findings", False),
        "olympus.helios-result": (_HeliosResult, "findings", False),
        "olympus.security-report": (SecurityReport, "findings", False),
    },
    Alert: {
        "olympus.apollo-alerts": (_ApolloAlerts, "alerts", False),
        "olympus.security-report": (SecurityReport, "alerts", False),
    },
}
_ITEM_SCHEMAS: dict[type[BaseModel], str] = {
    Asset: "olympus.asset",
    Finding: "olympus.finding",
    Alert: "olympus.alert",
}
_KNOWN_COLLECTION_SCHEMAS = {
    schema for supported in _COLLECTION_SCHEMAS.values() for schema in supported
}
_ModelT = TypeVar("_ModelT", bound=BaseModel)


class AggregationError(ValueError):
    """Raised when an input is unsafe, incompatible, oversized or malformed."""


def _load_array(
    path: Path,
    model: type[_ModelT],
    *,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_items: int = DEFAULT_MAX_ITEMS_PER_FILE,
    progress_check: Callable[[], None] | None = None,
) -> list[_ModelT]:
    """Load a bounded versioned collection or one named legacy array/object."""
    if not 1 <= max_items <= 1_000_000:
        raise AggregationError("max_items must be between 1 and 1000000")
    if progress_check is not None:
        progress_check()
    try:
        raw = json.loads(read_regular_text(path, max_bytes=max_bytes, label="aggregation input"))
    except FileNotFoundError as exc:
        raise AggregationError(f"input file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AggregationError(f"invalid JSON input {path}: {exc.msg}") from exc
    except (OSError, ValueError) as exc:
        raise AggregationError(str(exc)) from exc

    items: object
    if isinstance(raw, list):
        # Explicit compatibility adapter for the original bare-array CLI output.
        items = raw
    elif isinstance(raw, dict):
        schema_name = raw.get("schema_name")
        if schema_name == _ITEM_SCHEMAS[model]:
            try:
                validate_contract_header(raw, schema_name=schema_name)
            except ContractCompatibilityError as exc:
                raise AggregationError(f"{path} has an incompatible item contract: {exc}") from exc
            items = [raw]
        elif isinstance(schema_name, str) and schema_name in _KNOWN_COLLECTION_SCHEMAS:
            specification = _COLLECTION_SCHEMAS[model].get(schema_name)
            if specification is None:
                raise AggregationError(
                    f"{path} schema {schema_name!r} cannot be consumed as {model.__name__}"
                )
            try:
                validate_contract_header(raw, schema_name=schema_name)
            except ContractCompatibilityError as exc:
                raise AggregationError(f"{path} has an incompatible contract: {exc}") from exc
            envelope_type, key, singular = specification
            raw_payload = raw.get(key)
            raw_count = (
                1
                if singular and raw_payload is not None
                else (len(raw_payload) if isinstance(raw_payload, list) else 0)
            )
            if raw_count > max_items:
                raise AggregationError(f"{path} exceeds the {max_items} item limit")
            try:
                envelope = envelope_type.model_validate(raw)
            except ValidationError as exc:
                details = exc.errors(include_input=False, include_url=False)
                raise AggregationError(f"{path} has an invalid envelope: {details}") from exc
            payload = getattr(envelope, key)
            items = [payload] if singular and payload is not None else payload
        elif schema_name is None:
            # Explicit compatibility adapter for the original bare single object.
            items = [raw]
        else:
            raise AggregationError(f"{path} uses unsupported schema_name {schema_name!r}")
    else:
        raise AggregationError(f"{path} must contain a JSON object or array")
    if not isinstance(items, list):
        raise AggregationError(f"{path} collection payload must be a JSON array")
    if len(items) > max_items:
        raise AggregationError(f"{path} exceeds the {max_items} item limit")
    validated: list[_ModelT] = []
    for item in items:
        if progress_check is not None:
            progress_check()
        try:
            validated.append(model.model_validate(item))
        except ValidationError as exc:
            details = exc.errors(include_input=False, include_url=False)
            raise AggregationError(
                f"{path} failed validation against {model.__name__}: {details}"
            ) from exc
    return validated


def load_assets(
    paths: Sequence[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_items_per_file: int = DEFAULT_MAX_ITEMS_PER_FILE,
    max_total_items: int = DEFAULT_MAX_TOTAL_ITEMS,
    progress_check: Callable[[], None] | None = None,
) -> list[Asset]:
    """Load bounded shared assets from supported producer envelopes."""
    return _load_many(
        paths,
        Asset,
        max_files=max_files,
        max_bytes=max_bytes,
        max_items_per_file=max_items_per_file,
        max_total_items=max_total_items,
        progress_check=progress_check,
    )


def load_findings(
    paths: Sequence[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_items_per_file: int = DEFAULT_MAX_ITEMS_PER_FILE,
    max_total_items: int = DEFAULT_MAX_TOTAL_ITEMS,
    progress_check: Callable[[], None] | None = None,
) -> list[Finding]:
    """Load bounded shared findings from supported producer envelopes."""
    return _load_many(
        paths,
        Finding,
        max_files=max_files,
        max_bytes=max_bytes,
        max_items_per_file=max_items_per_file,
        max_total_items=max_total_items,
        progress_check=progress_check,
    )


def load_alerts(
    paths: Sequence[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_items_per_file: int = DEFAULT_MAX_ITEMS_PER_FILE,
    max_total_items: int = DEFAULT_MAX_TOTAL_ITEMS,
    progress_check: Callable[[], None] | None = None,
) -> list[Alert]:
    """Load bounded shared alerts from supported producer envelopes."""
    return _load_many(
        paths,
        Alert,
        max_files=max_files,
        max_bytes=max_bytes,
        max_items_per_file=max_items_per_file,
        max_total_items=max_total_items,
        progress_check=progress_check,
    )


def _load_many(
    paths: Sequence[Path],
    model: type[_ModelT],
    *,
    max_files: int,
    max_bytes: int,
    max_items_per_file: int,
    max_total_items: int,
    progress_check: Callable[[], None] | None,
) -> list[_ModelT]:
    if not 1 <= max_files <= 1_000:
        raise AggregationError("max_files must be between 1 and 1000")
    if not 1 <= max_total_items <= 1_000_000:
        raise AggregationError("max_total_items must be between 1 and 1000000")
    if len(paths) > max_files:
        raise AggregationError(f"input set exceeds the {max_files} file limit")
    resolved = [path.resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        raise AggregationError("the same input path must not be supplied more than once")
    loaded: list[_ModelT] = []
    for path in paths:
        loaded.extend(
            _load_array(
                path,
                model,
                max_bytes=max_bytes,
                max_items=max_items_per_file,
                progress_check=progress_check,
            )
        )
        if len(loaded) > max_total_items:
            raise AggregationError(f"aggregate exceeds the {max_total_items} total item limit")
    return loaded


def dedupe_assets(assets: Sequence[Asset]) -> list[Asset]:
    """Remove exact repeated asset IDs and reject conflicting versions."""
    return _dedupe_by_id(assets, "asset_id", "asset")


def dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Remove exact repeated finding IDs and reject conflicting versions."""
    return _dedupe_by_id(findings, "finding_id", "finding")


def dedupe_alerts(alerts: Sequence[Alert]) -> list[Alert]:
    """Remove exact repeated alert IDs and reject conflicting versions."""
    return _dedupe_by_id(alerts, "alert_id", "alert")


def _dedupe_by_id(items: Sequence[_ModelT], identifier: str, label: str) -> list[_ModelT]:
    seen: dict[str, _ModelT] = {}
    unique: list[_ModelT] = []
    for item in items:
        value = getattr(item, identifier)
        prior = seen.get(value)
        if prior is None:
            seen[value] = item
            unique.append(item)
        elif prior != item:
            raise AggregationError(f"conflicting duplicate {label} ID: {value}")
    return unique


def rank_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Return findings sorted by severity, title and stable ID."""
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER[finding.severity],
            finding.title.casefold(),
            finding.finding_id,
        ),
    )


def severity_breakdown(findings: Sequence[Finding]) -> dict[str, int]:
    """Return a count of findings per severity level (all levels present)."""
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def filter_min_severity(findings: Sequence[Finding], minimum: Severity) -> list[Finding]:
    """Keep only findings at or above ``minimum`` severity."""
    threshold = _SEVERITY_ORDER[minimum]
    return [finding for finding in findings if _SEVERITY_ORDER[finding.severity] <= threshold]

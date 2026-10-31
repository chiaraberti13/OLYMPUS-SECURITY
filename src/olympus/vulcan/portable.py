"""Portable, versioned NDJSON import/export for findings and assets (ROADMAP ``WEB-J``).

Findings and assets move between installations and line-oriented tools as
**NDJSON**: one record per line, each the deterministic JSON encoding of its
versioned contract (``olympus.finding`` / ``olympus.asset``). This module is the
single, tested place that serialises them and parses them back, the sibling of
:mod:`olympus.engagements.portable` for the shared scoped contracts.

Export sorts by id so the same set always produces byte-identical output (an
export is diffable and a round-trip is verifiable). Import is strict and bounded —
every line is validated against the contract, oversize lines and oversize sets are
refused, and parsing is **all-or-nothing**: a single malformed record raises
before any record is returned, so a partial or corrupt file can never be
half-imported. The operation is pure and offline, and it round-trips losslessly
with the JSON bundles the Vulcan loaders already consume
(:func:`olympus.vulcan.aggregate.load_findings` / ``load_assets``).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import TypeVar

from olympus.core.contracts import ContractCompatibilityError, validate_contract_header
from olympus.core.models import Asset, Finding

#: Reject a single line larger than this (bytes).
MAX_LINE_BYTES = 1_000_000
#: Reject an import set larger than this, to bound memory on a hostile file.
MAX_RECORDS = 1_000_000

_ModelT = TypeVar("_ModelT", Finding, Asset)


class PortabilityError(ValueError):
    """Raised when an NDJSON export cannot be parsed or is out of bounds."""


def _canonical(model: Finding | Asset) -> str:
    """Deterministic one-line JSON encoding (sorted keys, no spurious spacing)."""
    return json.dumps(model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _export(models: Sequence[_ModelT], id_attr: str) -> str:
    ordered = sorted(models, key=lambda model: getattr(model, id_attr))
    return "".join(f"{_canonical(model)}\n" for model in ordered)


def _import(
    text: str,
    model_type: type[_ModelT],
    schema_name: str,
    *,
    max_records: int,
    max_line_bytes: int,
) -> list[_ModelT]:
    records: list[_ModelT] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if len(line.encode("utf-8")) > max_line_bytes:
            raise PortabilityError(f"line {number} exceeds the {max_line_bytes}-byte limit")
        if len(records) >= max_records:
            raise PortabilityError(f"import exceeds the {max_records}-record limit")
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PortabilityError(f"line {number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise PortabilityError(f"line {number}: expected a JSON object")
        try:
            payload = validate_contract_header(payload, schema_name=schema_name)
            records.append(model_type.model_validate(payload))
        except (ContractCompatibilityError, ValueError) as exc:
            raise PortabilityError(f"line {number}: {exc}") from exc
    return records


def export_findings(findings: Sequence[Finding]) -> str:
    """Serialise findings to deterministic NDJSON (one record per line, sorted by id)."""
    return _export(findings, "finding_id")


def import_findings(
    text: str, *, max_records: int = MAX_RECORDS, max_line_bytes: int = MAX_LINE_BYTES
) -> list[Finding]:
    """Parse NDJSON into validated findings, strictly and all-or-nothing."""
    return _import(
        text, Finding, "olympus.finding", max_records=max_records, max_line_bytes=max_line_bytes
    )


def export_assets(assets: Sequence[Asset]) -> str:
    """Serialise assets to deterministic NDJSON (one record per line, sorted by id)."""
    return _export(assets, "asset_id")


def import_assets(
    text: str, *, max_records: int = MAX_RECORDS, max_line_bytes: int = MAX_LINE_BYTES
) -> list[Asset]:
    """Parse NDJSON into validated assets, strictly and all-or-nothing."""
    return _import(
        text, Asset, "olympus.asset", max_records=max_records, max_line_bytes=max_line_bytes
    )

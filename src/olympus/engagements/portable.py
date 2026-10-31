"""Portable, versioned NDJSON import/export for engagements (ROADMAP ``WEB-J``).

An engagement created in one Olympus installation must be movable to another
without loss and without breaking its data contract. This module is the single,
tested place that serialises engagements to a portable wire format and parses
them back, so every interface shares one definition of "exported engagement".

The format is **NDJSON**: one engagement per line, each the engagement's
deterministic :meth:`~olympus.core.models.Engagement.canonical_json` (which
carries the versioned ``olympus.engagement`` contract header). Export sorts by
``engagement_id`` so the same set always produces byte-identical output. Import
is strict and bounded — every line is validated against the contract, oversize
lines and oversize sets are refused, and parsing is **all-or-nothing**: a single
malformed record raises before any engagement is returned, so a partial or
corrupt file can never be half-imported. The operation is pure and offline.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from olympus.core.contracts import ContractCompatibilityError, validate_contract_header
from olympus.core.models import Engagement

#: Reject a single line larger than this (bytes); mirrors the store's per-document
#: ceiling so what imports is exactly what the store will accept.
MAX_LINE_BYTES = 1_000_000
#: Reject an import set larger than this, to bound memory on a hostile file.
MAX_ENGAGEMENTS = 100_000


class EngagementPortabilityError(ValueError):
    """Raised when an NDJSON engagement export cannot be parsed or is out of bounds."""


def export_engagements(engagements: Sequence[Engagement]) -> str:
    """Serialise engagements to deterministic NDJSON (one canonical record per line).

    Sorted by ``engagement_id`` so the same set is always byte-identical, which
    makes an export diffable and a round-trip verifiable.
    """
    ordered = sorted(engagements, key=lambda engagement: engagement.engagement_id)
    return "".join(f"{engagement.canonical_json()}\n" for engagement in ordered)


def import_engagements(
    text: str,
    *,
    max_engagements: int = MAX_ENGAGEMENTS,
    max_line_bytes: int = MAX_LINE_BYTES,
) -> list[Engagement]:
    """Parse NDJSON into validated engagements, strictly and all-or-nothing.

    Blank lines are ignored. Every non-blank line must be one JSON object that
    validates against the versioned ``olympus.engagement`` contract. Any oversize
    line, an oversize set, invalid JSON or a contract violation raises
    :class:`EngagementPortabilityError` naming the 1-based line, and no partial
    result is returned.
    """
    engagements: list[Engagement] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if len(line.encode("utf-8")) > max_line_bytes:
            raise EngagementPortabilityError(
                f"line {number} exceeds the {max_line_bytes}-byte limit"
            )
        if len(engagements) >= max_engagements:
            raise EngagementPortabilityError(
                f"import exceeds the {max_engagements}-engagement limit"
            )
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EngagementPortabilityError(f"line {number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise EngagementPortabilityError(f"line {number}: expected a JSON object")
        try:
            payload = validate_contract_header(payload, schema_name="olympus.engagement")
            engagements.append(Engagement.model_validate(payload))
        except (ContractCompatibilityError, ValueError) as exc:
            raise EngagementPortabilityError(f"line {number}: {exc}") from exc
    return engagements

"""Version negotiation helpers for persisted Olympus contracts.

Olympus documents use Semantic Versioning. Consumers accept their exact schema
name and the same major/minor version they implement; patch releases remain
wire-compatible. A major or newer-minor document requires an explicit adapter
instead of being guessed into an older model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CURRENT_CONTRACT_VERSION = "1.0.0"
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

#: Legacy schema names renamed to their current identity (ROADMAP ``DEV-I``).
#: The AEGIS subsystem became Themis; documents persisted under the old
#: ``olympus.aegis-*`` names are accepted and rewritten to the current name on
#: load, so no stored contract becomes unreadable.
RENAMED_SCHEMAS: dict[str, str] = {
    "olympus.aegis-scope": "olympus.themis-scope",
    "olympus.aegis-job": "olympus.themis-job",
    "olympus.aegis-job-list": "olympus.themis-job-list",
    "olympus.aegis-result": "olympus.themis-result",
    "olympus.aegis-readiness": "olympus.themis-readiness",
    "olympus.aegis-capability-inventory": "olympus.themis-capability-inventory",
    "olympus.aegis-api-identities": "olympus.themis-api-identities",
}


def canonicalize_schema_name(document: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a legacy ``schema_name`` to its current identity, if renamed.

    Returns the document unchanged when its name is current or absent; otherwise
    returns a shallow copy with the canonical name, so a document stored under a
    pre-rename contract name still loads.
    """
    name = document.get("schema_name")
    if isinstance(name, str) and name in RENAMED_SCHEMAS:
        migrated = dict(document)
        migrated["schema_name"] = RENAMED_SCHEMAS[name]
        return migrated
    return document


class ContractCompatibilityError(ValueError):
    """Raised when a persisted document is not compatible with a consumer."""


@dataclass(frozen=True, order=True)
class ContractVersion:
    """Parsed, comparable Semantic Versioning core triplet."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: object) -> ContractVersion:
        """Parse a strict ``MAJOR.MINOR.PATCH`` string without coercion."""
        if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
            raise ContractCompatibilityError(
                f"schema_version must be semantic version MAJOR.MINOR.PATCH, got {value!r}"
            )
        return cls(*(int(part) for part in match.groups()))


def validate_contract_header(
    document: object,
    *,
    schema_name: str,
    supported_version: str = CURRENT_CONTRACT_VERSION,
) -> dict[str, Any]:
    """Validate a document's identity/version and return its typed mapping.

    Same-major, same-or-older-minor documents are compatible. Patch differences
    are accepted. Callers still validate the full payload with the strict model,
    so compatible headers cannot bypass structural validation.
    """
    if not isinstance(document, dict):
        raise ContractCompatibilityError("contract document must be a JSON object")
    document = canonicalize_schema_name(document)
    actual_name = document.get("schema_name")
    if actual_name != schema_name:
        raise ContractCompatibilityError(
            f"expected schema_name {schema_name!r}, got {actual_name!r}"
        )
    actual = ContractVersion.parse(document.get("schema_version"))
    supported = ContractVersion.parse(supported_version)
    if actual.major != supported.major or actual.minor > supported.minor:
        raise ContractCompatibilityError(
            f"unsupported {schema_name} version {actual.major}.{actual.minor}.{actual.patch}; "
            f"consumer supports {supported_version}"
        )
    return document

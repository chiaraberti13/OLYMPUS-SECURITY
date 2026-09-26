"""Strict, versioned contracts for METIS planning and intelligence cases."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from olympus.core.migrations import migrate_document


class OperatingMode(StrEnum):
    """Highest operational effect a capability may produce."""

    ADVISORY = "advisory"
    PASSIVE = "passive"
    ACTIVE = "active"


class NoiseLevel(StrEnum):
    """Expected observability of a capability."""

    QUIET = "quiet"
    MODERATE = "moderate"
    LOUD = "loud"


class IndicatorType(StrEnum):
    """Normalized CTI indicator types supported by the native case store."""

    DOMAIN = "domain"
    EMAIL = "email"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    CVE = "cve"


class CapabilityProfile(BaseModel):
    """One independently implemented Olympus cyber capability profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.metis-capability"] = "olympus.metis-capability"
    schema_version: Literal["1.0.0"] = "1.0.0"
    capability_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    title: str = Field(min_length=2, max_length=120)
    summary: str = Field(min_length=10, max_length=500)
    tags: tuple[str, ...] = Field(min_length=1, max_length=32)
    phases: tuple[str, ...] = Field(min_length=1, max_length=16)
    commands: tuple[str, ...] = Field(min_length=1, max_length=16)
    mode: OperatingMode
    noise: NoiseLevel
    requires_authorization: bool
    mitre_attack: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("tags", "phases", "commands", "mitre_attack")
    @classmethod
    def _unique_trimmed(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() or item != item.strip() for item in values):
            raise ValueError("catalog values must be non-empty and trimmed")
        if len(values) != len(set(values)):
            raise ValueError("catalog values must be unique")
        return values


class Recommendation(BaseModel):
    """A scored, explainable routing decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: CapabilityProfile
    score: int = Field(ge=1)
    matched_terms: tuple[str, ...] = Field(default=(), max_length=64)


class PlanStep(BaseModel):
    """One ordered step in a generated engagement plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    order: int = Field(ge=1, le=100)
    capability_id: str
    title: str
    commands: tuple[str, ...]
    mode: OperatingMode
    noise: NoiseLevel
    authorization_required: bool
    status: Literal["ready", "authorization-required"]


class EngagementPlan(BaseModel):
    """Versioned deterministic plan; it never executes a target itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.metis-plan"] = "olympus.metis-plan"
    schema_version: Literal["1.0.0"] = "1.0.0"
    objective: str = Field(min_length=3, max_length=2_000)
    scope: tuple[str, ...] = Field(default=(), max_length=1_024)
    authorization_confirmed: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    steps: tuple[PlanStep, ...] = Field(min_length=1, max_length=32)

    @field_validator("scope")
    @classmethod
    def _valid_scope(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not value.strip()
            or value != value.strip()
            or len(value) > 2_048
            or any(character in value for character in "\r\n\x00")
            for value in values
        ):
            raise ValueError("scope entries must be trimmed and contain no CR/LF/NUL")
        if len(values) != len(set(values)):
            raise ValueError("scope entries must be unique")
        return values


class Indicator(BaseModel):
    """One normalized case indicator with provenance and confidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    indicator_id: str = Field(pattern=r"^ioc-[a-f0-9]{24}$")
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=2_048)
    source: str = Field(min_length=1, max_length=500)
    confidence: int = Field(ge=0, le=100)
    first_seen: datetime


class IntelFinding(BaseModel):
    """An analytic finding, distinct from an automatically extracted IOC."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=r"^cti-[a-f0-9]{24}$")
    title: str = Field(min_length=3, max_length=300)
    assessment: str = Field(min_length=3, max_length=10_000)
    source: str = Field(min_length=1, max_length=500)
    confidence: int = Field(ge=0, le=100)
    indicator_ids: tuple[str, ...] = Field(default=(), max_length=1_000)
    created_at: datetime


class IntelCaseDocument(BaseModel):
    """Portable CTI case document emitted by the SQLite store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.metis-case"] = "olympus.metis-case"
    schema_version: Literal["1.0.0"] = "1.0.0"
    case_id: str = Field(pattern=r"^case-[a-f0-9]{24}$")
    title: str = Field(min_length=3, max_length=300)
    status: Literal["open", "monitoring", "closed"]
    created_at: datetime
    updated_at: datetime
    indicators: tuple[Indicator, ...] = Field(default=(), max_length=100_000)
    findings: tuple[IntelFinding, ...] = Field(default=(), max_length=100_000)
    correlations: tuple[tuple[str, str], ...] = Field(default=(), max_length=100_000)


def load_case_document(raw: object) -> IntelCaseDocument:
    """Load a current portable case or migrate its declared legacy shape."""
    candidate = migrate_document(raw, schema_name="olympus.metis-case", current_version="1.0.0")
    return IntelCaseDocument.model_validate(candidate)

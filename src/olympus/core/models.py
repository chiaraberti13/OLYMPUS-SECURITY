"""Canonical Pydantic models shared by every Olympus module.

These models are the interoperability contract: the same ``Asset`` or
``Finding`` can be produced by one tool and consumed by another without any
format negotiation. Each model declares its ``schema_name`` and
``schema_version`` (Semantic Versioning) and forbids unknown fields.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from olympus.core.enums import (
    AlertStatus,
    AssetType,
    Criticality,
    EngagementStatus,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.ids import new_id


def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class OlympusModel(BaseModel):
    """Base class for every Olympus object.

    Enforces a strict contract: unknown fields are rejected and every object
    is self-describing through its schema name and version.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_name: str
    schema_version: Literal["1.0.0"] = "1.0.0"


class Asset(OlympusModel):
    """A resource observed or managed by the platform (host, domain, URL...)."""

    schema_name: Literal["olympus.asset"] = "olympus.asset"
    asset_id: str = Field(default_factory=lambda: new_id("asset"))
    asset_type: AssetType
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    criticality: Criticality = Criticality.MEDIUM
    owner: str | None = None
    source: Source = Source.MANUAL
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class Finding(OlympusModel):
    """A weakness, vulnerability or misconfiguration attached to an asset."""

    schema_name: Literal["olympus.finding"] = "olympus.finding"
    finding_id: str = Field(default_factory=lambda: new_id("finding"))
    asset_id: str
    source: Source
    title: str = Field(min_length=1)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.NEW
    cvss: float | None = None
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    references: list[str] = Field(default_factory=list)

    @field_validator("cvss")
    @classmethod
    def _validate_cvss(cls, value: float | None) -> float | None:
        """Ensure CVSS, when present, stays within the 0.0-10.0 range."""
        if value is not None and not 0.0 <= value <= 10.0:
            raise ValueError("cvss must be between 0.0 and 10.0")
        return value


class Event(OlympusModel):
    """A normalized observable consumed by detection rules."""

    schema_name: Literal["olympus.event"] = "olympus.event"
    event_id: str = Field(default_factory=lambda: new_id("event"))
    event_type: str = Field(min_length=1)
    source: Source
    observed_at: datetime = Field(default_factory=_utcnow)
    asset_id: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class Evidence(OlympusModel):
    """An immutable reference to material supporting a finding or alert."""

    schema_name: Literal["olympus.evidence"] = "olympus.evidence"
    evidence_id: str = Field(default_factory=lambda: new_id("evidence"))
    evidence_type: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    collected_at: datetime = Field(default_factory=_utcnow)


class Alert(OlympusModel):
    """A detection result linked to its source event and supporting evidence."""

    schema_name: Literal["olympus.alert"] = "olympus.alert"
    alert_id: str = Field(default_factory=lambda: new_id("alert"))
    event_id: str
    title: str = Field(min_length=1)
    source: Source
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    rule_id: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"APL-[A-Z0-9-]+", value) is None:
            raise ValueError("rule_id must match APL-[A-Z0-9-]+")
        return value

    @field_validator("mitre_attack")
    @classmethod
    def _validate_mitre_attack(cls, value: list[str]) -> list[str]:
        if any(re.fullmatch(r"T\d{4}(?:\.\d{3})?", item) is None for item in value):
            raise ValueError("mitre_attack IDs must match T#### or T####.###")
        if len(value) != len(set(value)):
            raise ValueError("mitre_attack IDs must be unique")
        return value


class Incident(OlympusModel):
    """An incident response case linking alerts, evidence and lifecycle state."""

    schema_name: Literal["olympus.incident"] = "olympus.incident"
    incident_id: str = Field(default_factory=lambda: new_id("incident"))
    title: str = Field(min_length=1)
    summary: str = ""
    source: Source
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    alert_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    owner: str | None = None
    opened_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    closed_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_timeline(self) -> Self:
        """Keep incident timestamps and closed state internally consistent."""
        if self.updated_at < self.opened_at:
            raise ValueError("updated_at cannot be before opened_at")
        if self.closed_at is not None:
            if self.status is not IncidentStatus.CLOSED:
                raise ValueError("closed_at requires closed status")
            if self.closed_at < self.opened_at:
                raise ValueError("closed_at cannot be before opened_at")
        return self


class Observation(OlympusModel):
    """One normalized, non-interpretive fact produced by a scanner or sensor."""

    schema_name: Literal["olympus.observation"] = "olympus.observation"
    observation_id: str = Field(default_factory=lambda: new_id("observation"))
    observation_type: str = Field(min_length=1)
    source: Source
    asset_id: str | None = None
    observed_at: datetime = Field(default_factory=_utcnow)
    attributes: dict[str, str] = Field(default_factory=dict)


ScanJobState = Literal["queued", "running", "succeeded", "failed", "timed_out", "cancelled"]


class ScanJob(OlympusModel):
    """Persistable shared view of one bounded adapter invocation."""

    schema_name: Literal["olympus.scan-job"] = "olympus.scan-job"
    job_id: str = Field(min_length=1)
    assessment_id: str = Field(min_length=1)
    adapter: str = Field(min_length=1)
    target_kind: str = Field(min_length=1)
    target_value: str = Field(min_length=1)
    state: ScanJobState = "queued"
    error_code: str | None = None
    result_id: str | None = None


class ReportSummary(BaseModel):
    """Stable counters embedded in a consolidated security report."""

    model_config = ConfigDict(extra="forbid")

    assets: int = Field(ge=0)
    findings: int = Field(ge=0)
    alerts: int = Field(ge=0)
    severity_breakdown: dict[str, int]


class SecurityReport(OlympusModel):
    """Canonical machine-readable engagement report consumed across Olympus."""

    schema_name: Literal["olympus.security-report"] = "olympus.security-report"
    engagement: str = Field(min_length=1)
    generated_at: datetime = Field(default_factory=_utcnow)
    summary: ReportSummary
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)


class EngagementScope(BaseModel):
    """The authorized perimeter of an engagement: included minus excluded.

    Entries are hostnames or domains (matched like the rest of Olympus: an entry
    covers itself and its subdomains). IP/CIDR matching is a planned extension
    (ROADMAP ``WEB-B``); until then IPs must be listed verbatim.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    included: tuple[str, ...] = Field(min_length=1)
    excluded: tuple[str, ...] = ()

    @field_validator("included", "excluded")
    @classmethod
    def _normalize(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = []
        for entry in value:
            cleaned = entry.strip().lower().rstrip(".")
            if not cleaned or " " in cleaned:
                raise ValueError("scope entries must be non-empty and contain no spaces")
            normalized.append(cleaned)
        return tuple(normalized)

    @staticmethod
    def _matches(target: str, entries: tuple[str, ...]) -> bool:
        return any(target == entry or target.endswith(f".{entry}") for entry in entries)

    def covers(self, host: str) -> bool:
        """Return ``True`` if ``host`` is included and not excluded."""
        target = host.strip().lower().rstrip(".")
        return self._matches(target, self.included) and not self._matches(target, self.excluded)


class Engagement(OlympusModel):
    """The top-level container that groups an authorized assessment's work.

    An engagement owns its scope and authorization reference; assets, scans,
    jobs, findings, evidence, alerts, incidents and reports are associated with
    it by ``engagement_id``. CLI, TUI, API and Web all reference this one model
    (ROADMAP ``WEB-B``) rather than a private per-interface notion of scope.
    """

    schema_name: Literal["olympus.engagement"] = "olympus.engagement"
    engagement_id: str = Field(default_factory=lambda: new_id("engagement"))
    name: str = Field(min_length=1)
    client: str = ""
    status: EngagementStatus = EngagementStatus.ACTIVE
    scope: EngagementScope
    #: An authorization reference (contract/approval id), never a secret.
    authorization_reference: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    def canonical_json(self) -> str:
        """Return the deterministic JSON encoding used for digesting and storage."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Return the SHA-256 digest of the engagement's canonical encoding."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

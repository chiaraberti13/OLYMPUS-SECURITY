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
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from olympus.core.enums import (
    AlertStatus,
    AssetType,
    Confidence,
    Criticality,
    EngagementStatus,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.ids import new_id

#: CVE and CWE identifier patterns, used to validate structured finding fields and
#: to extract identifiers from free-text when the structured fields are unset.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

#: A canonical engagement id, e.g. ``ENG-2026-00001`` (see :func:`new_id`).
_ENGAGEMENT_ID_RE = re.compile(r"ENG-\d{4}-\d{5}", re.IGNORECASE)


def is_canonical_engagement_id(value: str | None) -> bool:
    """Return ``True`` if ``value`` is a canonical engagement id (``ENG-YYYY-NNNNN``).

    Producers that carry a free-form engagement label (for example an Athena plan
    whose ``engagement_id`` is a human tag like ``ENG-DEMO-2026``) use this to
    decide whether the label is a real reference to an ``olympus.engagement``
    record — and therefore safe to stamp onto scoped objects — or just a plan-local
    name that must not masquerade as an engagement link.
    """
    return value is not None and _ENGAGEMENT_ID_RE.fullmatch(value.strip()) is not None


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


class EngagementScopedModel(OlympusModel):
    """An Olympus object that can be linked to an engagement (ROADMAP ``WEB-B``).

    ``engagement_id`` is optional and additive: objects created before an
    engagement existed, produced outside any engagement, or imported from a
    legacy document leave it ``None``. When set it must be a canonical engagement
    id (``ENG-YYYY-NNNNN``), tying the object to the shared ``olympus.engagement``
    record so CLI, TUI, API and Web scope it identically rather than inventing a
    per-interface notion of ownership.
    """

    engagement_id: str | None = None

    @field_validator("engagement_id")
    @classmethod
    def _validate_engagement_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().upper()
        if not _ENGAGEMENT_ID_RE.fullmatch(cleaned):
            raise ValueError(f"invalid engagement_id {value!r}; expected ENG-YYYY-NNNNN")
        return cleaned


#: A generic engagement-scoped object, so :meth:`Engagement.stamp` returns the
#: same concrete type it was given (a stamped ``Finding`` is still a ``Finding``).
ScopedT = TypeVar("ScopedT", bound=EngagementScopedModel)


class Asset(EngagementScopedModel):
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


class Finding(EngagementScopedModel):
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
    #: Structured vulnerability intelligence. Optional and additive: when unset,
    #: CVE/CWE ids are still derived from the free-text fields (see :meth:`cves`
    #: and :meth:`cwes`). EPSS/KEV are populated by the enrichment overlay.
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    confidence: Confidence | None = None
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    references: list[str] = Field(default_factory=list)
    #: Free-form operator labels for triage, grouping, search and filters
    #: (ROADMAP ``WEB-C``). Additive and optional, like ``Asset.tags``.
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        """Trim tags, drop empties, and de-duplicate while preserving order."""
        seen: dict[str, None] = {}
        for raw in value:
            tag = raw.strip()
            if tag:
                seen.setdefault(tag, None)
        return list(seen)

    @field_validator("cvss")
    @classmethod
    def _validate_cvss(cls, value: float | None) -> float | None:
        """Ensure CVSS, when present, stays within the 0.0-10.0 range."""
        if value is not None and not 0.0 <= value <= 10.0:
            raise ValueError("cvss must be between 0.0 and 10.0")
        return value

    @field_validator("cve")
    @classmethod
    def _validate_cve(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().upper() for item in value]
        for item in normalized:
            if not _CVE_RE.fullmatch(item):
                raise ValueError(f"invalid CVE identifier: {item!r}")
        return normalized

    @field_validator("cwe")
    @classmethod
    def _validate_cwe(cls, value: list[str]) -> list[str]:
        normalized = [item.strip().upper() for item in value]
        for item in normalized:
            if not _CWE_RE.fullmatch(item):
                raise ValueError(f"invalid CWE identifier: {item!r}")
        return normalized

    @field_validator("epss", "epss_percentile")
    @classmethod
    def _validate_probability(cls, value: float | None) -> float | None:
        if value is not None and not 0.0 <= value <= 1.0:
            raise ValueError("EPSS score and percentile must be between 0.0 and 1.0")
        return value

    def cves(self) -> list[str]:
        """Return the finding's CVE ids: the structured field, or text-derived."""
        if self.cve:
            return sorted(set(self.cve))
        haystack = " ".join([self.title, self.description, *self.references, *self.evidence])
        return sorted({match.group().upper() for match in _CVE_RE.finditer(haystack)})

    def cwes(self) -> list[str]:
        """Return the finding's CWE ids: the structured field, or text-derived."""
        if self.cwe:
            return sorted(set(self.cwe))
        haystack = " ".join([self.title, self.description, *self.references, *self.evidence])
        return sorted({match.group().upper() for match in _CWE_RE.finditer(haystack)})

    def risk_score(self) -> float:
        """Return a contextual risk score in ``[0, 100]`` (ROADMAP ``WEB-C``).

        Risk is more than raw severity: a vulnerability's real-world urgency
        depends on whether it is actually being exploited. The score blends the
        finding's own fields in the same priority order Vulcan uses to rank
        findings (KEV > EPSS > CVSS > severity; see
        :func:`olympus.vulcan.enrichment.prioritize`), as a single scalar a UI or
        report can sort and threshold on:

        * the **base** is CVSS x10 when a CVSS is present, else a severity band;
        * **CISA KEV** membership (confirmed in-the-wild exploitation) raises the
          score to at least 95 - it dominates everything else;
        * otherwise **EPSS** (predicted exploitation probability, 0-1) lifts the
          floor to ``epss x100``, so a likely-exploited finding outranks a merely
          severe one;
        * **confidence** is a mild modifier only (``high`` +5, ``low`` -10): it
          nudges, it never decides.

        It is computed on demand from the current fields, so it is never stale and
        adds nothing to the stored contract.
        """
        severity_base = {
            Severity.INFO: 10.0,
            Severity.LOW: 30.0,
            Severity.MEDIUM: 50.0,
            Severity.HIGH: 75.0,
            Severity.CRITICAL: 90.0,
        }
        score = self.cvss * 10.0 if self.cvss is not None else severity_base[self.severity]
        if self.kev:
            score = max(score, 95.0)
        elif self.epss is not None:
            score = max(score, self.epss * 100.0)
        if self.confidence is Confidence.HIGH:
            score += 5.0
        elif self.confidence is Confidence.LOW:
            score -= 10.0
        return round(min(100.0, max(0.0, score)), 1)


class FindingTransition(EngagementScopedModel):
    """One immutable audit record of a finding's lifecycle status change (``WEB-C``).

    The finding itself only carries its *current* status; this record is the
    durable trail of *how it got there* — who moved it, when, from what to what,
    and why (the rationale for a suppression or accepted-risk decision). Appended
    to an append-only ledger, these records let a report answer "who accepted this
    risk, and when?" without trusting the mutable finding.
    """

    schema_name: Literal["olympus.finding-transition"] = "olympus.finding-transition"
    transition_id: str = Field(default_factory=lambda: new_id("finding_transition"))
    finding_id: str = Field(min_length=1)
    from_status: FindingStatus
    to_status: FindingStatus
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=2_000)
    occurred_at: datetime = Field(default_factory=_utcnow)

    @field_validator("actor")
    @classmethod
    def _single_line_actor(cls, value: str) -> str:
        """Actor is trimmed single-line text (no control characters)."""
        if value != value.strip() or any(ch in value for ch in "\r\n\x00"):
            raise ValueError("actor must be trimmed single-line text without control characters")
        return value


class Event(EngagementScopedModel):
    """A normalized observable consumed by detection rules."""

    schema_name: Literal["olympus.event"] = "olympus.event"
    event_id: str = Field(default_factory=lambda: new_id("event"))
    event_type: str = Field(min_length=1)
    source: Source
    observed_at: datetime = Field(default_factory=_utcnow)
    asset_id: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class Evidence(EngagementScopedModel):
    """An immutable reference to material supporting a finding or alert."""

    schema_name: Literal["olympus.evidence"] = "olympus.evidence"
    evidence_id: str = Field(default_factory=lambda: new_id("evidence"))
    evidence_type: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    collected_at: datetime = Field(default_factory=_utcnow)


class Alert(EngagementScopedModel):
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


class Incident(EngagementScopedModel):
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


class Observation(EngagementScopedModel):
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

    def covers(self, host: str) -> bool:
        """Return ``True`` if ``host`` is inside this engagement's scope.

        Convenience that forwards to :meth:`EngagementScope.covers`, so producers
        can scope-check against an engagement without reaching into ``scope``.
        """
        return self.scope.covers(host)

    def stamp(self, obj: ScopedT) -> ScopedT:
        """Return a copy of ``obj`` linked to this engagement.

        The original is left unchanged (a new, validated copy is returned), so a
        producer can associate an asset, finding, alert or any engagement-scoped
        object with this engagement by its ``engagement_id`` without mutating the
        object it was handed.
        """
        return obj.model_copy(update={"engagement_id": self.engagement_id})

    def stamp_all(self, objects: Iterable[ScopedT]) -> list[ScopedT]:
        """Return copies of every object in ``objects`` linked to this engagement."""
        return [self.stamp(obj) for obj in objects]

    def canonical_json(self) -> str:
        """Return the deterministic JSON encoding used for digesting and storage."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Return the SHA-256 digest of the engagement's canonical encoding."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

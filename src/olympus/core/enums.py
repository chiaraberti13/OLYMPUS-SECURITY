"""Shared enumerations used across the whole Olympus data contract."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Normalized severity scale shared by findings, alerts and reports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Lifecycle state of a finding inside the remediation workflow."""

    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    IN_REMEDIATION = "in_remediation"
    CLOSED = "closed"


class AlertStatus(StrEnum):
    """Lifecycle state of a detection alert."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class IncidentStatus(StrEnum):
    """Lifecycle state of an incident response case."""

    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class EngagementStatus(StrEnum):
    """Lifecycle state of an engagement (the top-level assessment container)."""

    PLANNED = "planned"
    ACTIVE = "active"
    CLOSED = "closed"


class Confidence(StrEnum):
    """How confident Olympus is that a finding is a true positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EpistemicClass(StrEnum):
    """What kind of knowledge a statement is (ROADMAP ``EXPL-1``/``CORR-1``).

    Shared across explainability (`EXPL-1`) and correlation (`CORR-1`) so every
    surface labels a claim by how it is known. The ordering is from strongest to
    weakest epistemic standing; a weaker class must never be presented as a
    stronger one (an inference is not an observation, a hypothesis is not a
    demonstrated compromise).
    """

    #: Directly recorded by a tool/scanner or attached as evidence.
    OBSERVED_EVIDENCE = "observed_evidence"
    #: Produced by a deterministic rule/computation over observed inputs.
    DETERMINISTIC_RESULT = "deterministic_result"
    #: Derived by reasoning over observed inputs (may be wrong).
    INFERENCE = "inference"
    #: A relationship proposed between items, still to be confirmed.
    SUGGESTED_CORRELATION = "suggested_correlation"
    #: An unproven possibility; never a demonstrated fact.
    UNVERIFIED_HYPOTHESIS = "unverified_hypothesis"


class Criticality(StrEnum):
    """Business criticality of an asset."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetType(StrEnum):
    """Kind of asset observed or managed by the platform."""

    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    WEB_SERVER = "web_server"
    SERVICE = "service"
    URL = "url"
    PHONE = "phone"
    ACCOUNT = "account"
    OTHER = "other"


class Source(StrEnum):
    """Producing module for a given object (provenance)."""

    ARGUS = "argus"
    HELIOS = "helios"
    ARTEMIS = "artemis"
    PROTEUS = "proteus"
    HERMES = "hermes"
    APOLLO = "apollo"
    MINERVA = "minerva"
    VULCAN = "vulcan"
    ATHENA = "athena"
    # The subsystem was renamed AEGIS -> Themis (ROADMAP DEV-I). New records use
    # THEMIS ("themis"); the deprecated AEGIS ("aegis") member is retained so
    # findings/alerts persisted before the rename still validate on load.
    THEMIS = "themis"
    AEGIS = "aegis"
    MARS = "mars"
    MANUAL = "manual"

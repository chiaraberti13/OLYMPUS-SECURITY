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
    # The subsystem was renamed AEGIS -> Themis (ROADMAP DEV-I). The provenance
    # *value* stays "aegis" so findings/alerts stored before the rename remain
    # valid; migrating the value to "themis" is staged with the schema-name
    # migration (DEV-I, follow-up).
    THEMIS = "aegis"
    MARS = "mars"
    MANUAL = "manual"

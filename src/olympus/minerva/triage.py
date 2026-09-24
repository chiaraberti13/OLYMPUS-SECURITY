"""Deterministic, bounded alert-to-incident triage for Minerva."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from datetime import UTC
from pathlib import Path

from pydantic import ValidationError

from olympus.core.contracts import validate_contract_header
from olympus.core.enums import IncidentStatus, Severity, Source
from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.core.models import Alert, Incident

DEFAULT_MAX_ALERT_BYTES = 50_000_000
DEFAULT_MAX_ALERTS = 100_000
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def triage_alerts(alerts: Sequence[Alert], title: str, owner: str | None = None) -> Incident:
    """Create one stable incident linked to unique, non-conflicting alerts."""
    normalized_title = _single_line(title, "title", 500)
    normalized_owner = _single_line(owner, "owner", 200) if owner is not None else None
    unique = _unique_alerts(alerts)
    if not unique:
        raise ValueError("at least one alert is required for triage")
    if any(
        alert.created_at.tzinfo is None or alert.created_at.utcoffset() is None for alert in unique
    ):
        raise ValueError("alert created_at values must include a timezone")
    severity = max((alert.severity for alert in unique), key=_SEVERITY_RANK.__getitem__)
    alert_ids = [alert.alert_id for alert in unique]
    evidence_ids = list(
        dict.fromkeys(evidence_id for alert in unique for evidence_id in alert.evidence_ids)
    )
    opened_at = min(alert.created_at.astimezone(UTC) for alert in unique)
    updated_at = max(alert.created_at.astimezone(UTC) for alert in unique)
    identity = json.dumps(
        {"alert_ids": sorted(alert_ids), "owner": normalized_owner, "title": normalized_title},
        separators=(",", ":"),
        sort_keys=True,
    )
    incident_id = f"INC-{hashlib.sha256(identity.encode()).hexdigest()[:24].upper()}"
    return Incident(
        incident_id=incident_id,
        title=normalized_title,
        summary=f"Triaged from {len(alert_ids)} alert(s).",
        source=Source.MINERVA,
        severity=severity,
        status=IncidentStatus.TRIAGED,
        alert_ids=alert_ids,
        evidence_ids=evidence_ids,
        owner=normalized_owner,
        opened_at=opened_at,
        updated_at=updated_at,
    )


def export_incident(incident: Incident, output: Path) -> None:
    """Write a private core-compatible Incident document atomically."""
    atomic_write_text(output, incident.model_dump_json(indent=2) + "\n", mode=0o600)


def load_alerts(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_ALERT_BYTES,
    max_alerts: int = DEFAULT_MAX_ALERTS,
    progress_check: Callable[[], None] | None = None,
) -> list[Alert]:
    """Load one strict, bounded Apollo collection and validate every alert."""
    if not 1 <= max_alerts <= 1_000_000:
        raise ValueError("max_alerts must be between 1 and 1000000")
    try:
        payload = json.loads(read_regular_text(path, max_bytes=max_bytes, label="alert input"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid alert JSON: {exc.msg}") from exc
    validate_contract_header(payload, schema_name="olympus.apollo-alerts")
    if set(payload) != {"schema_name", "schema_version", "alerts"}:
        raise ValueError("Apollo alert collection contains missing or unknown top-level fields")
    raw_alerts = payload.get("alerts")
    if not isinstance(raw_alerts, list):
        raise ValueError("alerts must be a JSON array")
    if len(raw_alerts) > max_alerts:
        raise ValueError(f"alert collection exceeds the {max_alerts} alert limit")
    alerts: list[Alert] = []
    for item in raw_alerts:
        if progress_check is not None:
            progress_check()
        try:
            alerts.append(Alert.model_validate(item))
        except ValidationError as exc:
            details = exc.errors(include_input=False, include_url=False)
            raise ValueError(f"invalid alert contract: {details}") from exc
    return _unique_alerts(alerts)


def _unique_alerts(alerts: Sequence[Alert]) -> list[Alert]:
    unique: list[Alert] = []
    seen: dict[str, Alert] = {}
    for alert in alerts:
        prior = seen.get(alert.alert_id)
        if prior is None:
            seen[alert.alert_id] = alert
            unique.append(alert)
        elif prior != alert:
            raise ValueError(f"conflicting duplicate alert_id: {alert.alert_id}")
    return unique


def _single_line(value: str, label: str, maximum: int) -> str:
    if not 1 <= len(value) <= maximum:
        raise ValueError(f"{label} must contain between 1 and {maximum} characters")
    if value != value.strip() or any(character in value for character in "\r\n\x00"):
        raise ValueError(f"{label} must be trimmed single-line text without NUL")
    return value

"""Tests for the W2 detection data contract."""

import pytest
from pydantic import ValidationError

from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert, Event, Evidence


def test_event_evidence_alert_round_trip() -> None:
    event = Event(event_type="process.start", source=Source.APOLLO, attributes={"image": "demo"})
    evidence = Evidence(evidence_type="log", uri="memory://olympus-demo", sha256="a" * 64)
    alert = Alert(
        event_id=event.event_id,
        title="Synthetic suspicious process",
        source=Source.APOLLO,
        severity=Severity.HIGH,
        evidence_ids=[evidence.evidence_id],
    )

    assert Event.model_validate_json(event.model_dump_json()) == event
    assert Evidence.model_validate_json(evidence.model_dump_json()) == evidence
    assert Alert.model_validate_json(alert.model_dump_json()) == alert
    assert alert.status is AlertStatus.OPEN


def test_evidence_rejects_invalid_digest() -> None:
    with pytest.raises(ValidationError):
        Evidence(evidence_type="log", uri="memory://demo", sha256="not-a-digest")

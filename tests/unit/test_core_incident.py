"""Tests for the W3 Incident data contract."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from olympus.core.enums import IncidentStatus, Severity, Source
from olympus.core.models import Incident


def test_incident_round_trip_and_links() -> None:
    opened_at = datetime(2026, 8, 14, tzinfo=UTC)
    incident = Incident(
        title="Olympus Demo Corp malware containment",
        summary="Synthetic incident used for contract validation.",
        source=Source.MINERVA,
        severity=Severity.HIGH,
        status=IncidentStatus.CLOSED,
        alert_ids=["ALT-2026-00001"],
        evidence_ids=["EVD-2026-00001"],
        owner="demo-soc",
        opened_at=opened_at,
        updated_at=opened_at + timedelta(hours=2),
        closed_at=opened_at + timedelta(hours=3),
    )

    assert incident.incident_id.startswith("INC-")
    assert Incident.model_validate_json(incident.model_dump_json()) == incident


@pytest.mark.parametrize(
    "changes",
    [
        {"updated_at": datetime(2026, 8, 13, tzinfo=UTC)},
        {"closed_at": datetime(2026, 8, 15, tzinfo=UTC)},
    ],
)
def test_incident_rejects_invalid_timeline_or_state(changes: dict[str, datetime]) -> None:
    values = {
        "title": "Invalid synthetic incident",
        "source": Source.MINERVA,
        "opened_at": datetime(2026, 8, 14, tzinfo=UTC),
        "updated_at": datetime(2026, 8, 14, tzinfo=UTC),
    }
    values.update(changes)
    with pytest.raises(ValidationError):
        Incident.model_validate(values)

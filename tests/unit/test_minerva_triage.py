"""Tests for deterministic Minerva alert triage."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import IncidentStatus, Severity, Source
from olympus.core.execution import CancellationRequested, CancellationToken
from olympus.core.models import Alert, Incident
from olympus.minerva.application import MinervaApplicationService, MinervaTriageRequest
from olympus.minerva.triage import (
    export_incident,
    incident_status_breakdown,
    load_alerts,
    load_incidents,
    triage_alerts,
)

runner = CliRunner()


def _alert(identifier: str, severity: Severity, evidence: list[str]) -> Alert:
    return Alert(
        alert_id=identifier,
        event_id="EVT-2026-00001",
        title="Synthetic alert",
        source=Source.APOLLO,
        severity=severity,
        evidence_ids=evidence,
    )


def test_triage_selects_max_severity_and_deduplicates_links() -> None:
    low = _alert("ALT-2026-00001", Severity.LOW, ["EVD-2026-00001"])
    high = _alert(
        "ALT-2026-00002",
        Severity.HIGH,
        ["EVD-2026-00001", "EVD-2026-00002"],
    )

    incident = triage_alerts([low, high, high], "Olympus Demo triage", "demo-soc")

    assert incident.severity is Severity.HIGH
    assert incident.alert_ids == ["ALT-2026-00001", "ALT-2026-00002"]
    assert incident.evidence_ids == ["EVD-2026-00001", "EVD-2026-00002"]
    assert incident.owner == "demo-soc"
    assert (
        incident.incident_id
        == triage_alerts([low, high], "Olympus Demo triage", "demo-soc").incident_id
    )


def test_triage_rejects_empty_alerts() -> None:
    with pytest.raises(ValueError, match="at least one alert"):
        triage_alerts([], "Invalid")


def test_load_alerts_and_cli_export_round_trip(tmp_path: Path) -> None:
    alert = _alert("ALT-2026-00001", Severity.CRITICAL, [])
    source = tmp_path / "alerts.json"
    source.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-alerts",
                "schema_version": "1.0.0",
                "alerts": [alert.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )
    assert load_alerts(source) == [alert]
    output = tmp_path / "incident.json"

    result = runner.invoke(
        app,
        [
            "minerva",
            "triage",
            str(source),
            "--title",
            "Critical synthetic incident",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    incident = Incident.model_validate_json(output.read_text(encoding="utf-8"))
    assert incident.alert_ids == [alert.alert_id]
    assert incident.severity is Severity.CRITICAL


def test_cli_sanitizes_hostile_triage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail_triage(self: MinervaApplicationService, request: MinervaTriageRequest) -> Incident:
        raise ValueError("invalid \x1b[31mrecord\x1b[0m\nforged: clean")

    monkeypatch.setattr(MinervaApplicationService, "triage", fail_triage)
    result = runner.invoke(
        app,
        [
            "minerva",
            "triage",
            str(tmp_path / "alerts.json"),
            "--title",
            "Synthetic incident",
            "--output",
            str(tmp_path / "incident.json"),
        ],
    )

    assert result.exit_code == 2
    assert "\x1b" not in result.output
    assert "forged: clean" in result.output
    assert result.output.count("\n") == 1


def test_export_incident_is_atomic_shape(tmp_path: Path) -> None:
    incident = triage_alerts([_alert("ALT-2026-00001", Severity.MEDIUM, [])], "Synthetic incident")
    output = tmp_path / "incident.json"
    export_incident(incident, output)
    assert Incident.model_validate_json(output.read_text(encoding="utf-8")) == incident


def test_load_alerts_rejects_incompatible_collection_version(tmp_path: Path) -> None:
    source = tmp_path / "alerts-v2.json"
    source.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-alerts",
                "schema_version": "2.0.0",
                "alerts": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported"):
        load_alerts(source)


def test_load_alerts_rejects_conflicts_symlinks_and_limits(tmp_path: Path) -> None:
    first = _alert("ALT-2026-00001", Severity.LOW, [])
    conflicting = first.model_copy(update={"severity": Severity.HIGH})
    source = tmp_path / "alerts.json"
    source.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-alerts",
                "schema_version": "1.0.0",
                "alerts": [
                    first.model_dump(mode="json"),
                    conflicting.model_dump(mode="json"),
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="conflicting duplicate"):
        load_alerts(source)
    with pytest.raises(ValueError, match="alert limit"):
        load_alerts(source, max_alerts=1)
    with pytest.raises(ValueError, match="byte limit"):
        load_alerts(source, max_bytes=5)

    link = tmp_path / "alerts-link.json"
    link.symlink_to(source)
    with pytest.raises(OSError, match="symlink"):
        load_alerts(link)


def test_triage_application_protects_output_and_cancellation(tmp_path: Path) -> None:
    alert = _alert("ALT-2026-00001", Severity.MEDIUM, [])
    source = tmp_path / "alerts.json"
    source.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-alerts",
                "schema_version": "1.0.0",
                "alerts": [alert.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="paths must differ"):
        MinervaApplicationService().triage(
            MinervaTriageRequest(source, "Incident", excluded_paths=(source,))
        )

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        MinervaApplicationService(token).triage(MinervaTriageRequest(source, "Incident"))


def test_triage_rejects_conflicting_duplicate_alerts() -> None:
    first = _alert("ALT-2026-00001", Severity.LOW, [])
    conflict = first.model_copy(update={"title": "different"})
    with pytest.raises(ValueError, match="conflicting duplicate"):
        triage_alerts([first, conflict], "Incident")


def _incident(incident_id: str, status: IncidentStatus) -> Incident:
    return Incident(
        incident_id=incident_id, title=f"Case {incident_id}", source=Source.MINERVA, status=status
    )


def test_load_incidents_round_trips_exported_documents(tmp_path: Path) -> None:
    directory = tmp_path / "incidents"
    directory.mkdir()
    open_case = _incident("INC-2026-00001", IncidentStatus.OPEN)
    triaged_case = _incident("INC-2026-00002", IncidentStatus.TRIAGED)
    export_incident(open_case, directory / "a.json")
    export_incident(triaged_case, directory / "b.json")
    loaded = load_incidents(sorted(directory.glob("*.json")))
    assert [incident.incident_id for incident in loaded] == ["INC-2026-00001", "INC-2026-00002"]
    assert loaded == [open_case, triaged_case]


def test_load_incidents_rejects_a_non_incident_document(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_name": "olympus.finding", "schema_version": "1.0.0"}))
    with pytest.raises(ValueError):
        load_incidents([bad])


def test_load_incidents_enforces_the_file_limit(tmp_path: Path) -> None:
    path = tmp_path / "only.json"
    export_incident(_incident("INC-2026-00001", IncidentStatus.OPEN), path)
    with pytest.raises(ValueError, match="file limit"):
        load_incidents([path, path], max_files=1)


def test_incident_status_breakdown_covers_every_status() -> None:
    counts = incident_status_breakdown(
        [
            _incident("INC-2026-00001", IncidentStatus.OPEN),
            _incident("INC-2026-00002", IncidentStatus.OPEN),
            _incident("INC-2026-00003", IncidentStatus.TRIAGED),
        ]
    )
    assert counts["open"] == 2
    assert counts["triaged"] == 1
    assert counts["closed"] == 0
    assert set(counts) == {status.value for status in IncidentStatus}

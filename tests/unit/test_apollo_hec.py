"""Apollo alerts render to Splunk HEC event envelopes for SIEM ingestion (BLUE-2).

The HEC envelope is plain JSON wrapping the ECS document, so no dependency is
added and no network I/O happens here. These tests check the envelope shape, the
newline-delimited output, owner-only file permissions and the CLI --hec option.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ecs import ECS_VERSION
from olympus.apollo.hec import HEC_SOURCETYPE, alert_to_hec, alerts_to_hec
from olympus.cli import app
from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert, Event

runner = CliRunner()


def _alert(**overrides: object) -> Alert:
    fields: dict[str, object] = {
        "event_id": "EVT-1",
        "title": "Suspicious PowerShell",
        "source": Source.APOLLO,
        "severity": Severity.HIGH,
        "status": AlertStatus.OPEN,
        "rule_id": "APL-DEMO",
        "mitre_attack": ["T1059.001"],
        "evidence_ids": ["EVD-1"],
    }
    fields.update(overrides)
    return Alert(**fields)  # type: ignore[arg-type]


def test_alert_to_hec_wraps_the_ecs_document_in_a_hec_envelope() -> None:
    envelope = alert_to_hec(_alert())
    # HEC metadata.
    assert envelope["sourcetype"] == HEC_SOURCETYPE
    assert envelope["host"] == "olympus"
    assert envelope["source"] == "olympus.apollo"
    # time is epoch seconds (a float), the unit HEC expects.
    assert isinstance(envelope["time"], float)
    # The payload is the ECS document verbatim (no duplicated mapping).
    event = envelope["event"]
    assert event["ecs"]["version"] == ECS_VERSION
    assert event["event"]["kind"] == "alert"
    assert event["rule"] == {"id": "APL-DEMO", "name": "Suspicious PowerShell"}
    assert event["threat"]["technique"] == [{"id": "T1059.001"}]


def test_alert_to_hec_time_matches_created_at() -> None:
    alert = _alert()
    assert alert_to_hec(alert)["time"] == alert.created_at.timestamp()


def test_alerts_to_hec_is_one_json_object_per_line() -> None:
    text = alerts_to_hec([_alert(), _alert(title="Second")])
    lines = text.splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["sourcetype"] == HEC_SOURCETYPE for line in lines)
    # Empty in, empty out — never a stray newline.
    assert alerts_to_hec([]) == ""


def test_apollo_test_writes_owner_only_hec(tmp_path: Path) -> None:
    rule = tmp_path / "rule.json"
    rule.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-HEC",
                "title": "PowerShell start",
                "event_type": "process.start",
                "conditions": {"image": "powershell.exe"},
                "severity": "high",
                "mitre_attack": ["T1059.001"],
            }
        ),
        encoding="utf-8",
    )
    event = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    event_path = tmp_path / "event.json"
    event_path.write_text(event.model_dump_json(), encoding="utf-8")
    output = tmp_path / "alerts.json"
    hec_path = tmp_path / "alerts.hec.ndjson"

    result = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(rule),
            str(event_path),
            "--output",
            str(output),
            "--hec",
            str(hec_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(hec_path.stat().st_mode) == 0o600
    envelope = json.loads(hec_path.read_text(encoding="utf-8").splitlines()[0])
    assert envelope["sourcetype"] == HEC_SOURCETYPE
    assert envelope["event"]["rule"]["id"] == "APL-HEC"

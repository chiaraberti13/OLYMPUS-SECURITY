"""Offline Azure Monitor / Sentinel DCR input-format contract (BLUE-2)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.sentinel import alert_to_sentinel, alerts_to_sentinel_json
from olympus.cli import app
from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert, Event

runner = CliRunner()


def _alert() -> Alert:
    return Alert(
        event_id="EVT-1",
        title="Suspicious PowerShell",
        source=Source.APOLLO,
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        rule_id="APL-DEMO",
        mitre_attack=["T1059.001"],
        evidence_ids=["EVD-1"],
    )


def test_sentinel_contract_is_flat_json_array_and_keeps_alert_identity() -> None:
    alert = _alert()
    record = alert_to_sentinel(alert)
    assert record["TimeGenerated"] == alert.created_at.isoformat()
    assert record["AlertId"] == alert.alert_id
    assert record["EventId"] == "EVT-1"
    assert record["Severity"] == "high"
    assert record["RuleId"] == "APL-DEMO"
    assert json.loads(record["MitreAttackIds"]) == ["T1059.001"]
    assert json.loads(record["EvidenceIds"]) == ["EVD-1"]
    assert set(record) == {
        "TimeGenerated",
        "AlertId",
        "EventId",
        "Title",
        "Source",
        "Severity",
        "Status",
        "RuleId",
        "MitreAttackIds",
        "EvidenceIds",
    }
    assert json.loads(alerts_to_sentinel_json([alert, alert])) == [record, record]


def test_sentinel_empty_and_optional_values() -> None:
    assert json.loads(alerts_to_sentinel_json([])) == []
    alert = _alert().model_copy(update={"rule_id": None, "mitre_attack": []})
    record = alert_to_sentinel(alert)
    assert record["RuleId"] == ""
    assert json.loads(record["MitreAttackIds"]) == []


def test_sentinel_escapes_untrusted_title() -> None:
    alert = _alert().model_copy(update={"title": 'quoted " value\\n<xml>'})
    assert json.loads(alerts_to_sentinel_json([alert]))[0]["Title"] == alert.title


def test_apollo_test_writes_owner_only_sentinel_json(tmp_path: Path) -> None:
    rule = tmp_path / "rule.json"
    rule.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-SENTINEL",
                "title": "PowerShell start",
                "event_type": "process.start",
                "conditions": {"image": "powershell.exe"},
                "severity": "high",
            }
        ),
        encoding="utf-8",
    )
    event = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    event_path = tmp_path / "event.json"
    event_path.write_text(event.model_dump_json(), encoding="utf-8")
    destination = tmp_path / "sentinel.json"
    result = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(rule),
            str(event_path),
            "--output",
            str(tmp_path / "alerts.json"),
            "--sentinel",
            str(destination),
        ],
    )
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    records = json.loads(destination.read_text(encoding="utf-8"))
    assert len(records) == 1
    assert records[0]["RuleId"] == "APL-SENTINEL"

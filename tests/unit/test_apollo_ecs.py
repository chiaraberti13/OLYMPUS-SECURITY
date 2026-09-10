"""Apollo alerts render to Elastic Common Schema for SIEM ingestion (§2).

ECS is plain JSON, so no dependency is added. These tests check the field
mapping, the newline-delimited output shape, and the CLI --ecs option.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ecs import ECS_VERSION, alert_to_ecs, alerts_to_ndjson
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


def test_alert_to_ecs_maps_the_defined_fields() -> None:
    document = alert_to_ecs(_alert())
    assert document["ecs"]["version"] == ECS_VERSION
    assert document["event"]["kind"] == "alert"
    assert document["event"]["severity"] == 73  # HIGH on the 0-100 scale
    assert document["event"]["provider"] == "apollo"
    assert document["message"] == "Suspicious PowerShell"
    assert document["rule"] == {"id": "APL-DEMO", "name": "Suspicious PowerShell"}
    assert document["threat"]["technique"] == [{"id": "T1059.001"}]
    assert document["olympus"]["event_id"] == "EVT-1"
    assert document["olympus"]["evidence_ids"] == ["EVD-1"]
    assert document["tags"] == ["open"]
    # @timestamp is ISO 8601.
    assert document["@timestamp"].endswith("+00:00") or "T" in document["@timestamp"]


def test_alert_without_rule_or_mitre_omits_those_sections() -> None:
    document = alert_to_ecs(_alert(rule_id=None, mitre_attack=[]))
    assert "rule" not in document
    assert "threat" not in document


def test_alerts_to_ndjson_is_one_json_object_per_line() -> None:
    text = alerts_to_ndjson([_alert(), _alert(title="Second")])
    lines = text.splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["ecs"]["version"] == ECS_VERSION for line in lines)
    assert alerts_to_ndjson([]) == ""  # empty in, empty out


def test_apollo_test_writes_owner_only_ecs(tmp_path: Path) -> None:
    rule = tmp_path / "rule.json"
    rule.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-ECS",
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
    ecs_path = tmp_path / "alerts.ndjson"

    result = runner.invoke(
        app,
        ["apollo", "test", str(rule), str(event_path),
         "--output", str(output), "--ecs", str(ecs_path)],
    )

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(ecs_path.stat().st_mode) == 0o600
    line = ecs_path.read_text(encoding="utf-8").splitlines()[0]
    document = json.loads(line)
    assert document["event"]["kind"] == "alert"
    assert document["rule"]["id"] == "APL-ECS"

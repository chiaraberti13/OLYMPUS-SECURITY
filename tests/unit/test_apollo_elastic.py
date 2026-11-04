"""Apollo alerts render to an Elasticsearch _bulk request body (BLUE-2).

The _bulk body is plain NDJSON (action line + ECS document per alert), so no
dependency is added and no network I/O happens here. These tests check the
action/metadata lines, the trailing newline the API requires, owner-only file
permissions and the CLI --elastic-bulk / --elastic-index options.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ecs import ECS_VERSION
from olympus.apollo.elastic import DEFAULT_ELASTIC_INDEX, alerts_to_elastic_bulk
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


def test_bulk_pairs_a_create_action_with_each_ecs_document() -> None:
    alert = _alert()
    body = alerts_to_elastic_bulk([alert], index="siem-test")
    lines = body.splitlines()
    assert len(lines) == 2  # action line + document line
    action = json.loads(lines[0])
    assert action == {"create": {"_index": "siem-test", "_id": alert.alert_id}}
    document = json.loads(lines[1])
    assert document["ecs"]["version"] == ECS_VERSION
    assert document["event"]["kind"] == "alert"
    # The _bulk API requires a trailing newline after the last line.
    assert body.endswith("\n")


def test_bulk_defaults_to_the_olympus_index_and_is_empty_for_no_alerts() -> None:
    body = alerts_to_elastic_bulk([_alert()])
    assert json.loads(body.splitlines()[0])["create"]["_index"] == DEFAULT_ELASTIC_INDEX
    # Empty in, empty out — never a stray newline.
    assert alerts_to_elastic_bulk([]) == ""


def test_bulk_emits_two_lines_per_alert() -> None:
    body = alerts_to_elastic_bulk([_alert(), _alert(title="Second")])
    assert len(body.splitlines()) == 4


def test_apollo_test_writes_owner_only_elastic_bulk(tmp_path: Path) -> None:
    rule = tmp_path / "rule.json"
    rule.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-ES",
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
    bulk_path = tmp_path / "alerts.bulk.ndjson"

    result = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(rule),
            str(event_path),
            "--output",
            str(output),
            "--elastic-bulk",
            str(bulk_path),
            "--elastic-index",
            "detections-2026",
        ],
    )

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(bulk_path.stat().st_mode) == 0o600
    lines = bulk_path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["create"]["_index"] == "detections-2026"
    assert json.loads(lines[1])["event"]["kind"] == "alert"

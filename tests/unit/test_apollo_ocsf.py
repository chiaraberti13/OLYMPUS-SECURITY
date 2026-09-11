"""Apollo alerts render to OCSF Detection Findings (§2).

OCSF is plain JSON, so no dependency is added. These tests check the class/type
mapping, severity/status ids, ATT&CK attacks, the NDJSON shape, and the CLI
--ocsf option.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ocsf import OCSF_VERSION, alert_to_ocsf, alerts_to_ndjson
from olympus.cli import app
from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert, Event

runner = CliRunner()


def _alert(**overrides: object) -> Alert:
    fields: dict[str, object] = {
        "event_id": "EVT-1",
        "title": "Suspicious PowerShell",
        "source": Source.APOLLO,
        "severity": Severity.CRITICAL,
        "status": AlertStatus.OPEN,
        "rule_id": "APL-DEMO",
        "mitre_attack": ["T1059.001"],
        "evidence_ids": ["EVD-1"],
    }
    fields.update(overrides)
    return Alert(**fields)  # type: ignore[arg-type]


def test_alert_to_ocsf_is_a_detection_finding() -> None:
    document = alert_to_ocsf(_alert())
    assert document["class_uid"] == 2004
    assert document["category_uid"] == 2
    assert document["type_uid"] == 200401
    assert document["activity_id"] == 1
    assert document["severity_id"] == 5  # CRITICAL
    assert document["status_id"] == 1  # OPEN -> New
    assert document["metadata"]["version"] == OCSF_VERSION
    assert document["finding_info"]["title"] == "Suspicious PowerShell"
    assert document["finding_info"]["analytic"] == {
        "uid": "APL-DEMO",
        "name": "Suspicious PowerShell",
    }
    assert document["attacks"] == [{"technique": {"uid": "T1059.001"}}]
    assert document["unmapped"]["event_id"] == "EVT-1"
    assert isinstance(document["time"], int)


def test_status_and_severity_ids_map() -> None:
    closed = alert_to_ocsf(_alert(status=AlertStatus.CLOSED, severity=Severity.LOW))
    assert closed["status_id"] == 4  # CLOSED -> Resolved
    assert closed["severity_id"] == 2  # LOW
    investigating = alert_to_ocsf(_alert(status=AlertStatus.INVESTIGATING))
    assert investigating["status_id"] == 2  # In Progress


def test_alert_without_rule_or_mitre_omits_those_sections() -> None:
    document = alert_to_ocsf(_alert(rule_id=None, mitre_attack=[]))
    assert "analytic" not in document["finding_info"]
    assert "attacks" not in document


def test_alerts_to_ndjson_is_one_finding_per_line() -> None:
    text = alerts_to_ndjson([_alert(), _alert(title="Second")])
    lines = text.splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["class_uid"] == 2004 for line in lines)
    assert alerts_to_ndjson([]) == ""


def test_apollo_run_writes_owner_only_ocsf(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yaml").write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-OCSF",
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
    events = tmp_path / "events.ndjson"
    events.write_text(event.model_dump_json() + "\n", encoding="utf-8")
    output = tmp_path / "alerts.json"
    ocsf_path = tmp_path / "alerts.ocsf.ndjson"

    result = runner.invoke(
        app,
        ["apollo", "run", "--rules", str(rules_dir), "--events", str(events),
         "--output", str(output), "--ocsf", str(ocsf_path)],
    )

    # apollo run exits 1 when alerts are produced; the OCSF file must still exist.
    assert result.exit_code in (0, 1), result.output
    assert stat.S_IMODE(ocsf_path.stat().st_mode) == 0o600
    document = json.loads(ocsf_path.read_text(encoding="utf-8").splitlines()[0])
    assert document["class_uid"] == 2004
    assert document["finding_info"]["analytic"]["uid"] == "APL-OCSF"

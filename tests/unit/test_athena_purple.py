"""Purple-team detection exercise engine and ``athena purple`` CLI (ROADMAP ``PURPLE-1``).

The exercise scores each planned ATT&CK technique as detected (a rule fired on the
replayed telemetry) or missed (a real detection gap). These tests pin that a gap
is never counted as a detection, the fail-closed input validation, determinism,
and the CLI's canonical exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.athena.purple import (
    DetectionResult,
    PurpleExerciseReport,
    evaluate_detection_exercise,
)
from olympus.cli import app
from olympus.core.enums import Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Alert

runner = CliRunner()


def _alert(rule_id: str, *techniques: str) -> Alert:
    return Alert(
        title=f"alert {rule_id}",
        source=Source.APOLLO,
        rule_id=rule_id,
        event_id="EVT-2026-00001",
        mitre_attack=list(techniques),
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_planned_technique_is_detected_or_a_gap() -> None:
    alerts = [_alert("APL-A", "T1059"), _alert("APL-B", "T1562.001")]
    report = evaluate_detection_exercise(alerts, ["T1059", "T1071", "T1562.001"], events_total=5)
    by_tech = {o.technique: o for o in report.outcomes}
    assert by_tech["T1059"].result is DetectionResult.DETECTED
    assert by_tech["T1059"].fired_rules == ("APL-A",)
    assert by_tech["T1562.001"].result is DetectionResult.DETECTED
    # A planned technique no rule fired on is a MISS — never silently a detection.
    assert by_tech["T1071"].result is DetectionResult.MISSED
    assert by_tech["T1071"].fired_rules == ()
    assert report.has_gaps is True
    assert report.detection_rate == round(2 / 3, 4)
    assert report.summary()["missed"] == 1


def test_detections_outside_the_plan_are_reported_not_scored() -> None:
    alerts = [_alert("APL-A", "T1059"), _alert("APL-B", "T1486")]
    report = evaluate_detection_exercise(alerts, ["T1059"], events_total=2)
    assert report.detection_rate == 1.0  # the one planned technique was detected
    assert report.has_gaps is False
    assert report.unexpected_detections == ("T1486",)  # reported separately, not in the score


def test_multiple_rules_detecting_one_technique_are_all_listed() -> None:
    alerts = [_alert("APL-A", "T1059"), _alert("APL-B", "T1059")]
    report = evaluate_detection_exercise(alerts, ["T1059"], events_total=2)
    assert report.outcomes[0].fired_rules == ("APL-A", "APL-B")  # sorted, de-duplicated


def test_empty_plan_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one planned"):
        evaluate_detection_exercise([_alert("APL-A", "T1059")], [], events_total=1)


def test_malformed_planned_technique_is_rejected_fail_closed() -> None:
    with pytest.raises(ValueError, match="malformed ATT&CK technique"):
        evaluate_detection_exercise([], ["T1059", "not-a-technique"], events_total=0)


def test_no_alerts_means_every_planned_technique_is_a_gap() -> None:
    report = evaluate_detection_exercise([], ["T1059", "T1071"], events_total=4)
    assert {o.result for o in report.outcomes} == {DetectionResult.MISSED}
    assert report.detection_rate == 0.0
    assert report.has_gaps is True


def test_is_deterministic() -> None:
    alerts = [_alert("APL-B", "T1071"), _alert("APL-A", "T1059")]
    plan = ["T1071", "T1059"]
    first = evaluate_detection_exercise(alerts, plan, events_total=2)
    second = evaluate_detection_exercise(alerts, plan, events_total=2)
    assert first.to_dict() == second.to_dict()
    # Outcomes are sorted by technique id regardless of input order.
    assert [o.technique for o in first.outcomes] == ["T1059", "T1071"]


def test_alert_without_a_rule_id_still_counts_as_a_detection() -> None:
    # The Alert contract allows a null rule_id; the technique is still detected,
    # just with no rule id to list.
    alert = Alert(
        title="no rule", source=Source.APOLLO, event_id="EVT-2026-00001", mitre_attack=["T1059"]
    )
    report = evaluate_detection_exercise([alert], ["T1059"], events_total=1)
    assert report.outcomes[0].result is DetectionResult.DETECTED
    assert report.outcomes[0].fired_rules == ()


def test_detection_rate_of_an_empty_report_is_zero() -> None:
    # Defensive guard: a report with no outcomes reports 0.0, never divides by zero.
    empty = PurpleExerciseReport(
        outcomes=(), unexpected_detections=(), events_total=0, alerts_total=0
    )
    assert empty.detection_rate == 0.0
    assert empty.has_gaps is False


def test_document_states_the_replay_limit() -> None:
    document = evaluate_detection_exercise([_alert("APL-A", "T1059")], ["T1059"], events_total=1)
    assert "PURPLE-2" in document.to_dict()["limit"]
    assert "not a live attack" in document.to_dict()["limit"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _rule_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "proc.yaml").write_text(
        "schema_name: olympus.apollo-rule\n"
        "schema_version: 1.0.0\n"
        "rule_id: APL-PROC\n"
        "title: suspicious shell\n"
        "event_type: process\n"
        "conditions:\n  command_line: evil\n"
        "severity: high\n"
        "mitre_attack:\n  - T1059\n",
        encoding="utf-8",
    )
    return directory


def _events(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "event_id": "EVT-2026-00001",
                "observed_at": "2026-10-31T09:00:00Z",
                "event_type": "process",
                "source": "apollo",
                "attributes": {"command_line": "evil"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_cli_strict_exits_findings_on_a_detection_gap(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    events = _events(tmp_path / "attack.ndjson")
    # T1059 is detected by APL-PROC; T1071 is planned but no rule covers it -> gap.
    result = runner.invoke(
        app,
        [
            "athena",
            "purple",
            "--rules",
            str(rules),
            "--events",
            str(events),
            "--technique",
            "T1059",
            "--technique",
            "T1071",
            "--strict",
        ],
    )
    assert result.exit_code == int(ExitCode.FINDINGS), result.output
    assert "detected" in result.stdout
    assert "missed" in result.stdout


def test_cli_json_reports_detection_and_exits_zero_without_gaps(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    events = _events(tmp_path / "attack.ndjson")
    result = runner.invoke(
        app,
        [
            "athena",
            "purple",
            "--rules",
            str(rules),
            "--events",
            str(events),
            "--technique",
            "T1059",
            "--format",
            "json",
            "--strict",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.stdout
    document = json.loads(out[out.index("{") : out.rindex("}") + 1])
    assert document["summary"]["detected"] == 1
    assert document["summary"]["has_gaps"] is False
    assert document["outcomes"][0]["fired_rules"] == ["APL-PROC"]


def test_cli_requires_at_least_one_technique(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    events = _events(tmp_path / "attack.ndjson")
    result = runner.invoke(
        app,
        ["athena", "purple", "--rules", str(rules), "--events", str(events)],
    )
    # Typer rejects a missing required option before the command body runs.
    assert result.exit_code != 0


def test_cli_rejects_a_malformed_technique(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    events = _events(tmp_path / "attack.ndjson")
    result = runner.invoke(
        app,
        [
            "athena",
            "purple",
            "--rules",
            str(rules),
            "--events",
            str(events),
            "--technique",
            "nope",
        ],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "malformed" in result.stderr

"""Tests for secure Apollo rule loading and detection evaluation."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.apollo.application import (
    ApolloApplicationService,
    ApolloRunRequest,
)
from olympus.apollo.engine import evaluate, evaluate_stream
from olympus.apollo.export import export_alerts
from olympus.apollo.rules import load_rule, load_rules
from olympus.cli import app
from olympus.core.enums import Source
from olympus.core.execution import CancellationRequested, CancellationToken
from olympus.core.models import Alert, Event

runner = CliRunner()


def _rule(path: Path, technique: str = "T1059.001") -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-DEMO",
                "title": "Synthetic detection",
                "event_type": "process.start",
                "conditions": {"image": "powershell.exe"},
                "severity": "high",
                "mitre_attack": [technique],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_rule_validation_and_true_false_positives(tmp_path: Path) -> None:
    rule = load_rule(_rule(tmp_path / "rule.yaml"))
    matching = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    benign = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "notepad.exe"}
    )

    alerts = evaluate([rule], matching)
    assert len(alerts) == 1
    assert alerts[0].rule_id == rule.rule_id
    assert alerts[0].mitre_attack == ["T1059.001"]
    assert alerts[0].alert_id == evaluate([rule], matching)[0].alert_id
    assert alerts[0].created_at == matching.observed_at
    assert evaluate([rule], benign) == []


def test_rule_rejects_invalid_mitre_id_and_document(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_rule(_rule(tmp_path / "bad.yaml", "invalid"))
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("not executable yaml", encoding="utf-8")
    with pytest.raises(ValueError, match="expected key/value"):
        load_rule(malformed)


def test_rule_contract_migrates_legacy_but_rejects_partial_or_empty(tmp_path: Path) -> None:
    versioned = load_rule(_rule(tmp_path / "versioned.yaml"))
    legacy_payload = versioned.model_dump(mode="json")
    legacy_payload.pop("schema_name")
    legacy_payload.pop("schema_version")
    legacy_path = tmp_path / "legacy.yaml"
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")
    migrated = load_rule(legacy_path)
    assert migrated.schema_name == "olympus.apollo-rule"
    assert migrated.schema_version == "1.0.0"

    payload = migrated.model_dump(mode="json")
    payload.pop("schema_version")
    partial = tmp_path / "partial.yaml"
    partial.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        load_rule(partial)

    payload = migrated.model_dump(mode="json")
    payload["conditions"] = {}
    empty = tmp_path / "empty.yaml"
    empty.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="conditions"):
        load_rule(empty)


def test_rule_loads_yaml_and_rejects_executable_features(tmp_path: Path) -> None:
    yaml_rule = tmp_path / "rule.yaml"
    yaml_rule.write_text(
        """rule_id: APL-YAML
title: Synthetic YAML rule
event_type: process.start
conditions:
  image: demo.exe
severity: low
mitre_attack:
  - T1059
""",
        encoding="utf-8",
    )
    assert load_rule(yaml_rule).conditions == {"image": "demo.exe"}

    yaml_rule.write_text("rule_id: !!python/object:unsafe\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported YAML scalar"):
        load_rule(yaml_rule)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("rule_id: APL-ONE\nrule_id: APL-TWO\n", "duplicate YAML key"),
        ("rule_id:\tAPL-TAB\n", "tabs are not allowed"),
        ("  orphan: value\n", "invalid YAML indentation"),
        (
            "rule_id: APL-DUP\nconditions:\n  image: one\n  image: two\n",
            "duplicate condition",
        ),
    ],
)
def test_rule_rejects_ambiguous_yaml(document: str, message: str, tmp_path: Path) -> None:
    rule = tmp_path / "ambiguous.yaml"
    rule.write_text(document, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_rule(rule)


def test_alert_export_round_trips_core_model(tmp_path: Path) -> None:
    event = Event(event_type="auth.failure", source=Source.APOLLO)
    alert = Alert(event_id=event.event_id, title="Synthetic alert", source=Source.APOLLO)
    output = tmp_path / "alerts.json"
    export_alerts([alert], output)
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert Alert.model_validate(payload["alerts"][0]) == alert


def test_apollo_cli_and_demo_export_alerts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = _rule(tmp_path / "rule.yaml")
    event = Event(
        event_type="process.start", source=Source.APOLLO, attributes={"image": "powershell.exe"}
    )
    event_path = tmp_path / "event.json"
    event_path.write_text(event.model_dump_json(), encoding="utf-8")
    output = tmp_path / "alerts.json"

    result = runner.invoke(
        app, ["apollo", "test", str(rule), str(event_path), "--output", str(output)]
    )
    assert result.exit_code == 0
    assert "1 alert" in result.stdout


def test_run_over_rule_dir_and_event_stream(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule(rules_dir / "r.yaml")
    assert len(load_rules(rules_dir)) == 1

    events = tmp_path / "events.ndjson"
    event = Event(
        event_type="process.start",
        source=Source.APOLLO,
        attributes={"image": "powershell.exe"},
    )
    events.write_text(event.model_dump_json() + "\n\n{malformed json}\n", encoding="utf-8")
    out = tmp_path / "alerts.json"
    result = runner.invoke(
        app,
        ["apollo", "run", "--rules", str(rules_dir), "--events", str(events), "--output", str(out)],
    )
    assert result.exit_code == 5  # partial input takes precedence over the fired alert
    assert "malformed event" in result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["rule_id"] == "APL-DEMO"


def test_application_deduplicates_events_and_enforces_product_and_cancellation(
    tmp_path: Path,
) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule(rules_dir / "r.yaml")
    matching = Event(
        event_id="EVT-APOLLO-DEMO-1",
        event_type="process.start",
        source=Source.APOLLO,
        attributes={"image": "powershell.exe"},
    )
    second = Event(
        event_id="EVT-APOLLO-DEMO-2",
        event_type="process.start",
        source=Source.APOLLO,
        attributes={"image": "powershell.exe"},
    )
    events = tmp_path / "events.ndjson"
    events.write_text(
        matching.model_dump_json() + "\n" + matching.model_dump_json() + "\n",
        encoding="utf-8",
    )
    outcome = ApolloApplicationService().run(
        ApolloRunRequest(rules_path=rules_dir, events_path=events)
    )
    assert outcome.events == 1
    assert outcome.duplicates == 1
    assert len(outcome.alerts) == 1

    events.write_text(
        matching.model_dump_json() + "\n" + second.model_dump_json() + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="evaluation limit"):
        ApolloApplicationService().run(
            ApolloRunRequest(
                rules_path=rules_dir,
                events_path=events,
                max_evaluations=1,
            )
        )

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        ApolloApplicationService(token).run(
            ApolloRunRequest(rules_path=rules_dir, events_path=events)
        )

    rule = load_rule(rules_dir / "r.yaml")
    with pytest.raises(ValueError, match="evaluation limit"):
        evaluate_stream([rule], [matching, second], max_evaluations=1)
    with pytest.raises(CancellationRequested):
        evaluate_stream([rule], [matching], cancellation=token)


def test_event_stream_never_invents_identity_and_rejects_output_conflicts(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule(rules_dir / "r.yaml")
    events = tmp_path / "events.ndjson"
    events.write_text(
        '{"event_type":"process.start","source":"apollo","attributes":{"image":"powershell.exe"}}\n',
        encoding="utf-8",
    )
    outcome = ApolloApplicationService().run(
        ApolloRunRequest(rules_path=rules_dir, events_path=events)
    )
    assert outcome.events == 0
    assert outcome.alerts == ()
    assert "missing required fields" in outcome.input_errors[0].message

    with pytest.raises(ValueError, match="conflicts"):
        ApolloApplicationService().run(
            ApolloRunRequest(
                rules_path=rules_dir,
                events_path=events,
                excluded_paths=(events,),
            )
        )
    with pytest.raises(ValueError, match="byte limit"):
        ApolloApplicationService().run(
            ApolloRunRequest(
                rules_path=rules_dir,
                events_path=events,
                max_event_bytes=5,
            )
        )


def test_rules_command_lists_and_validates(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule(rules_dir / "r.yaml")
    result = runner.invoke(app, ["apollo", "rules", "--rules", str(rules_dir), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["rule_id"] == "APL-DEMO"


def test_rules_command_reports_duplicate_ids(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule(rules_dir / "a.yaml")
    _rule(rules_dir / "b.yaml")  # same rule_id APL-DEMO
    result = runner.invoke(app, ["apollo", "rules", "--rules", str(rules_dir)])
    assert result.exit_code == 2
    assert "duplicate rule_id" in result.output


def test_rules_loader_rejects_empty_symlink_and_rule_limit(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="contains no"):
        load_rules(empty)

    rules = tmp_path / "rules"
    rules.mkdir()
    _rule(rules / "a.yaml")
    _rule(rules / "b.yaml")
    link = tmp_path / "rules-link"
    link.symlink_to(rules, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        load_rules(link)
    with pytest.raises(ValueError, match="rule limit"):
        load_rules(rules, max_rules=1)
    with pytest.raises(ValueError, match="byte limit"):
        load_rule(rules / "a.yaml", max_rule_bytes=5)

    rule_link = tmp_path / "rule-link.yaml"
    rule_link.symlink_to(rules / "a.yaml")
    with pytest.raises(ValueError, match="non-symlink"):
        load_rule(rule_link)

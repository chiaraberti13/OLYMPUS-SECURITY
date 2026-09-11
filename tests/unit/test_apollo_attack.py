"""MITRE ATT&CK Navigator layer export from Apollo detections (§3.3).

The layer is plain JSON renderable in the MITRE ATT&CK Navigator; no dependency
is added. These tests check technique counting, the layer shape, and the CLI.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.attack import (
    NAVIGATOR_LAYER_VERSION,
    build_navigator_layer,
    techniques_from_alerts,
    techniques_from_rules,
)
from olympus.apollo.rules import load_rule
from olympus.cli import app
from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert

runner = CliRunner()


def _rule_file(path: Path, rule_id: str, techniques: list[str]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": rule_id,
                "title": f"Rule {rule_id}",
                "event_type": "process.start",
                "conditions": {"image": "x.exe"},
                "severity": "high",
                "mitre_attack": techniques,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_techniques_from_rules_counts_across_rules(tmp_path: Path) -> None:
    r1 = load_rule(_rule_file(tmp_path / "a.yaml", "APL-A", ["T1059.001", "T1078"]))
    r2 = load_rule(_rule_file(tmp_path / "b.yaml", "APL-B", ["T1059.001"]))
    counts = techniques_from_rules([r1, r2])
    assert counts == Counter({"T1059.001": 2, "T1078": 1})


def test_techniques_from_alerts_counts() -> None:
    alert = Alert(
        event_id="EVT-1",
        title="t",
        source=Source.APOLLO,
        severity=Severity.HIGH,
        status=AlertStatus.OPEN,
        mitre_attack=["T1110"],
    )
    assert techniques_from_alerts([alert]) == Counter({"T1110": 1})


def test_build_navigator_layer_shape() -> None:
    layer = build_navigator_layer(Counter({"T1059.001": 3, "T1078": 1}))
    assert layer["versions"]["layer"] == NAVIGATOR_LAYER_VERSION
    assert layer["domain"] == "enterprise-attack"
    assert layer["showSubtechniques"] is True
    assert layer["gradient"]["maxValue"] == 3
    ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert ids == {"T1059.001": 3, "T1078": 1}


def test_empty_layer_has_default_maxvalue() -> None:
    layer = build_navigator_layer(Counter())
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1  # no division-by-zero / empty gradient


def test_cli_attack_layer_writes_owner_only_layer(tmp_path: Path) -> None:
    import stat

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _rule_file(rules_dir / "a.yaml", "APL-A", ["T1059.001"])
    _rule_file(rules_dir / "b.yaml", "APL-B", ["T1059.001", "T1078"])
    output = tmp_path / "layer.json"

    result = runner.invoke(
        app, ["apollo", "attack-layer", "--rules", str(rules_dir), "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    layer = json.loads(output.read_text(encoding="utf-8"))
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1059.001": 2, "T1078": 1}

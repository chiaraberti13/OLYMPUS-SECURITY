"""Detection-coverage trend across an ordered history (ROADMAP ``VAL-3``).

The trend reuses the coverage matrix (:mod:`olympus.apollo.coverage`) over an
ordered series of telemetry snapshots and reports how defensive coverage evolved.
These tests pin the honesty invariants: a reopened blind spot is surfaced (never
averaged away), the metrics carry their definition and the structural-coverage
limit, and the CLI signals regression through the canonical exit code.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.coverage import assess_coverage
from olympus.apollo.coverage_trend import (
    METRIC_LIMIT,
    build_coverage_trend,
)
from olympus.apollo.rules import DetectionRule
from olympus.cli import app
from olympus.core.exit_codes import ExitCode

runner = CliRunner()


def _rule(rule_id: str, event_type: str, *techniques: str) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        title=f"rule {rule_id}",
        event_type=event_type,
        conditions={"k": "v"},
        mitre_attack=list(techniques),
    )


_RULES = [_rule("APL-A", "process", "T1059"), _rule("APL-B", "network", "T1071")]


def _trend_reports() -> list[tuple[str, object]]:
    # both present -> network lost (T1071 blind) -> network back (recovered)
    return [
        ("2026-08", assess_coverage(_RULES, {"process", "network"})),
        ("2026-09", assess_coverage(_RULES, {"process"})),
        ("2026-10", assess_coverage(_RULES, {"process", "network"})),
    ]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_a_reopened_blind_spot_is_surfaced_not_averaged_away() -> None:
    trend = build_coverage_trend(_trend_reports())
    baseline, lost, recovered = trend.points
    assert baseline.is_baseline and baseline.coverage_delta == 0.0
    # Coverage fell from 100% to 50% when the network log source stopped.
    assert baseline.metrics.structural_detection_coverage == 1.0
    assert lost.metrics.structural_detection_coverage == 0.5
    assert lost.newly_blind == ("T1071",)
    assert lost.regressed is True
    assert recovered.newly_covered == ("T1071",)
    # Baseline and latest coverage are both 100%, yet the trend still reports a
    # regression happened in between — a gap is never hidden by the endpoints.
    summary = trend.summary()
    assert summary["baseline_coverage"] == 1.0
    assert summary["latest_coverage"] == 1.0
    assert summary["regressed"] is True


def test_metrics_carry_definitions_and_the_structural_limit() -> None:
    document = build_coverage_trend(_trend_reports()).to_dict()
    assert "structural_detection_coverage" in document["metric_definitions"]
    assert "blind_spot_ratio" in document["metric_definitions"]
    # The epistemic ceiling is explicit: structural coverage is not proven detection.
    assert "PURPLE-1" in document["limit"]
    assert document["limit"] == METRIC_LIMIT


def test_metrics_ratios_are_the_documented_formulas() -> None:
    report = assess_coverage(_RULES, {"process"})  # 1 covered (T1059), 1 blind (T1071)
    (point,) = build_coverage_trend([("only", report)]).points
    m = point.metrics
    assert (m.total_techniques, m.covered, m.no_telemetry) == (2, 1, 1)
    assert m.structural_detection_coverage == 0.5  # covered / total
    assert m.blind_spot_ratio == 0.5  # no_telemetry / total
    assert point.is_baseline is True


def test_trend_is_deterministic() -> None:
    reports = _trend_reports()
    assert build_coverage_trend(reports).to_dict() == build_coverage_trend(reports).to_dict()


def test_empty_history_is_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="at least one snapshot"):
        build_coverage_trend([])


def test_empty_rule_set_yields_zero_ratios_without_dividing_by_zero() -> None:
    # No rules -> no techniques: every ratio is a defined 0.0, never a ZeroDivisionError.
    empty = assess_coverage([], set())
    trend = build_coverage_trend([("t0", empty), ("t1", empty)])
    metrics = trend.points[0].metrics
    assert metrics.total_techniques == 0
    assert metrics.structural_detection_coverage == 0.0
    assert metrics.partial_ratio == 0.0
    assert metrics.blind_spot_ratio == 0.0
    assert trend.regressed is False


def test_no_regression_when_coverage_only_grows() -> None:
    reports = [
        ("t0", assess_coverage(_RULES, {"process"})),  # T1071 blind
        ("t1", assess_coverage(_RULES, {"process", "network"})),  # recovered, grew
    ]
    trend = build_coverage_trend(reports)
    assert trend.points[1].newly_covered == ("T1071",)
    assert trend.regressed is False  # growth is not a regression


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
        "title: process rule\n"
        "event_type: process\n"
        "conditions:\n  k: v\n"
        "severity: high\n"
        "mitre_attack:\n  - T1059\n",
        encoding="utf-8",
    )
    return directory


def _telemetry(path: Path, *event_types: str) -> Path:
    path.write_text(
        "".join(
            json.dumps({"event_type": et, "source": "apollo", "attributes": {}}) + "\n"
            for et in event_types
        ),
        encoding="utf-8",
    )
    return path


def test_cli_strict_exits_findings_on_regression(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    present = _telemetry(tmp_path / "s1.ndjson", "process")  # T1059 covered
    lost = _telemetry(tmp_path / "s2.ndjson", "other")  # process telemetry gone -> blind
    result = runner.invoke(
        app,
        [
            "apollo",
            "coverage-trend",
            "--rules",
            str(rules),
            "--snapshot",
            str(present),
            "--snapshot",
            str(lost),
            "--strict",
        ],
    )
    assert result.exit_code == int(ExitCode.FINDINGS), result.output
    assert "coverage" in result.stdout.lower()


def test_cli_json_emits_trend_document(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    s1 = _telemetry(tmp_path / "s1.ndjson", "process")
    s2 = _telemetry(tmp_path / "s2.ndjson", "process")
    result = runner.invoke(
        app,
        [
            "apollo",
            "coverage-trend",
            "--rules",
            str(rules),
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    out = result.stdout
    document = json.loads(out[out.index("{") : out.rindex("}") + 1])
    assert document["summary"]["snapshots"] == 2
    assert "PURPLE-1" in document["limit"]
    assert len(document["points"]) == 2


def test_cli_needs_at_least_two_snapshots(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    s1 = _telemetry(tmp_path / "s1.ndjson", "process")
    result = runner.invoke(
        app,
        ["apollo", "coverage-trend", "--rules", str(rules), "--snapshot", str(s1)],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "at least two" in result.stderr


def test_cli_reports_a_missing_snapshot_as_usage_error(tmp_path: Path) -> None:
    rules = _rule_dir(tmp_path)
    s1 = _telemetry(tmp_path / "s1.ndjson", "process")
    result = runner.invoke(
        app,
        [
            "apollo",
            "coverage-trend",
            "--rules",
            str(rules),
            "--snapshot",
            str(s1),
            "--snapshot",
            str(tmp_path / "missing.ndjson"),
        ],
    )
    assert result.exit_code == ExitCode.USAGE

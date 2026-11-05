"""Finding-lifecycle engine and ``olympus vulcan lifecycle`` CLI (ROADMAP ``VAL-1``).

The lifecycle engine classifies the latest run's logical findings against the
whole assessment history as new, persistent, reappeared or resolved — matched by
logical identity (same asset + same vulnerability), never by the per-run
``finding_id``. "Reappeared" is derived from history, not a new canonical finding
state. These tests pin that classification, its determinism, and the CLI's
canonical exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.vulcan.lifecycle import classify_lifecycle

runner = CliRunner()


def _finding(
    title: str,
    severity: Severity = Severity.HIGH,
    *,
    asset_id: str = "AST-1",
    finding_id: str | None = None,
) -> Finding:
    kwargs: dict[str, object] = {
        "asset_id": asset_id,
        "source": Source.ARTEMIS,
        "title": title,
        "severity": severity,
    }
    if finding_id is not None:
        kwargs["finding_id"] = finding_id
    return Finding(**kwargs)  # type: ignore[arg-type]


def _bundle(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_three_assessments_classify_new_persistent_reappeared_resolved() -> None:
    # Oldest first: SQLi+XSS -> only XSS (SQLi fixed) -> XSS+SQLi(back)+new OpenPort.
    s0 = ("a0", [_finding("SQLi"), _finding("XSS")])
    s1 = ("a1", [_finding("XSS")])
    s2 = ("a2", [_finding("XSS"), _finding("SQLi"), _finding("OpenPort", asset_id="AST-2")])
    result = classify_lifecycle([s0, s1, s2])

    assert [f.title for f in result.new] == ["OpenPort"]
    assert [p.current.title for p in result.persistent] == ["XSS"]
    assert [x.current.title for x in result.reappeared] == ["SQLi"]
    assert result.reappeared[0].absent_for == 1
    assert [f.title for f in result.resolved] == []
    assert result.has_reappearances is True
    assert result.summary() == {
        "new": 1,
        "persistent": 1,
        "reappeared": 1,
        "resolved": 0,
        "worsened": 0,
    }


def test_identity_ignores_the_per_run_finding_id() -> None:
    # Same asset + title, fresh id each run: one logical issue, so it persists.
    s0 = ("a0", [_finding("XSS", finding_id="FND-1")])
    s1 = ("a1", [_finding("XSS", finding_id="FND-2")])
    result = classify_lifecycle([s0, s1])
    assert [p.current.title for p in result.persistent] == ["XSS"]
    assert not result.new and not result.reappeared and not result.resolved


def test_resolved_is_present_in_previous_but_absent_now() -> None:
    s0 = ("a0", [_finding("XSS"), _finding("SQLi")])
    s1 = ("a1", [_finding("XSS")])
    result = classify_lifecycle([s0, s1])
    assert [f.title for f in result.resolved] == ["SQLi"]
    assert [p.current.title for p in result.persistent] == ["XSS"]
    assert not result.new and not result.reappeared


def test_single_snapshot_is_all_new() -> None:
    result = classify_lifecycle([("only", [_finding("XSS"), _finding("SQLi")])])
    assert {f.title for f in result.new} == {"XSS", "SQLi"}
    assert not result.persistent and not result.reappeared and not result.resolved


def test_a_finding_absent_only_in_the_previous_run_is_reappeared_not_new() -> None:
    # Seen at index 0, gone at 1 and 2, back at 3: absent for two snapshots.
    s0 = ("a0", [_finding("SQLi")])
    s1 = ("a1", [_finding("XSS")])
    s2 = ("a2", [_finding("XSS")])
    s3 = ("a3", [_finding("SQLi")])
    result = classify_lifecycle([s0, s1, s2, s3])
    assert [x.current.title for x in result.reappeared] == ["SQLi"]
    assert result.reappeared[0].absent_for == 2
    assert not result.new


def test_reappeared_carries_severity_delta_from_when_last_seen() -> None:
    s0 = ("a0", [_finding("SQLi", Severity.LOW)])
    s1 = ("a1", [_finding("XSS")])
    s2 = ("a2", [_finding("SQLi", Severity.CRITICAL)])
    result = classify_lifecycle([s0, s1, s2])
    (back,) = result.reappeared
    assert back.severity_changed is True
    assert back.severity_worsened is True
    assert back.risk_delta > 0
    assert result.summary()["worsened"] == 1


def test_classification_is_deterministic_and_risk_ordered() -> None:
    s0 = ("a0", [_finding("A")])
    s1 = (
        "a1",
        [
            _finding("low new", Severity.LOW, asset_id="AST-9"),
            _finding("crit new", Severity.CRITICAL, asset_id="AST-8"),
        ],
    )
    result = classify_lifecycle([s0, s1])
    # Ordered by descending risk: the critical one first.
    assert [f.title for f in result.new] == ["crit new", "low new"]
    # Repeated runs give byte-identical projections.
    assert classify_lifecycle([s0, s1]).to_dict() == result.to_dict()


def test_empty_history_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one snapshot"):
        classify_lifecycle([])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_lifecycle_exits_1_on_new_or_reappeared(tmp_path: Path) -> None:
    s0 = _bundle(tmp_path / "s0.json", [_finding("SQLi"), _finding("XSS")])
    s1 = _bundle(tmp_path / "s1.json", [_finding("XSS")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("XSS"), _finding("SQLi")])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "lifecycle",
            "--snapshot",
            str(s0),
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
        ],
    )
    assert result.exit_code == ExitCode.FINDINGS
    assert "1 reappeared" in result.stderr


def test_cli_lifecycle_exits_0_when_stable(tmp_path: Path) -> None:
    s0 = _bundle(tmp_path / "s0.json", [_finding("XSS"), _finding("SQLi")])
    s1 = _bundle(tmp_path / "s1.json", [_finding("XSS")])
    result = runner.invoke(
        app, ["vulcan", "lifecycle", "--snapshot", str(s0), "--snapshot", str(s1)]
    )
    assert result.exit_code == ExitCode.OK
    assert "0 new, 0 reappeared" in result.stderr


def test_cli_lifecycle_json_output(tmp_path: Path) -> None:
    s0 = _bundle(tmp_path / "s0.json", [_finding("SQLi")])
    s1 = _bundle(tmp_path / "s1.json", [_finding("XSS")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi")])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "lifecycle",
            "--snapshot",
            str(s0),
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.FINDINGS
    payload = json.loads(result.stdout)
    assert payload["summary"]["reappeared"] == 1
    assert payload["reappeared"][0]["absent_for"] == 1


def test_cli_lifecycle_single_snapshot_is_all_new(tmp_path: Path) -> None:
    s0 = _bundle(tmp_path / "s0.json", [_finding("XSS")])
    result = runner.invoke(app, ["vulcan", "lifecycle", "--snapshot", str(s0)])
    assert result.exit_code == ExitCode.FINDINGS
    assert "1 new" in result.stderr


def test_cli_lifecycle_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["vulcan", "lifecycle", "--snapshot", str(bad)])
    assert result.exit_code == ExitCode.USAGE

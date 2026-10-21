"""Scan-diff engine and ``olympus vulcan diff`` CLI (ROADMAP ``WEB-I``).

The diff classifies logical findings across two runs as new, resolved or
persistent, matched by logical identity (same asset + same vulnerability), never
by the per-run ``finding_id``. These tests pin that classification, its
determinism, and the CLI's canonical exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.vulcan.compare import diff_findings

runner = CliRunner()


def _finding(
    title: str,
    severity: Severity = Severity.HIGH,
    *,
    asset_id: str = "AST-1",
    finding_id: str | None = None,
    cve: list[str] | None = None,
) -> Finding:
    kwargs: dict[str, object] = {
        "asset_id": asset_id,
        "source": Source.ARTEMIS,
        "title": title,
        "severity": severity,
    }
    if finding_id is not None:
        kwargs["finding_id"] = finding_id
    if cve is not None:
        kwargs["cve"] = cve
    return Finding(**kwargs)  # type: ignore[arg-type]


def test_new_resolved_and_persistent_are_classified() -> None:
    baseline = [_finding("XSS"), _finding("SQLi", Severity.CRITICAL)]
    current = [_finding("XSS"), _finding("Open redirect", asset_id="AST-2")]
    diff = diff_findings(baseline, current)
    assert [f.title for f in diff.new] == ["Open redirect"]
    assert [f.title for f in diff.resolved] == ["SQLi"]
    assert [p.current.title for p in diff.persistent] == ["XSS"]
    assert diff.summary() == {"new": 1, "resolved": 1, "persistent": 1, "worsened": 0}
    assert diff.has_regressions is True


def test_identity_ignores_the_per_run_finding_id() -> None:
    # Same asset + same title, but a fresh id each run: still one logical issue.
    baseline = [_finding("XSS", finding_id="FND-2026-00001")]
    current = [_finding("XSS", finding_id="FND-2026-99999")]
    diff = diff_findings(baseline, current)
    assert not diff.new
    assert not diff.resolved
    assert len(diff.persistent) == 1


def test_identity_matches_on_shared_cve_across_titles() -> None:
    baseline = [_finding("Outdated nginx", cve=["CVE-2024-0001"])]
    current = [_finding("nginx RCE", cve=["CVE-2024-0001"])]
    diff = diff_findings(baseline, current)
    assert not diff.new and not diff.resolved
    assert len(diff.persistent) == 1


def test_persistent_detects_a_worsened_severity() -> None:
    diff = diff_findings([_finding("XSS", Severity.LOW)], [_finding("XSS", Severity.CRITICAL)])
    (persistent,) = diff.persistent
    assert persistent.severity_changed is True
    assert persistent.severity_worsened is True
    assert persistent.risk_delta > 0
    assert diff.summary()["worsened"] == 1


def test_an_identical_run_has_no_changes() -> None:
    findings = [_finding("XSS"), _finding("SQLi", Severity.CRITICAL)]
    diff = diff_findings(findings, findings)
    assert not diff.new and not diff.resolved
    assert len(diff.persistent) == 2
    assert diff.has_regressions is False


def test_diff_is_deterministic_and_ranked_by_risk() -> None:
    current = [
        _finding("low", Severity.LOW, asset_id="AST-9"),
        _finding("crit", Severity.CRITICAL, asset_id="AST-8"),
    ]
    diff = diff_findings([], current)
    assert [f.title for f in diff.new] == ["crit", "low"]  # critical first


def _bundle(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


def test_cli_diff_exits_1_when_there_are_new_findings(tmp_path: Path) -> None:
    base = _bundle(tmp_path / "base.json", [_finding("XSS")])
    current = _bundle(tmp_path / "cur.json", [_finding("XSS"), _finding("New one", asset_id="A2")])
    result = runner.invoke(
        app, ["vulcan", "diff", "--baseline", str(base), "--current", str(current)]
    )
    assert result.exit_code == ExitCode.FINDINGS
    assert "New one" in result.stdout
    assert "1 new" in result.stderr


def test_cli_diff_exits_0_when_nothing_is_new(tmp_path: Path) -> None:
    base = _bundle(tmp_path / "base.json", [_finding("XSS"), _finding("SQLi")])
    current = _bundle(tmp_path / "cur.json", [_finding("XSS")])
    result = runner.invoke(
        app, ["vulcan", "diff", "--baseline", str(base), "--current", str(current)]
    )
    assert result.exit_code == ExitCode.OK
    assert "0 new" in result.stderr


def test_cli_diff_json_output(tmp_path: Path) -> None:
    base = _bundle(tmp_path / "base.json", [_finding("XSS", Severity.LOW)])
    current = _bundle(tmp_path / "cur.json", [_finding("XSS", Severity.CRITICAL)])
    result = runner.invoke(
        app,
        ["vulcan", "diff", "--baseline", str(base), "--current", str(current), "--format", "json"],
    )
    assert result.exit_code == ExitCode.OK
    payload = json.loads(result.stdout)
    assert payload["summary"] == {"new": 0, "resolved": 0, "persistent": 1, "worsened": 1}
    assert payload["persistent"][0]["severity_worsened"] is True


def test_cli_diff_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    base = _bundle(tmp_path / "base.json", [_finding("XSS")])
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["vulcan", "diff", "--baseline", str(base), "--current", str(bad)])
    assert result.exit_code == ExitCode.USAGE

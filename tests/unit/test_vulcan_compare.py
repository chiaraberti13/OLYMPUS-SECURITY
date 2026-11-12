"""Scan-diff engine and ``olympus vulcan diff`` CLI (ROADMAP ``WEB-I``).

The diff classifies logical findings across two runs as new, resolved or
persistent, matched by logical identity (same asset + same vulnerability), never
by the per-run ``finding_id``. These tests pin that classification, its
determinism, and the CLI's canonical exit codes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import AssetType, Criticality, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Asset, Finding
from olympus.vulcan.compare import diff_assets, diff_findings
from olympus.vulcan.trend import build_finding_trend

runner = CliRunner()

_WHEN = datetime(2026, 1, 1, tzinfo=UTC)


def _asset(
    asset_id: str,
    *,
    ips: list[str] | None = None,
    criticality: Criticality = Criticality.MEDIUM,
    hostname: str | None = None,
    asset_type: AssetType = AssetType.HOST,
) -> Asset:
    return Asset(
        asset_id=asset_id,
        asset_type=asset_type,
        hostname=hostname,
        ip_addresses=ips or [],
        criticality=criticality,
        source=Source.ARGUS,
        first_seen=_WHEN,
        last_seen=_WHEN,
    )


def _asset_bundle(path: Path, assets: list[Asset]) -> Path:
    path.write_text(json.dumps([json.loads(a.model_dump_json()) for a in assets]), encoding="utf-8")
    return path


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


# ---------------------------------------------------------------------------
# Finding severity trend across runs (ROADMAP WEB-I)
# ---------------------------------------------------------------------------


def test_trend_tracks_counts_and_step_deltas() -> None:
    s1 = [_finding("XSS"), _finding("SQLi", Severity.CRITICAL)]
    s2 = [_finding("XSS", Severity.CRITICAL), _finding("Open redirect", asset_id="AST-2")]
    s3 = [_finding("Open redirect", asset_id="AST-2")]
    trend = build_finding_trend([("aug", s1), ("sep", s2), ("oct", s3)])
    labels = [p.label for p in trend.points]
    assert labels == ["aug", "sep", "oct"]
    # First point is a baseline with no deltas.
    assert trend.points[0].is_baseline and trend.points[0].new == 0
    # sep: SQLi resolved, Open redirect new, XSS persists.
    assert (trend.points[1].new, trend.points[1].resolved, trend.points[1].persistent) == (1, 1, 1)
    # oct: XSS resolved, nothing new.
    assert (trend.points[2].new, trend.points[2].resolved) == (0, 1)
    assert trend.points[2].total == 1


def test_trend_regressed_reflects_the_last_step() -> None:
    worse = build_finding_trend(
        [("base", [_finding("XSS")]), ("now", [_finding("XSS"), _finding("New", asset_id="A2")])]
    )
    assert worse.regressed is True
    better = build_finding_trend(
        [("base", [_finding("XSS"), _finding("Gone", asset_id="A2")]), ("now", [_finding("XSS")])]
    )
    assert better.regressed is False


def test_trend_severity_breakdown_has_every_level() -> None:
    trend = build_finding_trend([("a", [_finding("x", Severity.LOW)]), ("b", [])])
    assert set(trend.points[0].severity_breakdown) == {"critical", "high", "medium", "low", "info"}
    assert trend.points[0].severity_breakdown["low"] == 1


def test_cli_trend_needs_at_least_two_snapshots(tmp_path: Path) -> None:
    one = _bundle(tmp_path / "one.json", [_finding("XSS")])
    result = runner.invoke(app, ["vulcan", "trend", "--snapshot", str(one)])
    assert result.exit_code == ExitCode.USAGE


def test_cli_trend_exit_codes_and_json(tmp_path: Path) -> None:
    base = _bundle(tmp_path / "base.json", [_finding("XSS")])
    regressed = _bundle(tmp_path / "now.json", [_finding("XSS"), _finding("New", asset_id="A2")])
    table = runner.invoke(
        app, ["vulcan", "trend", "--snapshot", str(base), "--snapshot", str(regressed)]
    )
    assert table.exit_code == ExitCode.FINDINGS
    payload = runner.invoke(
        app,
        [
            "vulcan",
            "trend",
            "--snapshot",
            str(base),
            "--snapshot",
            str(regressed),
            "--format",
            "json",
        ],
    )
    assert payload.exit_code == ExitCode.FINDINGS
    data = json.loads(payload.stdout)
    assert [p["label"] for p in data["points"]] == ["base", "now"]
    assert data["points"][1]["new"] == 1


# ---------------------------------------------------------------------------
# Attack-surface (asset) diff — VAL-1
# ---------------------------------------------------------------------------


def test_diff_assets_classifies_new_removed_and_persistent() -> None:
    baseline = [_asset("AST-1", ips=["10.0.0.1"]), _asset("AST-9", ips=["10.0.0.9"])]
    current = [
        _asset("AST-1", ips=["10.0.0.1", "10.0.0.2"]),  # reachable surface grew
        _asset("AST-2", ips=["10.0.0.3"]),  # brand-new asset
    ]
    diff = diff_assets(baseline, current)
    assert [a.asset_id for a in diff.new] == ["AST-2"]
    assert [a.asset_id for a in diff.removed] == ["AST-9"]
    assert [p.current.asset_id for p in diff.persistent] == ["AST-1"]
    assert diff.persistent[0].attack_surface_changed is True
    assert diff.persistent[0].criticality_changed is False
    assert diff.surface_expanded is True
    assert diff.summary() == {"new": 1, "removed": 1, "persistent": 1, "surface_changed": 1}


def test_diff_assets_detects_a_criticality_change_without_surface_change() -> None:
    diff = diff_assets(
        [_asset("AST-1", ips=["10.0.0.1"], criticality=Criticality.LOW)],
        [_asset("AST-1", ips=["10.0.0.1"], criticality=Criticality.HIGH)],
    )
    assert diff.new == () and diff.removed == ()
    only = diff.persistent[0]
    assert only.criticality_changed is True
    assert only.attack_surface_changed is False
    assert diff.surface_expanded is False


def test_diff_assets_is_deterministic_and_matches_on_identity() -> None:
    # Same asset id seen twice (duplicate) counts once; order is stable by id.
    baseline = [_asset("AST-2"), _asset("AST-1")]
    current = [_asset("AST-1"), _asset("AST-1"), _asset("AST-2")]
    diff = diff_assets(baseline, current)
    assert diff.new == () and diff.removed == ()
    assert [p.current.asset_id for p in diff.persistent] == ["AST-1", "AST-2"]


def test_cli_asset_diff_exits_1_when_the_surface_expands(tmp_path: Path) -> None:
    base = _asset_bundle(tmp_path / "base.json", [_asset("AST-1", ips=["10.0.0.1"])])
    grown = _asset_bundle(
        tmp_path / "now.json",
        [_asset("AST-1", ips=["10.0.0.1"]), _asset("AST-2", ips=["10.0.0.2"])],
    )
    result = runner.invoke(
        app, ["vulcan", "asset-diff", "--baseline", str(base), "--current", str(grown)]
    )
    assert result.exit_code == ExitCode.FINDINGS
    assert "1 new" in result.stderr


def test_cli_asset_diff_json_and_zero_exit_when_stable(tmp_path: Path) -> None:
    snapshot = _asset_bundle(tmp_path / "s.json", [_asset("AST-1", ips=["10.0.0.1"])])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "asset-diff",
            "--baseline",
            str(snapshot),
            "--current",
            str(snapshot),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.stdout)
    assert payload["summary"] == {"new": 0, "removed": 0, "persistent": 1, "surface_changed": 0}


def test_cli_asset_diff_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    good = _asset_bundle(tmp_path / "g.json", [_asset("AST-1")])
    result = runner.invoke(
        app, ["vulcan", "asset-diff", "--baseline", str(bad), "--current", str(good)]
    )
    assert result.exit_code == ExitCode.USAGE

"""Comparative Vulcan report engine and CLI (ROADMAP ``VAL-1``).

The comparative report combines the finding lifecycle over a whole assessment
history (new / persistent / reappeared / resolved) with the optional
attack-surface diff between a baseline and a current asset snapshot, into one
offline, deterministic, injection-safe document. These tests pin the
classification, the regression verdict, determinism, the reuse of the shared
projections (no duplicated logic), Markdown injection safety, and the CLI's
canonical exit codes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import AssetType, Confidence, Criticality, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Asset, Finding
from olympus.vulcan.comparative import (
    SCHEMA_NAME,
    SCHEMA_VERSION,
    build_comparative_report,
)
from olympus.vulcan.compare import diff_assets
from olympus.vulcan.lifecycle import classify_lifecycle

runner = CliRunner()

_WHEN = datetime(2026, 1, 1, tzinfo=UTC)
_FIXED = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _finding(
    title: str,
    severity: Severity = Severity.HIGH,
    *,
    asset_id: str = "AST-1",
) -> Finding:
    return Finding(
        asset_id=asset_id,
        source=Source.ARTEMIS,
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
    )


def _asset(
    asset_id: str,
    *,
    ips: list[str] | None = None,
    criticality: Criticality = Criticality.MEDIUM,
    hostname: str | None = None,
) -> Asset:
    return Asset(
        asset_id=asset_id,
        asset_type=AssetType.HOST,
        hostname=hostname,
        ip_addresses=ips or [],
        criticality=criticality,
        source=Source.ARGUS,
        first_seen=_WHEN,
        last_seen=_WHEN,
    )


def _bundle(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


def _asset_bundle(path: Path, assets: list[Asset]) -> Path:
    path.write_text(json.dumps([json.loads(a.model_dump_json()) for a in assets]), encoding="utf-8")
    return path


def _history() -> list[tuple[str, list[Finding]]]:
    # Oldest first: SQLi+XSS -> only SQLi (XSS fixed) -> SQLi+XSS(back)+RCE(new).
    return [
        ("run1", [_finding("SQLi"), _finding("XSS", asset_id="AST-2")]),
        ("run2", [_finding("SQLi")]),
        (
            "run3",
            [
                _finding("SQLi"),
                _finding("XSS", asset_id="AST-2"),
                _finding("RCE", asset_id="AST-3"),
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_report_classifies_history_as_new_persistent_reappeared_resolved() -> None:
    report = build_comparative_report(snapshots=_history(), generated_at=_FIXED)
    summary = report.summary()
    assert summary["findings"] == {
        "new": 1,
        "persistent": 1,
        "reappeared": 1,
        "resolved": 0,
        "worsened": 0,
    }
    assert report.has_regression is True  # a new (RCE) and a reappeared (XSS) finding
    titles = {"new": [f.title for f in report.lifecycle.new]}
    assert titles["new"] == ["RCE"]
    assert [item.current.title for item in report.lifecycle.reappeared] == ["XSS"]
    assert [item.current.title for item in report.lifecycle.persistent] == ["SQLi"]


def test_report_has_no_regression_when_latest_only_resolves() -> None:
    history = [
        ("run1", [_finding("SQLi"), _finding("XSS", asset_id="AST-2")]),
        ("run2", [_finding("SQLi")]),
    ]
    report = build_comparative_report(snapshots=history, generated_at=_FIXED)
    assert report.lifecycle.summary() == {
        "new": 0,
        "persistent": 1,
        "reappeared": 0,
        "resolved": 1,
        "worsened": 0,
    }
    assert report.has_regression is False


def test_attack_surface_included_only_when_both_snapshots_given() -> None:
    base = [_asset("AST-1")]
    grown = [_asset("AST-1"), _asset("AST-2")]
    with_assets = build_comparative_report(
        snapshots=_history(), asset_baseline=base, asset_current=grown, generated_at=_FIXED
    )
    assert with_assets.asset_diff is not None
    assert with_assets.asset_diff.summary()["new"] == 1
    assert "attack_surface" in with_assets.summary()

    without = build_comparative_report(snapshots=_history(), generated_at=_FIXED)
    assert without.asset_diff is None
    assert "attack_surface" not in without.summary()


def test_grown_attack_surface_is_a_regression_even_without_new_findings() -> None:
    stable = [
        ("run1", [_finding("SQLi")]),
        ("run2", [_finding("SQLi")]),
    ]
    report = build_comparative_report(
        snapshots=stable,
        asset_baseline=[_asset("AST-1")],
        asset_current=[_asset("AST-1"), _asset("AST-2")],
        generated_at=_FIXED,
    )
    assert report.has_regression is True  # findings stable, but the surface grew


def test_only_one_asset_snapshot_is_a_usage_error() -> None:
    with pytest.raises(ValueError, match="baseline and a current asset snapshot"):
        build_comparative_report(
            snapshots=_history(), asset_baseline=[_asset("AST-1")], generated_at=_FIXED
        )


def test_report_requires_at_least_two_snapshots() -> None:
    with pytest.raises(ValueError, match="at least two finding snapshots"):
        build_comparative_report(snapshots=[("only", [_finding("SQLi")])], generated_at=_FIXED)


def test_to_dict_is_versioned_and_reuses_the_shared_projections() -> None:
    base = [_asset("AST-1")]
    grown = [_asset("AST-1"), _asset("AST-2")]
    history = _history()  # one instance: finding ids are minted fresh per call
    report = build_comparative_report(
        snapshots=history,
        asset_baseline=base,
        asset_current=grown,
        engagement="ACME",
        generated_at=_FIXED,
    )
    document = report.to_dict()
    assert document["schema_name"] == SCHEMA_NAME
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["report_type"] == "comparative"
    assert document["engagement"] == "ACME"
    assert document["generated_at"] == _FIXED.isoformat()
    assert document["baseline_label"] == "run1"
    assert document["latest_label"] == "run3"
    # The embedded sections are byte-for-byte the shared projections — no
    # duplicated classification logic lives in the comparative report.
    assert document["findings"] == classify_lifecycle(history).to_dict()
    assert document["attack_surface"] == diff_assets(base, grown).to_dict()


def test_report_is_deterministic_for_fixed_inputs() -> None:
    history = _history()  # same inputs for both runs
    first = build_comparative_report(snapshots=history, generated_at=_FIXED)
    second = build_comparative_report(snapshots=history, generated_at=_FIXED)
    assert first.to_dict() == second.to_dict()
    assert first.render_markdown() == second.render_markdown()


def test_markdown_renders_each_lifecycle_section() -> None:
    report = build_comparative_report(
        snapshots=_history(),
        asset_baseline=[_asset("AST-1")],
        asset_current=[_asset("AST-1"), _asset("AST-2")],
        generated_at=_FIXED,
    )
    markdown = report.render_markdown()
    assert "# Comparative security report" in markdown
    assert "## Findings lifecycle" in markdown
    assert "### New (never seen before)" in markdown
    assert "### Reappeared (fixed earlier, open again)" in markdown
    assert "## Attack surface" in markdown
    assert "Regression since previous assessment: **yes**" in markdown
    assert "absent for 1 run(s)" in markdown


def test_markdown_neutralises_hostile_finding_titles() -> None:
    # A target-controlled title cannot forge Markdown structure or a clickable link.
    hostile = "# pwned [x](http://evil.test) `code` \x1b[31m"
    history = [
        ("run1", [_finding("SQLi")]),
        ("run2", [_finding("SQLi"), _finding(hostile, asset_id="AST-9")]),
    ]
    markdown = build_comparative_report(snapshots=history, generated_at=_FIXED).render_markdown()
    # The raw escape byte never reaches the rendered report.
    assert "\x1b" not in markdown
    # The Markdown link syntax is escaped (the bracket is backslash-escaped), so
    # it renders as visible text, not navigation.
    assert "[x](http://evil.test)" not in markdown
    assert "\\[x\\]" in markdown
    # A bare URL is defused so CommonMark/GFM will not autolink it.
    assert "http://evil.test" not in markdown
    assert "http&#58;//evil.test" in markdown


def test_markdown_marks_a_worsened_persistent_finding() -> None:
    history = [
        ("run1", [_finding("SQLi", Severity.LOW)]),
        ("run2", [_finding("SQLi", Severity.CRITICAL)]),
    ]
    report = build_comparative_report(snapshots=history, generated_at=_FIXED)
    assert report.lifecycle.summary()["worsened"] == 1
    assert "**(worsened)**" in report.render_markdown()


def test_markdown_marks_a_reappeared_finding_that_returned_worse() -> None:
    # XSS fixed at LOW, then back at CRITICAL: a reappearance that worsened.
    history = [
        ("run1", [_finding("XSS", Severity.LOW, asset_id="AST-2")]),
        ("run2", [_finding("SQLi")]),
        ("run3", [_finding("XSS", Severity.CRITICAL, asset_id="AST-2")]),
    ]
    report = build_comparative_report(snapshots=history, generated_at=_FIXED)
    assert [item.severity_worsened for item in report.lifecycle.reappeared] == [True]
    markdown = report.render_markdown()
    assert "absent for 1 run(s), **worsened**" in markdown


def test_markdown_renders_empty_sections_as_honest_absence() -> None:
    # No reappeared findings, and an asset diff whose snapshots share no asset
    # (so no persistent asset) — the empty sections must render "_None._", never
    # a blank that reads like "nothing to see".
    history = [
        ("run1", [_finding("SQLi")]),
        ("run2", [_finding("SQLi")]),
    ]
    report = build_comparative_report(
        snapshots=history,
        asset_baseline=[_asset("AST-1")],
        asset_current=[_asset("AST-2")],
        generated_at=_FIXED,
    )
    markdown = report.render_markdown()
    assert "### Reappeared (fixed earlier, open again)\n\n_None._" in markdown
    assert "### Persistent assets\n\n_None._" in markdown


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_markdown_report_exits_findings_on_regression(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi"), _finding("RCE", asset_id="AST-2")])
    result = runner.invoke(
        app,
        ["vulcan", "comparative-report", "--snapshot", str(s1), "--snapshot", str(s2)],
    )
    assert result.exit_code == ExitCode.FINDINGS
    assert "# Comparative security report" in result.stdout
    assert "### New (never seen before)" in result.stdout


def test_cli_json_report_emits_versioned_document(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi")])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "comparative-report",
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == ExitCode.OK  # no regression: only persistent
    payload = json.loads(result.stdout)
    assert payload["schema_name"] == SCHEMA_NAME
    assert payload["summary"]["regression"] is False


def test_cli_writes_report_to_output_file(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi"), _finding("RCE", asset_id="AST-2")])
    out = tmp_path / "comparative.md"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "comparative-report",
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == ExitCode.FINDINGS
    assert out.read_text(encoding="utf-8").startswith("# Comparative security report")


def test_cli_with_asset_snapshots(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi")])
    base = _asset_bundle(tmp_path / "ab.json", [_asset("AST-1", ips=["10.0.0.1"])])
    cur = _asset_bundle(
        tmp_path / "ac.json",
        [_asset("AST-1", ips=["10.0.0.1"]), _asset("AST-2", ips=["10.0.0.2"])],
    )
    result = runner.invoke(
        app,
        [
            "vulcan",
            "comparative-report",
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--asset-baseline",
            str(base),
            "--asset-current",
            str(cur),
        ],
    )
    # Findings are stable but the attack surface grew — that is a regression.
    assert result.exit_code == ExitCode.FINDINGS
    assert "## Attack surface" in result.stdout


def test_cli_needs_two_snapshots(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    result = runner.invoke(app, ["vulcan", "comparative-report", "--snapshot", str(s1)])
    assert result.exit_code == ExitCode.USAGE
    assert "at least two" in result.stderr


def test_cli_asset_baseline_without_current_is_usage_error(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi")])
    base = _asset_bundle(tmp_path / "ab.json", [_asset("AST-1")])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "comparative-report",
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--asset-baseline",
            str(base),
        ],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "both --asset-baseline and --asset-current" in result.stderr


def test_cli_rejects_unknown_format(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    s2 = _bundle(tmp_path / "s2.json", [_finding("SQLi")])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "comparative-report",
            "--snapshot",
            str(s1),
            "--snapshot",
            str(s2),
            "--format",
            "pdf",
        ],
    )
    assert result.exit_code == ExitCode.USAGE
    assert "must be 'markdown' or 'json'" in result.stderr


def test_cli_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    s1 = _bundle(tmp_path / "s1.json", [_finding("SQLi")])
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app,
        ["vulcan", "comparative-report", "--snapshot", str(s1), "--snapshot", str(bad)],
    )
    assert result.exit_code == ExitCode.USAGE

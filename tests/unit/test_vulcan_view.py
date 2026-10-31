"""Unit tests for the interface-agnostic finding view and its CLI (WEB-C)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Confidence, FindingStatus, Severity, Source
from olympus.core.models import Finding
from olympus.vulcan.view import ABSENT, LIST_COLUMNS, FindingView, finding_views, rank_by_risk

runner = CliRunner()


def _rich(asset: str = "AST-1") -> Finding:
    return Finding(
        finding_id="FND-RICH",
        asset_id=asset,
        source=Source.THEMIS,
        title="Log4Shell",
        description="Remote code execution via JNDI lookup.",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        cwe=["CWE-502"],
        epss=0.97,
        epss_percentile=0.99,
        kev=True,
        confidence=Confidence.HIGH,
        evidence=["cmd: curl ..."],
        remediation="Upgrade log4j to 2.17.1.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        tags=["web", "urgent"],
        engagement_id="ENG-2026-00001",
    )


def _sparse() -> Finding:
    # A finding that carries none of the optional intelligence.
    return Finding(
        finding_id="FND-SPARSE",
        asset_id="AST-2",
        source=Source.HELIOS,
        title="Open port 22",
        severity=Severity.LOW,
        status=FindingStatus.NEW,
    )


def _write(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


def test_row_covers_list_columns() -> None:
    row = FindingView(_rich()).row()
    assert set(row) == set(LIST_COLUMNS)
    assert row["severity"] == "critical"
    assert row["status"] == "confirmed"
    assert row["cve"] == "CVE-2021-44228"
    assert row["kev"] == "yes"
    assert row["risk"] == "100"  # KEV + CVSS 10 -> capped at 100, formatted with %g


def test_sparse_row_marks_absent_data() -> None:
    row = FindingView(_sparse()).row()
    assert row["cve"] == ABSENT
    assert row["kev"] == ABSENT  # absent, not a misleading "no"


def test_detail_keeps_machine_types_and_absence() -> None:
    detail = FindingView(_rich()).detail()
    assert detail["cvss"] == 10.0
    assert detail["kev"] is True
    assert detail["cve"] == ["CVE-2021-44228"]
    assert detail["confidence"] == "high"
    assert detail["risk_score"] == 100.0

    sparse = FindingView(_sparse()).detail()
    # Absent scalars stay None (not 0/""), so a consumer can tell them apart.
    assert sparse["cvss"] is None
    assert sparse["epss"] is None
    assert sparse["confidence"] is None
    assert sparse["remediation"] is None
    assert sparse["cve"] == []
    assert sparse["kev"] is False


def test_display_items_render_absent_as_placeholder() -> None:
    items = dict(FindingView(_sparse()).display_items())
    assert items["CVSS"] == ABSENT
    assert items["EPSS"] == ABSENT
    assert items["CVE"] == ABSENT
    assert items["Remediation"] == ABSENT
    assert items["CISA KEV"] == ABSENT
    # The source doubles as the provenance/scanner column.
    assert items["Source"] == "helios"

    rich = dict(FindingView(_rich()).display_items())
    assert rich["CVE"] == "CVE-2021-44228"
    assert rich["CWE"] == "CWE-502"
    assert rich["CISA KEV"] == "yes"
    assert rich["Confidence"] == "high"
    assert rich["Risk"] == "100/100"


def test_rank_by_risk_is_descending_and_stable() -> None:
    findings = [_sparse(), _rich()]
    ranked = rank_by_risk(findings)
    assert [f.finding_id for f in ranked] == ["FND-RICH", "FND-SPARSE"]
    # finding_views preserves the order it is given.
    assert [v.finding.finding_id for v in finding_views(ranked)] == ["FND-RICH", "FND-SPARSE"]


def test_cli_list_table_orders_by_risk(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_sparse(), _rich()])
    result = runner.invoke(app, ["vulcan", "findings", "list", "--findings", str(source)])
    assert result.exit_code == 0, result.output
    # Highest-risk finding appears before the low one in the rendered table.
    assert result.stdout.index("Log4Shell") < result.stdout.index("Open port 22")
    assert "2 finding(s) matched of 2 loaded" in result.output


def test_cli_list_json_filter_kev_only(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_sparse(), _rich()])
    result = runner.invoke(
        app,
        ["vulcan", "findings", "list", "--findings", str(source), "--kev-only", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [row["finding_id"] for row in payload] == ["FND-RICH"]
    assert payload[0]["kev"] is True


def test_cli_list_filter_min_severity(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_sparse(), _rich()])
    result = runner.invoke(
        app,
        [
            "vulcan",
            "findings",
            "list",
            "--findings",
            str(source),
            "--min-severity",
            "high",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert [row["finding_id"] for row in json.loads(result.stdout)] == ["FND-RICH"]


def test_cli_show_renders_all_columns(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_sparse(), _rich()])
    result = runner.invoke(
        app, ["vulcan", "findings", "show", "FND-RICH", "--findings", str(source)]
    )
    assert result.exit_code == 0, result.output
    for label in ("Severity", "CVE", "CWE", "CISA KEV", "Remediation", "First seen"):
        assert label in result.stdout
    assert "CVE-2021-44228" in result.stdout


def test_cli_show_json(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_rich()])
    result = runner.invoke(
        app,
        ["vulcan", "findings", "show", "FND-RICH", "--findings", str(source), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["finding_id"] == "FND-RICH"


def test_cli_show_missing_id_fails_cleanly(tmp_path: Path) -> None:
    source = _write(tmp_path / "f.json", [_rich()])
    result = runner.invoke(
        app, ["vulcan", "findings", "show", "FND-NOPE", "--findings", str(source)]
    )
    assert result.exit_code != 0
    assert "no finding with id" in result.output

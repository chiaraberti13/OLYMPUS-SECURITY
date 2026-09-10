"""Offline contract, routing, case and CLI tests for METIS."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.metis.cases import CaseStore, export_report, extract_indicators
from olympus.metis.catalog import CAPABILITIES, recommend
from olympus.metis.models import IndicatorType, OperatingMode
from olympus.metis.planner import build_plan

runner = CliRunner()


def test_catalog_is_unique_and_router_is_explainable() -> None:
    identifiers = [item.capability_id for item in CAPABILITIES]
    assert len(identifiers) == len(set(identifiers))
    results = recommend("correlate IOC malware campaign threat intelligence")
    assert results[0].capability.capability_id == "threat-intelligence"
    assert "ioc" in results[0].matched_terms
    assert all(item.score > 0 for item in results)


def test_router_advisory_filter_and_fallback() -> None:
    assert all(
        item.capability.mode is not OperatingMode.ACTIVE
        for item in recommend("web vulnerability scan", include_active=False)
    )
    assert recommend("unmatched frobnicator")[0].capability.capability_id == "engagement-planning"
    with pytest.raises(ValueError, match="must not be empty"):
        recommend(" ")


def test_plan_never_hides_authorization_gate() -> None:
    plan = build_plan("scan web API vulnerabilities", include_active=True)
    active = [step for step in plan.steps if step.mode is OperatingMode.ACTIVE]
    assert active and all(step.status == "authorization-required" for step in active)
    authorized = build_plan(
        "scan web API vulnerabilities",
        include_active=True,
        scope=("https://lab.example",),
        authorization_confirmed=True,
    )
    assert all(step.status == "ready" for step in authorized.steps)


def test_indicator_extraction_normalizes_and_deduplicates() -> None:
    text = """
    Contact SOC@example[.]COM about hxxps://portal.example[.]com/a?x=1.
    Seen 192.0.2.10 twice: 192.0.2.10 and CVE-2026-12345.
    SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    """
    indicators = extract_indicators(text, source="fixture", confidence=75)
    pairs = {(item.indicator_type, item.value) for item in indicators}
    assert (IndicatorType.EMAIL, "SOC@example.com") in pairs
    assert (IndicatorType.DOMAIN, "portal.example.com") in pairs
    assert (IndicatorType.IPV4, "192.0.2.10") in pairs
    assert (IndicatorType.CVE, "CVE-2026-12345") in pairs
    assert len([item for item in indicators if item.value == "192.0.2.10"]) == 1


def test_case_store_ingest_findings_correlations_and_private_report(tmp_path: Path) -> None:
    database = tmp_path / "private" / "cases.sqlite3"
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("alpha.example CVE-2026-12345 192.0.2.10", encoding="utf-8")
    with CaseStore(database) as store:
        case_id = store.create_case("Synthetic CTI case")
        assert store.ingest_file(case_id, evidence, source="fixture", confidence=80) == 3
        document = store.load_case(case_id)
        indicator_id = document.indicators[0].indicator_id
        first = store.add_finding(
            case_id,
            title="Shared infrastructure",
            assessment="The synthetic fixture shares one indicator.",
            source="analyst-a",
            confidence=70,
            indicator_ids=(indicator_id,),
        )
        second = store.add_finding(
            case_id,
            title="Related activity",
            assessment="A second synthetic observation uses the same indicator.",
            source="analyst-b",
            confidence=60,
            indicator_ids=(indicator_id,),
        )
        document = store.load_case(case_id)
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert document.correlations == (tuple(sorted((first, second))),)
    report = tmp_path / "report.md"
    export_report(document, report)
    assert "Synthetic CTI case" in report.read_text(encoding="utf-8")
    assert stat.S_IMODE(report.stat().st_mode) == 0o600


def test_case_store_rejects_unknown_links_and_symlinks(tmp_path: Path) -> None:
    database = tmp_path / "case.sqlite3"
    with CaseStore(database) as store:
        case_id = store.create_case("Synthetic CTI case")
        with pytest.raises(ValueError, match="unknown indicator"):
            store.add_finding(
                case_id,
                title="Invalid link",
                assessment="This references a missing indicator.",
                source="fixture",
                confidence=50,
                indicator_ids=("ioc-" + "a" * 24,),
            )
    link = tmp_path / "link.sqlite3"
    link.symlink_to(database)
    with pytest.raises(OSError, match="symlink"):
        CaseStore(link)


def test_markdown_report_escapes_untrusted_markup(tmp_path: Path) -> None:
    database = tmp_path / "case.sqlite3"
    with CaseStore(database) as store:
        case_id = store.create_case("Case <script>alert(1)</script>")
        store.add_finding(
            case_id,
            title="Finding [link](javascript:alert(1))",
            assessment="<img src=x onerror=alert(1)>",
            source="fixture|unsafe",
            confidence=50,
        )
        document = store.load_case(case_id)
    report = tmp_path / "report.md"
    export_report(document, report)
    rendered = report.read_text(encoding="utf-8")
    assert "<script>" not in rendered
    assert "\\<script\\>" in rendered
    assert "\\<img src=x onerror=alert(1)\\>" in rendered
    assert "\\[link\\]" in rendered


def test_metis_cli_roundtrip(tmp_path: Path) -> None:
    recommendation = runner.invoke(app, ["metis", "recommend", "incident evidence timeline"])
    assert recommendation.exit_code == 0
    assert json.loads(recommendation.stdout)[0]["capability_id"] == "incident-response"

    database = tmp_path / "cases.sqlite3"
    created = runner.invoke(app, ["metis", "case", "create", str(database), "CLI case"])
    assert created.exit_code == 0
    case_id = created.stdout.strip()
    shown = runner.invoke(app, ["metis", "case", "show", str(database), case_id])
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["schema_name"] == "olympus.metis-case"


# --- Backup / restore of the case store (roadmap §2 Metis) ------------------- #


def test_backup_and_restore_round_trips_a_case(tmp_path: Path) -> None:
    from olympus.metis.cases import _indicator, restore_backup, verify_backup

    database = tmp_path / "cases.db"
    with CaseStore(database) as store:
        case_id = store.create_case("Backup case")
        store.add_indicators(case_id, [_indicator(IndicatorType.DOMAIN, "evil.tld", "src", 60)])
        snapshot = store.backup(tmp_path / "snap.db")

    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    assert verify_backup(snapshot) == {"cases": 1, "indicators": 1, "findings": 0}

    restored = tmp_path / "restored.db"
    counts = restore_backup(snapshot, restored)
    assert counts["cases"] == 1
    with CaseStore(restored) as store:
        document = store.load_case(case_id)
    assert document.title == "Backup case"
    assert len(document.indicators) == 1


def test_backup_refuses_to_overwrite_the_live_database(tmp_path: Path) -> None:
    database = tmp_path / "cases.db"
    with CaseStore(database) as store, pytest.raises(ValueError, match="must differ"):
        store.backup(database)


def test_verify_backup_rejects_a_non_metis_file(tmp_path: Path) -> None:
    from olympus.metis.cases import BackupError, verify_backup

    bogus = tmp_path / "bogus.db"
    bogus.write_text("not a database", encoding="utf-8")
    with pytest.raises(BackupError):
        verify_backup(bogus)


def test_cli_backup_verify_restore(tmp_path: Path) -> None:
    database = tmp_path / "cases.db"
    created = runner.invoke(app, ["metis", "case", "create", str(database), "CLI backup case"])
    case_id = created.stdout.strip()
    snapshot = tmp_path / "snap.db"

    backed = runner.invoke(app, ["metis", "case", "backup", str(database), str(snapshot)])
    assert backed.exit_code == 0, backed.output
    assert snapshot.exists()

    verified = runner.invoke(app, ["metis", "case", "verify-backup", str(snapshot)])
    assert verified.exit_code == 0
    assert json.loads(verified.stdout)["cases"] == 1

    restored = tmp_path / "restored.db"
    result = runner.invoke(app, ["metis", "case", "restore", str(snapshot), str(restored)])
    assert result.exit_code == 0, result.output
    shown = runner.invoke(app, ["metis", "case", "show", str(restored), case_id])
    assert "CLI backup case" in shown.output

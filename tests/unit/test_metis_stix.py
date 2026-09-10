"""STIX 2.1 export/import for METIS indicators (§2).

STIX is plain JSON, so no dependency is added. These tests round-trip Olympus
indicators through a bundle, prove the export is deterministic, and prove the
importer faithfully skips (never mangles) patterns Olympus cannot represent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.metis.models import Indicator, IndicatorType
from olympus.metis.stix import (
    StixError,
    bundle_to_indicators,
    indicators_to_bundle,
)

runner = CliRunner()


def _indicator(indicator_type: IndicatorType, value: str, confidence: int = 70) -> Indicator:
    return Indicator(
        indicator_id="ioc-" + "a" * 24,
        indicator_type=indicator_type,
        value=value,
        source="fixture",
        confidence=confidence,
        first_seen=datetime(2026, 9, 1, tzinfo=UTC),
    )


_SAMPLE = [
    _indicator(IndicatorType.DOMAIN, "evil.example"),
    _indicator(IndicatorType.IPV4, "203.0.113.7"),
    _indicator(IndicatorType.SHA256, "a" * 64),
    _indicator(IndicatorType.URL, "https://evil.example/x?y='z'"),  # value contains a quote
    _indicator(IndicatorType.CVE, "CVE-2021-44228"),
]


def test_export_emits_indicator_and_vulnerability_sdos() -> None:
    bundle = indicators_to_bundle(_SAMPLE)
    assert bundle["type"] == "bundle"
    kinds = sorted(obj["type"] for obj in bundle["objects"])
    assert kinds == ["indicator", "indicator", "indicator", "indicator", "vulnerability"]
    domain = next(o for o in bundle["objects"] if o.get("pattern", "").startswith("[domain-name"))
    assert domain["pattern"] == "[domain-name:value = 'evil.example']"
    assert domain["pattern_type"] == "stix"
    vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert vuln["name"] == "CVE-2021-44228"


def test_export_is_deterministic() -> None:
    assert indicators_to_bundle(_SAMPLE)["id"] == indicators_to_bundle(_SAMPLE)["id"]


def test_round_trip_preserves_every_indicator_including_escaped_values() -> None:
    bundle = indicators_to_bundle(_SAMPLE)
    parsed = bundle_to_indicators(json.dumps(bundle))
    recovered = {(item.indicator_type, item.value) for item in parsed.indicators}
    assert recovered == {
        (IndicatorType.DOMAIN, "evil.example"),
        (IndicatorType.IPV4, "203.0.113.7"),
        (IndicatorType.SHA256, "a" * 64),
        (IndicatorType.URL, "https://evil.example/x?y='z'"),
        (IndicatorType.CVE, "CVE-2021-44228"),
    }
    assert parsed.skipped == ()


def test_import_skips_compound_patterns_with_a_reason() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--x",
        "objects": [
            {
                "type": "indicator",
                "pattern_type": "stix",
                "pattern": "[domain-name:value = 'a.tld' OR domain-name:value = 'b.tld']",
            },
            {"type": "indicator", "pattern_type": "stix", "pattern": "[file:size > 100]"},
        ],
    }
    parsed = bundle_to_indicators(json.dumps(bundle))
    assert parsed.indicators == ()
    assert len(parsed.skipped) == 2
    assert all("not a simple equality" in item.reason for item in parsed.skipped)


def test_import_skips_a_non_stix_pattern_type() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--x",
        "objects": [
            {"type": "indicator", "pattern_type": "sigma", "pattern": "whatever"},
        ],
    }
    parsed = bundle_to_indicators(json.dumps(bundle))
    assert parsed.indicators == ()
    assert parsed.skipped[0].reason == "non-STIX pattern_type"


def test_import_rejects_a_non_bundle_and_bad_json() -> None:
    with pytest.raises(StixError, match="not a STIX bundle"):
        bundle_to_indicators(json.dumps({"type": "indicator"}))
    with pytest.raises(StixError, match="invalid STIX JSON"):
        bundle_to_indicators("{not json")


# --- CLI: export from one case, import into another --------------------------- #


def test_cli_stix_export_then_import_round_trips_through_cases(tmp_path: Path) -> None:
    database = tmp_path / "cases.db"
    # Seed a case with indicators by ingesting an evidence file.
    evidence = tmp_path / "evidence.txt"
    evidence.write_text(
        "Contact evil.example at 203.0.113.7; hash a" + "a" * 63 + " CVE-2021-44228",
        encoding="utf-8",
    )
    created = runner.invoke(app, ["metis", "case", "create", str(database), "source case"])
    assert created.exit_code == 0, created.output
    source_case = created.stdout.strip()
    ingested = runner.invoke(
        app,
        ["metis", "case", "ingest", str(database), source_case, str(evidence),
         "--source", "fixture", "--confidence", "80"],
    )
    assert ingested.exit_code == 0, ingested.output

    bundle_path = tmp_path / "bundle.json"
    exported = runner.invoke(
        app, ["metis", "case", "stix-export", str(database), source_case, str(bundle_path)]
    )
    assert exported.exit_code == 0, exported.output
    assert bundle_path.exists()
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle" and bundle["objects"]

    # Import into a fresh case and confirm the indicators land there.
    target = runner.invoke(app, ["metis", "case", "create", str(database), "target case"])
    target_case = target.stdout.strip()
    imported = runner.invoke(
        app,
        ["metis", "case", "stix-import", str(database), target_case, str(bundle_path),
         "--source", "stix-import", "--confidence", "60"],
    )
    assert imported.exit_code == 0, imported.output
    summary = json.loads(imported.stdout)
    assert summary["imported"] >= 3
    assert summary["inserted"] == summary["imported"]

    shown = runner.invoke(app, ["metis", "case", "show", str(database), target_case])
    assert "evil.example" in shown.output
    assert "CVE-2021-44228" in shown.output

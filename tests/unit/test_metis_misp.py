"""MISP event export/import for METIS indicators (§2).

MISP events are plain JSON, so no dependency is added. These tests round-trip
indicators through an event, prove the export is deterministic and conservative,
and prove the importer skips (never guesses) attribute types Olympus does not
represent.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.metis.misp import (
    MispError,
    event_to_indicators,
    indicators_to_event,
)
from olympus.metis.models import Indicator, IndicatorType

runner = CliRunner()


def _indicator(indicator_type: IndicatorType, value: str) -> Indicator:
    return Indicator(
        indicator_id="ioc-" + "a" * 24,
        indicator_type=indicator_type,
        value=value,
        source="fixture",
        confidence=70,
        first_seen=datetime(2026, 9, 1, tzinfo=UTC),
    )


_SAMPLE = [
    _indicator(IndicatorType.DOMAIN, "evil.example"),
    _indicator(IndicatorType.IPV4, "203.0.113.7"),
    _indicator(IndicatorType.IPV6, "2001:db8::1"),
    _indicator(IndicatorType.SHA256, "a" * 64),
    _indicator(IndicatorType.CVE, "CVE-2021-44228"),
]


def test_export_is_conservative_and_maps_types() -> None:
    event = indicators_to_event(_SAMPLE, info="case X", event_date=date(2026, 9, 10))["Event"]
    assert event["distribution"] == "0"  # org-only by default, never widened
    assert event["date"] == "2026-09-10"
    types = {attr["type"] for attr in event["Attribute"]}
    assert types == {"domain", "ip-dst", "sha256", "vulnerability"}
    assert all(attr["to_ids"] is True for attr in event["Attribute"])


def test_export_is_deterministic() -> None:
    first = indicators_to_event(_SAMPLE, info="c", event_date=date(2026, 9, 10))
    second = indicators_to_event(_SAMPLE, info="c", event_date=date(2026, 9, 10))
    assert first["Event"]["uuid"] == second["Event"]["uuid"]


def test_round_trip_preserves_indicators() -> None:
    event = indicators_to_event(_SAMPLE)
    parsed = event_to_indicators(json.dumps(event))
    recovered = {(item.indicator_type, item.value) for item in parsed.indicators}
    assert recovered == {
        (IndicatorType.DOMAIN, "evil.example"),
        (IndicatorType.IPV4, "203.0.113.7"),
        (IndicatorType.IPV6, "2001:db8::1"),
        (IndicatorType.SHA256, "a" * 64),
        (IndicatorType.CVE, "CVE-2021-44228"),
    }
    assert parsed.skipped == ()


def test_import_splits_ip_port_and_detects_v6() -> None:
    event = {
        "Event": {
            "Attribute": [
                {"type": "ip-src", "value": "198.51.100.9"},
                {"type": "ip-dst|port", "value": "203.0.113.8|443"},
                {"type": "ip-dst", "value": "2001:db8::2"},
            ]
        }
    }
    parsed = event_to_indicators(json.dumps(event))
    recovered = {(item.indicator_type, item.value) for item in parsed.indicators}
    assert recovered == {
        (IndicatorType.IPV4, "198.51.100.9"),
        (IndicatorType.IPV4, "203.0.113.8"),  # port stripped
        (IndicatorType.IPV6, "2001:db8::2"),
    }


def test_import_skips_unmapped_attribute_types() -> None:
    event = {"Event": {"Attribute": [{"type": "btc", "value": "1abc"}]}}
    parsed = event_to_indicators(json.dumps(event))
    assert parsed.indicators == ()
    assert parsed.skipped[0].misp_type == "btc"
    assert "unmapped" in parsed.skipped[0].reason


def test_import_accepts_a_bare_event_body() -> None:
    parsed = event_to_indicators(json.dumps({"Attribute": [{"type": "domain", "value": "x.tld"}]}))
    assert parsed.indicators[0].value == "x.tld"


def test_import_rejects_bad_json_and_missing_attributes() -> None:
    with pytest.raises(MispError, match="invalid MISP JSON"):
        event_to_indicators("{not json")
    with pytest.raises(MispError, match="Attribute"):
        event_to_indicators(json.dumps({"Event": {}}))


# --- CLI: export from one case, import into another --------------------------- #


def test_cli_misp_export_then_import_round_trips(tmp_path: Path) -> None:
    database = tmp_path / "cases.db"
    evidence = tmp_path / "evidence.txt"
    evidence.write_text(
        "Contact evil.example at 203.0.113.7; CVE-2021-44228", encoding="utf-8"
    )
    created = runner.invoke(app, ["metis", "case", "create", str(database), "source case"])
    source_case = created.stdout.strip()
    runner.invoke(
        app,
        ["metis", "case", "ingest", str(database), source_case, str(evidence),
         "--source", "fixture", "--confidence", "80"],
    )

    event_path = tmp_path / "event.json"
    exported = runner.invoke(
        app, ["metis", "case", "misp-export", str(database), source_case, str(event_path)]
    )
    assert exported.exit_code == 0, exported.output
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert event["Event"]["Attribute"]

    target = runner.invoke(app, ["metis", "case", "create", str(database), "target case"])
    target_case = target.stdout.strip()
    imported = runner.invoke(
        app,
        ["metis", "case", "misp-import", str(database), target_case, str(event_path),
         "--source", "misp-import", "--confidence", "60"],
    )
    assert imported.exit_code == 0, imported.output
    summary = json.loads(imported.stdout)
    assert summary["imported"] >= 2
    assert summary["inserted"] == summary["imported"]

    shown = runner.invoke(app, ["metis", "case", "show", str(database), target_case])
    assert "evil.example" in shown.output

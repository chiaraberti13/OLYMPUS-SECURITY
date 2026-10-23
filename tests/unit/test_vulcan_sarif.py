"""SARIF 2.1.0 import to Olympus findings, and its CLI (ROADMAP ``WEB-J``).

These tests pin the level→severity mapping, rule/location projection, strict
version/structure validation, the hostile-input bounds, and the CLI producing a
loadable finding bundle (or rejecting a malformed document without writing).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.vulcan.aggregate import load_findings
from olympus.vulcan.sarif import MAX_RESULTS, SarifImportError, sarif_to_findings

runner = CliRunner()


def _doc(
    results: list[dict[str, Any]], rules: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "demo", "rules": rules or []}},
                "results": results,
            }
        ],
    }


def test_level_maps_to_severity() -> None:
    doc = _doc(
        [
            {"level": "error", "message": {"text": "e"}},
            {"level": "warning", "message": {"text": "w"}},
            {"level": "note", "message": {"text": "n"}},
            {"level": "none", "message": {"text": "x"}},
            {"message": {"text": "missing level"}},
        ]
    )
    findings = sarif_to_findings(doc, asset_id="AST-1")
    assert [f.severity for f in findings] == [
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
        Severity.MEDIUM,  # absent level → safe default, never silently INFO
    ]
    assert all(f.source is Source.MANUAL and f.asset_id == "AST-1" for f in findings)


def test_rule_and_location_are_projected() -> None:
    doc = _doc(
        [
            {
                "ruleId": "R1",
                "level": "error",
                "message": {"text": "Weak cipher\nsecond line"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 7},
                        }
                    },
                    {"physicalLocation": {"artifactLocation": {"uri": "b.py"}}},
                ],
            }
        ],
        rules=[{"id": "R1", "shortDescription": {"text": "Weak"}, "helpUri": "https://x.test/r1"}],
    )
    (finding,) = sarif_to_findings(doc, asset_id="AST-1")
    assert finding.title == "Weak cipher"  # first line of the message
    assert finding.description == "Weak cipher\nsecond line"
    assert finding.references == ["R1", "https://x.test/r1"]
    assert finding.evidence == ["a.py:7", "b.py"]


def test_title_falls_back_to_rule_then_ruleid_then_placeholder() -> None:
    doc = _doc(
        [
            {"ruleId": "R1", "message": {"text": ""}},
            {"ruleId": "R2", "message": {"text": ""}},
            {"message": {"text": ""}},
        ],
        rules=[{"id": "R1", "shortDescription": {"text": "From rule"}}],
    )
    findings = sarif_to_findings(doc, asset_id="AST-1")
    assert [f.title for f in findings] == ["From rule", "R2", "SARIF result"]


def test_rejects_non_2_1_0_and_malformed_structure() -> None:
    for bad in ({"version": "2.0.0", "runs": []}, {"runs": []}, {"version": "2.1.0"}):
        try:
            sarif_to_findings(bad, asset_id="AST-1")
        except SarifImportError:
            continue
        raise AssertionError(f"expected rejection for {bad}")


def test_hostile_fields_do_not_crash_and_are_bounded() -> None:
    # Non-string/garbage fields must be ignored, not raise, and text is capped.
    doc = _doc(
        [
            {"ruleId": 123, "level": 9, "message": "not-an-object", "locations": "nope"},
            {"message": {"text": "x" * 50_000}},
        ]
    )
    findings = sarif_to_findings(doc, asset_id="AST-1")
    assert findings[0].title == "SARIF result" and findings[0].severity is Severity.MEDIUM
    assert len(findings[1].title) <= 500 and len(findings[1].description) <= 10_000


def test_result_cap_is_enforced() -> None:
    doc = _doc([{"message": {"text": "x"}}, {"message": {"text": "y"}}])
    try:
        sarif_to_findings(doc, asset_id="AST-1", max_results=1)
    except SarifImportError as exc:
        assert "limit" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected a result-cap rejection")
    assert MAX_RESULTS > 0


def test_cli_imports_sarif_into_a_loadable_bundle(tmp_path: Path) -> None:
    sarif = tmp_path / "r.sarif.json"
    sarif.write_text(
        json.dumps(_doc([{"ruleId": "R1", "level": "error", "message": {"text": "XSS"}}])),
        encoding="utf-8",
    )
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "sarif-import",
            "-i",
            str(sarif),
            "-o",
            str(out),
            "--asset-id",
            "AST-2026-00001",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["imported"] == 1
    loaded = load_findings([out])
    assert loaded[0].title == "XSS" and loaded[0].severity is Severity.HIGH
    assert loaded[0].asset_id == "AST-2026-00001"


def test_cli_rejects_malformed_sarif_without_writing(tmp_path: Path) -> None:
    sarif = tmp_path / "bad.sarif.json"
    sarif.write_text('{"version": "2.0.0"}', encoding="utf-8")
    out = tmp_path / "out.json"
    result = runner.invoke(
        app, ["vulcan", "sarif-import", "-i", str(sarif), "-o", str(out), "--asset-id", "AST-1"]
    )
    assert result.exit_code == ExitCode.USAGE
    assert not out.exists()


# ---------------------------------------------------------------------------
# SARIF export (findings -> SARIF 2.1.0)
# ---------------------------------------------------------------------------

from olympus.vulcan.sarif import findings_to_sarif  # noqa: E402


def _finding(fid: str, title: str, severity: Severity, asset: str = "AST-1") -> Any:
    from olympus.core.models import Finding

    return Finding(
        finding_id=fid, asset_id=asset, source=Source.ARTEMIS, title=title, severity=severity
    )


def test_export_is_valid_sarif_and_deterministic() -> None:
    a = _finding("FND-2026-00001", "XSS", Severity.CRITICAL)
    b = _finding("FND-2026-00002", "Open port", Severity.LOW)
    doc = findings_to_sarif([b, a])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    results = doc["runs"][0]["results"]
    # Sorted by finding id, so the output is byte-stable.
    assert [r["ruleId"] for r in results] == ["FND-2026-00001", "FND-2026-00002"]
    assert findings_to_sarif([a, b]) == findings_to_sarif([b, a])
    # Round-trippable through json.
    json.dumps(doc)


def test_export_maps_severity_to_level_and_keeps_detail_in_properties() -> None:
    doc = findings_to_sarif(
        [
            _finding("FND-2026-00001", "crit", Severity.CRITICAL),
            _finding("FND-2026-00002", "high", Severity.HIGH),
            _finding("FND-2026-00003", "med", Severity.MEDIUM),
            _finding("FND-2026-00004", "low", Severity.LOW),
            _finding("FND-2026-00005", "info", Severity.INFO),
        ]
    )
    levels = [(r["level"], r["properties"]["severity"]) for r in doc["runs"][0]["results"]]
    assert levels == [
        ("error", "critical"),  # critical and high both collapse to error...
        ("error", "high"),
        ("warning", "medium"),
        ("note", "low"),
        ("none", "info"),
    ]
    # ...but the exact Olympus severity survives in the property bag.


def test_export_puts_asset_in_location() -> None:
    doc = findings_to_sarif([_finding("FND-2026-00001", "x", Severity.LOW, asset="AST-2026-00042")])
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "AST-2026-00042"


def test_export_neutralizes_hostile_finding_text(tmp_path: Path) -> None:
    """SEC-H: a target-controlled title/description cannot carry terminal-control
    sequences or forged lines into the SARIF a consumer renders."""
    from olympus.core.models import Finding

    hostile = Finding(
        finding_id="FND-2026-00001",
        asset_id="AST-1",
        source=Source.ARTEMIS,
        severity=Severity.HIGH,
        # ANSI colour, an OSC title-set sequence, and an embedded newline that
        # would otherwise forge a second log/line in a consumer.
        title="Reflected \x1b[31mXSS\x1b[0m\nStatus: clean",
        description="see \x1b]0;pwned\x07 details",
    )
    doc = findings_to_sarif([hostile])
    text = doc["runs"][0]["results"][0]["message"]["text"]
    title_line, _, description_line = text.partition("\n")
    # No raw escape/control bytes survive anywhere.
    assert "\x1b" not in text and "\x07" not in text
    # The embedded newline inside the title is collapsed, so the attacker cannot
    # forge a second line: the whole title stays on one line.
    assert "\n" not in title_line and "Status: clean" in title_line
    # The genuine title/description boundary is still exactly one newline.
    assert text.count("\n") == 1
    assert description_line and "\n" not in description_line


def test_cli_export_then_reimport_round_trips(tmp_path: Path) -> None:
    from olympus.core.models import Finding

    findings = [
        Finding(
            finding_id="FND-2026-00001",
            asset_id="AST-1",
            source=Source.ARTEMIS,
            title="XSS",
            severity=Severity.HIGH,
        ),
    ]
    bundle = tmp_path / "in.json"
    bundle.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    sarif = tmp_path / "out.sarif.json"
    exported = runner.invoke(app, ["vulcan", "sarif-export", "-i", str(bundle), "-o", str(sarif)])
    assert exported.exit_code == 0, exported.output
    assert json.loads(exported.output)["exported"] == 1

    restored = tmp_path / "back.json"
    reimported = runner.invoke(
        app,
        ["vulcan", "sarif-import", "-i", str(sarif), "-o", str(restored), "--asset-id", "AST-1"],
    )
    assert reimported.exit_code == 0, reimported.output
    loaded = load_findings([restored])
    assert loaded[0].title == "XSS" and loaded[0].severity is Severity.HIGH

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

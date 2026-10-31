"""Tests for the offensive-finding MITRE ATT&CK overlay (ROADMAP ``OPS-RED``).

Pin the OPS-RED bullet: findings are associated with ATT&CK technique/tactic/
confidence/rationale from a versioned mapping, the overlay never mutates the
finding contract, automatic and human-reviewed associations are distinguished,
and the derivation is deterministic and offline.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Confidence, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.vulcan.attack import (
    ATTACK_MAP_VERSION,
    AttackMappingError,
    AttackSource,
    ReviewedAssociation,
    associate_all,
    associate_attack,
    technique_counts,
)

runner = CliRunner()


def _finding(fid: str, *cwes: str, title: str = "x") -> Finding:
    return Finding(
        finding_id=fid,
        asset_id="AST-1",
        source=Source.ARTEMIS,
        severity=Severity.HIGH,
        title=title,
        cwe=list(cwes),
    )


def test_cwe_maps_to_expected_technique_automatically() -> None:
    overlay = associate_attack(_finding("FND-2026-00001", "CWE-89"))
    assert [a.technique for a in overlay.associations] == ["T1190"]
    (association,) = overlay.associations
    assert association.source is AttackSource.AUTOMATIC
    assert association.confidence is Confidence.HIGH
    assert f"map {ATTACK_MAP_VERSION}" in association.rationale


def test_unmapped_cwe_invents_no_association() -> None:
    # Honest absence: an unknown weakness never yields a guessed technique.
    overlay = associate_attack(_finding("FND-2026-00002", "CWE-1021"))
    assert overlay.associations == ()


def test_multiple_cwes_dedupe_a_shared_technique() -> None:
    # CWE-89 and CWE-78 both map to T1190; it must appear once.
    overlay = associate_attack(_finding("FND-2026-00003", "CWE-89", "CWE-78"))
    techniques = [a.technique for a in overlay.associations]
    assert techniques.count("T1190") == 1
    assert "T1059" in techniques  # the command-injection-only technique


def test_reviewed_association_overrides_and_sorts_first() -> None:
    review = ReviewedAssociation(
        technique="T1190",
        name="Exploit Public-Facing Application",
        tactic="initial-access",
        confidence=Confidence.HIGH,
        rationale="analyst confirmed exploitation in the engagement",
    )
    overlay = associate_attack(_finding("FND-2026-00005", "CWE-89"), reviews=[review])
    # The automatic T1190 is replaced by the reviewed one (no duplicate), first.
    matching = [a for a in overlay.associations if a.technique == "T1190"]
    assert len(matching) == 1
    assert matching[0].source is AttackSource.REVIEWED
    assert overlay.associations[0].source is AttackSource.REVIEWED


def test_reviewed_association_requires_tactic_and_rationale() -> None:
    bad = ReviewedAssociation("T1190", "x", "", Confidence.HIGH, "r")
    with pytest.raises(AttackMappingError):
        associate_attack(_finding("FND-2026-00006", "CWE-89"), reviews=[bad])


def test_reviewed_association_rejects_invalid_technique_id() -> None:
    bad = ReviewedAssociation("NOT-A-TECH", "x", "execution", Confidence.HIGH, "r")
    with pytest.raises(AttackMappingError):
        associate_attack(_finding("FND-2026-00007", "CWE-89"), reviews=[bad])


def test_associate_all_is_deterministic_and_sorted() -> None:
    findings = [_finding("FND-2026-00002", "CWE-78"), _finding("FND-2026-00001", "CWE-89")]
    first = associate_all(findings)
    second = associate_all(list(reversed(findings)))
    assert [o.finding_id for o in first] == ["FND-2026-00001", "FND-2026-00002"]
    assert [o.to_dict() for o in first] == [o.to_dict() for o in second]


def test_technique_counts_feed_the_navigator() -> None:
    overlays = associate_all([_finding("FND-2026-00001", "CWE-78")])
    counts = technique_counts(overlays)
    assert counts["T1190"] == 1
    assert counts["T1059"] == 1


# --- CLI -------------------------------------------------------------------- #


def _write_findings(path, *findings: Finding) -> None:
    path.write_text(json.dumps([f.model_dump(mode="json") for f in findings]), encoding="utf-8")


def test_attack_cli_writes_overlay_and_navigator(tmp_path) -> None:
    bundle = tmp_path / "findings.json"
    _write_findings(bundle, _finding("FND-2026-00001", "CWE-89"), _finding("FND-2026-00002"))
    overlay = tmp_path / "attack.json"
    navigator = tmp_path / "nav.json"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "attack",
            "--findings",
            str(bundle),
            "--output",
            str(overlay),
            "--navigator",
            str(navigator),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    overlays = json.loads(overlay.read_text(encoding="utf-8"))
    assert overlays[0]["finding_id"] == "FND-2026-00001"
    assert overlays[0]["associations"][0]["technique"] == "T1190"
    assert overlays[1]["associations"] == []  # honest absence persists to disk
    layer = json.loads(navigator.read_text(encoding="utf-8"))
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1190"]


def test_attack_cli_applies_human_reviews(tmp_path) -> None:
    bundle = tmp_path / "findings.json"
    _write_findings(bundle, _finding("FND-2026-00001", "CWE-89"))
    reviews = tmp_path / "reviews.json"
    reviews.write_text(
        json.dumps(
            {
                "FND-2026-00001": [
                    {
                        "technique": "T1210",
                        "name": "Exploitation of Remote Services",
                        "tactic": "lateral-movement",
                        "confidence": "high",
                        "rationale": "confirmed in lab",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "vulcan",
            "attack",
            "--findings",
            str(bundle),
            "--reviews",
            str(reviews),
            "--output",
            str(tmp_path / "o.json"),
        ],
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    assert "T1210" in result.output and "reviewed" in result.output


def test_attack_cli_rejects_a_malformed_review_file(tmp_path) -> None:
    bundle = tmp_path / "findings.json"
    _write_findings(bundle, _finding("FND-2026-00001", "CWE-89"))
    reviews = tmp_path / "reviews.json"
    reviews.write_text(json.dumps({"FND-2026-00001": [{"technique": "T1210"}]}), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "vulcan",
            "attack",
            "--findings",
            str(bundle),
            "--reviews",
            str(reviews),
            "--output",
            str(tmp_path / "o.json"),
        ],
    )
    assert result.exit_code == int(ExitCode.USAGE)

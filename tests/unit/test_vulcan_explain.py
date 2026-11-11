"""Finding explainability contract and ``olympus vulcan explain`` CLI (ROADMAP ``EXPL-1``).

The explanation is derived purely from a finding's own fields — no scanning, no
network, nothing invented — and its risk rationale must reproduce the exact score
the finding computes. These tests pin that parity, the honest "decisive" factor,
the observed/inferred/limits separation, and the CLI's behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Confidence, EpistemicClass, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.vulcan.explain import (
    EXPLANATIONS_SCHEMA_NAME,
    EXPLANATIONS_SCHEMA_VERSION,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    FindingExplanationDocument,
    FindingExplanationsDocument,
    explain_finding,
    explanations_document,
)

runner = CliRunner()


def _finding(title: str = "SQL injection", **kwargs: object) -> Finding:
    data: dict[str, object] = {
        "asset_id": "AST-1",
        "source": Source.ARTEMIS,
        "title": title,
        "severity": Severity.HIGH,
    }
    data.update(kwargs)
    return Finding(**data)  # type: ignore[arg-type]


def _bundle(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


# ---------------------------------------------------------------------------
# Contract / builder
# ---------------------------------------------------------------------------


def test_explanation_risk_score_matches_the_finding() -> None:
    # The explanation must never diverge from Finding.risk_score() itself.
    for finding in (
        _finding(severity=Severity.LOW),
        _finding(cvss=9.8, kev=True, confidence=Confidence.HIGH),
        _finding(severity=Severity.MEDIUM, epss=0.8, confidence=Confidence.LOW),
        _finding(severity=Severity.CRITICAL),
    ):
        assert explain_finding(finding).risk_score == finding.risk_score()


def test_cvss_base_is_decisive_when_it_exceeds_the_kev_floor() -> None:
    # CVSS 9.8 -> base 98 already above the KEV floor 95, so KEV is not decisive.
    explanation = explain_finding(_finding(cvss=9.8, kev=True))
    decisive = {f.factor: f.decisive for f in explanation.risk_factors}
    assert decisive["cvss-base"] is True
    assert decisive["kev"] is False
    assert explanation.risk_score == 98.0


def test_kev_floor_is_decisive_when_it_raises_a_low_base() -> None:
    explanation = explain_finding(_finding(severity=Severity.LOW, kev=True))
    decisive = {f.factor: f.decisive for f in explanation.risk_factors}
    assert decisive["severity-base"] is False
    assert decisive["kev"] is True
    assert explanation.risk_score == 95.0


def test_epss_floor_is_decisive_only_when_it_lifts_the_base() -> None:
    lifted = explain_finding(_finding(severity=Severity.LOW, epss=0.9))  # 90 > 30
    assert next(f for f in lifted.risk_factors if f.factor == "epss").decisive is True
    not_lifted = explain_finding(_finding(severity=Severity.CRITICAL, epss=0.1))  # 10 < 90
    assert next(f for f in not_lifted.risk_factors if f.factor == "epss").decisive is False
    assert next(f for f in not_lifted.risk_factors if f.factor == "severity-base").decisive is True


def test_confidence_is_a_nudge_never_decisive() -> None:
    explanation = explain_finding(_finding(confidence=Confidence.HIGH))
    confidence = next(f for f in explanation.risk_factors if f.factor == "confidence")
    assert confidence.decisive is False


def test_observed_statements_are_classified_as_observed_evidence() -> None:
    explanation = explain_finding(
        _finding(cvss=7.5, kev=True, cve=["CVE-2024-0001"], evidence=["e1", "e2"])
    )
    observed = " ".join(s.text for s in explanation.observed)
    assert "2 evidence" in observed
    assert "KEV" in observed
    assert "CVE-2024-0001" in observed
    assert all(s.epistemic_class is EpistemicClass.OBSERVED_EVIDENCE for s in explanation.observed)


def test_risk_score_is_a_deterministic_result_never_an_observation() -> None:
    # The core EXPL-1 guard: a derived value must never be labelled observed.
    explanation = explain_finding(_finding(cvss=9.8, kev=True))
    score_claims = [s for s in explanation.statements if "risk score" in s.text]
    assert len(score_claims) == 1
    assert score_claims[0].epistemic_class is EpistemicClass.DETERMINISTIC_RESULT
    assert all(
        s.epistemic_class is not EpistemicClass.OBSERVED_EVIDENCE
        for s in explanation.statements
        if "risk score" in s.text
    )


def test_structured_identifier_is_observed_but_text_derived_is_only_inference() -> None:
    structured = explain_finding(_finding(cve=["CVE-2024-0001"]))
    cve_claim = next(s for s in structured.statements if "CVE-2024-0001" in s.text)
    assert cve_claim.epistemic_class is EpistemicClass.OBSERVED_EVIDENCE

    text_derived = explain_finding(_finding(title="RCE per CVE-2024-0002 nel modulo"))
    assert text_derived.cve == ("CVE-2024-0002",)
    derived_claim = next(s for s in text_derived.statements if "CVE-2024-0002" in s.text)
    assert derived_claim.epistemic_class is EpistemicClass.INFERENCE


def test_limits_flag_text_derived_identifiers_and_missing_data() -> None:
    # CWE only in free text, no structured field, no evidence, no confidence.
    explanation = explain_finding(_finding(title="Reflected XSS via CWE-79 in search"))
    assert explanation.cwe == ("CWE-79",)
    limits = " ".join(explanation.limits)
    assert "free text" in limits
    assert "No evidence" in limits
    assert "No confidence" in limits


def test_low_confidence_is_called_out_as_a_lead() -> None:
    explanation = explain_finding(_finding(confidence=Confidence.LOW))
    assert any("lead to verify" in limit for limit in explanation.limits)


def test_to_dict_is_versioned_json_serialisable_and_complete() -> None:
    explanation = explain_finding(_finding(cvss=9.8, kev=True, remediation="Upgrade"))
    payload = json.loads(json.dumps(explanation.to_dict()))
    assert payload["schema_name"] == SCHEMA_NAME
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["risk_score"] == explanation.risk_score
    assert payload["remediation"] == "Upgrade"
    assert payload["risk_factors"][0]["factor"] == "cvss-base"
    # Every statement carries a valid epistemic class.
    classes = {EpistemicClass(s["epistemic_class"]) for s in payload["statements"]}
    assert classes  # non-empty
    assert all(isinstance(s["text"], str) for s in payload["statements"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_explain_text_block(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "f.json", [_finding(cvss=9.8, kev=True, remediation="Patch")])
    result = runner.invoke(app, ["vulcan", "explain", "-i", str(bundle)])
    assert result.exit_code == ExitCode.OK
    assert "Risk factors:" in result.stdout
    assert "Limits:" in result.stdout
    assert "explained 1 finding(s)" in result.stderr


def test_cli_explain_orders_by_descending_risk(tmp_path: Path) -> None:
    low = _finding("Low issue", severity=Severity.LOW, asset_id="A-low")
    high = _finding("Critical issue", severity=Severity.CRITICAL, asset_id="A-high")
    bundle = _bundle(tmp_path / "f.json", [low, high])
    result = runner.invoke(app, ["vulcan", "explain", "-i", str(bundle), "--format", "json"])
    assert result.exit_code == ExitCode.OK
    payload = json.loads(result.stdout)
    assert [item["title"] for item in payload] == ["Critical issue", "Low issue"]


def test_attack_techniques_are_suggested_correlations_not_observations() -> None:
    # CWE-89 maps to T1190 via the reviewed CWE->ATT&CK table.
    explanation = explain_finding(_finding("SQL injection", cwe=["CWE-89"]))
    assert explanation.attack, "expected a CWE->ATT&CK association"
    assert explanation.attack[0].technique == "T1190"
    attack_claims = [
        s
        for s in explanation.statements
        if s.epistemic_class is EpistemicClass.SUGGESTED_CORRELATION
    ]
    assert attack_claims and "T1190" in attack_claims[0].text
    # Never presented as observed exploitation.
    assert all(
        s.epistemic_class is not EpistemicClass.OBSERVED_EVIDENCE
        for s in explanation.statements
        if "ATT&CK" in s.text
    )
    assert any("ATT&CK techniques are suggested" in limit for limit in explanation.limits)


def test_a_finding_without_a_mappable_cwe_has_no_attack() -> None:
    explanation = explain_finding(_finding("Generic info", asset_id="AST-2"))
    assert explanation.attack == ()
    assert not [
        s
        for s in explanation.statements
        if s.epistemic_class is EpistemicClass.SUGGESTED_CORRELATION
    ]


def test_one_finding_exercises_the_core_epistemic_classes() -> None:
    # EXPL-1 fixture: a single finding spanning observed / inference / deterministic
    # / suggested_correlation (a text-derived CVE is the inference).
    explanation = explain_finding(
        _finding(
            "Injection via CVE-2024-9999 in handler",
            cwe=["CWE-89"],
            cvss=9.0,
            evidence=["ev-1"],
        )
    )
    classes = {s.epistemic_class for s in explanation.statements}
    assert EpistemicClass.OBSERVED_EVIDENCE in classes
    assert EpistemicClass.DETERMINISTIC_RESULT in classes
    assert EpistemicClass.SUGGESTED_CORRELATION in classes
    assert EpistemicClass.INFERENCE in classes  # the free-text CVE id


def test_to_dict_validates_and_round_trips_the_published_contract() -> None:
    # EXPL-1 JSON Schema catalog: the pure core's output IS the published contract,
    # so the schema and the core can never drift.
    explanation = explain_finding(
        _finding("Injection via CVE-2024-9999", cwe=["CWE-89"], cvss=9.0, kev=True, evidence=["e"])
    )
    document = explanation.to_dict()
    assert FindingExplanationDocument.model_validate(document).model_dump(mode="json") == document


def test_explanations_document_validates_the_published_collection_contract() -> None:
    collection = explanations_document([_finding("A", cwe=["CWE-89"]), _finding("B", asset_id="X")])
    assert (
        FindingExplanationsDocument.model_validate(collection).model_dump(mode="json") == collection
    )


def test_published_contract_rejects_an_unknown_field() -> None:
    document = explain_finding(_finding("X")).to_dict()
    document["sneaky"] = "nope"
    with pytest.raises(ValueError, match="not permitted"):
        FindingExplanationDocument.model_validate(document)


def test_cli_explain_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["vulcan", "explain", "-i", str(bad)])
    assert result.exit_code == ExitCode.USAGE


# ---------------------------------------------------------------------------
# Report companion document (EXPL-2)
# ---------------------------------------------------------------------------


def test_explanations_document_is_versioned_and_preserves_order() -> None:
    findings = [_finding("First", cvss=9.0), _finding("Second", asset_id="AST-2")]
    document = explanations_document(findings)
    assert document["schema_name"] == EXPLANATIONS_SCHEMA_NAME
    assert document["schema_version"] == EXPLANATIONS_SCHEMA_VERSION
    assert document["count"] == 2
    explanations = document["explanations"]
    assert isinstance(explanations, list)
    assert [e["title"] for e in explanations] == ["First", "Second"]


def test_explanations_document_entries_match_the_shared_core() -> None:
    findings = [_finding("A", cvss=9.8, kev=True), _finding("B", asset_id="AST-2")]
    document = explanations_document(findings)
    expected = [explain_finding(f).to_dict() for f in findings]
    assert document["explanations"] == expected


def test_cli_report_writes_an_explanations_companion_matching_the_core(tmp_path: Path) -> None:
    # EXPL-2 parity on the report surface: the companion equals explain_finding,
    # over the report's own ranked findings.
    findings = [
        _finding("Low thing", severity=Severity.LOW, asset_id="AST-low"),
        _finding("Critical RCE", severity=Severity.CRITICAL, asset_id="AST-crit", cvss=9.8),
    ]
    bundle = _bundle(tmp_path / "findings.json", findings)
    report_out = tmp_path / "report.json"
    explanations_out = tmp_path / "explanations.json"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "Acme",
            "--findings",
            str(bundle),
            "--output",
            str(report_out),
            "--explanations",
            str(explanations_out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "wrote finding explanations" in result.stderr

    document = json.loads(explanations_out.read_text(encoding="utf-8"))
    assert document["schema_name"] == EXPLANATIONS_SCHEMA_NAME
    report = json.loads(report_out.read_text(encoding="utf-8"))
    report_ids = [f["finding_id"] for f in report["findings"]]
    # Ranked: the critical finding comes before the low one.
    assert document["explanations"][0]["severity"] == "critical"
    # Same findings, same order, same explanation as the shared core.
    assert [e["finding_id"] for e in document["explanations"]] == report_ids
    by_id = {f.finding_id: f for f in findings}
    for entry in document["explanations"]:
        assert entry == explain_finding(by_id[entry["finding_id"]]).to_dict()

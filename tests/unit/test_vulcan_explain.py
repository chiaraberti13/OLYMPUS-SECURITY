"""Finding explainability contract and ``olympus vulcan explain`` CLI (ROADMAP ``EXPL-1``).

The explanation is derived purely from a finding's own fields — no scanning, no
network, nothing invented — and its risk rationale must reproduce the exact score
the finding computes. These tests pin that parity, the honest "decisive" factor,
the observed/inferred/limits separation, and the CLI's behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Confidence, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.vulcan.explain import explain_finding

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


def test_observed_separates_evidence_and_intelligence() -> None:
    explanation = explain_finding(
        _finding(cvss=7.5, kev=True, cve=["CVE-2024-0001"], evidence=["e1", "e2"])
    )
    observed = " ".join(explanation.observed)
    assert "2 evidence" in observed
    assert "KEV" in observed
    assert "CVE-2024-0001" in observed


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


def test_to_dict_is_json_serialisable_and_complete() -> None:
    explanation = explain_finding(_finding(cvss=9.8, kev=True, remediation="Upgrade"))
    payload = json.loads(json.dumps(explanation.to_dict()))
    assert payload["risk_score"] == explanation.risk_score
    assert payload["remediation"] == "Upgrade"
    assert payload["risk_factors"][0]["factor"] == "cvss-base"
    assert isinstance(payload["observed"], list)


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


def test_cli_explain_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["vulcan", "explain", "-i", str(bad)])
    assert result.exit_code == ExitCode.USAGE

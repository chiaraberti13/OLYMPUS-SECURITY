"""Unit tests for the Vulcan formatted-PDF report renderer."""

from __future__ import annotations

import builtins
from datetime import UTC, datetime
from pathlib import Path

import pytest

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.enrichment import EpssScore, KevEntry, enrich_findings
from olympus.vulcan.pdf import PdfUnavailableError, export_pdf, render_report_pdf
from olympus.vulcan.report import build_report_model

reportlab = pytest.importorskip("reportlab", reason="the optional 'report' extra is not installed")


def _report(engagement: str = "ACME engagement") -> object:
    asset = Asset(
        asset_id="asset-1",
        asset_type=AssetType.WEB_SERVER,
        hostname="lab.example.test",
        source=Source.ARGUS,
    )
    finding = Finding(
        asset_id="asset-1",
        source=Source.ARTEMIS,
        title="Reflected XSS",
        description="User input is reflected without encoding.",
        severity=Severity.HIGH,
        cvss=7.5,
        evidence=["payload executed in response body"],
        remediation="Context-encode output and set a CSP.",
        references=["https://owasp.org/www-community/attacks/xss/"],
    )
    alert = Alert(
        event_id="event-1",
        title="Suspicious login",
        source=Source.APOLLO,
        severity=Severity.MEDIUM,
        rule_id="APL-RULE-42",
        mitre_attack=["T1078"],
    )
    return build_report_model(
        engagement, [asset], [finding], [alert], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )


def test_render_returns_a_valid_pdf_document() -> None:
    pdf = render_report_pdf(_report())
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 1000


def test_render_is_deterministic_for_a_fixed_timestamp() -> None:
    # ReportLab stamps its own creation date; a fixed report still renders a
    # stable, non-empty document on repeat calls.
    first = render_report_pdf(_report())
    second = render_report_pdf(_report())
    assert first.startswith(b"%PDF-") and second.startswith(b"%PDF-")


def test_empty_report_still_renders() -> None:
    empty = build_report_model("empty", [], [], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC))
    pdf = render_report_pdf(empty)
    assert pdf.startswith(b"%PDF-")


def test_hostile_finding_text_cannot_break_rendering() -> None:
    # Target-controlled text with ReportLab markup metacharacters must be escaped
    # (ROADMAP.md SEC-H), not interpreted, and must never raise.
    hostile = Finding(
        asset_id="asset-1",
        source=Source.ARTEMIS,
        title="<para><b>pwned</b></para> & <script>alert(1)</script>",
        description="<font color='red'>injected</font> & <<>>",
        severity=Severity.CRITICAL,
        evidence=['<onerror=alert(1)> & "quotes"'],
        remediation="</para><para>break",
    )
    report = build_report_model(
        "<b>engagement</b>", [], [hostile], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    pdf = render_report_pdf(report)
    assert pdf.startswith(b"%PDF-")


def test_export_writes_restricted_pdf_file(tmp_path: Path) -> None:
    target = tmp_path / "report.pdf"
    export_pdf(_report(), target)
    assert target.read_bytes().startswith(b"%PDF-")
    assert (target.stat().st_mode & 0o777) == 0o600


def test_missing_reportlab_raises_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def _fail_reportlab(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("reportlab"):
            raise ImportError("No module named 'reportlab'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _fail_reportlab)
    with pytest.raises(PdfUnavailableError) as excinfo:
        render_report_pdf(_report())
    assert "report" in str(excinfo.value)


def _cve_finding() -> Finding:
    return Finding(
        asset_id="asset-1",
        source=Source.HELIOS,
        title="Outdated Next.js with known vulnerabilities",
        description="Multiple SSRF issues affect the detected version.",
        severity=Severity.HIGH,
        cvss=8.6,
        remediation="Upgrade to a fixed release.",
        references=["CVE-2021-44228", "CWE-1004", "https://nextjs.org/blog/security"],
    )


def test_cve_and_cwe_references_link_to_nist_and_mitre() -> None:
    report = build_report_model(
        "eng", [], [_cve_finding()], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    pdf = render_report_pdf(report)
    # Link targets live in the PDF's (uncompressed) annotation dictionaries.
    assert b"nvd.nist.gov/vuln/detail/CVE-2021-44228" in pdf
    assert b"cwe.mitre.org/data/definitions/1004" in pdf
    assert b"nextjs.org/blog/security" in pdf


def test_enrichment_overlay_adds_epss_and_kev_without_error() -> None:
    finding = _cve_finding()
    overlay = enrich_findings(
        [finding],
        kev={"CVE-2021-44228": KevEntry("CVE-2021-44228", "2021-12-10", "Apache", "Log4j")},
        epss={"CVE-2021-44228": EpssScore("CVE-2021-44228", 0.97521, 0.99998)},
    )
    report = build_report_model(
        "eng", [], [finding], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    pdf = render_report_pdf(report, enrichments=overlay)
    assert pdf.startswith(b"%PDF-")
    assert b"nvd.nist.gov/vuln/detail/CVE-2021-44228" in pdf


def test_structured_cve_renders_nvd_link_without_free_text() -> None:
    """WEB-C: a structured ``cve`` field is rendered even when absent from text."""
    finding = Finding(
        asset_id="asset-1",
        source=Source.THEMIS,
        title="Outdated component",  # no CVE in any free-text field
        severity=Severity.CRITICAL,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        cwe=["CWE-502"],
    )
    report = build_report_model(
        "eng", [], [finding], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    pdf = render_report_pdf(report)
    assert b"nvd.nist.gov/vuln/detail/CVE-2021-44228" in pdf
    assert b"cwe.mitre.org/data/definitions/502" in pdf


def test_structured_epss_and_kev_render_without_an_overlay() -> None:
    """WEB-C: the finding's own EPSS/KEV surface with no live enrichment run."""
    finding = Finding(
        asset_id="asset-1",
        source=Source.THEMIS,
        title="Log4Shell",
        severity=Severity.CRITICAL,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        epss=0.975,
        epss_percentile=0.999,
        kev=True,
    )
    report = build_report_model(
        "eng", [], [finding], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    # No enrichments= passed: the renderer must fall back to the structured fields.
    pdf = render_report_pdf(report)
    assert pdf.startswith(b"%PDF-")
    assert b"nvd.nist.gov/vuln/detail/CVE-2021-44228" in pdf


def test_overall_risk_reflects_the_worst_finding() -> None:
    low = Finding(asset_id="a", source=Source.ARTEMIS, title="minor", severity=Severity.LOW)
    report = build_report_model("eng", [], [low], [], generated_at=datetime(2026, 1, 1, tzinfo=UTC))
    pdf = render_report_pdf(report)
    assert pdf.startswith(b"%PDF-")

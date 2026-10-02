"""Unit tests for composable finding search and filtering (WEB-C)."""

from __future__ import annotations

from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.models import Finding
from olympus.vulcan.search import FindingFilter, search_findings


def _findings() -> list[Finding]:
    return [
        Finding(
            asset_id="AST-1",
            source=Source.THEMIS,
            title="Log4Shell",
            severity=Severity.CRITICAL,
            status=FindingStatus.CONFIRMED,
            cve=["CVE-2021-44228"],
            kev=True,
            tags=["web", "urgent"],
            engagement_id="ENG-2026-00001",
        ),
        Finding(
            asset_id="AST-2",
            source=Source.HELIOS,
            title="Open port 22",
            severity=Severity.LOW,
            status=FindingStatus.NEW,
            tags=["net"],
        ),
        Finding(
            asset_id="AST-3",
            source=Source.THEMIS,
            title="Weak TLS configuration",
            severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED,
        ),
    ]


def _titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]


def test_empty_filter_keeps_everything_in_order() -> None:
    findings = _findings()
    assert search_findings(findings, FindingFilter()) == findings


def test_filter_by_status_and_source() -> None:
    findings = _findings()
    confirmed = search_findings(
        findings, FindingFilter(statuses=frozenset({FindingStatus.CONFIRMED}))
    )
    assert _titles(confirmed) == ["Log4Shell", "Weak TLS configuration"]
    themis = search_findings(findings, FindingFilter(sources=frozenset({Source.HELIOS})))
    assert _titles(themis) == ["Open port 22"]


def test_min_severity_is_a_threshold() -> None:
    findings = _findings()
    assert _titles(search_findings(findings, FindingFilter(min_severity=Severity.HIGH))) == [
        "Log4Shell"
    ]
    assert len(search_findings(findings, FindingFilter(min_severity=Severity.LOW))) == 3


def test_kev_only_and_has_cve() -> None:
    findings = _findings()
    assert _titles(search_findings(findings, FindingFilter(kev_only=True))) == ["Log4Shell"]
    assert _titles(search_findings(findings, FindingFilter(has_cve=True))) == ["Log4Shell"]
    assert _titles(search_findings(findings, FindingFilter(has_cve=False))) == [
        "Open port 22",
        "Weak TLS configuration",
    ]


def test_tags_match_is_case_insensitive_and_requires_all() -> None:
    findings = _findings()
    assert _titles(search_findings(findings, FindingFilter(tags=frozenset({"WEB"})))) == [
        "Log4Shell"
    ]
    # Requires ALL tags: "web" + "missing" matches nothing.
    assert search_findings(findings, FindingFilter(tags=frozenset({"web", "missing"}))) == []


def test_text_search_spans_fields_including_cve() -> None:
    findings = _findings()
    assert _titles(search_findings(findings, FindingFilter(text="tls"))) == [
        "Weak TLS configuration"
    ]
    assert _titles(search_findings(findings, FindingFilter(text="CVE-2021-44228"))) == ["Log4Shell"]
    assert _titles(search_findings(findings, FindingFilter(text="AST-2"))) == ["Open port 22"]


def test_min_risk_score_threshold() -> None:
    findings = _findings()
    # Only the KEV critical clears a high risk bar.
    assert _titles(search_findings(findings, FindingFilter(min_risk_score=90.0))) == ["Log4Shell"]


def test_criteria_combine_with_and_semantics() -> None:
    findings = _findings()
    query = FindingFilter(
        statuses=frozenset({FindingStatus.CONFIRMED}),
        min_severity=Severity.HIGH,
        engagement_id="ENG-2026-00001",
    )
    assert _titles(search_findings(findings, query)) == ["Log4Shell"]


def test_finding_tags_are_normalized() -> None:
    finding = Finding(
        asset_id="AST-1",
        source=Source.THEMIS,
        title="x",
        tags=["  web  ", "web", "", "   ", "urgent"],
    )
    assert finding.tags == ["web", "urgent"]

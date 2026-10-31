"""Unit tests for reusable, manifest-parametrized Vulcan report sections."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, EngagementScope, Finding
from olympus.engagements.manifest import EngagementManifest
from olympus.vulcan.engagement_report import EngagementReportContext, engagement_context
from olympus.vulcan.report import (
    build_report_model,
    render_report_html,
    render_report_markdown,
)

_VALID_FROM = datetime(2026, 1, 1, tzinfo=UTC)


def _manifest(**overrides: object) -> EngagementManifest:
    base: dict[str, object] = {
        "engagement_id": "ENG-2026-00001",
        "client": "Example Client",
        "owner": "Security Owner",
        "approver": "Authorized Approver",
        "contract_id": "CONTRACT-2026-01",
        "scope": EngagementScope(included=("example.com",), excluded=("admin.example.com",)),
        "valid_from": _VALID_FROM,
        "expires_at": _VALID_FROM + timedelta(hours=8),
        "allowed_techniques": ("nmap", "httpx"),
    }
    base.update(overrides)
    return EngagementManifest(**base)  # type: ignore[arg-type]


def _finding(severity: Severity) -> Finding:
    return Finding(
        finding_id=f"FND-{severity.value}",
        title=f"{severity.value} issue",
        severity=severity,
        source=Source.THEMIS,
        asset_id="AST-1",
    )


def test_engagement_context_extracts_display_fields() -> None:
    context = engagement_context(_manifest())
    assert isinstance(context, EngagementReportContext)
    assert context.engagement_id == "ENG-2026-00001"
    assert context.client == "Example Client"
    assert context.scope_included == ("example.com",)
    assert context.scope_excluded == ("admin.example.com",)
    assert context.allowed_techniques == ("httpx", "nmap")  # manifest sorts techniques
    start, end = context.window_utc()
    assert start == "2026-01-01T00:00:00+00:00"
    assert end == "2026-01-01T08:00:00+00:00"


def test_markdown_includes_all_reusable_sections() -> None:
    report = build_report_model("ENG-2026-00001", [], [], [])
    markdown = render_report_markdown(report, engagement=engagement_context(_manifest()))
    for heading in ("## Scope", "## Methodology", "## Disclaimer", "## Executive summary"):
        assert heading in markdown
    assert "Authorized techniques: httpx, nmap" in markdown
    assert "confidential to Example Client" in markdown


def test_sections_are_absent_without_an_engagement() -> None:
    report = build_report_model("ENG-2026-00001", [], [], [])
    assert "## Scope" not in render_report_markdown(report)
    assert "<h2>Scope</h2>" not in render_report_html(report)


def test_executive_summary_counts_findings() -> None:
    assets = [Asset(asset_id="AST-1", asset_type=AssetType.HOST, source=Source.THEMIS)]
    findings = [_finding(Severity.CRITICAL), _finding(Severity.LOW)]
    report = build_report_model("ENG-2026-00001", assets, findings, [])
    markdown = render_report_markdown(report, engagement=engagement_context(_manifest()))
    assert "identified 2 finding(s)" in markdown
    assert "1 critical" in markdown
    assert "1 finding(s) at high or critical severity" in markdown


def test_executive_summary_reports_no_findings_honestly() -> None:
    report = build_report_model("ENG-2026-00001", [], [], [])
    markdown = render_report_markdown(report, engagement=engagement_context(_manifest()))
    assert "No findings were identified" in markdown


def test_markdown_neutralizes_control_sequences_and_metacharacters() -> None:
    hostile = _manifest(client="Acme\x1b<Corp>\nFORGED LINE")
    report = build_report_model("ENG-2026-00001", [], [], [])
    markdown = render_report_markdown(report, engagement=engagement_context(hostile))
    assert "\x1b" not in markdown  # ESC control byte removed (no terminal injection)
    assert "\nFORGED LINE" not in markdown  # newline collapsed (no forged line)
    assert "FORGED LINE" in markdown  # the text survives, inert, on the same line
    assert "\\<Corp\\>" in markdown  # Markdown metacharacters escaped


def test_html_sections_are_escaped() -> None:
    hostile = _manifest(approver="Approver\x1b[0m <script>")
    report = build_report_model("ENG-2026-00001", [], [], [])
    html = render_report_html(report, engagement=engagement_context(hostile))
    assert "<h2>Scope</h2>" in html
    assert "<h2>Executive summary</h2>" in html
    assert "\x1b" not in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_sections_render_in_executive_slice_too() -> None:
    report = build_report_model("ENG-2026-00001", [], [], [])
    markdown = render_report_markdown(
        report, section="executive", engagement=engagement_context(_manifest())
    )
    assert "## Scope" in markdown
    assert "## Executive summary" in markdown
    # Executive slice still omits the asset inventory.
    assert "## Assets" not in markdown


@pytest.mark.parametrize("renderer", (render_report_markdown, render_report_html))
def test_empty_scope_lists_render_gracefully(renderer: object) -> None:
    manifest = _manifest(scope=EngagementScope(included=("example.com",), excluded=()))
    report = build_report_model("ENG-2026-00001", [], [], [])
    rendered = renderer(report, engagement=engagement_context(manifest))  # type: ignore[operator]
    assert "example.com" in rendered

"""Report renderer adapter delegating to Vulcan without copying its logic."""

from __future__ import annotations

import json

from olympus.core.models import Finding
from olympus.vulcan.pdf import render_report_pdf
from olympus.vulcan.report import build_report_model, render_report_html, render_report_markdown


class VulcanReportRenderer:
    """Render Athena findings through the shared Vulcan reporting functions."""

    def __init__(self, engagement: str) -> None:
        self._engagement = engagement

    def render(self, findings: list[Finding], fmt: str) -> str:
        """Render a text report format (``json``, ``markdown`` or ``html``)."""
        report = build_report_model(self._engagement, [], findings, [])
        if fmt == "markdown":
            return render_report_markdown(report)
        if fmt == "html":
            return render_report_html(report)
        return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True, default=str)

    def render_pdf(self, findings: list[Finding]) -> bytes:
        """Render the formatted PDF report (requires the optional ``report`` extra)."""
        return render_report_pdf(build_report_model(self._engagement, [], findings, []))

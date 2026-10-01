"""Render one canonical Vulcan security report as a formatted PDF.

The PDF is the operator-facing counterpart to the JSON/Markdown/HTML renderers in
:mod:`olympus.vulcan.report`: a cover page, an executive summary with the severity
breakdown, the ranked findings (each with severity, CVSS, evidence, remediation
and references) and the asset/alert inventories. It is built from the same
:class:`~olympus.core.models.SecurityReport` model, so every renderer tells the
same story.

ReportLab is an **optional** dependency (the ``report`` extra). This module is the
only place that imports it, so the rest of Vulcan stays dependency-free and
importable without it; :func:`render_report_pdf` raises a clear
:class:`PdfUnavailableError` when the library is missing, instead of failing at
import time.

Every value that can originate from a scanned target — finding titles,
descriptions, evidence, asset labels, alert text — is hostile input
(``ROADMAP.md`` ``SEC-H``). ReportLab's ``Paragraph`` interprets a small XML-like
markup, so all such text is passed through :func:`_safe`, which escapes the XML
metacharacters before it ever reaches the document. A malicious banner can
therefore never inject markup, break the layout, or forge report structure.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from olympus.core.fileio import atomic_write_bytes
from olympus.core.models import SecurityReport

#: Severity row order and the fill colours used for the summary table and badges.
#: Kept in step with the HTML renderer's palette so both outputs read alike.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_HEX = {
    "critical": "#7f1d1d",
    "high": "#b45309",
    "medium": "#a16207",
    "low": "#3f6212",
    "info": "#374151",
}


class PdfUnavailableError(RuntimeError):
    """Raised when a PDF render is requested but ReportLab is not installed."""


def _safe(value: str) -> str:
    """Escape untrusted text for ReportLab's XML-like paragraph markup."""
    return escape(" ".join(value.split()))


def render_report_pdf(report: SecurityReport) -> bytes:
    """Render ``report`` as a self-contained PDF document and return its bytes.

    Raises :class:`PdfUnavailableError` if the optional ``report`` extra
    (ReportLab) is not installed, with the exact command to install it.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.platypus import (
            Flowable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised via a stubbed import
        raise PdfUnavailableError(
            "PDF reports require the optional 'report' extra: "
            "install it with `pip install olympus-security[report]`."
        ) from exc

    base = getSampleStyleSheet()
    body = base["BodyText"]
    heading = base["Heading2"]
    title_style = ParagraphStyle(
        "OlympusTitle", parent=base["Title"], alignment=TA_CENTER, spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "OlympusSubtitle",
        parent=base["Normal"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#555555"),
        fontSize=11,
        leading=16,
    )

    generated = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    story: list[Flowable] = [
        Spacer(1, 60 * mm),
        Paragraph("Security Assessment Report", title_style),
        Paragraph(_safe(report.engagement), subtitle_style),
        Spacer(1, 6 * mm),
        Paragraph(f"Generated {generated} · Olympus Vulcan", subtitle_style),
        PageBreak(),
    ]

    # --- Executive summary --------------------------------------------------- #
    story.append(Paragraph("Executive summary", heading))
    story.append(
        Paragraph(
            f"This report consolidates {report.summary.findings} finding(s) across "
            f"{report.summary.assets} asset(s), plus {report.summary.alerts} alert(s), "
            "ranked by severity. Findings are listed worst-first so the most urgent "
            "remediation leads.",
            body,
        )
    )
    story.append(Spacer(1, 4 * mm))

    breakdown = report.summary.severity_breakdown
    summary_rows: list[list[str]] = [["Severity", "Count"]]
    summary_rows += [
        [level.capitalize(), str(breakdown.get(level, 0))] for level in _SEVERITY_ORDER
    ]
    summary_table = Table(summary_rows, colWidths=[60 * mm, 30 * mm], hAlign="LEFT")
    summary_style: list[tuple[object, ...]] = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for index, level in enumerate(_SEVERITY_ORDER, start=1):
        summary_style.append(
            ("TEXTCOLOR", (0, index), (0, index), colors.HexColor(_SEVERITY_HEX[level]))
        )
    summary_table.setStyle(TableStyle(summary_style))
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    # --- Findings ------------------------------------------------------------ #
    story.append(Paragraph("Findings (ranked)", heading))
    if not report.findings:
        story.append(Paragraph("No findings.", body))
    for finding in report.findings:
        colour = _SEVERITY_HEX[finding.severity.value]
        finding_heading = ParagraphStyle(
            f"Finding-{finding.finding_id}",
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor(colour),
            spaceBefore=6,
        )
        story.append(
            Paragraph(f"[{finding.severity.value.upper()}] {_safe(finding.title)}", finding_heading)
        )
        meta = (
            f"ID {_safe(finding.finding_id)} · source {_safe(finding.source.value)} "
            f"· asset {_safe(finding.asset_id)}"
        )
        if finding.cvss is not None:
            meta += f" · CVSS {finding.cvss}"
        story.append(Paragraph(meta, body))
        if finding.description:
            story.append(Paragraph(_safe(finding.description), body))
        for item in finding.evidence:
            story.append(Paragraph(f"Evidence: {_safe(item)}", body))
        if finding.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {_safe(finding.remediation)}", body))
        for reference in finding.references:
            story.append(Paragraph(f"Reference: {_safe(reference)}", body))
        story.append(Spacer(1, 2 * mm))

    # --- Assets -------------------------------------------------------------- #
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Assets", heading))
    if not report.assets:
        story.append(Paragraph("No assets.", body))
    for asset in report.assets:
        label = asset.hostname or ", ".join(asset.ip_addresses) or asset.asset_id
        story.append(
            Paragraph(
                f"{_safe(asset.asset_id)} — {_safe(label)} "
                f"({_safe(asset.asset_type.value)}, {_safe(asset.source.value)})",
                body,
            )
        )

    # --- Alerts -------------------------------------------------------------- #
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Alerts", heading))
    if not report.alerts:
        story.append(Paragraph("No alerts.", body))
    for alert in report.alerts:
        provenance = f"rule {_safe(alert.rule_id)}" if alert.rule_id else "rule unavailable"
        if alert.mitre_attack:
            provenance += "; MITRE " + ", ".join(_safe(item) for item in alert.mitre_attack)
        story.append(
            Paragraph(
                f"[{alert.severity.value.upper()}] {_safe(alert.title)} "
                f"({_safe(alert.alert_id)}; {provenance})",
                body,
            )
        )

    engagement = report.engagement

    def _footer(canvas: Canvas, _doc: object) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#999999"))
        canvas.drawString(18 * mm, 10 * mm, "Olympus Vulcan — confidential security assessment")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Security report — {engagement}",
        author="Olympus Vulcan",
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def export_pdf(report: SecurityReport, path: Path) -> None:
    """Render ``report`` and durably write the PDF to ``path`` (atomic, 0600)."""
    atomic_write_bytes(path, render_report_pdf(report), mode=0o600)

"""Render one canonical Vulcan security report as a designed, formatted PDF.

The PDF is the operator-facing counterpart to the JSON/Markdown/HTML renderers in
:mod:`olympus.vulcan.report`, built from the same
:class:`~olympus.core.models.SecurityReport` model so every output tells the same
story. The layout is a deliberate design system rather than default styling:

* a branded **cover** (navy masthead, report title, engagement, confidentiality);
* an **executive summary** with KPI tiles and a proportional severity
  distribution bar plus a labelled legend;
* **finding cards**, each with a severity chip, a left accent rule in the
  severity colour, a muted metadata line, and tinted callouts for evidence and
  remediation;
* compact **asset** and **alert** inventories;
* a running header and footer with page numbers on every content page.

Colour is a validated, ordinal **severity** scale (critical → info). Because
severity is a status scale, every mark that carries it also carries its text
label (the chip text, the bar/legend labels), so meaning is never colour-alone,
and each chip's text colour is chosen by WCAG contrast against its own fill.

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
from olympus.core.models import Finding, SecurityReport

# --- Design tokens ---------------------------------------------------------- #
# Neutral brand palette (ink, surfaces, hairlines) plus the semantic severity
# ramp. Kept here as plain hex so the module imports without ReportLab.
_BRAND_INK = "#0f172a"  # deep slate — masthead and section headings
_BRAND_ACCENT = "#2563eb"  # accent rule under section headings, callouts
_INK = "#111827"  # primary text
_MUTED = "#6b7280"  # secondary / metadata text
_FAINT = "#9ca3af"  # footer, de-emphasised labels
_HAIRLINE = "#e5e7eb"  # table borders, dividers
_SURFACE_TINT = "#f8fafc"  # KPI tiles, card ground
_EVIDENCE_TINT = "#f3f4f6"  # monospace evidence box
_CALLOUT_TINT = "#eff4ff"  # remediation callout ground

#: Severity row order (worst first) and the validated ordinal fill colours. The
#: ramp is an ordinal status scale, so every use is paired with a text label.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_HEX = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#2a78d6",
    "info": "#64748b",
}


class PdfUnavailableError(RuntimeError):
    """Raised when a PDF render is requested but ReportLab is not installed."""


def _safe(value: str) -> str:
    """Escape untrusted text for ReportLab's XML-like paragraph markup."""
    return escape(" ".join(value.split()))


def _relative_luminance(hex_color: str) -> float:
    """Return the WCAG relative luminance of an ``#rrggbb`` colour."""
    raw = hex_color.lstrip("#")
    channels = [int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _text_on(background: str) -> str:
    """Pick near-black or white text for the higher contrast on ``background``."""
    lum = _relative_luminance(background)
    white_contrast = 1.05 / (lum + 0.05)
    dark_contrast = (lum + 0.05) / (_relative_luminance("#111111") + 0.05)
    return "#111111" if dark_contrast >= white_contrast else "#ffffff"


def render_report_pdf(report: SecurityReport) -> bytes:
    """Render ``report`` as a self-contained, designed PDF and return its bytes.

    Raises :class:`PdfUnavailableError` if the optional ``report`` extra
    (ReportLab) is not installed, with the exact command to install it.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.platypus import (
            Flowable,
            HRFlowable,
            KeepTogether,
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

    page_width, _page_height = A4
    margin = 18 * mm
    content_width = page_width - 2 * margin

    ink = colors.HexColor(_BRAND_INK)
    accent = colors.HexColor(_BRAND_ACCENT)
    hairline = colors.HexColor(_HAIRLINE)

    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body", parent=base["BodyText"], fontSize=9.5, leading=14, textColor=colors.HexColor(_INK)
    )
    meta = ParagraphStyle(
        "Meta", parent=base["Normal"], fontSize=8, leading=12, textColor=colors.HexColor(_MUTED)
    )
    section = ParagraphStyle(
        "Section",
        parent=base["Heading2"],
        fontSize=14,
        leading=18,
        textColor=ink,
        spaceBefore=2,
        spaceAfter=0,
    )
    cover_title = ParagraphStyle(
        "CoverTitle",
        parent=base["Title"],
        fontSize=30,
        leading=34,
        textColor=ink,
        alignment=TA_LEFT,
    )
    cover_engagement = ParagraphStyle(
        "CoverEngagement",
        parent=base["Normal"],
        fontSize=16,
        leading=20,
        textColor=accent,
        spaceBefore=6,
    )
    cover_meta = ParagraphStyle(
        "CoverMeta",
        parent=base["Normal"],
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor(_MUTED),
        spaceBefore=16,
    )
    finding_title = ParagraphStyle(
        "FindingTitle", parent=base["Normal"], fontSize=11, leading=15, textColor=ink
    )
    callout_label = ParagraphStyle(
        "CalloutLabel",
        parent=base["Normal"],
        fontSize=7.5,
        leading=10,
        textColor=accent,
        spaceAfter=2,
    )
    mono = ParagraphStyle(
        "Mono",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=12,
        textColor=colors.HexColor(_INK),
    )

    def _section(title: str) -> list[Flowable]:
        """A section heading with an accent underline."""
        return [
            Spacer(1, 6 * mm),
            Paragraph(_safe(title), section),
            HRFlowable(
                width="100%",
                thickness=1.5,
                color=accent,
                spaceBefore=3,
                spaceAfter=7,
                lineCap="round",
            ),
        ]

    def _chip(level: str) -> Table:
        """A rounded severity chip whose text contrasts with its own fill."""
        fill = _SEVERITY_HEX[level]
        chip_style = ParagraphStyle(
            f"Chip-{level}",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            alignment=TA_CENTER,
            textColor=colors.HexColor(_text_on(fill)),
        )
        chip = Table([[Paragraph(level.upper(), chip_style)]], colWidths=[24 * mm])
        chip.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(fill)),
                    ("ROUNDEDCORNERS", [3, 3, 3, 3]),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        return chip

    def _kpi_tile(value: str, label: str, value_color: str) -> Table:
        """One KPI stat tile: a large number over a small caption."""
        number_style = ParagraphStyle(
            f"Kpi-{label}",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=24,
            textColor=colors.HexColor(value_color),
        )
        caption = ParagraphStyle(
            f"KpiCap-{label}",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor(_MUTED),
        )
        tile = Table([[Paragraph(value, number_style)], [Paragraph(_safe(label), caption)]])
        tile.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_SURFACE_TINT)),
                    ("BOX", (0, 0), (-1, -1), 0.5, hairline),
                    ("ROUNDEDCORNERS", [4, 4, 4, 4]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (0, 0), 9),
                    ("BOTTOMPADDING", (0, 0), (0, 0), 0),
                    ("TOPPADDING", (0, 1), (0, 1), 1),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 9),
                ]
            )
        )
        return tile

    def _kpi_row() -> Table:
        gap = 5 * mm
        tile_width = (content_width - 2 * gap) / 3
        critical_high = sum(
            report.summary.severity_breakdown.get(level, 0) for level in ("critical", "high")
        )
        tiles = [
            _kpi_tile(str(report.summary.findings), "Findings", _INK),
            _kpi_tile(str(critical_high), "Critical + High", _SEVERITY_HEX["critical"]),
            _kpi_tile(str(report.summary.assets), "Assets assessed", _INK),
        ]
        spacer = ""
        row = Table(
            [[tiles[0], spacer, tiles[1], spacer, tiles[2]]],
            colWidths=[tile_width, gap, tile_width, gap, tile_width],
        )
        row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return row

    def _severity_bar() -> list[Flowable]:
        """A proportional, gapped severity bar plus a labelled legend."""
        breakdown = report.summary.severity_breakdown
        present = [(level, breakdown.get(level, 0)) for level in _SEVERITY_ORDER]
        total = sum(count for _, count in present)
        flow: list[Flowable] = []

        if total == 0:
            empty = Table([[Paragraph("No findings", meta)]], colWidths=[content_width])
            empty.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_SURFACE_TINT)),
                        ("BOX", (0, 0), (-1, -1), 0.5, hairline),
                        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
                        ("TOPPADDING", (0, 0), (-1, -1), 7),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ]
                )
            )
            return [empty]

        segments = [(level, count) for level, count in present if count > 0]
        widths = [content_width * count / total for _, count in segments]
        cells = []
        for level, count in segments:
            seg_style = ParagraphStyle(
                f"Seg-{level}",
                parent=base["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=11,
                alignment=TA_CENTER,
                textColor=colors.HexColor(_text_on(_SEVERITY_HEX[level])),
            )
            cells.append(Paragraph(str(count), seg_style))
        bar = Table([cells], colWidths=widths)
        bar_style: list[tuple[object, ...]] = [
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for index, (level, _count) in enumerate(segments):
            bar_style.append(
                ("BACKGROUND", (index, 0), (index, 0), colors.HexColor(_SEVERITY_HEX[level]))
            )
            if index < len(segments) - 1:
                # A 2px surface-coloured gap between stacked fills.
                bar_style.append(("LINEAFTER", (index, 0), (index, 0), 2, colors.white))
        bar.setStyle(TableStyle(bar_style))
        flow.append(bar)
        flow.append(Spacer(1, 3 * mm))

        legend_cells = []
        for level in _SEVERITY_ORDER:
            count = breakdown.get(level, 0)
            swatch = _SEVERITY_HEX[level]
            legend_cells.append(
                Paragraph(
                    f'<font color="{swatch}">■</font> {level.capitalize()} '
                    f'<font color="{_INK}"><b>{count}</b></font>',
                    meta,
                )
            )
        legend = Table(
            [legend_cells], colWidths=[content_width / len(_SEVERITY_ORDER)] * len(_SEVERITY_ORDER)
        )
        legend.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        flow.append(legend)
        return flow

    def _finding_card(finding: Finding) -> KeepTogether:
        """One finding as a card with a severity-coloured left rule."""
        level = finding.severity.value
        fill = _SEVERITY_HEX[level]

        header = Table(
            [[_chip(level), Paragraph(_safe(finding.title), finding_title)]],
            colWidths=[26 * mm, content_width - 26 * mm - 12],
        )
        header.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (0, 0), 0),
                    ("LEFTPADDING", (1, 0), (1, 0), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )

        meta_bits = [
            f"ID {_safe(finding.finding_id)}",
            f"source {_safe(finding.source.value)}",
            f"asset {_safe(finding.asset_id)}",
        ]
        if finding.cvss is not None:
            meta_bits.insert(0, f"CVSS {finding.cvss}")

        inner: list[Flowable] = [header, Spacer(1, 2 * mm), Paragraph(" · ".join(meta_bits), meta)]
        if finding.description:
            inner.append(Spacer(1, 1.5 * mm))
            inner.append(Paragraph(_safe(finding.description), body))

        if finding.evidence:
            evidence_rows = [
                [Paragraph(f"Evidence: {_safe(item)}", mono)] for item in finding.evidence
            ]
            evidence = Table(evidence_rows, colWidths=[content_width - 16])
            evidence.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_EVIDENCE_TINT)),
                        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            inner.append(Spacer(1, 2 * mm))
            inner.append(evidence)

        if finding.remediation:
            callout = Table(
                [
                    [Paragraph("REMEDIATION", callout_label)],
                    [Paragraph(_safe(finding.remediation), body)],
                ],
                colWidths=[content_width - 16],
            )
            callout.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_CALLOUT_TINT)),
                        ("LINEBEFORE", (0, 0), (0, -1), 2, accent),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (0, 0), 5),
                        ("BOTTOMPADDING", (0, 0), (0, 0), 0),
                        ("TOPPADDING", (0, 1), (0, 1), 0),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
                    ]
                )
            )
            inner.append(Spacer(1, 2 * mm))
            inner.append(callout)

        if finding.references:
            refs = "  ·  ".join(_safe(reference) for reference in finding.references)
            inner.append(Spacer(1, 1.5 * mm))
            inner.append(Paragraph(f"References: {refs}", meta))

        card = Table([[inner]], colWidths=[content_width])
        card.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.5, hairline),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(fill)),
                    ("ROUNDEDCORNERS", [4, 4, 4, 4]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 11),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 11),
                    ("TOPPADDING", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                ]
            )
        )
        return KeepTogether([card, Spacer(1, 3 * mm)])

    generated = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    # --- Cover --------------------------------------------------------------- #
    story: list[Flowable] = [
        Spacer(1, 34 * mm),  # clear the canvas-drawn masthead band
        Paragraph("Security Assessment Report", cover_title),
        Paragraph(_safe(report.engagement), cover_engagement),
        Paragraph(f"Generated {generated}<br/>Prepared by Olympus Vulcan", cover_meta),
        Spacer(1, 10 * mm),
        Paragraph(
            f"<b>{report.summary.findings}</b> finding(s) across "
            f"<b>{report.summary.assets}</b> asset(s), with "
            f"<b>{report.summary.alerts}</b> alert(s).",
            body,
        ),
        PageBreak(),
    ]

    # --- Executive summary --------------------------------------------------- #
    story.extend(_section("Executive summary"))
    story.append(
        Paragraph(
            "Findings are ranked worst-first so the most urgent remediation leads. "
            "The bar below shows how findings are distributed across severities.",
            body,
        )
    )
    story.append(Spacer(1, 4 * mm))
    story.append(_kpi_row())
    story.append(Spacer(1, 6 * mm))
    story.extend(_severity_bar())

    # --- Findings ------------------------------------------------------------ #
    story.extend(_section("Findings (ranked)"))
    if not report.findings:
        story.append(Paragraph("No findings.", body))
    for finding in report.findings:
        story.append(_finding_card(finding))

    # --- Assets -------------------------------------------------------------- #
    story.extend(_section("Assets"))
    if not report.assets:
        story.append(Paragraph("No assets.", body))
    else:
        asset_rows = [
            [
                Paragraph("<b>Asset</b>", meta),
                Paragraph("<b>Identifier</b>", meta),
                Paragraph("<b>Type</b>", meta),
                Paragraph("<b>Source</b>", meta),
            ]
        ]
        for asset in report.assets:
            label = asset.hostname or ", ".join(asset.ip_addresses) or asset.asset_id
            asset_rows.append(
                [
                    Paragraph(_safe(asset.asset_id), meta),
                    Paragraph(_safe(label), meta),
                    Paragraph(_safe(asset.asset_type.value), meta),
                    Paragraph(_safe(asset.source.value), meta),
                ]
            )
        assets_table = Table(
            asset_rows,
            colWidths=[
                content_width * 0.3,
                content_width * 0.34,
                content_width * 0.18,
                content_width * 0.18,
            ],
        )
        assets_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_SURFACE_TINT)),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, hairline),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(assets_table)

    # --- Alerts -------------------------------------------------------------- #
    story.extend(_section("Alerts"))
    if not report.alerts:
        story.append(Paragraph("No alerts.", body))
    for alert in report.alerts:
        provenance = f"rule {_safe(alert.rule_id)}" if alert.rule_id else "rule unavailable"
        if alert.mitre_attack:
            provenance += "; MITRE " + ", ".join(_safe(item) for item in alert.mitre_attack)
        story.append(
            Paragraph(
                f"<b>[{alert.severity.value.upper()}]</b> {_safe(alert.title)} "
                f"<font color='{_MUTED}'>({_safe(alert.alert_id)}; {provenance})</font>",
                body,
            )
        )
        story.append(Spacer(1, 1.5 * mm))

    engagement = report.engagement

    def _decorate(canvas: Canvas, doc: object, *, cover: bool) -> None:
        canvas.saveState()
        if cover:
            band_height = 24 * mm
            canvas.setFillColor(ink)
            canvas.rect(0, A4[1] - band_height, A4[0], band_height, stroke=0, fill=1)
            canvas.setFillColor(accent)
            canvas.rect(0, A4[1] - band_height - 2, A4[0], 2, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 13)
            canvas.drawString(margin, A4[1] - 15 * mm, "OLYMPUS")
            canvas.setFont("Helvetica", 13)
            canvas.drawString(margin + 27 * mm, A4[1] - 15 * mm, "VULCAN")
            canvas.setFillColor(colors.HexColor("#9fb4d8"))
            canvas.setFont("Helvetica", 7.5)
            canvas.drawRightString(
                A4[0] - margin, A4[1] - 15 * mm, "SECURITY ASSESSMENT · CONFIDENTIAL"
            )
        else:
            canvas.setFillColor(colors.HexColor(_MUTED))
            canvas.setFont("Helvetica", 7.5)
            canvas.drawString(margin, A4[1] - 12 * mm, _ascii(engagement))
            canvas.drawRightString(A4[0] - margin, A4[1] - 12 * mm, "CONFIDENTIAL")
            canvas.setStrokeColor(hairline)
            canvas.setLineWidth(0.5)
            canvas.line(margin, A4[1] - 14 * mm, A4[0] - margin, A4[1] - 14 * mm)
        # Footer on every page.
        canvas.setFillColor(colors.HexColor(_FAINT))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(margin, 10 * mm, "Olympus Vulcan — confidential security assessment")
        canvas.drawRightString(A4[0] - margin, 10 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    def _first_page(canvas: Canvas, doc: object) -> None:
        _decorate(canvas, doc, cover=True)

    def _later_page(canvas: Canvas, doc: object) -> None:
        _decorate(canvas, doc, cover=False)

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Security report — {engagement}",
        author="Olympus Vulcan",
        leftMargin=margin,
        rightMargin=margin,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
    )
    document.build(story, onFirstPage=_first_page, onLaterPages=_later_page)
    return buffer.getvalue()


def _ascii(value: str) -> str:
    """A header-safe single-line rendering of untrusted text for canvas drawing.

    The canvas string APIs do not interpret markup, but we still collapse
    whitespace and drop control characters so a hostile engagement name cannot
    disturb the running header.
    """
    collapsed = " ".join(value.split())
    return "".join(ch for ch in collapsed if ch.isprintable())[:80]


def export_pdf(report: SecurityReport, path: Path) -> None:
    """Render ``report`` and durably write the PDF to ``path`` (atomic, 0600)."""
    atomic_write_bytes(path, render_report_pdf(report), mode=0o600)

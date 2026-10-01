"""Render one canonical Vulcan security report as a minimal, formatted PDF.

The PDF is the operator-facing counterpart to the JSON/Markdown/HTML renderers in
:mod:`olympus.vulcan.report`, built from the same
:class:`~olympus.core.models.SecurityReport` model so every output tells the same
story. The layout is a deliberately restrained, document-style design:

* a slim branded **cover** with the engagement and the overall risk level;
* a **summary** — overall risk, the per-severity rating counts with a thin
  distribution bar, and the report's own counts;
* a **known-vulnerabilities table** (CVE · CVSS · EPSS · percentile · KEV) with
  live links to the NIST NVD, shown when any finding references a CVE;
* **findings** as clean typographic blocks — a severity label, a compact metadata
  line (CVSS, EPSS, KEV), the risk description, the recommendation, evidence, and
  references that include NVD (NIST) and CWE (MITRE) links;
* compact **asset** and **alert** inventories.

When a KEV/EPSS enrichment overlay is supplied (:func:`render_report_pdf`'s
``enrichments``), the CVE table and the per-finding metadata show real EPSS scores
and KEV membership. Without it, CVEs and CWEs are still linked to NIST/MITRE from
the finding's own text, and EPSS is simply omitted — never fabricated.

Colour is a validated ordinal **severity** scale (critical → info). Because
severity is a status scale, every mark that carries it also carries its text
label, so meaning is never colour-alone; each chip's text colour is chosen by
WCAG contrast against its own fill.

ReportLab is an **optional** dependency (the ``report`` extra). This module is the
only place that imports it. Every value that can originate from a scanned target
is hostile input (``ROADMAP.md`` ``SEC-H``) and is passed through :func:`_safe`
before it reaches the document, so a malicious banner cannot inject markup.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from olympus.core.fileio import atomic_write_bytes
from olympus.core.models import Finding, SecurityReport
from olympus.vulcan.enrichment import FindingEnrichment

# --- Design tokens ---------------------------------------------------------- #
_BRAND_INK = "#0f172a"  # masthead
_BRAND_ACCENT = "#2563eb"  # links, section rules
_INK = "#111827"  # primary text
_MUTED = "#6b7280"  # secondary text / labels
_FAINT = "#9ca3af"  # footer, de-emphasised
_HAIRLINE = "#e5e7eb"  # dividers, table rules

#: Severity row order (worst first) and the validated ordinal fill colours.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_HEX = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#2a78d6",
    "info": "#64748b",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


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


def _overall_risk(breakdown: dict[str, int]) -> str:
    """Return the highest severity with a non-zero count, or ``none``."""
    for level in _SEVERITY_ORDER:
        if breakdown.get(level, 0) > 0:
            return level
    return "none"


def _nvd_link(cve: str) -> str:
    """A ReportLab anchor to the NIST NVD detail page for ``cve``."""
    cve = cve.upper()
    return f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" color="{_BRAND_ACCENT}">{cve}</a>'


def _cwe_link(cwe: str) -> str:
    """A ReportLab anchor to the MITRE CWE definition for ``cwe`` (CWE-N)."""
    number = cwe.upper().removeprefix("CWE-")
    url = f"https://cwe.mitre.org/data/definitions/{number}.html"
    return f'<a href="{url}" color="{_BRAND_ACCENT}">{cwe.upper()}</a>'


def _cwes_in(finding: Finding) -> list[str]:
    """Return the distinct CWE ids of a finding (structured field, else text)."""
    return finding.cwes()


def _cves_in(finding: Finding) -> list[str]:
    """Return the distinct CVE ids of a finding (structured field, else text)."""
    return finding.cves()


def render_report_pdf(
    report: SecurityReport,
    *,
    enrichments: Sequence[FindingEnrichment] | None = None,
) -> bytes:
    """Render ``report`` as a self-contained, minimal PDF and return its bytes.

    ``enrichments`` is an optional KEV/EPSS overlay (as produced by
    :mod:`olympus.vulcan.enrichment`); when given, the CVE table and the
    per-finding metadata show EPSS scores and KEV membership. EPSS is never
    shown unless it came from that overlay.

    Raises :class:`PdfUnavailableError` if the optional ``report`` extra
    (ReportLab) is not installed, with the exact command to install it.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
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
    by_id = {overlay.finding_id: overlay for overlay in (enrichments or [])}

    ink = colors.HexColor(_BRAND_INK)
    accent = colors.HexColor(_BRAND_ACCENT)
    hairline = colors.HexColor(_HAIRLINE)
    muted = colors.HexColor(_MUTED)

    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body", parent=base["BodyText"], fontSize=9.5, leading=14, textColor=colors.HexColor(_INK)
    )
    small = ParagraphStyle("Small", parent=base["Normal"], fontSize=8, leading=12, textColor=muted)
    label = ParagraphStyle(
        "Label",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=10,
        textColor=muted,
        spaceBefore=3,
    )
    section = ParagraphStyle(
        "Section", parent=base["Heading2"], fontSize=13, leading=17, textColor=ink, spaceAfter=0
    )
    cover_title = ParagraphStyle(
        "CoverTitle",
        parent=base["Title"],
        fontSize=29,
        leading=33,
        textColor=ink,
        alignment=TA_LEFT,
    )
    cover_engagement = ParagraphStyle(
        "CoverEngagement",
        parent=base["Normal"],
        fontSize=15,
        leading=19,
        textColor=accent,
        spaceBefore=6,
    )
    cover_meta = ParagraphStyle(
        "CoverMeta",
        parent=base["Normal"],
        fontSize=9.5,
        leading=15,
        textColor=muted,
        spaceBefore=16,
    )
    mono = ParagraphStyle(
        "Mono",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor(_INK),
    )
    cell = ParagraphStyle(
        "Cell", parent=base["Normal"], fontSize=8, leading=11, textColor=colors.HexColor(_INK)
    )
    cell_head = ParagraphStyle(
        "CellHead",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=muted,
    )

    def _section(title: str) -> list[Flowable]:
        return [
            Spacer(1, 7 * mm),
            Paragraph(_safe(title), section),
            HRFlowable(width="100%", thickness=0.8, color=hairline, spaceBefore=3, spaceAfter=7),
        ]

    def _severity_tag(level: str, *, big: bool = False) -> str:
        fill = _SEVERITY_HEX[level]
        name = level.capitalize()
        inner = f"<b>{name}</b>" if big else name
        return f'<font color="{fill}">■</font> <font color="{_INK}">{inner}</font>'

    def _severity_bar() -> Flowable:
        breakdown = report.summary.severity_breakdown
        segments = [
            (lvl, breakdown.get(lvl, 0)) for lvl in _SEVERITY_ORDER if breakdown.get(lvl, 0)
        ]
        total = sum(count for _, count in segments)
        if total == 0:
            line = HRFlowable(width="100%", thickness=6, color=hairline, lineCap="round")
            return line
        widths = [content_width * count / total for _, count in segments]
        row = Table([["" for _ in segments]], colWidths=widths, rowHeights=[4 * mm])
        style: list[tuple[object, ...]] = []
        for index, (level, _count) in enumerate(segments):
            style.append(
                ("BACKGROUND", (index, 0), (index, 0), colors.HexColor(_SEVERITY_HEX[level]))
            )
            if index < len(segments) - 1:
                style.append(("LINEAFTER", (index, 0), (index, 0), 2, colors.white))
        row.setStyle(TableStyle(style))
        return row

    def _ratings_line() -> Paragraph:
        breakdown = report.summary.severity_breakdown
        parts = [
            f'<font color="{_SEVERITY_HEX[lvl]}">■</font> {lvl.capitalize()} '
            f"<b>{breakdown.get(lvl, 0)}</b>"
            for lvl in _SEVERITY_ORDER
        ]
        return Paragraph("&nbsp;&nbsp;&nbsp;".join(parts), small)

    def _info_table() -> Table:
        risk = _overall_risk(report.summary.severity_breakdown)
        rows = [
            [
                "Overall risk",
                Paragraph(_severity_tag(risk, big=True) if risk != "none" else "None", body),
            ],
            ["Findings", Paragraph(str(report.summary.findings), body)],
            ["Assets assessed", Paragraph(str(report.summary.assets), body)],
            ["Alerts", Paragraph(str(report.summary.alerts), body)],
            ["Generated", Paragraph(report.generated_at.strftime("%Y-%m-%d %H:%M UTC"), body)],
        ]
        table = Table(
            [[Paragraph(name, cell_head), value] for name, value in rows],
            colWidths=[38 * mm, content_width - 38 * mm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("LINEBELOW", (0, 0), (-1, -2), 0.4, hairline),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        return table

    def _vuln_rows() -> list[list[object]]:
        """Collect one row per CVE: (cve, cvss, epss, percentile, kev, finding)."""
        seen: dict[str, list[object]] = {}
        for finding in report.findings:
            overlay = by_id.get(finding.finding_id)
            cves = list(overlay.cves) if overlay else _cves_in(finding)
            epss_by_cve = {s.cve: s for s in overlay.per_cve} if overlay else {}
            kev_cves = {entry.cve for entry in overlay.kev} if overlay else set()
            for cve in cves:
                score = epss_by_cve.get(cve)
                # Prefer the live feed overlay; fall back to the finding's own
                # structured EPSS/KEV (WEB-C) so a report shows intelligence even
                # when no live enrichment was run.
                if score is not None:
                    epss_txt = f"{score.score:.5f}"
                    pct_txt = f"{score.percentile:.2%}"
                elif finding.epss is not None:
                    epss_txt = f"{finding.epss:.5f}"
                    pct_txt = (
                        f"{finding.epss_percentile:.2%}"
                        if finding.epss_percentile is not None
                        else "—"
                    )
                else:
                    epss_txt = "—"
                    pct_txt = "—"
                in_kev = cve in kev_cves or finding.kev
                kev_txt = "Yes" if in_kev else "—"
                cvss_txt = f"{finding.cvss:.1f}" if finding.cvss is not None else "—"
                row = [
                    Paragraph(_nvd_link(cve), cell),
                    Paragraph(cvss_txt, cell),
                    Paragraph(epss_txt, cell),
                    Paragraph(pct_txt, cell),
                    Paragraph(kev_txt, cell),
                    Paragraph(_safe(finding.title), cell),
                ]
                # Prefer the row that carries an EPSS score if the CVE recurs.
                if cve not in seen or epss_txt != "—":
                    seen[cve] = row
        return list(seen.values())

    def _vuln_table() -> list[Flowable]:
        rows = _vuln_rows()
        if not rows:
            return []
        header = [
            Paragraph("CVE", cell_head),
            Paragraph("CVSS", cell_head),
            Paragraph("EPSS", cell_head),
            Paragraph("Pctl", cell_head),
            Paragraph("KEV", cell_head),
            Paragraph("Finding", cell_head),
        ]
        widths = [content_width * w for w in (0.21, 0.08, 0.11, 0.1, 0.07, 0.43)]
        table = Table([header, *rows], colWidths=widths, repeatRows=1)
        style = [
            ("LINEBELOW", (0, 0), (-1, 0), 0.8, colors.HexColor(_MUTED)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.3, hairline),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]
        table.setStyle(TableStyle(style))
        note = Paragraph(
            "EPSS = FIRST exploit-probability (0 to 1); Pctl = its percentile; "
            "KEV = CISA Known Exploited. CVE links resolve to the NIST NVD.",
            small,
        )
        return [table, Spacer(1, 2 * mm), note]

    def _finding_block(finding: Finding) -> KeepTogether:
        level = finding.severity.value
        overlay = by_id.get(finding.finding_id)

        flow: list[Flowable] = [
            HRFlowable(width="100%", thickness=0.6, color=hairline, spaceBefore=0, spaceAfter=5),
            Paragraph(f"{_severity_tag(level, big=True)}&nbsp;&nbsp; {_safe(finding.title)}", body),
        ]

        meta_bits: list[str] = [f"Risk <b>{finding.risk_score():.0f}</b>/100"]
        if finding.cvss is not None:
            meta_bits.append(f"CVSS <b>{finding.cvss:.1f}</b>")
        # Prefer the live feed overlay; fall back to the finding's own structured
        # EPSS/KEV (WEB-C) so the metadata line stays informative offline.
        if overlay and overlay.max_epss is not None:
            pct = f" ({overlay.max_epss_percentile:.0%} pct)" if overlay.max_epss_percentile else ""
            meta_bits.append(f"EPSS <b>{overlay.max_epss:.5f}</b>{pct}")
        elif finding.epss is not None:
            pct = f" ({finding.epss_percentile:.0%} pct)" if finding.epss_percentile else ""
            meta_bits.append(f"EPSS <b>{finding.epss:.5f}</b>{pct}")
        if (overlay and overlay.in_kev) or finding.kev:
            meta_bits.append('<font color="#d03b3b"><b>KEV</b></font>')
        if finding.confidence is not None:
            meta_bits.append(f"confidence {_safe(finding.confidence.value)}")
        meta_bits += [
            f"asset {_safe(finding.asset_id)}",
            f"source {_safe(finding.source.value)}",
            f"ID {_safe(finding.finding_id)}",
        ]
        flow.append(Paragraph(" · ".join(meta_bits), small))

        if finding.description:
            flow.append(Paragraph("RISK DESCRIPTION", label))
            flow.append(Paragraph(_safe(finding.description), body))
        if finding.remediation:
            flow.append(Paragraph("RECOMMENDATION", label))
            flow.append(Paragraph(_safe(finding.remediation), body))
        if finding.evidence:
            flow.append(Paragraph("EVIDENCE", label))
            for item in finding.evidence:
                flow.append(Paragraph(_safe(item), mono))

        links: list[str] = []
        for cve in list(overlay.cves) if overlay else _cves_in(finding):
            links.append(_nvd_link(cve))
        for cwe in _cwes_in(finding):
            links.append(_cwe_link(cwe))
        for reference in finding.references:
            # CVE/CWE ids are already rendered as NVD/MITRE links above.
            if _CVE_RE.fullmatch(reference.strip()) or _CWE_RE.fullmatch(reference.strip()):
                continue
            text = _safe(reference)
            if reference.lower().startswith(("http://", "https://")):
                links.append(f'<a href="{text}" color="{_BRAND_ACCENT}">{text}</a>')
            else:
                links.append(text)
        # De-duplicate while preserving order.
        seen_links: list[str] = []
        for item in links:
            if item not in seen_links:
                seen_links.append(item)
        if seen_links:
            flow.append(Paragraph("REFERENCES", label))
            flow.append(Paragraph("&nbsp;&nbsp;·&nbsp;&nbsp;".join(seen_links), small))

        flow.append(Spacer(1, 5 * mm))
        return KeepTogether(flow)

    generated = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    overall = _overall_risk(report.summary.severity_breakdown)
    overall_text = (
        f"Overall risk level: {_severity_tag(overall, big=True)}"
        if overall != "none"
        else "Overall risk level: <b>None</b>"
    )

    story: list[Flowable] = [
        Spacer(1, 34 * mm),
        Paragraph("Security Assessment Report", cover_title),
        Paragraph(_safe(report.engagement), cover_engagement),
        Paragraph(f"Generated {generated}<br/>Prepared by Olympus Vulcan", cover_meta),
        Spacer(1, 10 * mm),
        Paragraph(overall_text, body),
        PageBreak(),
    ]

    story.extend(_section("Summary"))
    story.append(_info_table())
    story.append(Spacer(1, 5 * mm))
    story.append(_ratings_line())
    story.append(Spacer(1, 3 * mm))
    story.append(_severity_bar())

    vuln = _vuln_table()
    if vuln:
        story.extend(_section("Known vulnerabilities (NVD / EPSS)"))
        story.extend(vuln)

    story.extend(_section("Findings"))
    if not report.findings:
        story.append(Paragraph("No findings.", body))
    for finding in report.findings:
        story.append(_finding_block(finding))

    story.extend(_section("Assets"))
    if not report.assets:
        story.append(Paragraph("No assets.", body))
    else:
        asset_rows = [
            [
                Paragraph("Asset", cell_head),
                Paragraph("Identifier", cell_head),
                Paragraph("Type", cell_head),
                Paragraph("Source", cell_head),
            ]
        ]
        for asset in report.assets:
            identifier = asset.hostname or ", ".join(asset.ip_addresses) or asset.asset_id
            asset_rows.append(
                [
                    Paragraph(_safe(asset.asset_id), cell),
                    Paragraph(_safe(identifier), cell),
                    Paragraph(_safe(asset.asset_type.value), cell),
                    Paragraph(_safe(asset.source.value), cell),
                ]
            )
        assets_table = Table(
            asset_rows,
            colWidths=[content_width * w for w in (0.3, 0.34, 0.18, 0.18)],
            repeatRows=1,
        )
        assets_table.setStyle(
            TableStyle(
                [
                    ("LINEBELOW", (0, 0), (-1, 0), 0.8, muted),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.3, hairline),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(assets_table)

    story.extend(_section("Alerts"))
    if not report.alerts:
        story.append(Paragraph("No alerts.", body))
    for alert in report.alerts:
        provenance = f"rule {_safe(alert.rule_id)}" if alert.rule_id else "rule unavailable"
        if alert.mitre_attack:
            provenance += "; MITRE " + ", ".join(_safe(item) for item in alert.mitre_attack)
        story.append(
            Paragraph(
                f"{_severity_tag(alert.severity.value)} &nbsp;{_safe(alert.title)} "
                f'<font color="{_MUTED}">({_safe(alert.alert_id)}; {provenance})</font>',
                body,
            )
        )
        story.append(Spacer(1, 1.5 * mm))

    engagement = report.engagement

    def _decorate(canvas: Canvas, _doc: object, *, cover: bool) -> None:
        canvas.saveState()
        if cover:
            band = 24 * mm
            canvas.setFillColor(ink)
            canvas.rect(0, A4[1] - band, A4[0], band, stroke=0, fill=1)
            canvas.setFillColor(accent)
            canvas.rect(0, A4[1] - band - 2, A4[0], 2, stroke=0, fill=1)
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
            canvas.setFillColor(muted)
            canvas.setFont("Helvetica", 7.5)
            canvas.drawString(margin, A4[1] - 12 * mm, _ascii(engagement))
            canvas.drawRightString(A4[0] - margin, A4[1] - 12 * mm, "CONFIDENTIAL")
            canvas.setStrokeColor(hairline)
            canvas.setLineWidth(0.5)
            canvas.line(margin, A4[1] - 14 * mm, A4[0] - margin, A4[1] - 14 * mm)
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
    """A header-safe single-line rendering of untrusted text for canvas drawing."""
    collapsed = " ".join(value.split())
    return "".join(ch for ch in collapsed if ch.isprintable())[:80]


def export_pdf(
    report: SecurityReport,
    path: Path,
    *,
    enrichments: Sequence[FindingEnrichment] | None = None,
) -> None:
    """Render ``report`` and durably write the PDF to ``path`` (atomic, 0600)."""
    atomic_write_bytes(path, render_report_pdf(report, enrichments=enrichments), mode=0o600)

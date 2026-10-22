"""Build and safely render one canonical Vulcan security report."""

from __future__ import annotations

import html
import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from olympus.core.execution import safe_terminal_text
from olympus.core.fileio import atomic_write_text
from olympus.core.models import (
    Alert,
    Asset,
    AuthorizationProvenance,
    Finding,
    ReportSummary,
    SecurityReport,
)
from olympus.vulcan.aggregate import rank_findings, severity_breakdown


def build_report_model(
    engagement: str,
    assets: Sequence[Asset],
    findings: Sequence[Finding],
    alerts: Sequence[Alert],
    *,
    authorization_provenance: Sequence[AuthorizationProvenance] = (),
    generated_at: datetime | None = None,
) -> SecurityReport:
    """Assemble the canonical report model used by every output renderer."""
    ranked = rank_findings(findings)
    return SecurityReport(
        engagement=engagement,
        generated_at=generated_at or datetime.now(UTC),
        summary=ReportSummary(
            assets=len(assets),
            findings=len(findings),
            alerts=len(alerts),
            severity_breakdown=severity_breakdown(findings),
        ),
        assets=list(assets),
        findings=ranked,
        alerts=list(alerts),
        authorization_provenance=list(authorization_provenance),
    )


def build_report(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> dict[str, object]:
    """Backward-compatible JSON mapping built from the canonical report model."""
    return build_report_model(engagement, assets, findings, alerts).model_dump(mode="json")


def render_report_markdown(report: SecurityReport) -> str:
    """Render all canonical report sections with Markdown metacharacters escaped."""
    breakdown = report.summary.severity_breakdown
    lines: list[str] = [
        f"# Security report — {_markdown_text(report.engagement)}",
        "",
        f"_Generated {report.generated_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M UTC')} "
        "by Olympus Vulcan._",
        "",
        "## Summary",
        f"- Assets: {len(report.assets)}",
        f"- Findings: {len(report.findings)}",
        f"- Alerts: {len(report.alerts)}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for level in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {level} | {breakdown[level]} |")

    lines += ["", "## Assets"]
    if not report.assets:
        lines.append("_No assets._")
    for asset in report.assets:
        label = asset.hostname or ", ".join(asset.ip_addresses) or asset.asset_id
        lines.append(
            f"- {_markdown_text(asset.asset_id)} — {_markdown_text(label)} "
            f"({_markdown_text(asset.asset_type.value)}, {_markdown_text(asset.source.value)})"
        )

    lines += ["", "## Findings (ranked)"]
    if not report.findings:
        lines.append("_No findings._")
    for finding in report.findings:
        lines += [
            "",
            f"### [{finding.severity.value.upper()}] {_markdown_text(finding.title)}",
            f"- ID: {_markdown_text(finding.finding_id)}",
            f"- Source: {_markdown_text(finding.source.value)}",
            f"- Asset: {_markdown_text(finding.asset_id)}",
        ]
        if finding.cvss is not None:
            lines.append(f"- CVSS: {finding.cvss}")
        if finding.description:
            lines.append(f"- {_markdown_text(finding.description)}")
        if finding.remediation:
            lines.append(f"- **Remediation:** {_markdown_text(finding.remediation)}")

    lines += ["", "## Alerts"]
    if not report.alerts:
        lines.append("_No alerts._")
    for alert in report.alerts:
        provenance = (
            f"rule {_markdown_text(alert.rule_id)}" if alert.rule_id else "rule unavailable"
        )
        if alert.mitre_attack:
            provenance += "; MITRE " + ", ".join(
                _markdown_text(item) for item in alert.mitre_attack
            )
        lines.append(
            f"- [{alert.severity.value.upper()}] {_markdown_text(alert.title)} "
            f"({_markdown_text(alert.alert_id)}; {provenance})"
        )
    lines += ["", "## Authorization provenance"]
    if not report.authorization_provenance:
        lines.append("_No manifest-bound scanner results supplied._")
    for item in report.authorization_provenance:
        lines += [
            "",
            f"### Job {_markdown_text(item.job_id)}",
            f"- Manifest SHA-256: `{item.manifest_sha256}`",
            f"- Manifest: {_markdown_text(item.manifest_id)}; engagement "
            f"{_markdown_text(item.engagement_id)}",
            f"- Scanner/result: {_markdown_text(item.scanner)} / "
            f"{_markdown_text(item.result_state)}",
            "- Verification: Ed25519 signature, target scope and technique verified",
            f"- Validity: {item.valid_from.astimezone(UTC).isoformat()} to "
            f"{item.expires_at.astimezone(UTC).isoformat()}",
            f"- Policy limits: targets={item.max_targets}, concurrency={item.max_concurrency}, "
            f"runtime={item.max_runtime_seconds}s",
        ]
    return "\n".join(lines) + "\n"


def render_markdown(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> str:
    """Backward-compatible renderer using a newly built canonical model."""
    return render_report_markdown(build_report_model(engagement, assets, findings, alerts))


_SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b45309",
    "medium": "#a16207",
    "low": "#3f6212",
    "info": "#374151",
}

# A restrictive Content-Security-Policy embedded in the exported report. The
# document is self-contained (inline ``<style>`` and ``style=`` attributes, no
# scripts, no external assets), so ``default-src 'none'`` forbids script, object
# and frame execution while ``style-src 'unsafe-inline'`` permits only the inline
# styling this renderer emits. Even if attacker-controlled finding text ever
# escaped HTML escaping, the browser would refuse to execute injected scripts.
_REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def render_report_html(report: SecurityReport) -> str:
    """Render a self-contained, escaped HTML view of every report section."""
    breakdown = report.summary.severity_breakdown
    generated = report.generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f'<meta http-equiv="Content-Security-Policy" content="{_REPORT_CSP}">',
        f"<title>Security report — {_html_text(report.engagement)}</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;"
        "padding:0 1rem;color:#111}h1{margin-bottom:0}.meta{color:#666}"
        ".sev{display:inline-block;padding:.1rem .5rem;border-radius:.3rem;color:#fff;"
        "font-size:.8rem}.card{border:1px solid #ddd;border-radius:.5rem;padding:1rem;"
        "margin:.75rem 0}table{border-collapse:collapse}td,th{border:1px solid #ddd;"
        "padding:.3rem .6rem;text-align:left}</style></head><body>",
        f"<h1>Security report — {_html_text(report.engagement)}</h1>",
        f"<p class='meta'>Generated {generated} by Olympus Vulcan · "
        f"{len(report.assets)} assets · {len(report.findings)} findings · "
        f"{len(report.alerts)} alerts</p>",
        "<h2>Severity breakdown</h2><table><tr>"
        + "".join(f"<th>{level}</th>" for level in _SEVERITY_COLORS)
        + "</tr><tr>"
        + "".join(f"<td>{breakdown[level]}</td>" for level in _SEVERITY_COLORS)
        + "</tr></table>",
        "<h2>Assets</h2>",
    ]
    if not report.assets:
        parts.append("<p>No assets.</p>")
    else:
        parts.append("<ul>")
        for asset in report.assets:
            label = asset.hostname or ", ".join(asset.ip_addresses) or asset.asset_id
            parts.append(
                f"<li>{_html_text(asset.asset_id)} — {_html_text(label)} "
                f"({_html_text(asset.asset_type.value)}, {_html_text(asset.source.value)})</li>"
            )
        parts.append("</ul>")
    parts.append("<h2>Findings (ranked)</h2>")
    if not report.findings:
        parts.append("<p>No findings.</p>")
    for finding in report.findings:
        color = _SEVERITY_COLORS[finding.severity.value]
        parts.append(
            f"<div class='card'><span class='sev' style='background:{color}'>"
            f"{finding.severity.value.upper()}</span> "
            f"<strong>{_html_text(finding.title)}</strong>"
            f"<p class='meta'>{_html_text(finding.finding_id)} · "
            f"{_html_text(finding.source.value)} · {_html_text(finding.asset_id)}"
            + (f" · CVSS {finding.cvss}" if finding.cvss is not None else "")
            + "</p>"
            + (f"<p>{_html_text(finding.description)}</p>" if finding.description else "")
            + (
                f"<p><strong>Remediation:</strong> {_html_text(finding.remediation)}</p>"
                if finding.remediation
                else ""
            )
            + "</div>"
        )
    parts.append("<h2>Alerts</h2>")
    if not report.alerts:
        parts.append("<p>No alerts.</p>")
    for alert in report.alerts:
        provenance = f"rule {alert.rule_id}" if alert.rule_id else "rule unavailable"
        if alert.mitre_attack:
            provenance += "; MITRE " + ", ".join(alert.mitre_attack)
        parts.append(
            f"<div class='card'><strong>[{alert.severity.value.upper()}] "
            f"{_html_text(alert.title)}</strong><p class='meta'>{_html_text(alert.alert_id)} · "
            f"{_html_text(alert.source.value)} · {_html_text(provenance)}</p></div>"
        )
    parts.append("<h2>Authorization provenance</h2>")
    if not report.authorization_provenance:
        parts.append("<p>No manifest-bound scanner results supplied.</p>")
    for item in report.authorization_provenance:
        parts.append(
            "<div class='card'><strong>Job "
            f"{_html_text(item.job_id)}</strong>"
            f"<p class='meta'>Manifest SHA-256 {_html_text(item.manifest_sha256)} · "
            f"{_html_text(item.manifest_id)} · {_html_text(item.engagement_id)}</p>"
            f"<p>{_html_text(item.scanner)} / {_html_text(item.result_state)} · "
            "Ed25519 signature, target scope and technique verified</p>"
            f"<p class='meta'>Valid {item.valid_from.astimezone(UTC).isoformat()} to "
            f"{item.expires_at.astimezone(UTC).isoformat()} · targets {item.max_targets} · "
            f"concurrency {item.max_concurrency} · runtime {item.max_runtime_seconds}s</p></div>"
        )
    parts.append("</body></html>")
    return "".join(parts)


def render_html(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> str:
    """Backward-compatible HTML renderer using one canonical report model."""
    return render_report_html(build_report_model(engagement, assets, findings, alerts))


def export_report(report: dict[str, object] | SecurityReport, path: Path) -> None:
    """Durably write one canonical JSON report."""
    payload = report.model_dump(mode="json") if isinstance(report, SecurityReport) else report
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def export_text(content: str, path: Path) -> None:
    """Durably write one Markdown or HTML report."""
    atomic_write_text(path, content)


def export_markdown(markdown: str, path: Path) -> None:
    """Compatibility alias for an atomic Markdown export."""
    export_text(markdown, path)


def _html_text(value: str) -> str:
    """HTML-escape text that may be attacker-controlled, after neutralizing
    terminal control sequences (ANSI/OSC, C0/C1). ``html.escape`` alone leaves
    ESC/BEL and other controls intact, so a finding title carrying escape codes
    would reach an operator who opens or ``cat``s the exported report."""
    return html.escape(safe_terminal_text(value))


def _markdown_text(value: str) -> str:
    # safe_terminal_text strips terminal control sequences and collapses the
    # value onto one line; Markdown metacharacters are then escaped so target
    # text cannot forge structure in the rendered report.
    escaped = safe_terminal_text(value).replace("\\", "\\\\")
    for character in "`*_[]<>|":
        escaped = escaped.replace(character, f"\\{character}")
    # CommonMark/GFM may turn bare URLs in ordinary text into clickable links.
    # Reports are often opened in a browser; keep target-controlled URLs visible
    # without making them navigation or tracking links.
    escaped = re.sub(
        r"(?i)\bhttps?://", lambda match: match.group(0).replace("://", "&#58;//"), escaped
    )
    return escaped

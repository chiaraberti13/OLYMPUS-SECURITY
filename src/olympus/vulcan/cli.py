"""Command-line presentation for bounded Vulcan application workflows."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.enums import Severity
from olympus.core.execution import CancellationRequested, ExecutionPolicyError
from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.core.output import OutputFormat, render
from olympus.core.paths import output_path
from olympus.vulcan.aggregate import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_ITEMS_PER_FILE,
    DEFAULT_MAX_TOTAL_ITEMS,
    AggregationError,
    load_findings,
)
from olympus.vulcan.application import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_TOTAL_INPUT_BYTES,
    VulcanApplicationService,
    VulcanRankRequest,
    VulcanReportRequest,
)
from olympus.vulcan.enrichment import (
    DEFAULT_MAX_FEED_BYTES,
    EnrichmentError,
    enrich_findings,
    extract_cves,
    fetch_epss_scores,
    fetch_kev_catalog,
    parse_epss_response,
    parse_kev_catalog,
    prioritize,
)
from olympus.vulcan.report import export_report, export_text

DEFAULT_REPORT_OUTPUT = output_path("vulcan-report.json")

app = typer.Typer(
    help="Vulcan — Findings aggregation & report engine.",
    no_args_is_help=True,
)
_APPLICATION_ERRORS = (
    AggregationError,
    CancellationRequested,
    EnrichmentError,
    ExecutionPolicyError,
    OSError,
    TimeoutError,
    ValueError,
)
DEFAULT_ENRICH_OUTPUT = output_path("vulcan-enrichment.json")


@app.command()
def report(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name for the report."),
    assets: list[Path] = typer.Option(
        [], "--assets", help="core.Asset JSON file(s) to include (repeatable)."
    ),
    findings: list[Path] = typer.Option(
        [], "--findings", help="core.Finding JSON file(s) to include (repeatable)."
    ),
    alerts: list[Path] = typer.Option(
        [], "--alerts", help="core.Alert JSON file(s) to include (repeatable)."
    ),
    output: Path = typer.Option(
        DEFAULT_REPORT_OUTPUT, "--output", help="JSON report output path."
    ),
    markdown: Path | None = typer.Option(
        None, "--markdown", help="If set, also write a Markdown report to this path."
    ),
    html_output: Path | None = typer.Option(
        None, "--html", help="If set, also write a self-contained HTML report to this path."
    ),
    min_severity: Severity | None = typer.Option(
        None, "--min-severity", help="Only include findings at or above this severity."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_total_input_bytes: int = typer.Option(
        DEFAULT_MAX_TOTAL_INPUT_BYTES, "--max-total-input-bytes"
    ),
    max_items_per_file: int = typer.Option(
        DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"
    ),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    max_output_bytes: int = typer.Option(DEFAULT_MAX_OUTPUT_BYTES, "--max-output-bytes"),
    deadline: float = typer.Option(120.0, "--deadline"),
) -> None:
    """Aggregate strict inputs into consistent JSON, Markdown and HTML views."""
    outputs = tuple(path for path in (output, markdown, html_output) if path is not None)
    try:
        outcome = VulcanApplicationService().report(
            VulcanReportRequest(
                engagement=engagement,
                asset_paths=tuple(assets),
                finding_paths=tuple(findings),
                alert_paths=tuple(alerts),
                excluded_paths=outputs,
                min_severity=min_severity,
                render_markdown=markdown is not None,
                render_html=html_output is not None,
                max_files=max_files,
                max_input_bytes=max_input_bytes,
                max_total_input_bytes=max_total_input_bytes,
                max_items_per_file=max_items_per_file,
                max_total_items=max_total_items,
                max_output_bytes=max_output_bytes,
                deadline_seconds=deadline,
            )
        )
        export_report(outcome.report, output)
        if markdown is not None and outcome.markdown is not None:
            export_text(outcome.markdown, markdown)
        if html_output is not None and outcome.html is not None:
            export_text(outcome.html, html_output)
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(json.dumps(outcome.report.summary.model_dump(mode="json"), indent=2, sort_keys=True))
    typer.echo(f"vulcan: wrote report to {output}", err=True)
    if markdown is not None:
        typer.echo(f"vulcan: wrote Markdown report to {markdown}", err=True)
    if html_output is not None:
        typer.echo(f"vulcan: wrote HTML report to {html_output}", err=True)


@app.command()
def enrich(
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to enrich (repeatable)."
    ),
    kev: Path | None = typer.Option(
        None, "--kev", help="Local CISA KEV catalogue JSON (offline enrichment)."
    ),
    epss: Path | None = typer.Option(
        None, "--epss", help="Local FIRST EPSS API JSON response (offline enrichment)."
    ),
    fetch: bool = typer.Option(
        False, "--fetch", help="Fetch KEV and EPSS live instead of reading local files."
    ),
    output: Path = typer.Option(DEFAULT_ENRICH_OUTPUT, "--output", help="Overlay JSON output."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render the ranked view as table or json."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    max_feed_bytes: int = typer.Option(DEFAULT_MAX_FEED_BYTES, "--max-feed-bytes"),
) -> None:
    """Overlay CVE risk (CISA KEV + FIRST EPSS) onto findings and rank by urgency.

    Reads KEV/EPSS from local files by default (offline, reproducible); ``--fetch``
    pulls both live. The overlay never mutates the finding contract.
    """
    try:
        loaded = load_findings(
            findings,
            max_files=max_files,
            max_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
        if fetch:
            all_cves = sorted({cve for finding in loaded for cve in extract_cves(finding)})
            kev_catalog = fetch_kev_catalog(max_bytes=max_feed_bytes)
            epss_scores = fetch_epss_scores(all_cves, max_bytes=max_feed_bytes)
        else:
            kev_catalog = (
                parse_kev_catalog(
                    read_regular_text(kev, max_bytes=max_feed_bytes, label="KEV feed")
                )
                if kev is not None
                else {}
            )
            epss_scores = (
                parse_epss_response(
                    read_regular_text(epss, max_bytes=max_feed_bytes, label="EPSS feed")
                )
                if epss is not None
                else {}
            )
        enrichments = enrich_findings(loaded, kev=kev_catalog, epss=epss_scores)
        ranked = prioritize(loaded, enrichments)
        overlay = [enrichment.to_dict() for _, enrichment in ranked]
        atomic_write_text(
            output, json.dumps(overlay, indent=2, sort_keys=True) + "\n", mode=0o600
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    columns = ["kev", "epss", "cvss", "severity", "cves", "title"]
    records: list[dict[str, object]] = [
        {
            "kev": "YES" if enrichment.in_kev else "",
            "epss": f"{enrichment.max_epss:.3f}" if enrichment.max_epss is not None else "",
            "cvss": finding.cvss if finding.cvss is not None else "",
            "severity": finding.severity.value,
            "cves": ",".join(enrichment.cves),
            "title": finding.title,
        }
        for finding, enrichment in ranked
    ]
    kev_hits = sum(1 for _, enrichment in ranked if enrichment.in_kev)
    typer.echo(render(records, columns, output_format, title="Findings by real-world risk"))
    typer.echo(
        f"vulcan: enriched {len(loaded)} finding(s); {kev_hits} in CISA KEV; overlay: {output}",
        err=True,
    )


@app.command()
def rank(
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to rank (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_total_input_bytes: int = typer.Option(
        DEFAULT_MAX_TOTAL_INPUT_BYTES, "--max-total-input-bytes"
    ),
    max_items_per_file: int = typer.Option(
        DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"
    ),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Load strict findings and print exact-ID-deduplicated severity ranking."""
    try:
        ranked = VulcanApplicationService().rank(
            VulcanRankRequest(
                finding_paths=tuple(findings),
                max_files=max_files,
                max_input_bytes=max_input_bytes,
                max_total_input_bytes=max_total_input_bytes,
                max_items_per_file=max_items_per_file,
                max_total_items=max_total_items,
                deadline_seconds=deadline,
            )
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    columns = ["severity", "title", "source", "asset_id", "finding_id"]
    records: list[dict[str, object]] = [
        {
            "severity": finding.severity.value,
            "title": finding.title,
            "source": finding.source.value,
            "asset_id": finding.asset_id,
            "finding_id": finding.finding_id,
        }
        for finding in ranked
    ]
    typer.echo(render(records, columns, output_format, title="Findings (ranked)"))

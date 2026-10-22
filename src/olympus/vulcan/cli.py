"""Command-line presentation for bounded Vulcan application workflows."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.execution import CancellationRequested, ExecutionPolicyError, safe_terminal_text
from olympus.core.exit_codes import ExitCode
from olympus.core.fileio import atomic_write_bytes, atomic_write_text, read_regular_text
from olympus.core.models import Asset, Finding
from olympus.core.output import OutputFormat, render, render_table
from olympus.core.paths import output_path
from olympus.minerva.application import (
    MinervaApplicationService,
    MinervaLedgerRequest,
    load_evidence,
)
from olympus.minerva.custody import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_LEDGER_BYTES,
    CustodyRecord,
    load_custody_key,
)
from olympus.vulcan.aggregate import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_ITEMS_PER_FILE,
    DEFAULT_MAX_TOTAL_ITEMS,
    AggregationError,
    load_assets,
    load_findings,
)
from olympus.vulcan.application import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_TOTAL_INPUT_BYTES,
    VulcanApplicationService,
    VulcanRankRequest,
    VulcanReportRequest,
)
from olympus.vulcan.compare import ScanDiff, diff_findings
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
from olympus.vulcan.evidence_view import (
    LIST_COLUMNS as EVIDENCE_COLUMNS,
)
from olympus.vulcan.evidence_view import (
    build_finding_evidence_view,
)
from olympus.vulcan.pdf import PdfUnavailableError
from olympus.vulcan.portable import (
    PortabilityError,
)
from olympus.vulcan.portable import (
    export_assets as portable_export_assets,
)
from olympus.vulcan.portable import (
    export_findings as portable_export_findings,
)
from olympus.vulcan.portable import (
    import_assets as portable_import_assets,
)
from olympus.vulcan.portable import (
    import_findings as portable_import_findings,
)
from olympus.vulcan.report import export_report, export_text
from olympus.vulcan.sarif import SarifImportError, findings_to_sarif, sarif_to_findings
from olympus.vulcan.search import FindingFilter, search_findings
from olympus.vulcan.trend import build_finding_trend
from olympus.vulcan.view import LIST_COLUMNS, FindingView, rank_by_risk

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
    output: Path = typer.Option(DEFAULT_REPORT_OUTPUT, "--output", help="JSON report output path."),
    markdown: Path | None = typer.Option(
        None, "--markdown", help="If set, also write a Markdown report to this path."
    ),
    html_output: Path | None = typer.Option(
        None, "--html", help="If set, also write a self-contained HTML report to this path."
    ),
    pdf_output: Path | None = typer.Option(
        None,
        "--pdf",
        help="If set, also write a formatted PDF report (needs the 'report' extra).",
    ),
    kev: Path | None = typer.Option(
        None, "--kev", help="Local CISA KEV catalogue JSON: adds KEV flags to the PDF (offline)."
    ),
    epss: Path | None = typer.Option(
        None,
        "--epss",
        help="Local FIRST EPSS response JSON: adds EPSS scores to the PDF (offline).",
    ),
    min_severity: Severity | None = typer.Option(
        None, "--min-severity", help="Only include findings at or above this severity."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_total_input_bytes: int = typer.Option(
        DEFAULT_MAX_TOTAL_INPUT_BYTES, "--max-total-input-bytes"
    ),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    max_output_bytes: int = typer.Option(DEFAULT_MAX_OUTPUT_BYTES, "--max-output-bytes"),
    deadline: float = typer.Option(120.0, "--deadline"),
) -> None:
    """Aggregate strict inputs into consistent JSON, Markdown, HTML and PDF views."""
    outputs = tuple(
        path for path in (output, markdown, html_output, pdf_output) if path is not None
    )
    try:
        kev_catalog = (
            parse_kev_catalog(
                read_regular_text(kev, max_bytes=DEFAULT_MAX_FEED_BYTES, label="KEV feed")
            )
            if kev is not None
            else {}
        )
        epss_scores = (
            parse_epss_response(
                read_regular_text(epss, max_bytes=DEFAULT_MAX_FEED_BYTES, label="EPSS feed")
            )
            if epss is not None
            else {}
        )
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
                render_pdf=pdf_output is not None,
                kev_catalog=kev_catalog,
                epss_scores=epss_scores,
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
        if pdf_output is not None and outcome.pdf is not None:
            atomic_write_bytes(pdf_output, outcome.pdf, mode=0o600)
    except PdfUnavailableError as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    typer.echo(json.dumps(outcome.report.summary.model_dump(mode="json"), indent=2, sort_keys=True))
    typer.echo(f"vulcan: wrote report to {output}", err=True)
    if markdown is not None:
        typer.echo(f"vulcan: wrote Markdown report to {markdown}", err=True)
    if html_output is not None:
        typer.echo(f"vulcan: wrote HTML report to {html_output}", err=True)
    if pdf_output is not None:
        typer.echo(f"vulcan: wrote PDF report to {pdf_output}", err=True)


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
        atomic_write_text(output, json.dumps(overlay, indent=2, sort_keys=True) + "\n", mode=0o600)
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

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
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
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
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
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


def _diff_row(finding: Finding) -> list[str]:
    """One compact row for a scan-diff section, reusing the shared finding view."""
    cells = FindingView(finding).row()
    return [cells["risk"], cells["severity"], cells["title"], cells["asset"], cells["cve"]]


@app.command("diff")
def diff(
    baseline: list[Path] = typer.Option(
        ..., "--baseline", help="Earlier-run core.Finding JSON file(s) (repeatable)."
    ),
    current: list[Path] = typer.Option(
        ..., "--current", help="Later-run core.Finding JSON file(s) (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """Compare two assessment runs: what is new, resolved and still persistent.

    Findings are matched by logical identity (same asset + same vulnerability),
    not by the per-run id, so the same issue seen twice is recognised as one.
    The classification reuses ``vulcan.compare.diff_findings`` — the single place
    that decides new/resolved/persistent — so the CLI and the Web UI agree. Exit
    code ``1`` when the current run introduced any new finding (a regression the
    caller may want to act on), ``0`` when it did not.
    """
    try:
        base_findings = _load_for_view(
            baseline,
            max_files=max_files,
            max_input_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
        current_findings = _load_for_view(
            current,
            max_files=max_files,
            max_input_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    result: ScanDiff = diff_findings(base_findings, current_findings)
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        columns = ["risk", "severity", "title", "asset", "cve"]
        typer.echo(
            render_table(columns, [_diff_row(f) for f in result.new], title="New (regressions)")
        )
        typer.echo(render_table(columns, [_diff_row(f) for f in result.resolved], title="Resolved"))
        typer.echo(
            render_table(
                [*columns, "severity change"],
                [
                    [
                        *_diff_row(item.current),
                        (
                            f"{item.baseline.severity.value} → {item.current.severity.value}"
                            if item.severity_changed
                            else "—"
                        ),
                    ]
                    for item in result.persistent
                ],
                title="Persistent",
            )
        )
    summary = result.summary()
    typer.echo(
        "vulcan: {new} new, {resolved} resolved, {persistent} persistent "
        "({worsened} worsened)".format(**summary),
        err=True,
    )
    raise typer.Exit(code=ExitCode.FINDINGS if result.has_regressions else ExitCode.OK)


@app.command("trend")
def trend(
    snapshot: list[Path] = typer.Option(
        ...,
        "--snapshot",
        help="A core.Finding JSON bundle for one run, oldest first (repeatable, min 2).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """Show the finding severity trend across an ordered series of runs.

    Each ``--snapshot`` is one run's finding bundle, given oldest first. The trend
    reuses ``vulcan.trend.build_finding_trend`` — which in turn reuses the shared
    diff and severity breakdown — so the CLI and any report agree. Exit code ``1``
    when the most recent snapshot introduced any new finding (a regression), ``0``
    otherwise.
    """
    if len(snapshot) < 2:
        typer.echo("vulcan: trend needs at least two --snapshot bundles", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    try:
        snapshots = [
            (
                path.stem,
                _load_for_view(
                    [path],
                    max_files=max_files,
                    max_input_bytes=max_input_bytes,
                    max_items_per_file=max_items_per_file,
                    max_total_items=max_total_items,
                ),
            )
            for path in snapshot
        ]
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    result = build_finding_trend(snapshots)
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        columns = ["run", "total", "critical", "high", "medium", "low", "info", "new", "resolved"]
        rows = [
            [
                safe_terminal_text(point.label),
                str(point.total),
                str(point.severity_breakdown["critical"]),
                str(point.severity_breakdown["high"]),
                str(point.severity_breakdown["medium"]),
                str(point.severity_breakdown["low"]),
                str(point.severity_breakdown["info"]),
                "—" if point.is_baseline else str(point.new),
                "—" if point.is_baseline else str(point.resolved),
            ]
            for point in result.points
        ]
        typer.echo(render_table(columns, rows, title="Finding trend (oldest first)"))
    raise typer.Exit(code=ExitCode.FINDINGS if result.regressed else ExitCode.OK)


#: Bound the NDJSON import file so a hostile file cannot exhaust memory on read.
_MAX_IMPORT_BYTES = 64 * 1024 * 1024


@app.command("export")
def export_command(
    kind: str = typer.Option(..., "--kind", help="What to export: 'findings' or 'assets'."),
    input_files: list[Path] = typer.Option(
        ..., "--input", "-i", help="core.Finding/Asset JSON bundle(s) to read (repeatable)."
    ),
    output: Path = typer.Option(..., "--output", "-o", help="Portable NDJSON file to write."),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """Export findings or assets to portable, versioned NDJSON (one record per line).

    The file is reimportable with ``vulcan import`` and round-trips losslessly with
    the JSON bundles the loaders consume. Records are sorted by id, so the output
    is deterministic and diffable.
    """
    if kind not in {"findings", "assets"}:
        typer.echo("vulcan: --kind must be 'findings' or 'assets'", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    try:
        loader = load_findings if kind == "findings" else load_assets
        loaded = loader(
            input_files,
            max_files=max_files,
            max_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
        serialise = portable_export_findings if kind == "findings" else portable_export_assets
        atomic_write_text(output, serialise(loaded), mode=0o600)  # type: ignore[arg-type]
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(json.dumps({"kind": kind, "exported": len(loaded), "output": str(output)}, indent=2))


@app.command("import")
def import_command(
    kind: str = typer.Option(..., "--kind", help="What to import: 'findings' or 'assets'."),
    input_file: Path = typer.Option(..., "--input", "-i", help="Portable NDJSON file to read."),
    output: Path = typer.Option(..., "--output", "-o", help="core.* JSON bundle to write."),
) -> None:
    """Import findings or assets from portable NDJSON into a JSON bundle.

    Strict and all-or-nothing: the whole file is parsed and validated against the
    versioned contract before anything is written, so a malformed record imports
    nothing. The output is a canonical JSON array the Olympus loaders accept.
    """
    if kind not in {"findings", "assets"}:
        typer.echo("vulcan: --kind must be 'findings' or 'assets'", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    try:
        text = read_regular_text(input_file, max_bytes=_MAX_IMPORT_BYTES, label="vulcan import")
        parse = portable_import_findings if kind == "findings" else portable_import_assets
        records: list[Finding] | list[Asset] = parse(text)
    except (OSError, ValueError, PortabilityError) as exc:
        typer.echo(safe_terminal_text(f"vulcan: invalid import: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    bundle = [record.model_dump(mode="json") for record in records]
    atomic_write_text(output, json.dumps(bundle, indent=2, sort_keys=True) + "\n", mode=0o600)
    typer.echo(
        json.dumps({"kind": kind, "imported": len(records), "output": str(output)}, indent=2)
    )


@app.command("sarif-import")
def sarif_import_command(
    input_file: Path = typer.Option(..., "--input", "-i", help="SARIF 2.1.0 JSON file to import."),
    output: Path = typer.Option(..., "--output", "-o", help="core.Finding JSON bundle to write."),
    asset_id: str = typer.Option(
        ..., "--asset-id", help="Olympus asset id these SARIF results pertain to."
    ),
    source: Source = typer.Option(
        Source.MANUAL, "--source", help="Provenance stamped on the imported findings."
    ),
) -> None:
    """Import a third-party SARIF 2.1.0 report as a core.Finding JSON bundle.

    SARIF is the interoperability format for analysis results, so this ingests any
    SARIF-producing tool's findings into Olympus for the same lifecycle, dedup,
    diff, trend and reporting. The document is treated as hostile input: strict
    2.1.0 validation, type-checked fields and bounded sizes. A malformed document
    exits ``2`` and writes nothing. The output is a canonical JSON array the
    Olympus loaders accept.
    """
    try:
        text = read_regular_text(input_file, max_bytes=_MAX_IMPORT_BYTES, label="SARIF import")
        document = json.loads(text)
    except (OSError, ValueError) as exc:
        typer.echo(safe_terminal_text(f"vulcan: cannot read SARIF: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        findings = sarif_to_findings(document, asset_id=asset_id, source=source)
    except SarifImportError as exc:
        typer.echo(safe_terminal_text(f"vulcan: invalid SARIF: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    bundle = [finding.model_dump(mode="json") for finding in findings]
    atomic_write_text(output, json.dumps(bundle, indent=2, sort_keys=True) + "\n", mode=0o600)
    typer.echo(json.dumps({"imported": len(findings), "output": str(output)}, indent=2))


@app.command("sarif-export")
def sarif_export_command(
    input_files: list[Path] = typer.Option(
        ..., "--input", "-i", help="core.Finding JSON bundle(s) to export (repeatable)."
    ),
    output: Path = typer.Option(..., "--output", "-o", help="SARIF 2.1.0 JSON file to write."),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """Export findings as a SARIF 2.1.0 document for any SARIF consumer.

    Deterministic (results sorted by finding id). Severity maps to the SARIF level
    and the full Olympus severity/provenance/status/risk/CVE-CWE-KEV ride in each
    result's ``properties`` bag, so a SARIF-aware tool keeps the detail and a
    re-import loses nothing but the four-level severity collapse.
    """
    try:
        loaded = load_findings(
            input_files,
            max_files=max_files,
            max_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    document = findings_to_sarif(loaded)
    atomic_write_text(output, json.dumps(document, indent=2, sort_keys=True) + "\n", mode=0o600)
    typer.echo(json.dumps({"exported": len(loaded), "output": str(output)}, indent=2))


findings_app = typer.Typer(
    help="Browse, filter and inspect findings (ROADMAP WEB-C).",
    no_args_is_help=True,
)
app.add_typer(findings_app, name="findings")


def _load_for_view(
    paths: list[Path],
    *,
    max_files: int,
    max_input_bytes: int,
    max_items_per_file: int,
    max_total_items: int,
) -> list[Finding]:
    return load_findings(
        paths,
        max_files=max_files,
        max_bytes=max_input_bytes,
        max_items_per_file=max_items_per_file,
        max_total_items=max_total_items,
    )


@findings_app.command("list")
def findings_list(
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to view (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    status: list[FindingStatus] = typer.Option(
        [], "--status", help="Keep only findings in these statuses (repeatable)."
    ),
    source: list[Source] = typer.Option(
        [], "--source", help="Keep only findings from these sources (repeatable)."
    ),
    min_severity: Severity | None = typer.Option(
        None, "--min-severity", help="Keep only findings at or above this severity."
    ),
    engagement: str | None = typer.Option(
        None, "--engagement", help="Keep only findings linked to this engagement id."
    ),
    kev_only: bool = typer.Option(False, "--kev-only", help="Keep only CISA KEV-listed findings."),
    has_cve: bool | None = typer.Option(
        None, "--has-cve/--no-cve", help="Keep only findings that have (or lack) any CVE."
    ),
    tag: list[str] = typer.Option(
        [], "--tag", help="Require ALL of these tags, case-insensitive (repeatable)."
    ),
    text: str = typer.Option(
        "", "--text", help="Case-insensitive substring across finding fields."
    ),
    min_risk: float | None = typer.Option(
        None, "--min-risk", min=0.0, max=100.0, help="Keep only findings with risk score >= this."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """List findings, filtered and ordered by descending risk.

    The filter reuses ``vulcan.search.FindingFilter`` (the single place that
    decides what each criterion means) and the rows reuse
    ``vulcan.view.FindingView``, so the CLI narrows and renders findings exactly
    like the TUI and Web UI will. Absent data is shown as ``—``, never a
    fabricated zero.
    """
    try:
        loaded = _load_for_view(
            findings,
            max_files=max_files,
            max_input_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    query = FindingFilter(
        statuses=frozenset(status),
        sources=frozenset(source),
        min_severity=min_severity,
        engagement_id=engagement,
        kev_only=kev_only,
        has_cve=has_cve,
        tags=frozenset(tag),
        text=text,
        min_risk_score=min_risk,
    )
    views = [FindingView(finding) for finding in rank_by_risk(search_findings(loaded, query))]

    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps([view.detail() for view in views], indent=2, sort_keys=True))
    else:
        rows = [[view.row()[column] for column in LIST_COLUMNS] for view in views]
        typer.echo(render_table(list(LIST_COLUMNS), rows, title="Findings"))
    typer.echo(
        f"vulcan: {len(views)} finding(s) matched of {len(loaded)} loaded",
        err=True,
    )


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(..., help="The finding_id to inspect."),
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to search (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a field table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
) -> None:
    """Show one finding's full view, with every column and absent data as ``—``."""
    try:
        loaded = _load_for_view(
            findings,
            max_files=max_files,
            max_input_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    match = next((finding for finding in loaded if finding.finding_id == finding_id), None)
    if match is None:
        typer.echo(
            safe_terminal_text(f"vulcan: no finding with id {finding_id!r} in the given file(s)"),
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    view = FindingView(match)
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(view.detail(), indent=2, sort_keys=True))
    else:
        rows = [[label, value] for label, value in view.display_items()]
        typer.echo(render_table(["field", "value"], rows, title=f"Finding {finding_id}"))


@findings_app.command("evidence")
def findings_evidence(
    finding_id: str = typer.Argument(..., help="The finding_id whose evidence to browse."),
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to search (repeatable)."
    ),
    ledger: Path | None = typer.Option(
        None,
        "--ledger",
        help="Minerva custody ledger JSON: resolves the chain of custody for "
        "structured EVD-* evidence (verified; HMAC checked when the key is set).",
    ),
    evidence: list[Path] = typer.Option(
        [],
        "--evidence",
        help="core.Evidence JSON file(s) to resolve type/URI/digest (repeatable).",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_items_per_file: int = typer.Option(DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    max_ledger_bytes: int = typer.Option(DEFAULT_MAX_LEDGER_BYTES, "--max-ledger-bytes"),
    max_entries: int = typer.Option(DEFAULT_MAX_ENTRIES, "--max-entries"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Browse one finding's evidence, resolved against Minerva's chain of custody.

    Each evidence reference the finding carries is classified as a structured
    ``EVD-YYYY-NNNNN`` record or an inline snippet. Structured references are
    resolved against an optional ``--ledger`` (the verified Minerva custody chain
    and its signature state) and optional ``--evidence`` records (type, URI,
    digest); inline snippets are shown redacted and stripped of terminal control
    sequences. Raw evidence content is never read — only digests and custody
    metadata — and absent custody renders honestly as ``no-custody`` rather than a
    blank (ROADMAP ``WEB-C`` / ``SEC-H``).
    """
    try:
        loaded = _load_for_view(
            findings,
            max_files=max_files,
            max_input_bytes=max_input_bytes,
            max_items_per_file=max_items_per_file,
            max_total_items=max_total_items,
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    match = next((finding for finding in loaded if finding.finding_id == finding_id), None)
    if match is None:
        typer.echo(
            safe_terminal_text(f"vulcan: no finding with id {finding_id!r} in the given file(s)"),
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    custody_records: tuple[CustodyRecord, ...] = ()
    signed = signature_verified = False
    evidence_anchored = True
    try:
        if ledger is not None:
            outcome = MinervaApplicationService().inspect(
                MinervaLedgerRequest(
                    ledger, max_ledger_bytes, max_entries, deadline, key=load_custody_key()
                )
            )
            custody_records = outcome.entries
            signed = outcome.signed
            signature_verified = outcome.signature_verified
            evidence_anchored = outcome.evidence_anchored
        evidence_records = {
            record.evidence_id: record for record in (load_evidence(path) for path in evidence)
        }
    except _APPLICATION_ERRORS as exc:
        typer.echo(safe_terminal_text(f"vulcan: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    view = build_finding_evidence_view(
        match,
        custody_records=custody_records,
        evidence_records=evidence_records,
        signed=signed,
        signature_verified=signature_verified,
        evidence_anchored=evidence_anchored,
    )

    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(view.detail(), indent=2, sort_keys=True))
    else:
        rows = [[row[column] for column in EVIDENCE_COLUMNS] for row in view.rows()]
        typer.echo(render_table(list(EVIDENCE_COLUMNS), rows, title=f"Evidence for {finding_id}"))
    typer.echo(
        f"vulcan: {len(view.items)} evidence reference(s); "
        f"custody signature: {view.custody_signature()}",
        err=True,
    )

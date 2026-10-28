"""Unit tests for the Vulcan aggregation & report engine."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.execution import CancellationRequested, CancellationToken
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.aggregate import (
    AggregationError,
    asset_breakdown,
    dedupe_alerts,
    dedupe_findings,
    load_assets,
    load_findings,
    merge_duplicate_findings,
    rank_findings,
    severity_breakdown,
    source_breakdown,
)
from olympus.vulcan.application import (
    VulcanApplicationService,
    VulcanRankRequest,
    VulcanReportRequest,
)
from olympus.vulcan.report import (
    build_report,
    build_report_model,
    render_html,
    render_markdown,
    render_report_csv,
    render_report_html,
    render_report_markdown,
)

runner = CliRunner()


def _finding(title: str, severity: Severity, asset_id: str = "AST-1") -> Finding:
    return Finding(asset_id=asset_id, source=Source.ARTEMIS, title=title, severity=severity)


def _write(path: Path, models: list[Finding]) -> Path:
    path.write_text(json.dumps([json.loads(m.model_dump_json()) for m in models]), encoding="utf-8")
    return path


def test_load_findings_from_array(tmp_path: Path) -> None:
    path = _write(tmp_path / "f.json", [_finding("a", Severity.LOW)])
    loaded = load_findings([path])
    assert len(loaded) == 1
    assert loaded[0].title == "a"


def test_load_findings_from_versioned_collection(tmp_path: Path) -> None:
    finding = _finding("wrapped", Severity.MEDIUM)
    path = tmp_path / "wrapped.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.helios-findings",
                "schema_version": "1.0.0",
                "findings": [finding.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )

    assert load_findings([path]) == [finding]


def test_versioned_envelope_is_strict_and_argus_fronting_is_connected(tmp_path: Path) -> None:
    asset = Asset(asset_type=AssetType.DOMAIN, hostname="example.test", source=Source.ARGUS)
    finding = _finding("origin", Severity.MEDIUM, asset.asset_id)
    path = tmp_path / "fronting.json"
    payload = {
        "schema_name": "olympus.argus-fronting",
        "schema_version": "1.0.0",
        "domain": "example.test",
        "fronted": True,
        "cdn_providers": ["demo"],
        "asset": asset.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json")],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_assets([path]) == [asset]
    assert load_findings([path]) == [finding]

    payload["unexpected"] = "not ignored"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AggregationError, match="invalid envelope"):
        load_findings([path])


def test_load_findings_rejects_incompatible_collection_version(tmp_path: Path) -> None:
    path = tmp_path / "future.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.helios-findings",
                "schema_version": "2.0.0",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(AggregationError, match="incompatible contract"):
        load_findings([path])


def test_load_findings_accepts_single_object(tmp_path: Path) -> None:
    finding = _finding("solo", Severity.HIGH)
    (tmp_path / "one.json").write_text(finding.model_dump_json(), encoding="utf-8")
    assert len(load_findings([tmp_path / "one.json"])) == 1


def test_load_missing_file_errors(tmp_path: Path) -> None:
    with pytest.raises(AggregationError, match="not found"):
        load_findings([tmp_path / "nope.json"])


def test_load_invalid_payload_errors(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text(json.dumps([{"not": "a finding"}]), encoding="utf-8")
    with pytest.raises(AggregationError, match="failed validation"):
        load_findings([tmp_path / "bad.json"])


def test_dedupe_and_rank() -> None:
    duplicate = _finding("dup", Severity.LOW)
    findings = [
        duplicate,
        duplicate,
        _finding("crit", Severity.CRITICAL),
    ]
    deduped = dedupe_findings(findings)
    assert len(deduped) == 2
    ranked = rank_findings(deduped)
    assert ranked[0].severity is Severity.CRITICAL  # critical ranks first


def test_merge_collapses_cross_scanner_duplicates_without_losing_evidence() -> None:
    # Two scanners report the same CVE on the same asset with different ids.
    nmap = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title="Log4Shell (scanner A)",
        severity=Severity.HIGH,
        cvss=7.5,
        cve=["CVE-2021-44228"],
        evidence=["ev-a"],
        references=["https://a"],
    )
    nuclei = Finding(
        asset_id="AST-1",
        source=Source.HELIOS,
        title="Log4j RCE (scanner B)",
        severity=Severity.CRITICAL,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        cwe=["CWE-502"],
        evidence=["ev-b"],
        references=["https://b"],
        kev=True,
        epss=0.97,
    )
    merged = merge_duplicate_findings([nmap, nuclei])
    assert len(merged) == 1
    result = merged[0]
    # Most urgent signal wins for each scalar; nothing is lost.
    assert result.severity is Severity.CRITICAL
    assert result.cvss == 10.0
    assert result.kev is True
    assert result.epss == 0.97
    assert result.cwe == ["CWE-502"]
    assert set(result.evidence) == {"ev-a", "ev-b"}
    assert set(result.references) == {"https://a", "https://b"}


def test_merge_keeps_distinct_vulnerabilities_separate() -> None:
    same_asset_other_cve = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title="Other issue",
        severity=Severity.MEDIUM,
        cve=["CVE-2020-0001"],
    )
    log4shell = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title="Log4Shell",
        severity=Severity.HIGH,
        cve=["CVE-2021-44228"],
    )
    other_asset = _finding("Log4Shell", Severity.HIGH, asset_id="AST-2")
    other_asset = other_asset.model_copy(update={"cve": ["CVE-2021-44228"]})
    merged = merge_duplicate_findings([same_asset_other_cve, log4shell, other_asset])
    # Different CVE and different asset are never collapsed.
    assert len(merged) == 3


def test_merge_is_idempotent_and_passes_singletons_through() -> None:
    findings = [_finding("solo", Severity.LOW)]
    once = merge_duplicate_findings(findings)
    assert once == findings
    assert merge_duplicate_findings(once) == once


def test_dedupe_never_discards_distinct_or_conflicting_records() -> None:
    first = _finding("same", Severity.LOW)
    distinct = _finding("same", Severity.LOW)
    assert len(dedupe_findings([first, distinct])) == 2
    conflict = first.model_copy(update={"description": "changed"})
    with pytest.raises(AggregationError, match="conflicting duplicate finding ID"):
        dedupe_findings([first, conflict])

    alert = Alert(alert_id="ALT-ONE", event_id="EVT-1", title="one", source=Source.APOLLO)
    with pytest.raises(AggregationError, match="conflicting duplicate alert ID"):
        dedupe_alerts([alert, alert.model_copy(update={"title": "changed"})])


def test_severity_breakdown_covers_all_levels() -> None:
    counts = severity_breakdown([_finding("a", Severity.HIGH), _finding("b", Severity.HIGH)])
    assert counts["high"] == 2
    assert counts["info"] == 0


def test_source_breakdown_counts_only_producing_sources_ordered() -> None:
    findings = [
        Finding(asset_id="AST-1", source=Source.ARGUS, title="a", severity=Severity.LOW),
        Finding(asset_id="AST-1", source=Source.ARGUS, title="b", severity=Severity.LOW),
        Finding(asset_id="AST-1", source=Source.ARGUS, title="c", severity=Severity.LOW),
        Finding(asset_id="AST-1", source=Source.VULCAN, title="d", severity=Severity.LOW),
        Finding(asset_id="AST-1", source=Source.MINERVA, title="e", severity=Severity.LOW),
    ]
    counts = source_breakdown(findings)
    # Only sources that actually produced findings appear, ordered by count
    # descending then source name — not every member of the Source enum.
    assert list(counts.items()) == [("argus", 3), ("minerva", 1), ("vulcan", 1)]
    assert source_breakdown([]) == {}


def test_asset_breakdown_orders_by_worst_severity_then_count() -> None:
    findings = [
        _finding("a1", Severity.LOW, asset_id="AST-A"),
        _finding("a2", Severity.CRITICAL, asset_id="AST-A"),
        _finding("b1", Severity.HIGH, asset_id="AST-B"),
        _finding("b2", Severity.HIGH, asset_id="AST-B"),
        _finding("c1", Severity.HIGH, asset_id="AST-C"),
    ]
    exposures = asset_breakdown(findings)
    # AST-A is worst (critical) despite fewer-than-tied counts; AST-B and AST-C
    # share the highest severity (high) so the higher finding count wins.
    assert [(e.asset_id, e.finding_count, e.highest_severity) for e in exposures] == [
        ("AST-A", 2, Severity.CRITICAL),
        ("AST-B", 2, Severity.HIGH),
        ("AST-C", 1, Severity.HIGH),
    ]
    assert asset_breakdown([]) == []


def test_build_report_and_markdown() -> None:
    assets = [Asset(asset_type=AssetType.HOST, hostname="h1", source=Source.ARGUS)]
    findings = [_finding("SQLi", Severity.CRITICAL)]
    alerts = [Alert(event_id="EVT-1", title="brute force", source=Source.APOLLO)]
    report = build_report("eng", assets, findings, alerts)
    assert report["schema_name"] == "olympus.security-report"
    assert report["schema_version"] == "1.1.0"
    summary = report["summary"]
    assert isinstance(summary, dict)
    assert summary["findings"] == 1
    md = render_markdown("eng", assets, findings, alerts)
    assert "# Security report — eng" in md
    assert "SQLi" in md
    assert "brute force" in md


def test_security_report_previous_minor_remains_a_supported_input(tmp_path: Path) -> None:
    finding = _finding("legacy report finding", Severity.MEDIUM)
    report = build_report("eng", [], [finding], [])
    report["schema_version"] = "1.0.0"
    report.pop("authorization_provenance")
    path = tmp_path / "report-1.0.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert load_findings([path]) == [finding]

    report["schema_version"] = "1.2.0"
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(AggregationError, match="incompatible contract"):
        load_findings([path])


def test_cli_report_end_to_end(tmp_path: Path) -> None:
    duplicate = _finding("SQLi", Severity.CRITICAL)
    findings_path = _write(
        tmp_path / "f.json",
        [duplicate, duplicate],
    )
    out = tmp_path / "report.json"
    md = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "demo-eng",
            "--findings",
            str(findings_path),
            "--output",
            str(out),
            "--markdown",
            str(md),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] == 1  # deduped
    assert md.exists()


def test_cli_report_writes_csv(tmp_path: Path) -> None:
    findings_path = _write(tmp_path / "f.json", [_finding("SQLi", Severity.CRITICAL)])
    out = tmp_path / "report.json"
    csv_path = tmp_path / "report.csv"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "demo-eng",
            "--findings",
            str(findings_path),
            "--output",
            str(out),
            "--csv",
            str(csv_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert csv_path.exists()
    body = csv_path.read_text(encoding="utf-8")
    assert body.startswith("finding_id,severity,status,source,asset_id")
    assert "SQLi" in body


def test_cli_report_executive_section(tmp_path: Path) -> None:
    finding = _finding("SQLi", Severity.CRITICAL)
    findings_path = _write(tmp_path / "f.json", [finding])
    out = tmp_path / "report.json"
    md = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "demo-eng",
            "--findings",
            str(findings_path),
            "--output",
            str(out),
            "--markdown",
            str(md),
            "--section",
            "executive",
        ],
    )
    assert result.exit_code == 0, result.output
    body = md.read_text(encoding="utf-8")
    assert "## Summary" in body and "SQLi" in body
    assert "## Assets" not in body  # executive drops the asset inventory
    # An invalid section is rejected.
    bad = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "e",
            "--findings",
            str(findings_path),
            "--section",
            "x",
        ],
    )
    assert bad.exit_code != 0


def test_cli_rank(tmp_path: Path) -> None:
    findings_path = _write(
        tmp_path / "f.json", [_finding("low", Severity.LOW), _finding("crit", Severity.CRITICAL)]
    )
    result = runner.invoke(
        app, ["vulcan", "rank", "--findings", str(findings_path), "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["severity"] == "critical"


def test_cli_rank_filters_reuse_the_shared_finding_filter(tmp_path: Path) -> None:
    low = _finding("low banner", Severity.LOW, asset_id="AST-1")
    crit = _finding("crit sqli", Severity.CRITICAL, asset_id="AST-2")
    findings_path = _write(tmp_path / "f.json", [low, crit])
    # --min-severity narrows exactly like the Web findings view.
    result = runner.invoke(
        app,
        [
            "vulcan",
            "rank",
            "--findings",
            str(findings_path),
            "--format",
            "json",
            "--min-severity",
            "high",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert [row["severity"] for row in payload] == ["critical"]
    # --asset is exact and case-insensitive.
    scoped = runner.invoke(
        app,
        [
            "vulcan",
            "rank",
            "--findings",
            str(findings_path),
            "--format",
            "json",
            "--asset",
            "ast-1",
        ],
    )
    assert scoped.exit_code == 0, scoped.output
    scoped_payload = json.loads(scoped.output)
    assert [row["asset_id"] for row in scoped_payload] == ["AST-1"]


def test_cli_report_bad_input(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    result = runner.invoke(
        app, ["vulcan", "report", "--engagement", "e", "--findings", str(tmp_path / "bad.json")]
    )
    assert result.exit_code == 2


def test_vulcan_cli_errors_neutralize_terminal_controls(tmp_path: Path) -> None:
    """Dynamic paths and identifiers in CLI diagnostics are not terminal commands."""
    hostile_path = tmp_path / "\x1b[31mforged\nwarning.json"
    result = runner.invoke(
        app,
        ["vulcan", "findings", "list", "--findings", str(hostile_path)],
    )
    assert result.exit_code == 2
    assert "\x1b" not in result.output
    assert "\nwarning" not in result.output

    valid_path = _write(tmp_path / "findings.json", [_finding("present", Severity.LOW)])
    hostile_id = "\x1b[31mforged\nwarning"
    result = runner.invoke(
        app,
        ["vulcan", "findings", "show", hostile_id, "--findings", str(valid_path)],
    )
    assert result.exit_code == 2
    assert "\x1b" not in result.output
    assert "\nwarning" not in result.output


def test_filter_min_severity() -> None:
    from olympus.vulcan.aggregate import filter_min_severity

    findings = [_finding("a", Severity.LOW), _finding("b", Severity.CRITICAL)]
    kept = filter_min_severity(findings, Severity.HIGH)
    assert [f.severity for f in kept] == [Severity.CRITICAL]


def test_render_html_is_self_contained() -> None:
    asset = Asset(asset_type=AssetType.HOST, hostname="host<script>", source=Source.ARGUS)
    alert = Alert(
        alert_id="ALT-ONE",
        event_id="EVT-1",
        title="alert<script>",
        source=Source.APOLLO,
        rule_id="APL-ONE",
        mitre_attack=["T1059.001"],
    )
    html_doc = render_html("eng", [asset], [_finding("XSS<script>", Severity.HIGH)], [alert])
    assert "<!doctype html>" in html_doc
    assert "Security report" in html_doc
    assert "&lt;script&gt;" in html_doc  # finding title is HTML-escaped
    assert "APL-ONE" in html_doc and "T1059.001" in html_doc
    assert "host&lt;script&gt;" in html_doc
    assert "http://" not in html_doc and "https://" not in html_doc  # no external assets

    markdown = render_markdown("eng", [asset], [_finding("XSS<script>", Severity.HIGH)], [alert])
    assert "<script>" not in markdown
    assert "APL-ONE" in markdown


def test_render_report_csv_is_spreadsheet_safe() -> None:
    import csv as _csv
    import io as _io

    model = build_report_model(
        "eng",
        [],
        [
            _finding('=HYPERLINK("http://evil","x")', Severity.HIGH),
            _finding("normal finding", Severity.LOW),
        ],
        [],
    )
    csv_text = render_report_csv(model)
    assert "\r\n" in csv_text  # RFC 4180 line terminator
    rows = list(_csv.reader(_io.StringIO(csv_text)))
    assert rows[0][:5] == ["finding_id", "severity", "status", "source", "asset_id"]
    assert len(rows) == 3  # header + two findings, one row per finding
    title_index = rows[0].index("title")
    # The HIGH finding ranks first; its formula-injection title is neutralised
    # with a leading apostrophe so a spreadsheet shows it as literal text.
    assert rows[1][title_index] == '\'=HYPERLINK("http://evil","x")'
    assert rows[2][title_index] == "normal finding"


def test_report_executive_section_omits_technical_detail() -> None:
    assets = [Asset(asset_type=AssetType.HOST, hostname="h1", source=Source.ARGUS)]
    alerts = [Alert(event_id="EVT-1", title="brute force", source=Source.APOLLO)]
    finding = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title="SQLi",
        severity=Severity.CRITICAL,
        description="SENSITIVE technical detail",
        remediation="patch the parameter",
    )
    model = build_report_model("eng", assets, [finding], alerts)

    for render in (render_report_markdown, render_report_html):
        full = render(model)
        executive = render(model, section="executive")
        # The full report keeps the per-finding detail and the appendices.
        assert "SENSITIVE technical detail" in full
        # The executive summary keeps the headline (title, severity, counts) but
        # drops the technical detail, remediation and the alert/provenance blocks.
        assert "SQLi" in executive
        assert "SENSITIVE technical detail" not in executive
        assert "patch the parameter" not in executive
        assert "brute force" not in executive
    # Default stays full (backward compatible).
    assert render_report_markdown(model) == render_report_markdown(model, section="full")


def test_render_html_sets_restrictive_csp() -> None:
    """The exported report ships a script-forbidding Content-Security-Policy."""
    html_doc = render_html(
        "eng",
        [Asset(asset_type=AssetType.HOST, hostname="host", source=Source.ARGUS)],
        [_finding("finding", Severity.HIGH)],
        [],
    )
    # The policy keywords use single quotes, so the meta attribute must be
    # double-quoted; otherwise the value would truncate at the first keyword.
    assert '<meta http-equiv="Content-Security-Policy" content="' in html_doc
    assert "default-src 'none'" in html_doc  # scripts/objects/frames forbidden by default
    assert "style-src 'unsafe-inline'" in html_doc  # only the renderer's inline styling
    assert "base-uri 'none'" in html_doc and "form-action 'none'" in html_doc
    assert "frame-ancestors 'none'\">" in html_doc  # attribute closes cleanly, not truncated
    # No executable script surface is ever emitted, escaped or not.
    assert "<script" not in html_doc.lower()
    # The policy itself introduces no external origin.
    assert "http://" not in html_doc and "https://" not in html_doc


def test_report_exports_neutralize_terminal_control_sequences() -> None:
    """Target-controlled text cannot smuggle ANSI/OSC/C0 controls into a report."""
    hostile = "clear\x1b[2J\x1b]0;pwn\x07 then\x7f\x08more"
    asset = Asset(asset_type=AssetType.HOST, hostname=hostile, source=Source.ARGUS)
    finding = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title=hostile,
        severity=Severity.HIGH,
        description=hostile,
        remediation=hostile,
    )
    alert = Alert(alert_id="ALT-1", event_id="EVT-1", title=hostile, source=Source.APOLLO)

    control_bytes = ("\x1b", "\x07", "\x7f", "\x08")
    for render in (render_html, render_markdown):
        rendered = render("eng", [asset], [finding], [alert])
        for byte in control_bytes:
            assert byte not in rendered
        # The surrounding, printable text survives sanitization.
        assert "clear" in rendered and "more" in rendered


def test_markdown_report_defangs_target_controlled_bare_urls() -> None:
    """A report must not turn attacker-controlled target text into a link."""
    finding = Finding(
        asset_id="AST-1",
        source=Source.ARTEMIS,
        title="endpoint observed",
        description="redirect target https://tracker.invalid/path?token=secret",
        severity=Severity.HIGH,
    )

    markdown = render_markdown("eng", [], [finding], [])

    assert "https://tracker.invalid" not in markdown
    assert "https&#58;//tracker.invalid" in markdown
    assert "token=secret" not in markdown


def test_cli_report_html_and_min_severity(tmp_path: Path) -> None:
    findings_path = _write(
        tmp_path / "f.json", [_finding("low", Severity.LOW), _finding("crit", Severity.CRITICAL)]
    )
    out = tmp_path / "report.json"
    html_out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "e",
            "--findings",
            str(findings_path),
            "--output",
            str(out),
            "--html",
            str(html_out),
            "--min-severity",
            "high",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["findings"] == 1  # only critical kept
    assert html_out.exists()
    assert "crit" in html_out.read_text(encoding="utf-8")


def test_bounded_inputs_and_application_policy(tmp_path: Path) -> None:
    finding = _finding("bounded", Severity.MEDIUM)
    source = _write(tmp_path / "findings.json", [finding])
    with pytest.raises(AggregationError, match="byte limit"):
        load_findings([source], max_bytes=5)
    two = _write(tmp_path / "two-findings.json", [finding, finding])
    with pytest.raises(AggregationError, match="item limit"):
        load_findings([two], max_items_per_file=1)

    link = tmp_path / "findings-link.json"
    link.symlink_to(source)
    with pytest.raises(AggregationError, match="symlink"):
        load_findings([link])

    with pytest.raises(AggregationError, match="overwrite input"):
        VulcanApplicationService().report(
            VulcanReportRequest(
                engagement="eng",
                finding_paths=(source,),
                excluded_paths=(source,),
            )
        )
    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        VulcanApplicationService(token).rank(VulcanRankRequest((source,)))


def test_report_rejects_unknown_asset_reference_when_inventory_is_present(tmp_path: Path) -> None:
    asset = Asset(asset_type=AssetType.HOST, hostname="known", source=Source.ARGUS)
    assets = tmp_path / "assets.json"
    assets.write_text(json.dumps([asset.model_dump(mode="json")]), encoding="utf-8")
    findings = _write(tmp_path / "findings.json", [_finding("orphan", Severity.HIGH, "AST-X")])
    with pytest.raises(AggregationError, match="unknown report assets"):
        VulcanApplicationService().report(
            VulcanReportRequest(
                engagement="eng",
                asset_paths=(assets,),
                finding_paths=(findings,),
            )
        )

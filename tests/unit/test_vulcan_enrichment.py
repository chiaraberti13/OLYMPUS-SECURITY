"""Vulcan CVE enrichment: CISA KEV + FIRST EPSS overlay and risk ranking (§2).

Parsing the two feeds and ranking findings by real-world risk is tested here
with representative fixtures and no network — the fetch wrappers
(:func:`fetch_kev_catalog`, :func:`fetch_epss_scores`) are thin and exercised
only through the CLI's local-file path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.vulcan.enrichment import (
    EnrichmentError,
    enrich_finding,
    enrich_findings,
    extract_cves,
    parse_epss_response,
    parse_kev_catalog,
    prioritize,
)

runner = CliRunner()

# A representative CISA KEV document (the fields we surface), not a live capture.
_KEV_JSON = json.dumps(
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2019-0708",
                "vendorProject": "Microsoft",
                "product": "Remote Desktop Services",
                "vulnerabilityName": "BlueKeep",
                "dateAdded": "2021-11-03",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }
)

# A representative FIRST EPSS API response shape.
_EPSS_JSON = json.dumps(
    {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.97521",
                "percentile": "0.99987",
                "date": "2026-09-01",
            },
            {
                "cve": "CVE-2022-3602",
                "epss": "0.00042",
                "percentile": "0.10000",
                "date": "2026-09-01",
            },
        ],
    }
)


def _finding(title: str, *, severity: Severity, cvss: float | None = None, **kwargs) -> Finding:
    return Finding(
        asset_id="AST-1", source=Source.HELIOS, title=title, severity=severity, cvss=cvss, **kwargs
    )


# --- CVE extraction ---------------------------------------------------------- #


def test_extract_cves_reads_every_text_field_case_insensitively() -> None:
    finding = _finding(
        "Vulnerable to cve-2021-44228",
        severity=Severity.HIGH,
        description="see also CVE-2022-3602",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-3786"],
        evidence=["banner: CVE-2021-44228"],
    )
    assert extract_cves(finding) == ("CVE-2021-44228", "CVE-2022-3602", "CVE-2022-3786")


def test_extract_cves_is_empty_when_none_present() -> None:
    assert extract_cves(_finding("no cve here", severity=Severity.LOW)) == ()


# --- Feed parsing ------------------------------------------------------------ #


def test_parse_kev_catalog_reads_ransomware_flag() -> None:
    catalog = parse_kev_catalog(_KEV_JSON)
    assert set(catalog) == {"CVE-2021-44228", "CVE-2019-0708"}
    assert catalog["CVE-2021-44228"].known_ransomware is True
    assert catalog["CVE-2019-0708"].known_ransomware is False
    assert catalog["CVE-2021-44228"].vulnerability_name == "Log4Shell"


def test_parse_kev_catalog_rejects_a_document_without_the_array() -> None:
    with pytest.raises(EnrichmentError, match="vulnerabilities"):
        parse_kev_catalog(json.dumps({"title": "empty"}))


def test_parse_epss_response_skips_out_of_range_and_bad_rows() -> None:
    body = json.dumps(
        {
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "0.9"},
                {"cve": "CVE-2020-0001", "epss": "9.9", "percentile": "0.5"},  # out of range
                {"cve": "not-a-cve", "epss": "0.1", "percentile": "0.1"},  # bad id
                {"cve": "CVE-2020-0002", "epss": "n/a", "percentile": "0.1"},  # unparseable
            ]
        }
    )
    scores = parse_epss_response(body)
    assert set(scores) == {"CVE-2021-44228"}
    assert scores["CVE-2021-44228"].score == 0.5


def test_parse_epss_response_rejects_bad_json() -> None:
    with pytest.raises(EnrichmentError, match="invalid EPSS JSON"):
        parse_epss_response("{not json")


# --- Enrichment overlay ------------------------------------------------------ #


def test_enrich_finding_takes_the_max_epss_across_cves() -> None:
    kev = parse_kev_catalog(_KEV_JSON)
    epss = parse_epss_response(_EPSS_JSON)
    finding = _finding(
        "Two CVEs CVE-2021-44228 and CVE-2022-3602", severity=Severity.MEDIUM, cvss=6.0
    )
    overlay = enrich_finding(finding, kev=kev, epss=epss)
    assert overlay.in_kev is True  # Log4Shell is in KEV
    assert overlay.max_epss == 0.97521  # the higher of the two scores
    assert overlay.cves == ("CVE-2021-44228", "CVE-2022-3602")


def test_enrich_finding_without_a_cve_is_empty() -> None:
    overlay = enrich_finding(_finding("no cve", severity=Severity.LOW), kev={}, epss={})
    assert overlay.in_kev is False
    assert overlay.max_epss is None
    assert overlay.cves == ()


def test_to_dict_is_json_serializable() -> None:
    kev = parse_kev_catalog(_KEV_JSON)
    epss = parse_epss_response(_EPSS_JSON)
    overlay = enrich_finding(
        _finding("CVE-2021-44228", severity=Severity.HIGH), kev=kev, epss=epss
    )
    payload = json.loads(json.dumps(overlay.to_dict()))  # round-trips
    assert payload["in_kev"] is True
    assert payload["kev"][0]["cve"] == "CVE-2021-44228"


# --- Prioritisation ---------------------------------------------------------- #


def test_prioritize_puts_kev_first_then_epss_then_cvss() -> None:
    kev = parse_kev_catalog(_KEV_JSON)
    epss = parse_epss_response(_EPSS_JSON)
    kev_hit = _finding("KEV CVE-2021-44228", severity=Severity.MEDIUM, cvss=5.0)
    high_epss = _finding("CVE-2022-3602 low epss", severity=Severity.CRITICAL, cvss=9.9)
    no_cve_high_cvss = _finding("no cve", severity=Severity.CRITICAL, cvss=9.8)
    findings = [no_cve_high_cvss, high_epss, kev_hit]
    enrichments = enrich_findings(findings, kev=kev, epss=epss)

    order = [finding.title for finding, _ in prioritize(findings, enrichments)]
    # KEV membership dominates even a lower CVSS/severity.
    assert order[0] == "KEV CVE-2021-44228"
    # Between the two non-KEV findings, the one with any EPSS outranks the no-CVE one.
    assert order.index("CVE-2022-3602 low epss") < order.index("no cve")


# --- CLI --------------------------------------------------------------------- #


def _write_findings(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


def test_enrich_command_offline_writes_overlay_and_counts_kev(tmp_path: Path) -> None:
    findings = _write_findings(
        tmp_path / "findings.json",
        [
            _finding("Log4Shell CVE-2021-44228", severity=Severity.HIGH, cvss=10.0),
            _finding("no cve finding", severity=Severity.LOW),
        ],
    )
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(_KEV_JSON, encoding="utf-8")
    epss_file = tmp_path / "epss.json"
    epss_file.write_text(_EPSS_JSON, encoding="utf-8")
    output = tmp_path / "overlay.json"

    result = runner.invoke(
        app,
        [
            "vulcan", "enrich", "--findings", str(findings),
            "--kev", str(kev_file), "--epss", str(epss_file),
            "--output", str(output), "--format", "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "1 in CISA KEV" in result.output
    overlay = json.loads(output.read_text(encoding="utf-8"))
    kev_row = next(row for row in overlay if row["cves"] == ["CVE-2021-44228"])
    assert kev_row["in_kev"] is True
    assert kev_row["max_epss"] == 0.97521


def test_enrich_command_without_feeds_is_a_clean_no_op(tmp_path: Path) -> None:
    findings = _write_findings(
        tmp_path / "findings.json", [_finding("CVE-2021-44228", severity=Severity.HIGH)]
    )
    output = tmp_path / "overlay.json"
    result = runner.invoke(
        app, ["vulcan", "enrich", "--findings", str(findings), "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert "0 in CISA KEV" in result.output  # no KEV file -> nothing flagged

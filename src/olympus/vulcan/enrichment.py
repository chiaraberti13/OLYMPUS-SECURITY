"""Enrich findings with CISA KEV and FIRST EPSS, keyed by CVE (§2 Vulcan).

A finding's raw CVSS says how *bad* a vulnerability is if exploited; it says
nothing about whether anyone is actually exploiting it. Two public feeds close
that gap and are the backbone of modern risk-based triage:

* **CISA KEV** - the Known Exploited Vulnerabilities catalogue: CVEs with
  confirmed in-the-wild exploitation. A KEV hit is the strongest "fix this now"
  signal there is.
* **FIRST EPSS** - the Exploit Prediction Scoring System: a daily probability
  (0-1) that a CVE will be exploited in the next 30 days, plus a percentile.

This module keeps the shared :class:`~olympus.core.models.Finding` contract
untouched: enrichment is an *overlay* (:class:`FindingEnrichment`) computed from
the CVEs mentioned in a finding, not new fields on the model. Parsing the two
feeds (:func:`parse_kev_catalog`, :func:`parse_epss_response`) is deliberately
separated from fetching them (:func:`fetch_kev_catalog`, :func:`fetch_epss_scores`),
so the parsing and prioritisation logic is unit-tested with representative
fixtures and no network - the same split used for the hash-pinned lockfile.

Feed formats (as published):
* KEV: ``https://www.cisa.gov/.../known_exploited_vulnerabilities.json`` ->
  ``{"vulnerabilities": [{"cveID", "dateAdded", "vendorProject", "product",
  "vulnerabilityName", "knownRansomwareCampaignUse", ...}]}``.
* EPSS: ``https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...`` ->
  ``{"data": [{"cve", "epss", "percentile", "date"}]}``.
"""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from olympus.core.models import Finding

#: A CVE identifier: CVE-YYYY-NNNN(NNN...). Matched case-insensitively, uppercased.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

#: Guardrails so a hostile or oversized feed cannot exhaust memory.
DEFAULT_MAX_FEED_BYTES = 50_000_000
_MAX_EPSS_QUERY_CVES = 100


class EnrichmentError(RuntimeError):
    """Raised when a feed cannot be fetched or parsed."""


@dataclass(frozen=True)
class KevEntry:
    """One CISA Known-Exploited-Vulnerabilities record (the fields we surface)."""

    cve: str
    date_added: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    known_ransomware: bool = False


@dataclass(frozen=True)
class EpssScore:
    """One FIRST EPSS score for a CVE."""

    cve: str
    score: float  # probability in [0, 1]
    percentile: float  # in [0, 1]
    date: str = ""


@dataclass(frozen=True)
class FindingEnrichment:
    """KEV/EPSS overlay for a single finding, without mutating the Finding."""

    finding_id: str
    cves: tuple[str, ...]
    kev: tuple[KevEntry, ...] = ()
    max_epss: float | None = None
    max_epss_percentile: float | None = None

    @property
    def in_kev(self) -> bool:
        return bool(self.kev)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "cves": list(self.cves),
            "in_kev": self.in_kev,
            "kev": [
                {
                    "cve": entry.cve,
                    "date_added": entry.date_added,
                    "vendor_project": entry.vendor_project,
                    "product": entry.product,
                    "vulnerability_name": entry.vulnerability_name,
                    "known_ransomware": entry.known_ransomware,
                }
                for entry in self.kev
            ],
            "max_epss": self.max_epss,
            "max_epss_percentile": self.max_epss_percentile,
        }


def extract_cves(finding: Finding) -> tuple[str, ...]:
    """Return the sorted, de-duplicated CVE ids mentioned anywhere in a finding."""
    haystack = " ".join(
        [finding.title, finding.description, *finding.references, *finding.evidence]
    )
    return tuple(sorted({match.group().upper() for match in CVE_PATTERN.finditer(haystack)}))


def parse_kev_catalog(body: str) -> dict[str, KevEntry]:
    """Parse a CISA KEV JSON document into ``{cve: KevEntry}``."""
    try:
        document: Any = json.loads(body)
    except json.JSONDecodeError as exc:
        raise EnrichmentError(f"invalid KEV JSON: {exc.msg}") from exc
    vulnerabilities = document.get("vulnerabilities") if isinstance(document, dict) else None
    if not isinstance(vulnerabilities, list):
        raise EnrichmentError("KEV document has no 'vulnerabilities' array")
    catalog: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = item.get("cveID")
        if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve):
            continue
        catalog[cve.upper()] = KevEntry(
            cve=cve.upper(),
            date_added=str(item.get("dateAdded", "")),
            vendor_project=str(item.get("vendorProject", "")),
            product=str(item.get("product", "")),
            vulnerability_name=str(item.get("vulnerabilityName", "")),
            known_ransomware=str(item.get("knownRansomwareCampaignUse", "")).strip().lower()
            == "known",
        )
    return catalog


def parse_epss_response(body: str) -> dict[str, EpssScore]:
    """Parse a FIRST EPSS API JSON response into ``{cve: EpssScore}``."""
    try:
        document: Any = json.loads(body)
    except json.JSONDecodeError as exc:
        raise EnrichmentError(f"invalid EPSS JSON: {exc.msg}") from exc
    rows = document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        raise EnrichmentError("EPSS document has no 'data' array")
    scores: dict[str, EpssScore] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = row.get("cve")
        if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve):
            continue
        try:
            score = float(row.get("epss", ""))
            percentile = float(row.get("percentile", ""))
        except (TypeError, ValueError):
            continue
        if not (0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0):
            continue
        scores[cve.upper()] = EpssScore(
            cve=cve.upper(), score=score, percentile=percentile, date=str(row.get("date", ""))
        )
    return scores


def enrich_finding(
    finding: Finding,
    *,
    kev: dict[str, KevEntry],
    epss: dict[str, EpssScore],
) -> FindingEnrichment:
    """Build the KEV/EPSS overlay for one finding from the two catalogues."""
    cves = extract_cves(finding)
    matched_kev = tuple(kev[cve] for cve in cves if cve in kev)
    matched_epss = [epss[cve] for cve in cves if cve in epss]
    max_score: float | None = None
    max_percentile: float | None = None
    if matched_epss:
        best = max(matched_epss, key=lambda item: item.score)
        max_score, max_percentile = best.score, best.percentile
    return FindingEnrichment(
        finding_id=finding.finding_id,
        cves=cves,
        kev=matched_kev,
        max_epss=max_score,
        max_epss_percentile=max_percentile,
    )


def enrich_findings(
    findings: Iterable[Finding],
    *,
    kev: dict[str, KevEntry],
    epss: dict[str, EpssScore],
) -> list[FindingEnrichment]:
    """Overlay every finding; findings with no CVE get an empty overlay."""
    return [enrich_finding(finding, kev=kev, epss=epss) for finding in findings]


def prioritize(
    findings: Sequence[Finding], enrichments: Sequence[FindingEnrichment]
) -> list[tuple[Finding, FindingEnrichment]]:
    """Order (finding, overlay) pairs by real-world risk, most urgent first.

    Key: KEV membership first (confirmed exploitation dominates), then EPSS
    probability, then CVSS, then the finding's own severity. Deterministic ties
    break on finding_id.
    """
    by_id = {enrichment.finding_id: enrichment for enrichment in enrichments}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def sort_key(finding: Finding) -> tuple[int, float, float, int, str]:
        overlay = by_id.get(finding.finding_id)
        in_kev = 1 if (overlay and overlay.in_kev) else 0
        epss_score = overlay.max_epss if (overlay and overlay.max_epss is not None) else 0.0
        cvss = finding.cvss if finding.cvss is not None else 0.0
        severity = severity_rank.get(finding.severity.value, 0)
        return (in_kev, epss_score, cvss, severity, finding.finding_id)

    ordered = sorted(findings, key=sort_key, reverse=True)
    return [(finding, by_id[finding.finding_id]) for finding in ordered]


# --- Network fetch (separated from parsing; not unit-tested against the wire) - #


def _http_get(url: str, *, timeout: float, max_bytes: int) -> str:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw: bytes = response.read(max_bytes + 1)
    except (OSError, ValueError) as exc:
        raise EnrichmentError(f"cannot fetch {url}: {exc}") from exc
    if len(raw) > max_bytes:
        raise EnrichmentError(f"feed at {url} exceeds the {max_bytes} byte limit")
    body: str = raw.decode("utf-8")
    return body


def fetch_kev_catalog(
    url: str = CISA_KEV_URL,
    *,
    timeout: float = 30.0,
    max_bytes: int = DEFAULT_MAX_FEED_BYTES,
) -> dict[str, KevEntry]:
    """Fetch and parse the live CISA KEV catalogue."""
    return parse_kev_catalog(_http_get(url, timeout=timeout, max_bytes=max_bytes))


def fetch_epss_scores(
    cves: Sequence[str],
    *,
    url: str = EPSS_API_URL,
    timeout: float = 30.0,
    max_bytes: int = DEFAULT_MAX_FEED_BYTES,
) -> dict[str, EpssScore]:
    """Fetch EPSS scores for up to 100 CVEs from the FIRST EPSS API."""
    unique = sorted({cve.upper() for cve in cves if CVE_PATTERN.fullmatch(cve.upper())})
    if not unique:
        return {}
    if len(unique) > _MAX_EPSS_QUERY_CVES:
        raise EnrichmentError(
            f"EPSS query is limited to {_MAX_EPSS_QUERY_CVES} CVEs per request; "
            f"got {len(unique)} - batch the query"
        )
    query = f"{url}?cve={','.join(unique)}"
    return parse_epss_response(_http_get(query, timeout=timeout, max_bytes=max_bytes))


@dataclass(frozen=True)
class LocalCatalogs:
    """A pair of already-loaded catalogues for offline enrichment."""

    kev: dict[str, KevEntry] = field(default_factory=dict)
    epss: dict[str, EpssScore] = field(default_factory=dict)

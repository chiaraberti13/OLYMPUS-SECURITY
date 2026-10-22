"""SARIF 2.1.0 interoperability for Olympus findings (ROADMAP ``WEB-J``).

SARIF is the interoperability format for static- and dynamic-analysis results.
This module bridges it both ways for the shared ``core.Finding`` contract:

* **import** (:func:`sarif_to_findings`) consumes any SARIF-producing tool's
  results so they run through the same lifecycle, dedup, diff, trend and
  reporting as native findings;
* **export** (:func:`findings_to_sarif`) emits Olympus findings as a SARIF
  document that any SARIF consumer (CI code-scanning, dashboards) can ingest.

(Hermes has its own secret-finding SARIF exporter; this is the generic
``core.Finding`` bridge.) An imported SARIF document comes from an external tool,
so it is treated as **hostile input**: every field is type-checked before use,
strings are length-bounded, the result count is capped, and anything malformed
raises :class:`SarifImportError` rather than producing a half-built finding. Both
directions are deterministic and offline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from olympus import __version__
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding

#: The only SARIF version this importer accepts.
SARIF_VERSION = "2.1.0"
#: Bound the number of imported results so a hostile document cannot exhaust memory.
MAX_RESULTS = 100_000
#: Defensive caps on free-text taken from the external document.
_MAX_TITLE = 500
_MAX_TEXT = 10_000
_MAX_EVIDENCE = 100

#: SARIF ``result.level`` → Olympus severity. Unknown/absent falls back to MEDIUM,
#: the safe default (never silently downgraded to informational).
_LEVEL_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class SarifImportError(ValueError):
    """Raised when a SARIF document is not a compatible 2.1.0 document."""


def _text(value: Any, limit: int) -> str:
    """Return a bounded single-source string, or '' for any non-string input."""
    if not isinstance(value, str):
        return ""
    return value[:limit]


def _index_rules(run: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ``ruleId`` → rule object from a run's tool driver, defensively."""
    rules: dict[str, dict[str, Any]] = {}
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, Mapping) else None
    entries = driver.get("rules") if isinstance(driver, Mapping) else None
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, Mapping):
                rule_id = entry.get("id")
                if isinstance(rule_id, str):
                    rules[rule_id] = dict(entry)
    return rules


def _severity(result: Mapping[str, Any], rule: Mapping[str, Any] | None) -> Severity:
    level = result.get("level")
    if not isinstance(level, str) and rule is not None:
        config = rule.get("defaultConfiguration")
        level = config.get("level") if isinstance(config, Mapping) else None
    return (
        _LEVEL_SEVERITY.get(level, Severity.MEDIUM) if isinstance(level, str) else Severity.MEDIUM
    )


def _locations(result: Mapping[str, Any]) -> list[str]:
    """Render each physical location as a bounded ``uri`` or ``uri:line`` string."""
    out: list[str] = []
    locations = result.get("locations")
    if not isinstance(locations, list):
        return out
    for location in locations[:_MAX_EVIDENCE]:
        if not isinstance(location, Mapping):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, Mapping):
            continue
        artifact = physical.get("artifactLocation")
        uri = artifact.get("uri") if isinstance(artifact, Mapping) else None
        if not isinstance(uri, str) or not uri:
            continue
        region = physical.get("region")
        line = region.get("startLine") if isinstance(region, Mapping) else None
        out.append(f"{uri[:_MAX_TEXT]}:{line}" if isinstance(line, int) else uri[:_MAX_TEXT])
    return out


def _result_to_finding(
    result: Mapping[str, Any],
    rules: Mapping[str, dict[str, Any]],
    *,
    asset_id: str,
    source: Source,
) -> Finding:
    rule_id = result.get("ruleId")
    rule = rules.get(rule_id) if isinstance(rule_id, str) else None

    message = result.get("message")
    text = _text(message.get("text"), _MAX_TEXT) if isinstance(message, Mapping) else ""
    short = ""
    if rule is not None:
        description = rule.get("shortDescription")
        short = (
            _text(description.get("text"), _MAX_TITLE) if isinstance(description, Mapping) else ""
        )

    first_line = text.splitlines()[0] if text else ""
    title = (
        first_line[:_MAX_TITLE]
        or short
        or (rule_id if isinstance(rule_id, str) and rule_id else "")
        or "SARIF result"
    )

    references: list[str] = []
    if isinstance(rule_id, str) and rule_id:
        references.append(rule_id)
    if rule is not None:
        help_uri = rule.get("helpUri")
        if isinstance(help_uri, str) and help_uri:
            references.append(help_uri[:_MAX_TEXT])

    return Finding(
        asset_id=asset_id,
        source=source,
        title=title,
        description=text,
        severity=_severity(result, rule),
        references=references,
        evidence=_locations(result),
    )


def sarif_to_findings(
    document: Any,
    *,
    asset_id: str,
    source: Source = Source.MANUAL,
    max_results: int = MAX_RESULTS,
) -> list[Finding]:
    """Convert a SARIF 2.1.0 document into Olympus findings, strictly and bounded.

    ``asset_id`` is the Olympus asset these results pertain to (SARIF identifies
    scanned artifacts, not Olympus assets, so the caller supplies the link).
    ``source`` defaults to :attr:`Source.MANUAL` because the findings are ingested
    from outside Olympus. A non-2.1.0 document, a malformed structure, or more than
    ``max_results`` results raises :class:`SarifImportError` and yields nothing.
    """
    if not isinstance(document, Mapping):
        raise SarifImportError("SARIF document must be a JSON object")
    version = document.get("version")
    if version != SARIF_VERSION:
        raise SarifImportError(f"unsupported SARIF version {version!r}; expected {SARIF_VERSION}")
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise SarifImportError("SARIF document has no 'runs' list")

    findings: list[Finding] = []
    for run in runs:
        if not isinstance(run, Mapping):
            raise SarifImportError("each SARIF run must be an object")
        rules = _index_rules(run)
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise SarifImportError("a SARIF run's 'results' must be a list")
        for result in results:
            if len(findings) >= max_results:
                raise SarifImportError(f"SARIF import exceeds the {max_results}-result limit")
            if not isinstance(result, Mapping):
                raise SarifImportError("each SARIF result must be an object")
            findings.append(_result_to_finding(result, rules, asset_id=asset_id, source=source))
    return findings


#: Olympus severity → SARIF ``result.level``. SARIF has four levels and Olympus
#: five severities, so ``critical`` and ``high`` both map to ``error`` (SARIF's
#: most urgent level); the richer Olympus severity is preserved in the result's
#: ``properties`` bag so a round-trip or a rich consumer never loses it.
_SEVERITY_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

#: The published SARIF 2.1.0 schema, matching the Hermes exporter.
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _finding_result(finding: Finding) -> dict[str, Any]:
    """Project one finding into a SARIF result, preserving Olympus fields."""
    message = (
        finding.title if not finding.description else f"{finding.title}\n{finding.description}"
    )
    result: dict[str, Any] = {
        "ruleId": finding.finding_id,
        "level": _SEVERITY_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": finding.asset_id}}},
        ],
        # Olympus-specific fields ride in the SARIF property bag so a consumer
        # (or a re-import) keeps the full severity, provenance and intelligence.
        "properties": {
            "severity": finding.severity.value,
            "source": finding.source.value,
            "status": finding.status.value,
            "risk_score": finding.risk_score(),
            "cve": list(finding.cves()),
            "cwe": list(finding.cwes()),
            "kev": finding.kev,
        },
    }
    if finding.references:
        result["properties"]["references"] = list(finding.references)
    return result


def findings_to_sarif(
    findings: Sequence[Finding], *, tool_name: str = "Olympus Vulcan"
) -> dict[str, Any]:
    """Serialise Olympus findings into a deterministic SARIF 2.1.0 document.

    Results are ordered by ``finding_id`` so the same set always produces the same
    document (diffable, round-trip-verifiable). Severity maps to the SARIF level
    (:data:`_SEVERITY_LEVEL`); the finding's asset is the result location; and the
    full Olympus severity, provenance, status, risk score and CVE/CWE/KEV ride in
    the result ``properties`` bag so no information is lost to the four SARIF
    levels. Pure and offline.
    """
    ordered = sorted(findings, key=lambda finding: finding.finding_id)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": __version__,
                        "informationUri": "https://github.com/chiaraberti13/OLYMPUS-SECURITY",
                    }
                },
                "results": [_finding_result(finding) for finding in ordered],
            }
        ],
    }

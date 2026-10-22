"""Import third-party SARIF 2.1.0 results as Olympus findings (ROADMAP ``WEB-J``).

SARIF is the interoperability format for static- and dynamic-analysis results, so
ingesting it lets Olympus consume findings from any SARIF-producing tool and run
them through the same lifecycle, dedup, diff, trend and reporting as native
findings. Hermes already *exports* SARIF (:mod:`olympus.hermes.sarif`); this is
the *import* side.

A SARIF document comes from an external tool, so it is treated as **hostile
input**: every field is type-checked before use, strings are length-bounded, the
result count is capped, and anything malformed raises
:class:`SarifImportError` rather than producing a half-built finding. The mapping
is deterministic and offline.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

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

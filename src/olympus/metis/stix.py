"""STIX 2.1 export and import for METIS indicators (§2 Metis).

STIX 2.1 is the lingua franca for sharing cyber-threat intelligence, and it is
plain JSON — so this needs no new dependency. The module converts between
Olympus :class:`~olympus.metis.models.Indicator` objects and a STIX 2.1 bundle:

* **Export** (:func:`indicators_to_bundle`) emits one ``indicator`` SDO per IOC,
  with a single-comparison STIX pattern (e.g. ``[domain-name:value = 'evil.tld']``);
  a CVE becomes a ``vulnerability`` SDO. Object ids are deterministic (UUIDv5 over
  the IOC), so re-exporting the same case is byte-stable.
* **Import** (:func:`bundle_to_indicators`) reads a bundle and parses the *simple*
  equality patterns back into indicators. STIX patterns are a full language —
  ``AND``/``OR``/``FOLLOWEDBY``, ``LIKE``/``MATCHES``/``IN``, multiple
  observation expressions — and those cannot be represented by Olympus' exact
  single-value IOCs. Rather than silently mangle them into a wrong equality, the
  importer **skips** them and records the reason; the caller sees exactly what
  was not imported. This is the same honesty as the Hermes/Sigma boundary: import
  the faithful subset, refuse the rest out loud.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from olympus.metis.models import Indicator, IndicatorType

STIX_SPEC_VERSION = "2.1"

#: Namespace for deterministic STIX object ids (UUIDv5), so export is stable.
_OLYMPUS_STIX_NAMESPACE = uuid5(NAMESPACE_URL, "https://olympus.security/stix")

#: IndicatorType -> (STIX object type, STIX object property) for the pattern.
_PATTERN_FOR_TYPE: dict[IndicatorType, tuple[str, str]] = {
    IndicatorType.DOMAIN: ("domain-name", "value"),
    IndicatorType.IPV4: ("ipv4-addr", "value"),
    IndicatorType.IPV6: ("ipv6-addr", "value"),
    IndicatorType.URL: ("url", "value"),
    IndicatorType.EMAIL: ("email-addr", "value"),
    IndicatorType.SHA256: ("file", "hashes.'SHA-256'"),
    IndicatorType.SHA1: ("file", "hashes.'SHA-1'"),
    IndicatorType.MD5: ("file", "hashes.MD5"),
}

#: Reverse map for import: (object type, normalized property) -> IndicatorType.
_TYPE_FOR_PATTERN: dict[tuple[str, str], IndicatorType] = {
    ("domain-name", "value"): IndicatorType.DOMAIN,
    ("ipv4-addr", "value"): IndicatorType.IPV4,
    ("ipv6-addr", "value"): IndicatorType.IPV6,
    ("url", "value"): IndicatorType.URL,
    ("email-addr", "value"): IndicatorType.EMAIL,
    ("file", "hashes.sha-256"): IndicatorType.SHA256,
    ("file", "hashes.sha-1"): IndicatorType.SHA1,
    ("file", "hashes.md5"): IndicatorType.MD5,
}

#: A single STIX comparison expression: ``[ <obj>:<prop> = '<value>' ]``.
_SIMPLE_PATTERN = re.compile(
    r"^\[\s*(?P<obj>[a-z0-9-]+):(?P<prop>[A-Za-z0-9_.'\"-]+)\s*=\s*"
    r"'(?P<value>(?:[^'\\]|\\.)*)'\s*\]$"
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


class StixError(ValueError):
    """Raised when a STIX document is malformed or unreadable."""


@dataclass(frozen=True)
class ParsedIndicator:
    """An IOC recovered from a STIX pattern (type + value only)."""

    indicator_type: IndicatorType
    value: str


@dataclass(frozen=True)
class SkippedPattern:
    """A STIX object that could not be faithfully imported, and why."""

    pattern: str
    reason: str


@dataclass(frozen=True)
class ParsedBundle:
    """The faithful IOCs plus everything deliberately not imported."""

    indicators: tuple[ParsedIndicator, ...]
    skipped: tuple[SkippedPattern, ...]


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _unescape(value: str) -> str:
    return value.replace("\\'", "'").replace("\\\\", "\\")


def _stix_pattern(indicator: Indicator) -> str | None:
    mapping = _PATTERN_FOR_TYPE.get(indicator.indicator_type)
    if mapping is None:
        return None
    obj, prop = mapping
    return f"[{obj}:{prop} = '{_escape(indicator.value)}']"


def _object_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid5(_OLYMPUS_STIX_NAMESPACE, f'{kind}:{seed}')}"


def indicators_to_bundle(
    indicators: Sequence[Indicator], *, created: datetime | None = None
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from Olympus indicators.

    Non-CVE IOCs become ``indicator`` SDOs with a single-comparison pattern; CVEs
    become ``vulnerability`` SDOs. Timestamps default to each indicator's
    ``first_seen``; ``created`` overrides them for a fully reproducible document.
    """
    objects: list[dict[str, Any]] = []
    for indicator in indicators:
        stamp = (created or indicator.first_seen).astimezone(UTC).isoformat()
        if indicator.indicator_type is IndicatorType.CVE:
            objects.append(
                {
                    "type": "vulnerability",
                    "spec_version": STIX_SPEC_VERSION,
                    "id": _object_id("vulnerability", indicator.value.upper()),
                    "created": stamp,
                    "modified": stamp,
                    "name": indicator.value.upper(),
                    "external_references": [
                        {"source_name": "cve", "external_id": indicator.value.upper()}
                    ],
                }
            )
            continue
        pattern = _stix_pattern(indicator)
        if pattern is None:  # pragma: no cover - every non-CVE type is mapped
            continue
        seed = f"{indicator.indicator_type.value}:{indicator.value}"
        objects.append(
            {
                "type": "indicator",
                "spec_version": STIX_SPEC_VERSION,
                "id": _object_id("indicator", seed),
                "created": stamp,
                "modified": stamp,
                "name": f"{indicator.indicator_type.value}: {indicator.value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": stamp,
                "indicator_types": ["malicious-activity"],
                "confidence": indicator.confidence,
            }
        )
    seed = "|".join(sorted(item["id"] for item in objects))
    return {
        "type": "bundle",
        "id": _object_id("bundle", seed),
        "objects": objects,
    }


def _parse_pattern(pattern: str) -> ParsedIndicator | None:
    """Return the IOC for a single-comparison equality pattern, else ``None``.

    ``None`` means the pattern is well-formed STIX but outside the faithful
    subset (a compound expression, a non-equality operator, an unmapped object).
    """
    if any(token in pattern for token in (" AND ", " OR ", " FOLLOWEDBY ", " NOT ")):
        return None
    match = _SIMPLE_PATTERN.match(pattern.strip())
    if match is None:
        return None
    obj = match.group("obj").lower()
    prop = match.group("prop").replace("'", "").replace('"', "").lower()
    indicator_type = _TYPE_FOR_PATTERN.get((obj, prop))
    if indicator_type is None:
        return None
    value = _unescape(match.group("value"))
    if not value:
        return None
    return ParsedIndicator(indicator_type=indicator_type, value=value)


def bundle_to_indicators(text: str) -> ParsedBundle:
    """Parse a STIX 2.1 bundle into faithful IOCs plus a skipped-with-reason list."""
    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StixError(f"invalid STIX JSON: {exc.msg}") from exc
    if not isinstance(document, dict) or document.get("type") != "bundle":
        raise StixError("document is not a STIX bundle")
    objects = document.get("objects")
    if not isinstance(objects, list):
        raise StixError("STIX bundle has no 'objects' array")

    indicators: list[ParsedIndicator] = []
    skipped: list[SkippedPattern] = []
    seen: set[tuple[IndicatorType, str]] = set()

    def remember(parsed: ParsedIndicator) -> None:
        key = (parsed.indicator_type, parsed.value)
        if key not in seen:
            seen.add(key)
            indicators.append(parsed)

    for item in objects:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "vulnerability":
            name = str(item.get("name", "")).strip()
            cve = name if _CVE_RE.match(name) else _cve_from_references(item)
            if cve is not None:
                remember(ParsedIndicator(IndicatorType.CVE, cve.upper()))
            else:
                skipped.append(
                    SkippedPattern(name or "<vulnerability>", "no CVE id on vulnerability")
                )
            continue
        if kind != "indicator":
            continue
        pattern = item.get("pattern")
        if item.get("pattern_type") not in (None, "stix") or not isinstance(pattern, str):
            skipped.append(SkippedPattern(str(pattern), "non-STIX pattern_type"))
            continue
        parsed = _parse_pattern(pattern)
        if parsed is None:
            skipped.append(
                SkippedPattern(pattern, "compound or unmapped pattern (not a simple equality)")
            )
            continue
        remember(parsed)

    return ParsedBundle(indicators=tuple(indicators), skipped=tuple(skipped))


def _cve_from_references(item: dict[str, Any]) -> str | None:
    references = item.get("external_references")
    if not isinstance(references, list):
        return None
    for reference in references:
        if not isinstance(reference, dict):
            continue
        external_id = str(reference.get("external_id", ""))
        if _CVE_RE.match(external_id):
            return external_id
    return None

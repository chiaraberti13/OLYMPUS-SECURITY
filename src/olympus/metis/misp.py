"""MISP event export and import for METIS indicators (§2 Metis).

MISP is the other widely deployed way to exchange indicators, and — like STIX —
its event format is plain JSON, so this adds no dependency. The module mirrors
:mod:`olympus.metis.stix`:

* **Export** (:func:`indicators_to_event`) emits a single MISP ``Event`` whose
  ``Attribute`` list carries one entry per IOC, each with MISP's ``type`` and
  ``category``; a CVE becomes a ``vulnerability`` attribute. Attribute UUIDs are
  deterministic (UUIDv5), so re-exporting a case is byte-stable. The event
  defaults to the most conservative sharing settings (org-only distribution).
* **Import** (:func:`event_to_indicators`) reads an event and maps the attribute
  types Olympus represents back into indicators, **skipping** unmapped attribute
  types with a recorded reason rather than guessing — the same import-the-subset,
  refuse-the-rest discipline as the STIX and Hermes boundaries.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from olympus.metis.models import Indicator, IndicatorType

#: Namespace for deterministic MISP attribute/event UUIDs.
_OLYMPUS_MISP_NAMESPACE = uuid5(NAMESPACE_URL, "https://olympus.security/misp")

#: IndicatorType -> (MISP attribute type, MISP category).
_ATTRIBUTE_FOR_TYPE: dict[IndicatorType, tuple[str, str]] = {
    IndicatorType.DOMAIN: ("domain", "Network activity"),
    IndicatorType.IPV4: ("ip-dst", "Network activity"),
    IndicatorType.IPV6: ("ip-dst", "Network activity"),
    IndicatorType.URL: ("url", "Network activity"),
    IndicatorType.EMAIL: ("email-src", "Payload delivery"),
    IndicatorType.SHA256: ("sha256", "Payload delivery"),
    IndicatorType.SHA1: ("sha1", "Payload delivery"),
    IndicatorType.MD5: ("md5", "Payload delivery"),
    IndicatorType.CVE: ("vulnerability", "External analysis"),
}

#: Reverse map for import: MISP attribute type -> IndicatorType. ``ip-src`` and
#: ``ip-dst`` both map to IPv4/IPv6 by inspecting the value at parse time.
_TYPE_FOR_ATTRIBUTE: dict[str, IndicatorType] = {
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "email-src": IndicatorType.EMAIL,
    "email-dst": IndicatorType.EMAIL,
    "email": IndicatorType.EMAIL,
    "sha256": IndicatorType.SHA256,
    "sha1": IndicatorType.SHA1,
    "md5": IndicatorType.MD5,
    "vulnerability": IndicatorType.CVE,
}


class MispError(ValueError):
    """Raised when a MISP document is malformed or unreadable."""


@dataclass(frozen=True)
class ParsedAttribute:
    """An IOC recovered from a MISP attribute (type + value only)."""

    indicator_type: IndicatorType
    value: str


@dataclass(frozen=True)
class SkippedAttribute:
    """A MISP attribute that could not be faithfully imported, and why."""

    misp_type: str
    value: str
    reason: str


@dataclass(frozen=True)
class ParsedEvent:
    """The faithful IOCs plus everything deliberately not imported."""

    indicators: tuple[ParsedAttribute, ...]
    skipped: tuple[SkippedAttribute, ...]


def _attribute_uuid(misp_type: str, value: str) -> str:
    return str(uuid5(_OLYMPUS_MISP_NAMESPACE, f"{misp_type}:{value}"))


def indicators_to_event(
    indicators: Sequence[Indicator],
    *,
    info: str = "Olympus indicators",
    event_date: date | None = None,
) -> dict[str, Any]:
    """Build a conservative MISP event from Olympus indicators.

    ``to_ids`` is true for every attribute (these are detection-grade IOCs), and
    ``distribution`` is ``"0"`` (this organisation only) so an export never
    widens sharing by default. ``event_date`` defaults to today (UTC).
    """
    attributes: list[dict[str, Any]] = []
    for indicator in indicators:
        misp_type, category = _ATTRIBUTE_FOR_TYPE[indicator.indicator_type]
        value = (
            indicator.value.upper()
            if indicator.indicator_type is IndicatorType.CVE
            else indicator.value
        )
        attributes.append(
            {
                "uuid": _attribute_uuid(misp_type, value),
                "type": misp_type,
                "category": category,
                "value": value,
                "to_ids": True,
                "comment": indicator.source,
            }
        )
    stamp = (event_date or datetime.now(UTC).date()).isoformat()
    seed = "|".join(sorted(item["uuid"] for item in attributes))
    return {
        "Event": {
            "uuid": str(uuid5(_OLYMPUS_MISP_NAMESPACE, f"event:{info}:{seed}")),
            "info": info,
            "date": stamp,
            "threat_level_id": "4",  # undefined
            "analysis": "2",  # completed
            "distribution": "0",  # your organisation only
            "Attribute": attributes,
        }
    }


def event_to_indicators(text: str) -> ParsedEvent:
    """Parse a MISP event JSON into faithful IOCs plus a skipped-with-reason list."""
    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MispError(f"invalid MISP JSON: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise MispError("document is not a MISP event")
    event = document.get("Event", document)  # accept a bare Event body too
    if not isinstance(event, dict):
        raise MispError("MISP document has no 'Event' object")
    attributes = event.get("Attribute")
    if not isinstance(attributes, list):
        raise MispError("MISP event has no 'Attribute' array")

    indicators: list[ParsedAttribute] = []
    skipped: list[SkippedAttribute] = []
    seen: set[tuple[IndicatorType, str]] = set()

    for attribute in attributes:
        if not isinstance(attribute, dict):
            continue
        misp_type = str(attribute.get("type", ""))
        raw_value = attribute.get("value", "")
        # MISP values are strings; refuse a non-string (a malformed or hostile
        # event) rather than str()-ifying a dict/list into a bogus indicator.
        if not isinstance(raw_value, str):
            skipped.append(SkippedAttribute(misp_type, repr(raw_value)[:64], "non-string value"))
            continue
        value = raw_value.strip()
        if not value:
            skipped.append(SkippedAttribute(misp_type, value, "empty value"))
            continue
        resolved = _resolve(misp_type, value)
        if resolved is None:
            skipped.append(SkippedAttribute(misp_type, value, "unmapped MISP attribute type"))
            continue
        indicator_type, normalized = resolved
        key = (indicator_type, normalized)
        if key not in seen:
            seen.add(key)
            indicators.append(ParsedAttribute(indicator_type, normalized))
    return ParsedEvent(indicators=tuple(indicators), skipped=tuple(skipped))


def _resolve(misp_type: str, value: str) -> tuple[IndicatorType, str] | None:
    """Map a MISP attribute type+value to (IndicatorType, normalized value).

    Composite ``ip-*|port`` attributes carry ``ip|port`` as the value; only the
    host is kept. IPv4 vs IPv6 is decided from the host itself.
    """
    if misp_type in {"ip-src", "ip-dst", "ip-src|port", "ip-dst|port"}:
        host = value.split("|", 1)[0]
        return (IndicatorType.IPV6 if ":" in host else IndicatorType.IPV4), host
    indicator_type = _TYPE_FOR_ATTRIBUTE.get(misp_type)
    if indicator_type is None:
        return None
    normalized = value.upper() if indicator_type is IndicatorType.CVE else value
    return indicator_type, normalized

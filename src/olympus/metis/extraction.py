"""Unified, offline IOC extraction across free text, STIX and MISP inputs.

This module is the single reusable core behind the Metis extraction surfaces:
the CLI case ingest, the typed API slice (``POST /api/v1/metis/extract``) and the
Web workbench (``/metis``). It performs **no network access**: every format is
parsed and normalized locally and deterministically.

The three supported inputs collapse to one honest shape — the faithful IOCs plus
everything deliberately *not* imported, each with a reason — so a consumer never
mistakes a skipped/unparsed item for a clean result.
"""

from __future__ import annotations

from dataclasses import dataclass

from olympus.metis.cases import extract_indicators
from olympus.metis.misp import event_to_indicators
from olympus.metis.models import IndicatorType
from olympus.metis.stix import bundle_to_indicators

#: Formats the extraction surface understands. ``text`` runs the free-text IOC
#: extractor; ``stix`` and ``misp`` parse structured threat-intel documents.
EXTRACTION_FORMATS: tuple[str, ...] = ("text", "stix", "misp")

#: Hard cap on the raw input accepted by the Web/API boundary. Below the bulk
#: ``MAX_INGEST_BYTES`` used for CLI file ingest, because these surfaces accept
#: a pasted body rather than a vetted evidence file.
MAX_EXTRACTION_BYTES = 1_000_000

#: Cap on the number of parsed items (indicators + skipped) returned, so a
#: crafted STIX/MISP document cannot produce an unbounded response.
MAX_EXTRACTION_ITEMS = 10_000


@dataclass(frozen=True)
class ExtractedIndicator:
    """A normalized IOC recovered from the input (type + value only)."""

    indicator_type: IndicatorType
    value: str


@dataclass(frozen=True)
class SkippedItem:
    """An input element that was not faithfully imported, and why."""

    value: str
    reason: str


@dataclass(frozen=True)
class ExtractionResult:
    """The faithful IOCs plus everything deliberately not imported."""

    source_format: str
    indicators: tuple[ExtractedIndicator, ...]
    skipped: tuple[SkippedItem, ...]


def _check_bounds(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_EXTRACTION_BYTES:
        raise ValueError(f"input exceeds the {MAX_EXTRACTION_BYTES} byte limit")


def _guard_items(
    indicators: tuple[ExtractedIndicator, ...], skipped: tuple[SkippedItem, ...]
) -> None:
    if len(indicators) + len(skipped) > MAX_EXTRACTION_ITEMS:
        raise ValueError(f"parsed item count exceeds the {MAX_EXTRACTION_ITEMS} item limit")


def extract_from_source(source_format: str, text: str, *, source: str = "web") -> ExtractionResult:
    """Extract IOCs from ``text`` in ``source_format`` offline and deterministically.

    ``text`` runs the free-text extractor (refanging, dedupe, normalization);
    ``stix`` and ``misp`` parse structured documents into faithful IOCs plus a
    skipped-with-reason list. Indicators are sorted by ``(type, value)`` so the
    result is stable regardless of input ordering. Raises :class:`ValueError`
    (or its subclasses :class:`~olympus.metis.stix.StixError` /
    :class:`~olympus.metis.misp.MispError`) on malformed input or exceeded bounds.
    """
    if source_format not in EXTRACTION_FORMATS:
        raise ValueError(f"unsupported extraction format: {source_format!r}")
    _check_bounds(text)

    if source_format == "text":
        extracted = extract_indicators(text, source=source)
        indicators = tuple(
            ExtractedIndicator(item.indicator_type, item.value) for item in extracted
        )
        skipped: tuple[SkippedItem, ...] = ()
    elif source_format == "stix":
        bundle = bundle_to_indicators(text)
        indicators = tuple(
            ExtractedIndicator(item.indicator_type, item.value) for item in bundle.indicators
        )
        skipped = tuple(SkippedItem(item.pattern, item.reason) for item in bundle.skipped)
    else:  # misp
        event = event_to_indicators(text)
        indicators = tuple(
            ExtractedIndicator(item.indicator_type, item.value) for item in event.indicators
        )
        skipped = tuple(
            SkippedItem(f"{item.misp_type}: {item.value}", item.reason) for item in event.skipped
        )

    ordered = tuple(sorted(indicators, key=lambda item: (item.indicator_type.value, item.value)))
    _guard_items(ordered, skipped)
    return ExtractionResult(source_format=source_format, indicators=ordered, skipped=skipped)


__all__ = [
    "EXTRACTION_FORMATS",
    "MAX_EXTRACTION_BYTES",
    "MAX_EXTRACTION_ITEMS",
    "ExtractedIndicator",
    "ExtractionResult",
    "SkippedItem",
    "extract_from_source",
]

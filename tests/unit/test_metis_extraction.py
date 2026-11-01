"""Unit coverage for the unified, offline Metis IOC extraction core.

The three supported inputs (free text, STIX, MISP) collapse to one honest shape:
faithful indicators plus everything deliberately not imported, each with a
reason. These tests assert the normalization, determinism and bounds without any
network access.
"""

from __future__ import annotations

import json

import pytest

from olympus.metis.extraction import (
    EXTRACTION_FORMATS,
    MAX_EXTRACTION_BYTES,
    extract_from_source,
)
from olympus.metis.models import IndicatorType


def test_text_extraction_is_sorted_normalized_and_deduplicated() -> None:
    result = extract_from_source(
        "text",
        "hxxp://login[.]bad.example/a from 203.0.113.9 and 203.0.113.9; "
        "evil@bad.example; CVE-2021-44228",
    )
    assert result.source_format == "text"
    assert result.skipped == ()
    pairs = [(item.indicator_type, item.value) for item in result.indicators]
    # Sorted by (type, value); defanged host refanged; duplicate IP collapsed.
    assert pairs == sorted(pairs, key=lambda item: (item[0].value, item[1]))
    assert (IndicatorType.IPV4, "203.0.113.9") in pairs
    assert sum(1 for kind, value in pairs if value == "203.0.113.9") == 1
    assert (IndicatorType.CVE, "CVE-2021-44228") in pairs
    assert (IndicatorType.URL, "http://login.bad.example/a") in pairs


def test_stix_extraction_reports_unparseable_patterns_as_skipped() -> None:
    bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--22222222-2222-4222-8222-222222222222",
                    "pattern": "[domain-name:value = 'bad.example']",
                    "pattern_type": "stix",
                },
                {
                    "type": "indicator",
                    "id": "indicator--33333333-3333-4333-8333-333333333333",
                    "pattern": "[network-traffic:dst_ref.value = '1.2.3.4']",
                    "pattern_type": "stix",
                },
            ],
        }
    )
    result = extract_from_source("stix", bundle)
    assert [item.value for item in result.indicators] == ["bad.example"]
    assert len(result.skipped) == 1
    assert result.skipped[0].reason


def test_misp_extraction_labels_unmapped_attributes() -> None:
    event = json.dumps(
        {
            "Event": {
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.7"},
                    {"type": "comment", "value": "analyst note"},
                ]
            }
        }
    )
    result = extract_from_source("misp", event)
    assert [(i.indicator_type, i.value) for i in result.indicators] == [
        (IndicatorType.IPV4, "198.51.100.7")
    ]
    assert len(result.skipped) == 1
    assert "analyst note" in result.skipped[0].value


def test_unsupported_format_is_rejected() -> None:
    assert "yaml" not in EXTRACTION_FORMATS
    with pytest.raises(ValueError, match="unsupported extraction format"):
        extract_from_source("yaml", "irrelevant")


def test_oversized_input_is_rejected_before_parsing() -> None:
    with pytest.raises(ValueError, match="byte limit"):
        extract_from_source("text", "a" * (MAX_EXTRACTION_BYTES + 1))


@pytest.mark.parametrize("source_format", ["stix", "misp"])
def test_malformed_structured_input_raises_value_error(source_format: str) -> None:
    with pytest.raises(ValueError):
        extract_from_source(source_format, "definitely not json")

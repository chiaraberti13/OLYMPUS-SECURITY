"""Property-based fuzzing of the Apollo and Metis untrusted-input parsers (SEC-H).

Threat-intel feeds (STIX bundles, MISP events) and ingested access logs are
produced outside Olympus and must be treated as hostile. Each parser must map
any byte sequence to either a well-formed result or a *handled* ``ValueError``
(``StixError``, ``MispError`` and ``SigmaImportError`` all subclass it) — never
an unhandled exception that would crash the caller. This suite asserts that
invariant across hostile JSON, JSONL and free text, completing the parser-fuzz
coverage for the Apollo and Metis layers. Nothing network-active runs.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.apollo.ingest import IngestResult, parse_access_log
from olympus.apollo.sigma import parse_sigma_yaml
from olympus.metis.misp import ParsedEvent, event_to_indicators
from olympus.metis.stix import ParsedBundle, bundle_to_indicators

_json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=24),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=16), children, max_size=4),
    ),
    max_leaves=18,
)

_free_text = st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), max_size=400)


@st.composite
def _feed(draw: st.DrawFn) -> str:
    """One hostile feed blob: JSON, JSON lines, or raw text."""
    shape = draw(st.sampled_from(("json", "jsonl", "text")))
    if shape == "text":
        return draw(_free_text)
    if shape == "jsonl":
        rows = draw(st.lists(_json_values, min_size=1, max_size=4))
        return "\n".join(json.dumps(row) for row in rows)
    return json.dumps(draw(_json_values))


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_feed())
def test_stix_bundle_parser_never_crashes(text: str) -> None:
    try:
        parsed = bundle_to_indicators(text)
    except ValueError:
        return  # StixError (a ValueError) is the documented hostile-input outcome
    assert isinstance(parsed, ParsedBundle)
    assert isinstance(parsed.indicators, tuple | list)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_feed())
def test_misp_event_parser_never_crashes(text: str) -> None:
    try:
        parsed = event_to_indicators(text)
    except ValueError:
        return  # MispError (a ValueError) is the documented hostile-input outcome
    assert isinstance(parsed, ParsedEvent)
    assert isinstance(parsed.indicators, tuple | list)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_free_text)
def test_sigma_parser_never_crashes(text: str) -> None:
    try:
        rule = parse_sigma_yaml(text)
    except ValueError:
        return  # SigmaImportError (a ValueError) for anything outside the strict subset
    assert isinstance(rule, dict)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(text=_free_text)
def test_access_log_ingest_never_crashes(text: str) -> None:
    # Access-log ingestion never raises on content: unparseable lines are
    # recorded as skipped rather than guessed at or allowed to crash.
    result = parse_access_log(text)
    assert isinstance(result, IngestResult)
    assert len(result.events) + len(result.skipped) <= len(text.splitlines())

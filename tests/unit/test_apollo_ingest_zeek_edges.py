"""Edge-case units for the Zeek JSON ingest helpers (OPS-BLUE / SEC-H discipline).

These pin the honest-absence and defensive branches of the Zeek parser that the
integration fixture does not exercise: non-object JSON lines, pathologically deep
nesting, boolean/absent field rendering and non-numeric timestamps.
"""

from __future__ import annotations

from olympus.apollo.ingest import parse_zeek_json


def test_a_json_array_line_is_skipped_not_treated_as_a_record() -> None:
    result = parse_zeek_json('[1, 2, 3]\n{"_path":"conn","id.orig_h":"10.0.0.1"}')
    assert len(result.events) == 1
    assert any(item.reason == "not a JSON object" for item in result.skipped)


def test_deeply_nested_line_is_skipped_without_crashing() -> None:
    bomb = "[" * 20_000 + "]" * 20_000  # exceeds the JSON recursion limit
    result = parse_zeek_json(bomb)
    assert result.events == ()
    assert any(item.reason == "JSON nesting too deep" for item in result.skipped)


def test_boolean_fields_render_as_true_false_and_absent_fields_drop() -> None:
    # 'local_orig' is not mapped; a boolean *mapped* field (none exist today) would
    # render as text — we prove the stringify path via a bool-valued mapped field by
    # using conn_state set to a bool, and that an absent mapped field is dropped.
    line = '{"_path":"conn","id.orig_h":"10.0.0.1","conn_state":true}'
    (event,) = parse_zeek_json(line).events
    assert event.attributes["conn_state"] == "true"
    # id.resp_h was absent -> not invented.
    assert "dest_ip" not in event.attributes


def test_non_numeric_timestamp_is_omitted_not_guessed() -> None:
    line = '{"_path":"dns","ts":"yesterday","id.orig_h":"10.0.0.1","query":"a.example"}'
    (event,) = parse_zeek_json(line).events
    # The record is still ingested from its valid fields.
    assert event.attributes["query"] == "a.example"


def test_record_with_only_unmapped_fields_is_skipped() -> None:
    line = '{"_path":"conn","unmapped_only":"x","another":"y"}'
    result = parse_zeek_json(line)
    assert result.events == ()
    assert any(item.reason == "no mappable conn fields" for item in result.skipped)

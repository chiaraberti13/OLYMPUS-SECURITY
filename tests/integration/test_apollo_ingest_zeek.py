"""Apollo telemetry ingest: Zeek JSON-streaming logs -> core.Event NDJSON (OPS-BLUE).

The Zeek fixture under ``tests/fixtures/apollo/ingest/zeek.jsonl`` is a small,
**synthetic but format-faithful** JSON-streaming log (no real data): it carries
``conn``/``dns``/``http``/``ssl`` records — including the nested ``id`` form — plus
a non-JSON line, an unknown ``_path`` and a record with an invalid ``ts``, so it
also proves the parser skips what it cannot faithfully normalize instead of
guessing.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ingest import iter_zeek_json, parse_zeek_json
from olympus.cli import app
from olympus.core.enums import Source

runner = CliRunner()

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "apollo" / "ingest" / "zeek.jsonl"

_RULE = """\
schema_name: olympus.apollo-rule
schema_version: 1.0.0
rule_id: APL-TEST-C2-DNS
title: DNS query to a known C2 domain
event_type: dns.query
conditions:
  query: c2.evil.example
  query_type: A
severity: high
mitre_attack:
  - T1071.004
"""


def test_parse_maps_each_zeek_log_kind() -> None:
    result = parse_zeek_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)
    by_type = {event.event_type for event in result.events}
    assert by_type == {"network.connection", "dns.query", "http.request", "tls.session"}
    assert all(event.source is Source.MARS for event in result.events)

    conn = next(e for e in result.events if e.event_type == "network.connection")
    assert conn.attributes["client_ip"] == "10.10.0.5"
    assert conn.attributes["dest_port"] == "445"
    assert conn.attributes["service"] == "smb"
    # The Zeek epoch ts is anchored to UTC for ordering.
    assert conn.observed_at is not None and conn.observed_at.tzinfo is not None


def test_parse_reads_the_nested_id_form() -> None:
    result = parse_zeek_json(_FIXTURE.read_text(encoding="utf-8"))
    dns = next(e for e in result.events if e.event_type == "dns.query")
    # The dns record uses {"id": {"orig_h": ...}} rather than flat dotted keys.
    assert dns.attributes["client_ip"] == "10.10.0.5"
    assert dns.attributes["dest_ip"] == "10.10.0.53"
    assert dns.attributes["query"] == "c2.evil.example"


def test_parse_skips_malformed_unknown_and_never_guesses() -> None:
    result = parse_zeek_json(_FIXTURE.read_text(encoding="utf-8"))
    reasons = {item.reason for item in result.skipped}
    assert "not valid JSON" in reasons
    assert "unknown or missing Zeek _path" in reasons
    # The conn record with an invalid ts is still ingested from its mappable
    # fields; the unparseable ts is simply not carried, never coerced to a value.
    bad_ts = [
        e
        for e in result.events
        if e.event_type == "network.connection" and e.attributes.get("dest_port") == "22"
    ]
    assert bad_ts, "a record with a bad ts but valid fields must still be ingested"


def test_zeek_parser_applies_consumer_backpressure() -> None:
    consumed = 0

    def records():
        nonlocal consumed
        for line in _FIXTURE.open(encoding="utf-8"):
            consumed += 1
            yield line

    parsed = iter_zeek_json(records())
    first = next(parsed)
    assert consumed == 1
    assert first is not None


def test_ingest_cli_zeek_then_run_detects_c2_dns(tmp_path: Path) -> None:
    events = tmp_path / "events.ndjson"
    ingest = runner.invoke(
        app,
        [
            "apollo",
            "ingest",
            "--input",
            str(_FIXTURE),
            "--output",
            str(events),
            "--format",
            "zeek-json",
        ],
    )
    assert ingest.exit_code == 0, ingest.output
    assert "ingested 5 event(s)" in ingest.output  # conn, dns, http, ssl, conn(bad ts)

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "c2.yaml").write_text(_RULE, encoding="utf-8")
    run = runner.invoke(
        app,
        [
            "apollo",
            "run",
            "--rules",
            str(rules_dir),
            "--events",
            str(events),
            "--output",
            str(tmp_path / "alerts.json"),
        ],
    )
    assert run.exit_code == 1, run.output  # alerts present
    alerts = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert "APL-TEST-C2-DNS" in json.dumps(alerts)

"""Apollo telemetry ingest: Windows Event / Sysmon JSON -> core.Event NDJSON (OPS-BLUE).

The fixture ``tests/fixtures/apollo/ingest/windows.jsonl`` is a small, **synthetic
but format-faithful** NDJSON export (no real data, reserved/documentation IPs): it
carries Sysmon records (process create, network connection, DNS query, file
create, registry set) and Security logon records (4624/4625), plus a
provider-mismatched id, an unmapped id, a non-JSON line, a non-object line and a
record with an invalid timestamp — so it also proves the parser skips what it
cannot faithfully normalize instead of guessing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.apollo.ingest import iter_windows_json, parse_windows_json
from olympus.cli import app
from olympus.core.enums import Source

runner = CliRunner()

_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "apollo" / "ingest" / "windows.jsonl"
)

_RULE = """\
schema_name: olympus.apollo-rule
schema_version: 1.0.0
rule_id: APL-TEST-SYSMON-C2-DNS
title: Sysmon DNS query to a known C2 domain
event_type: dns.query
conditions:
  query: c2.evil.example
severity: high
mitre_attack:
  - T1071.004
"""


def test_parse_maps_sysmon_and_security_event_kinds() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)
    by_type = {event.event_type for event in result.events}
    assert by_type == {
        "process.create",
        "network.connection",
        "dns.query",
        "file.create",
        "registry.set",
        "auth.logon",
        "auth.logon_failed",
    }
    assert all(event.source is Source.MARS for event in result.events)

    proc = next(e for e in result.events if e.event_type == "process.create")
    assert proc.attributes["command_line"] == "cmd.exe /c whoami"
    assert proc.attributes["user"] == "LAB\\analyst"
    assert proc.attributes["event_id"] == "1"
    assert proc.observed_at is not None and proc.observed_at.tzinfo is not None

    logon_failed = next(e for e in result.events if e.event_type == "auth.logon_failed")
    assert logon_failed.attributes["user"] == "administrator"
    assert logon_failed.attributes["client_ip"] == "10.20.0.9"


def test_parse_skips_provider_mismatch_unknown_and_malformed() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"))
    reasons = {item.reason for item in result.skipped}
    assert "provider does not match EventID 1" in reasons
    assert "unknown or missing Windows EventID" in reasons  # EventID 4688 is not mapped
    assert "not valid JSON" in reasons
    assert "not a JSON object" in reasons
    # The network record with an invalid timestamp is still ingested from its
    # mappable fields; the unparseable timestamp is simply not carried over.
    bad_ts = [
        e
        for e in result.events
        if e.event_type == "network.connection" and e.attributes.get("dest_port") == "8080"
    ]
    assert bad_ts, "a record with a bad timestamp but valid fields must still be ingested"
    assert bad_ts[0].attributes["dest_ip"] == "203.0.113.7"


def test_windows_parser_applies_consumer_backpressure() -> None:
    consumed = 0

    def records():
        nonlocal consumed
        for line in _FIXTURE.open(encoding="utf-8"):
            consumed += 1
            yield line

    parsed = iter_windows_json(records())
    first = next(parsed)
    assert consumed == 1
    assert first is not None


@pytest.mark.parametrize(
    "hostile",
    [
        "",
        "   ",
        "}{ not json",
        '{"EventID": "abc", "Provider": "Microsoft-Windows-Sysmon"}',
        '{"EventID": 1}',  # no provider -> family mismatch, never guessed
        '{"EventID": 1, "Provider": "Microsoft-Windows-Sysmon"}',  # no mappable fields
        "42",
        "[1, 2, 3]",
    ],
)
def test_hostile_lines_never_crash_and_are_skipped(hostile: str) -> None:
    result = parse_windows_json(hostile)
    assert result.events == ()  # nothing invented
    # Blank lines are silently ignored; everything else is skipped with a reason.
    assert hostile.strip() == "" or len(result.skipped) == 1


def test_ingest_cli_windows_then_run_detects_c2_dns(tmp_path: Path) -> None:
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
            "windows-json",
        ],
    )
    assert ingest.exit_code == 0, ingest.output
    assert "ingested 8 event(s)" in ingest.output

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
    assert "APL-TEST-SYSMON-C2-DNS" in (tmp_path / "alerts.json").read_text(encoding="utf-8")

"""Apollo telemetry ingest: real HTTP access logs -> core.Event NDJSON (Blue).

The access-log fixture under ``tests/fixtures/apollo/ingest/`` is REAL captured
output: a live ``python -m http.server`` on ``127.0.0.1`` was hit with a set of
requests (including sensitive paths like ``/admin`` and ``/.env``) and its access
log saved verbatim. The log deliberately interleaves non-access diagnostic lines,
so it also proves the parser skips what it cannot faithfully parse.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.apollo.ingest import parse_access_log
from olympus.cli import app
from olympus.core.enums import Source

runner = CliRunner()

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "apollo" / "ingest" / "access.log"

_RULE = """\
schema_name: olympus.apollo-rule
schema_version: 1.0.0
rule_id: APL-TEST-ADMIN
title: Access to sensitive /admin path
event_type: http.request
conditions:
  path: /admin
  status: "404"
severity: medium
mitre_attack:
  - T1083
"""


def test_parse_reads_real_access_log_and_skips_non_records() -> None:
    result = parse_access_log(_FIXTURE.read_text(encoding="utf-8"))
    # Seven real request records; the interleaved "code NNN, message ..." lines
    # are skipped with a reason rather than coerced into events.
    assert len(result.events) == 7
    assert result.skipped, "expected non-access lines to be skipped"
    assert all(item.reason == "not an access-log record" for item in result.skipped)
    assert all(event.event_type == "http.request" for event in result.events)

    admin = next(e for e in result.events if e.attributes.get("path") == "/admin")
    assert admin.attributes["method"] == "GET"
    assert admin.attributes["status"] == "404"
    assert admin.attributes["client_ip"] == "127.0.0.1"
    # A dev-server timestamp is parsed and anchored to UTC for ordering.
    assert admin.observed_at.tzinfo is not None


def test_parse_extracts_query_and_combined_fields() -> None:
    combined = (
        '203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] '
        '"GET /search?q=secret HTTP/1.1" 200 2326 '
        '"http://ref.example/" "Mozilla/5.0 (X11)"'
    )
    result = parse_access_log(combined, source=Source.MARS)
    assert len(result.events) == 1
    event = result.events[0]
    assert event.source is Source.MARS
    assert event.attributes["path"] == "/search"
    assert event.attributes["query"] == "q=secret"
    assert event.attributes["user_agent"].startswith("Mozilla/5.0")
    assert event.attributes["bytes"] == "2326"


def test_ingest_cli_then_run_detects_a_sensitive_path(tmp_path: Path) -> None:
    events = tmp_path / "events.ndjson"
    ingest = runner.invoke(
        app,
        ["apollo", "ingest", "--input", str(_FIXTURE), "--output", str(events)],
    )
    assert ingest.exit_code == 0, ingest.output
    assert events.read_text(encoding="utf-8").count("\n") == 7  # one JSON event per line

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "admin.yaml").write_text(_RULE, encoding="utf-8")
    run = runner.invoke(
        app,
        ["apollo", "run", "--rules", str(rules_dir), "--events", str(events),
         "--output", str(tmp_path / "alerts.json")],
    )
    # Alerts present -> exit 1; the /admin 404 request is the one match.
    assert run.exit_code == 1, run.output
    assert "-> 1 alert(s)" in run.output
    alerts = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    rendered = json.dumps(alerts)
    assert "APL-TEST-ADMIN" in rendered


def test_ingest_rejects_an_unsupported_format(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["apollo", "ingest", "--input", str(_FIXTURE),
         "--output", str(tmp_path / "o.ndjson"), "--format", "sysmon"],
    )
    assert result.exit_code == 2
    assert "unsupported ingest format" in result.output

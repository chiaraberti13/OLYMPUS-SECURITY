"""Apollo telemetry ingest: Windows Event / Sysmon JSON -> core.Event NDJSON (OPS-BLUE).

The fixture ``tests/fixtures/apollo/ingest/windows.jsonl`` is a small, **synthetic
but format-faithful** NDJSON export (no real data, reserved/documentation IPs): it
carries Sysmon records (process create, file-create-time change / timestomp, network
connection, image/DLL load, create remote thread, process access, file create,
registry set, named pipe created/connected, file delete) and Security records
(4624/4625 logon, 4688 process create, 4697 service install, 4698 scheduled-task
create, 4720 account create), plus a provider-mismatched id, an unmapped id (4634),
a non-JSON line, a
non-object line and a record with an invalid timestamp — so it also proves the
parser skips what it cannot faithfully normalize instead of guessing.

Events use the established rule taxonomy (``windows.sysmon`` / ``windows.security``
with an ``event_id`` attribute), so ingested telemetry feeds the shipped Sysmon
detection rules in ``examples/input/apollo-sysmon`` end to end.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.apollo.ingest import iter_windows_json, parse_windows_json
from olympus.cli import app
from olympus.core.enums import Source

runner = CliRunner()

_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / "tests" / "fixtures" / "apollo" / "ingest" / "windows.jsonl"
_RULES = _ROOT / "examples" / "input" / "apollo-sysmon"


def test_parse_maps_to_the_sysmon_and_security_taxonomy() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)
    assert {event.event_type for event in result.events} == {"windows.sysmon", "windows.security"}
    assert all(event.source is Source.MARS for event in result.events)

    proc = next(
        e
        for e in result.events
        if e.event_type == "windows.sysmon" and e.attributes["event_id"] == "1"
    )
    assert proc.attributes["command_line"] == "cmd.exe /c whoami"
    assert proc.attributes["user"] == "LAB\\analyst"
    assert proc.attributes["process_name"] == "cmd.exe"  # basename derived from Image
    assert proc.observed_at is not None and proc.observed_at.tzinfo is not None

    logon_failed = next(
        e
        for e in result.events
        if e.event_type == "windows.security" and e.attributes["event_id"] == "4625"
    )
    assert logon_failed.attributes["user"] == "administrator"
    assert logon_failed.attributes["ip_address"] == "10.20.0.9"


def test_parse_derives_target_and_module_basenames() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)
    by_id = {e.attributes["event_id"]: e for e in result.events}

    # Sysmon 10 (process access) exposes the target basename for exact rule matching.
    access = by_id["10"]
    assert access.event_type == "windows.sysmon"
    assert access.attributes["target_process_name"] == "lsass.exe"
    assert access.attributes["granted_access"] == "0x1410"

    # Sysmon 8 (create remote thread) exposes the injected target's basename.
    assert by_id["8"].attributes["target_process_name"] == "explorer.exe"

    # Sysmon 7 (image/DLL load) exposes the loaded module basename.
    assert by_id["7"].attributes["loaded_module_name"] == "evil.dll"

    # Security 4688 maps NewProcessName to image, so process_name is derived too.
    assert by_id["4688"].attributes["process_name"] == "cmd.exe"
    assert by_id["4688"].attributes["parent_image"] == "C:\\Windows\\explorer.exe"

    # Security 4697 (service install) and 4720 (account create) carry their fields.
    assert by_id["4697"].attributes["service_name"] == "EvilSvc"
    assert by_id["4720"].attributes["account"] == "backdoor"


def test_parse_maps_timestomp_named_pipe_and_scheduled_task() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)
    by_id = {e.attributes["event_id"]: e for e in result.events}

    # Sysmon 2 (FileCreateTime): both the altered file and the actor basename, so a
    # timestomping rule can match the temp-dir binary that rewrote the timestamp.
    timestomp = by_id["2"]
    assert timestomp.event_type == "windows.sysmon"
    assert timestomp.attributes["target_filename"] == "C:\\Windows\\System32\\calc.exe"
    assert timestomp.attributes["process_name"] == "evil.exe"
    assert timestomp.attributes["creation_time"] == "2019-03-19T10:00:00.000Z"

    # Sysmon 17/18 (named pipe created/connected) both carry the pipe name verbatim;
    # 18 maps too even though no shipped rule targets it (coverage, not a guess).
    assert by_id["17"].attributes["pipe_name"] == r"\evilc2-pipe"
    assert by_id["17"].attributes["process_name"] == "beacon.exe"
    assert by_id["18"].attributes["pipe_name"] == r"\evilc2-pipe"
    assert by_id["18"].attributes["process_name"] == "svchost.exe"

    # Security 4698 (scheduled task created) carries the task name and the actor.
    scheduled = by_id["4698"]
    assert scheduled.event_type == "windows.security"
    assert scheduled.attributes["task_name"] == r"\UpdaterTask"
    assert scheduled.attributes["user"] == "svc-backup"


def test_parse_skips_provider_mismatch_unknown_and_malformed() -> None:
    result = parse_windows_json(_FIXTURE.read_text(encoding="utf-8"))
    reasons = {item.reason for item in result.skipped}
    assert "provider does not match EventID 1" in reasons
    assert "unknown or missing Windows EventID" in reasons  # EventID 4634 is not mapped
    assert "not valid JSON" in reasons
    assert "not a JSON object" in reasons
    # The network record with an invalid timestamp is still ingested from its
    # mappable fields; the unparseable timestamp is simply not carried over.
    bad_ts = [
        e
        for e in result.events
        if e.attributes.get("event_id") == "3" and e.attributes.get("dest_port") == "8080"
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


def test_ingest_cli_then_shipped_rules_detect_sysmon_and_security(tmp_path: Path) -> None:
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
    assert "ingested 19 event(s)" in ingest.output

    alerts_path = tmp_path / "alerts.json"
    run = runner.invoke(
        app,
        [
            "apollo",
            "run",
            "--rules",
            str(_RULES),
            "--events",
            str(events),
            "--output",
            str(alerts_path),
        ],
    )
    assert run.exit_code == 1, run.output  # alerts present
    fired = {a["rule_id"] for a in json.loads(alerts_path.read_text(encoding="utf-8"))["alerts"]}
    # The ingested Windows telemetry drives all shipped detection rules end to end.
    assert fired == {
        "APL-SYSMON-C2-DNS",
        "APL-SYSMON-RUNKEY-PERSISTENCE",
        "APL-SECURITY-FAILED-ADMIN-LOGON",
        "APL-SYSMON-LSASS-ACCESS",
        "APL-SYSMON-REMOTE-THREAD-INJECTION",
        "APL-SECURITY-SERVICE-INSTALL",
        "APL-SYSMON-TIMESTOMP",
        "APL-SYSMON-NAMED-PIPE-C2",
        "APL-SECURITY-SCHEDULED-TASK",
    }

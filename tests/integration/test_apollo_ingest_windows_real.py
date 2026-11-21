"""Apollo ``windows-json`` ingest validated against REAL captured Windows telemetry (BLUE-1).

The fixture ``tests/fixtures/apollo/ingest/windows-real-otrf.jsonl`` is a small,
verbatim excerpt of a public, MIT-licensed capture from the OTRF *Security-Datasets*
project (``empire_powerview_ldap_ntsecuritydescriptor``, simulated ``theshire.local``
lab — RFC 1918 / documentation hosts only, no real-world data). It is a genuine
NXLog/Winlogbeat export, whose shape differs from the synthetic
``windows.jsonl`` fixture in ways that matter:

* the ``EventID`` arrives as an int or a numeric string;
* the provider is in ``SourceName`` (and ``Channel``), not ``Provider``;
* **EventData fields are flattened to the top level** — there is no nested
  ``EventData`` object at all.

So this proves the parser works on telemetry a real SIEM pipeline produces, not
only on the ``Get-WinEvent | ConvertTo-Json`` layout, while still skipping the
event IDs it does not map (never guessing).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.apollo.ingest import parse_windows_json
from olympus.core.enums import Source

pytestmark = pytest.mark.integration

_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "apollo"
    / "ingest"
    / "windows-real-otrf.jsonl"
)


def _result():
    return parse_windows_json(_FIXTURE.read_text(encoding="utf-8"), source=Source.MARS)


def test_the_fixture_is_the_real_flattened_layout_not_the_synthetic_one() -> None:
    first = json.loads(_FIXTURE.read_text(encoding="utf-8").splitlines()[0])
    # Real NXLog/Winlogbeat shape: a SourceName provider and EventData flattened to the
    # top level (no nested object the synthetic fixture relies on). EventID arrives as an
    # int or a numeric string depending on the record; the parser accepts both.
    assert isinstance(first["EventID"], (int, str))
    assert "SourceName" in first
    assert not isinstance(first.get("EventData"), dict)
    assert any("EventID" in json.loads(line) for line in _FIXTURE.read_text().splitlines())


def test_real_capture_maps_to_the_sysmon_and_security_taxonomy() -> None:
    result = _result()
    assert result.events, "no real events ingested"
    assert {e.event_type for e in result.events} == {"windows.sysmon", "windows.security"}
    assert all(e.source is Source.MARS for e in result.events)
    # Every mapped record in the excerpt is recognised.
    ids = {e.attributes["event_id"] for e in result.events}
    assert {"1", "3", "7", "10", "11", "13", "18", "22", "23", "4624", "4688"} <= ids


def test_fields_are_mapped_from_the_flattened_record() -> None:
    by_id = {e.attributes["event_id"]: e for e in _result().events}
    # Sysmon 1 (process create): basename derived from the flat Image, real command line.
    proc = by_id["1"]
    assert proc.event_type == "windows.sysmon"
    assert (
        proc.attributes["process_name"]
        == proc.attributes["image"].replace("\\", "/").rsplit("/", 1)[-1]
    )
    assert proc.attributes.get("command_line")
    assert proc.observed_at is not None and proc.observed_at.tzinfo is not None
    # Sysmon 18 (named pipe) — added in the earlier BLUE-1 extension — fires on real data.
    assert by_id["18"].attributes.get("pipe_name")


def test_unmapped_event_ids_are_skipped_never_guessed() -> None:
    result = _result()
    assert result.skipped, "the excerpt includes an unmapped id to prove skip-never-guess"
    assert all(s.reason == "unknown or missing Windows EventID" for s in result.skipped)
    # The unmapped id (5156, WFP) never becomes an event.
    assert all(e.attributes["event_id"] != "5156" for e in result.events)


def test_provider_is_gated_by_sourcename_when_channel_is_absent() -> None:
    # A real NXLog Sysmon record identified only by SourceName (no Provider/Channel)
    # still gates to the sysmon family; a mismatched SourceName is still refused.
    ok = parse_windows_json(
        json.dumps(
            {
                "EventID": "1",
                "SourceName": "Microsoft-Windows-Sysmon",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd /c whoami",
            }
        )
    )
    assert len(ok.events) == 1 and ok.events[0].attributes["process_name"] == "cmd.exe"
    mismatch = parse_windows_json(
        json.dumps({"EventID": "1", "SourceName": "Some-Other-Provider", "Image": "x.exe"})
    )
    assert mismatch.events == ()

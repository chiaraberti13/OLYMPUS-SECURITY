"""Tests for the ATT&CK detection-coverage matrix (ROADMAP ``OPS-PURPLE``).

Pin the Purple-team invariant: coverage is measured against the telemetry that
was actually ingested, so a rule whose event type is absent is a blind spot
(``no-telemetry``), never counted as coverage. The analysis is deterministic.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus.apollo.coverage import (
    CoverageStatus,
    assess_coverage,
    event_types_from_ndjson,
)
from olympus.apollo.rules import DetectionRule
from olympus.cli import app
from olympus.core.exit_codes import ExitCode

runner = CliRunner()


def _rule(rule_id: str, event_type: str, *techniques: str) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        title=f"rule {rule_id}",
        event_type=event_type,
        conditions={"k": "v"},
        mitre_attack=list(techniques),
    )


def test_technique_is_covered_only_when_its_telemetry_is_present() -> None:
    rules = [_rule("APL-A", "network.dns", "T1071.004")]
    assert assess_coverage(rules, {"network.dns"}).techniques[0].status is CoverageStatus.COVERED
    blind = assess_coverage(rules, {"windows.sysmon"})
    assert blind.techniques[0].status is CoverageStatus.NO_TELEMETRY
    assert blind.blind_spots and blind.blind_spots[0].technique == "T1071.004"


def test_technique_is_partial_when_only_some_rules_have_telemetry() -> None:
    rules = [
        _rule("APL-A", "network.dns", "T1071"),
        _rule("APL-B", "windows.sysmon", "T1071"),
    ]
    report = assess_coverage(rules, {"network.dns"})
    (technique,) = report.techniques
    assert technique.status is CoverageStatus.PARTIAL
    present = {rule.event_type: rule.telemetry_present for rule in technique.rules}
    assert present == {"network.dns": True, "windows.sysmon": False}


def test_no_telemetry_at_all_marks_every_technique_blind() -> None:
    rules = [_rule("APL-A", "edr.api", "T1056.001"), _rule("APL-B", "network.http", "T1567.002")]
    report = assess_coverage(rules, set())
    assert {t.status for t in report.techniques} == {CoverageStatus.NO_TELEMETRY}
    assert report.counts["no-telemetry"] == 2


def test_report_is_deterministic_and_sorted() -> None:
    rules = [
        _rule("APL-B", "network.http", "T1190"),
        _rule("APL-A", "network.dns", "T1071.004"),
    ]
    first = assess_coverage(rules, {"network.dns", "network.http"})
    second = assess_coverage(list(reversed(rules)), {"network.http", "network.dns"})
    assert [t.technique for t in first.techniques] == ["T1071.004", "T1190"]
    assert first.to_dict() == second.to_dict()


def test_event_types_from_ndjson_collects_and_skips_noise() -> None:
    text = "\n".join(
        [
            '{"schema_name":"olympus.event","event_type":"network.dns"}',
            "not json",
            "[1,2,3]",
            '{"no_event_type":true}',
            '{"event_type":"windows.sysmon"}',
        ]
    )
    assert event_types_from_ndjson(text) == {"network.dns", "windows.sysmon"}


# --- CLI -------------------------------------------------------------------- #


def test_coverage_cli_reports_blind_spots_and_strict_exits_nonzero() -> None:
    result = runner.invoke(
        app,
        [
            "apollo",
            "coverage",
            "--rules",
            "examples/input/apollo-redteam",
            "--telemetry",
            "network.dns",
            "--format",
            "json",
            "--strict",
        ],
    )
    # With only DNS telemetry, most red-team techniques are blind -> strict fails.
    assert result.exit_code == int(ExitCode.FINDINGS), result.output
    # The human summary line is also emitted; parse just the JSON document.
    out = result.stdout
    report = json.loads(out[out.index("{") : out.rindex("}") + 1])
    assert report["summary"]["no-telemetry"] >= 1
    assert report["summary"]["covered"] >= 1  # the DNS C2 beacon rule is covered


def test_coverage_cli_all_telemetry_is_fully_covered_and_exits_zero() -> None:
    telemetry_flags: list[str] = []
    for event_type in (
        "network.dns",
        "network.http",
        "windows.sysmon",
        "windows.security",
        "edr.api",
    ):
        telemetry_flags += ["--telemetry", event_type]
    result = runner.invoke(
        app,
        [
            "apollo",
            "coverage",
            "--rules",
            "examples/input/apollo-redteam",
            "--strict",
            *telemetry_flags,
        ],
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    assert "0 without telemetry" in result.output

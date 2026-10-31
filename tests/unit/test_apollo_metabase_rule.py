"""Regression tests for the Metabase reset-password SQLi detection rule.

From the Metabase advisory GHSA-vwf4-m7j8-wcjf (CVE-2026-72898): an
unauthenticated SQL injection in ``/api/session/reset_password``. The rule
matches attacker telemetry (a request the pipeline flagged as SQL injection
against that endpoint); it never emits a payload itself.
"""

from pathlib import Path

from olympus.apollo.engine import evaluate
from olympus.apollo.rules import load_rule, matches
from olympus.core.enums import Severity, Source
from olympus.core.models import Event

RULE_PATH = Path("examples/input/apollo-metabase-rule.yaml")


def _event(**attributes: str) -> Event:
    return Event(event_type="web.request", source=Source.APOLLO, attributes=attributes)


def test_rule_loads_with_expected_metadata() -> None:
    rule = load_rule(RULE_PATH)
    assert rule.rule_id == "APL-METABASE-RESETPW-SQLI"
    assert rule.mitre_attack == ["T1190"]
    assert rule.severity is Severity.CRITICAL


def test_rule_fires_on_exploit_event() -> None:
    rule = load_rule(RULE_PATH)
    exploit = _event(http_path="/api/session/reset_password", injection_detected="sql")
    assert matches(rule, exploit) is True
    alerts = evaluate([rule], exploit)
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.CRITICAL


def test_rule_ignores_benign_reset() -> None:
    rule = load_rule(RULE_PATH)
    benign = _event(http_path="/api/session/reset_password")
    assert matches(rule, benign) is False


def test_rule_ignores_injection_on_other_paths() -> None:
    rule = load_rule(RULE_PATH)
    other = _event(http_path="/api/card", injection_detected="sql")
    assert matches(rule, other) is False


def test_example_event_fixture_matches() -> None:
    rule = load_rule(RULE_PATH)
    event = Event.model_validate_json(
        Path("examples/input/apollo-metabase-event.json").read_text(encoding="utf-8")
    )
    assert matches(rule, event) is True

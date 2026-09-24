"""End-to-end purple check for the Mars post-exploitation scenario.

``labs/mars/target/mars-post-exploitation.ndjson`` is a synthetic event trace (never a real
capture) that a trainee runs through the ``apollo-redteam`` pack after getting a foothold on
the Mars target via Artemis. It demonstrates the KLogger/symbiote techniques (keylogging,
covert webcam access) purely as detections.
"""

from pathlib import Path

from olympus.apollo.engine import evaluate_stream
from olympus.apollo.rules import load_rules
from olympus.core.models import Event

SCENARIO = Path("labs/mars/target/mars-post-exploitation.ndjson")
REDTEAM_RULES = Path("examples/input/apollo-redteam")


def _load_events() -> list[Event]:
    lines = SCENARIO.read_text(encoding="utf-8").splitlines()
    return [Event.model_validate_json(line) for line in lines if line.strip()]


def test_scenario_file_has_ten_synthetic_events() -> None:
    assert len(_load_events()) == 10


def test_scenario_fires_every_redteam_rule_exactly_once() -> None:
    rules = load_rules(REDTEAM_RULES)
    alerts = evaluate_stream(rules, _load_events())
    assert len(alerts) == len(rules) == 7
    fired_titles = {alert.title for alert in alerts}
    assert len(fired_titles) == 7  # each rule fired on its own dedicated event, no overlap


def test_scenario_benign_noise_events_do_not_alert() -> None:
    rules = load_rules(REDTEAM_RULES)
    benign_events = [event for event in _load_events() if not evaluate_stream(rules, [event])]
    assert len(benign_events) == 3

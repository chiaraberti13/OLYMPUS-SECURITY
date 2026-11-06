"""End-to-end purple check for the Mars post-exploitation scenario.

``labs/mars/target/mars-post-exploitation.ndjson`` is a synthetic event trace (never a real
capture) that a trainee runs through the ``apollo-redteam`` pack after getting a foothold on
the Mars target via Artemis. It demonstrates the KLogger/symbiote techniques (keylogging,
covert webcam access) purely as detections.
"""

import json
import runpy
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


def test_target_matches_mars_v1_profile() -> None:
    scope = json.loads(SCENARIO.with_name("practice-scope.json").read_text(encoding="utf-8"))
    assert scope["allowed_origins"] == ["http://127.0.0.1:8081"]
    assert scope["allowed_ip_networks"] == ["127.0.0.0/8"]

    target = runpy.run_path(str(SCENARIO.with_name("app.py")))
    response = target["build_response"]
    assert target["PracticeHandler"].server_version == "nginx/1.18.0"
    assert response("/", "")[0] == 200
    for path in ("/app/admin", "/app/.env", "/app/backup.zip"):
        assert response(path, "")[0] == 200
    assert response("/app/unknown", "")[0] == 404
    assert b"<em>mars</em>" in response("/app/search", "q=%3Cem%3Emars%3C%2Fem%3E")[2]
    assert json.loads(response("/api/session/properties", "")[2])["version"]["tag"] == "v0.60.10"

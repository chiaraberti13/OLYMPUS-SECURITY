"""Detection tests for the Blue Team endpoint/persistence rule pack.

Defensive content distilled from the BlueTeam-Tools catalog: each rule matches
attacker telemetry a SIEM/EDR pipeline would emit (Windows Security / Sysmon
events). Olympus only *detects* — it never performs the technique.
"""

from pathlib import Path

from olympus.apollo.engine import evaluate, evaluate_stream
from olympus.apollo.rules import load_rule, load_rules, matches
from olympus.core.enums import Source
from olympus.core.models import Event

BT_DIR = Path("examples/input/apollo-blueteam")

# rule file -> (event_type, attributes that MUST fire, one attribute to flip so it must NOT fire)
_CASES: dict[str, tuple[str, dict[str, str], str]] = {
    "lsass-credential-dump.yaml": (
        "windows.sysmon",
        {
            "event_id": "10",
            "target_image": r"C:\Windows\System32\lsass.exe",
            "granted_access": "0x1410",
            "source_is_system": "false",
        },
        "source_is_system",
    ),
    "encoded-powershell.yaml": (
        "windows.security",
        {"event_id": "4688", "process_name": "powershell.exe", "has_encoded_command": "true"},
        "has_encoded_command",
    ),
    "service-installation-persistence.yaml": (
        "windows.security",
        {"event_id": "7045", "service_file_path_is_temp": "true", "service_start_type": "auto"},
        "service_file_path_is_temp",
    ),
    "scheduled-task-persistence.yaml": (
        "windows.security",
        {"event_id": "4698", "task_runs_as_system": "true", "creator_is_admin": "false"},
        "creator_is_admin",
    ),
    "event-log-cleared.yaml": (
        "windows.security",
        {"event_id": "1102", "channel": "Security"},
        "channel",
    ),
    "office-spawns-shell.yaml": (
        "windows.sysmon",
        {"event_id": "1", "parent_image_is_office": "true", "child_is_shell": "true"},
        "child_is_shell",
    ),
}


def test_every_blueteam_rule_fires_on_its_attack_event() -> None:
    for filename, (event_type, attrs, _flip) in _CASES.items():
        rule = load_rule(BT_DIR / filename)
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=attrs)
        assert matches(rule, event) is True, filename
        assert evaluate([rule], event), filename


def test_every_blueteam_rule_ignores_benign_variant() -> None:
    for filename, (event_type, attrs, flip) in _CASES.items():
        rule = load_rule(BT_DIR / filename)
        benign = dict(attrs)
        benign[flip] = "benign-value"
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=benign)
        assert matches(rule, event) is False, filename


def test_blueteam_rules_have_unique_ids_and_mitre() -> None:
    rules = load_rules(BT_DIR)
    ids = {r.rule_id for r in rules}
    assert len(ids) == len(_CASES)  # no duplicate rule_id after dedup
    assert all(r.rule_id.startswith("APL-BT-") for r in rules)
    assert all(r.mitre_attack for r in rules)


def test_stream_evaluation_alerts_only_on_attack_events() -> None:
    rules = load_rules(BT_DIR)
    attack = Event(
        event_type="windows.security",
        source=Source.APOLLO,
        attributes={"event_id": "1102", "channel": "Security"},
    )
    benign = Event(
        event_type="windows.security",
        source=Source.APOLLO,
        attributes={"event_id": "4624", "logon_type": "2"},
    )
    alerts = evaluate_stream(rules, [attack, benign])
    assert len(alerts) == 1
    assert "log cleared" in alerts[0].title.lower()

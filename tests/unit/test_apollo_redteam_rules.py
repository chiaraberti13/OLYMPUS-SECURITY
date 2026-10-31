"""Detection tests for the Red Team technique-coverage rule pack.

Defensive content distilled from the RedTeam-Tools catalog (organized by MITRE
ATT&CK tactic: Discovery, Lateral Movement, Collection, Command and Control,
Exfiltration, Impact). Two rules in this pack turn the exact techniques used by
KLogger (global keyboard hook) and symbiote (covert webcam access) into
detections instead of reimplementing the tools themselves — Olympus only
*detects* the technique, it never performs it.
"""

from pathlib import Path

from olympus.apollo.engine import evaluate, evaluate_stream
from olympus.apollo.rules import load_rule, load_rules, matches
from olympus.core.enums import Source
from olympus.core.models import Event

RT_DIR = Path("examples/input/apollo-redteam")

# rule file -> (event_type, attributes that MUST fire, one attribute to flip so it must NOT fire)
_CASES: dict[str, tuple[str, dict[str, str], str]] = {
    "domain-trust-enumeration.yaml": (
        "windows.sysmon",
        {"event_id": "1", "process_name": "nltest.exe", "command_line_flag": "/domain_trusts"},
        "command_line_flag",
    ),
    "psexec-lateral-movement.yaml": (
        "windows.security",
        {"event_id": "7045", "service_name": "PSEXESVC", "image_path_is_admin_share": "true"},
        "image_path_is_admin_share",
    ),
    "keylogger-hook-install.yaml": (
        "edr.api",
        {
            "api_name": "SetWindowsHookExW",
            "hook_type": "WH_KEYBOARD_LL",
            "process_is_signed": "false",
        },
        "process_is_signed",
    ),
    "webcam-hidden-access.yaml": (
        "edr.api",
        {
            "device_class": "camera",
            "process_window_visible": "false",
            "process_is_signed": "false",
        },
        "process_window_visible",
    ),
    "dns-c2-beacon.yaml": (
        "network.dns",
        {"query_type": "TXT", "query_entropy": "high", "query_interval_regular": "true"},
        "query_interval_regular",
    ),
    "archive-then-cloud-upload.yaml": (
        "network.http",
        {
            "method": "POST",
            "destination_reputation": "anonymous-file-host",
            "preceded_by_archive_creation": "true",
        },
        "preceded_by_archive_creation",
    ),
    "mass-file-rename-impact.yaml": (
        "windows.sysmon",
        {"event_id": "11", "file_extension_changed_bulk": "true", "shadow_copies_deleted": "true"},
        "shadow_copies_deleted",
    ),
}


def test_every_redteam_rule_fires_on_its_attack_event() -> None:
    for filename, (event_type, attrs, _flip) in _CASES.items():
        rule = load_rule(RT_DIR / filename)
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=attrs)
        assert matches(rule, event) is True, filename
        assert evaluate([rule], event), filename


def test_every_redteam_rule_ignores_benign_variant() -> None:
    for filename, (event_type, attrs, flip) in _CASES.items():
        rule = load_rule(RT_DIR / filename)
        benign = dict(attrs)
        benign[flip] = "benign-value"
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=benign)
        assert matches(rule, event) is False, filename


def test_redteam_rules_have_unique_ids_and_mitre() -> None:
    rules = load_rules(RT_DIR)
    ids = {r.rule_id for r in rules}
    assert len(ids) == len(_CASES)  # no duplicate rule_id after dedup
    assert all(r.rule_id.startswith("APL-RT-") for r in rules)
    assert all(r.mitre_attack for r in rules)


def test_stream_evaluation_alerts_only_on_attack_events() -> None:
    rules = load_rules(RT_DIR)
    attack = Event(
        event_type="edr.api",
        source=Source.APOLLO,
        attributes={
            "api_name": "SetWindowsHookExW",
            "hook_type": "WH_KEYBOARD_LL",
            "process_is_signed": "false",
        },
    )
    benign = Event(
        event_type="edr.api",
        source=Source.APOLLO,
        attributes={
            "api_name": "SetWindowsHookExW",
            "hook_type": "WH_KEYBOARD_LL",
            "process_is_signed": "true",
        },
    )
    alerts = evaluate_stream(rules, [attack, benign])
    assert len(alerts) == 1
    assert "keyboard hook" in alerts[0].title.lower()

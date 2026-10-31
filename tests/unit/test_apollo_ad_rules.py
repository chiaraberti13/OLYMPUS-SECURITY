"""Detection tests for the Active Directory attack-detection rule pack.

Defensive content reimplemented from the ad_attack_architecture / adhammer
technique catalogs: each rule matches attacker telemetry (a normalized event
a SIEM pipeline would emit); Olympus never performs the offensive technique.
"""

from pathlib import Path

from olympus.apollo.engine import evaluate
from olympus.apollo.rules import load_rule, matches
from olympus.core.enums import Source
from olympus.core.models import Event

AD_DIR = Path("examples/input/apollo-ad")

# rule file -> (attributes that MUST fire, one attribute flipped so it must NOT fire)
_CASES: dict[str, tuple[str, dict[str, str], str]] = {
    "dcsync.yaml": (
        "windows.security",
        {
            "event_id": "4662",
            "property_access": "DS-Replication-Get-Changes-All",
            "actor_is_domain_controller": "false",
        },
        "actor_is_domain_controller",
    ),
    "kerberoasting.yaml": (
        "windows.security",
        {
            "event_id": "4769",
            "ticket_encryption_type": "rc4-hmac",
            "service_name_is_krbtgt": "false",
        },
        "ticket_encryption_type",
    ),
    "pass-the-hash.yaml": (
        "windows.security",
        {
            "event_id": "4624",
            "logon_type": "3",
            "authentication_package": "NTLM",
            "key_length": "0",
        },
        "authentication_package",
    ),
    "llmnr-poisoning.yaml": (
        "network",
        {"protocol": "llmnr", "message_type": "response", "responder_is_authorized": "false"},
        "responder_is_authorized",
    ),
    "golden-ticket.yaml": (
        "windows.security",
        {
            "event_id": "4769",
            "tgt_anomaly": "forged-lifetime",
            "account_domain_mismatch": "true",
        },
        "account_domain_mismatch",
    ),
}


def test_every_ad_rule_fires_on_its_attack_event() -> None:
    for filename, (event_type, attrs, _flip) in _CASES.items():
        rule = load_rule(AD_DIR / filename)
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=attrs)
        assert matches(rule, event) is True, filename
        assert evaluate([rule], event), filename


def test_every_ad_rule_ignores_benign_variant() -> None:
    for filename, (event_type, attrs, flip) in _CASES.items():
        rule = load_rule(AD_DIR / filename)
        benign = dict(attrs)
        benign[flip] = "benign-value"
        event = Event(event_type=event_type, source=Source.APOLLO, attributes=benign)
        assert matches(rule, event) is False, filename


def test_ad_rules_have_valid_mitre_mappings() -> None:
    expected = {
        "APL-AD-DCSYNC": "T1003.006",
        "APL-AD-KERBEROAST": "T1558.003",
        "APL-AD-PASS-THE-HASH": "T1550.002",
        "APL-AD-LLMNR-POISON": "T1557.001",
        "APL-AD-GOLDEN-TICKET": "T1558.001",
    }
    seen = {}
    for path in AD_DIR.glob("*.yaml"):
        rule = load_rule(path)
        seen[rule.rule_id] = rule.mitre_attack[0]
    assert seen == expected

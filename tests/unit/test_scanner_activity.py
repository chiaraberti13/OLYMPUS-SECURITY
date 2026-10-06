"""Tests for the operator-facing scanner activity/risk classification (WEB-E).

The guided New Assessment flow carries no security logic of its own: it reads
the activity type, risk class and plain-language summary from
:mod:`olympus.integrations.activity`. These tests pin that the classification is
complete, deterministic and fails safe (an unmapped scanner is never passive).
"""

from __future__ import annotations

from olympus.integrations.activity import (
    ACTIVITY_CATALOGUE,
    RISK_EXPLANATION,
    ActivityType,
    RiskClass,
    activity_info,
    classify,
    profile,
    profiles,
    recommended_scanner,
    scanners_for_activity,
)
from olympus.integrations.scanners import REGISTRY, ScannerSpec, by_name


def test_every_registered_scanner_is_classified() -> None:
    names = {item.name for item in profiles()}
    assert names == {spec.name for spec in REGISTRY}


def test_passive_class_is_only_assigned_deliberately() -> None:
    passive = {item.name for item in profiles() if item.risk is RiskClass.PASSIVE}
    # Only genuine public-record / OSINT collectors are passive.
    assert passive == {"subfinder", "theharvester"}


def test_injection_tools_are_intrusive() -> None:
    intrusive = {item.name for item in profiles() if item.risk is RiskClass.INTRUSIVE}
    assert {"sqlmap", "commix", "xsstrike", "dalfox", "nosqlmap"} <= intrusive


def test_unmapped_scanner_defaults_to_active_never_passive() -> None:
    spec = ScannerSpec(
        name="brand-new",
        purpose="A newly catalogued engine",
        category="web",
        binary="brand-new",
        licence="MIT",
        redistributable=True,
        install="n/a",
        in_scanner_image=False,
    )
    classified = classify(spec)
    assert classified.risk is RiskClass.ACTIVE
    # Falls back to the registry purpose when there is no friendly summary.
    assert classified.summary == "A newly catalogued engine"


def test_activity_is_derived_from_the_registry_category() -> None:
    assert profile("nmap") is not None
    assert profile("nmap").activity is ActivityType.NETWORK  # type: ignore[union-attr]
    assert profile("testssl").activity is ActivityType.NETWORK  # type: ignore[union-attr]
    assert profile("subfinder").activity is ActivityType.RECON  # type: ignore[union-attr]
    assert profile("nuclei").activity is ActivityType.WEB  # type: ignore[union-attr]
    assert profile("openvas").activity is ActivityType.VULNERABILITY  # type: ignore[union-attr]


def test_profile_of_unknown_scanner_is_none() -> None:
    assert profile("not-a-real-scanner") is None


def test_scanners_for_activity_are_sorted_passive_first() -> None:
    recon = scanners_for_activity(ActivityType.RECON)
    risks = [item.risk for item in recon]
    assert risks == sorted(
        risks, key=lambda risk: {"passive": 0, "active": 1, "intrusive": 2}[risk]
    )


def test_recommended_prefers_the_ready_tool_and_refuses_when_none() -> None:
    assert recommended_scanner(ActivityType.NETWORK, {"nmap", "testssl"}) == "nmap"
    # Preferred order skips a non-ready tool and picks the next ready one.
    assert recommended_scanner(ActivityType.NETWORK, {"testssl"}) == "testssl"
    # No ready tool → honest None, so the caller refuses instead of queueing.
    assert recommended_scanner(ActivityType.VULNERABILITY, set()) is None


def test_recommended_never_crosses_activities() -> None:
    # nmap is ready but belongs to NETWORK, not WEB: it must not be recommended.
    assert recommended_scanner(ActivityType.WEB, {"nmap"}) is None


def test_activity_catalogue_marks_native_vs_cli_activities() -> None:
    native = {info.activity for info in ACTIVITY_CATALOGUE if info.themis_native}
    assert native == {
        ActivityType.RECON,
        ActivityType.NETWORK,
        ActivityType.WEB,
        ActivityType.VULNERABILITY,
    }
    # Non-native activities must carry a CLI hint rather than pretend to run.
    for info in ACTIVITY_CATALOGUE:
        if not info.themis_native:
            assert info.cli_hint


def test_every_risk_class_has_an_explanation() -> None:
    assert set(RISK_EXPLANATION) == set(RiskClass)
    assert all(text for text in RISK_EXPLANATION.values())


def test_activity_info_round_trips_for_every_catalogue_entry() -> None:
    for info in ACTIVITY_CATALOGUE:
        assert activity_info(info.activity) is info


def test_profile_to_dict_is_json_friendly() -> None:
    data = classify(by_name("nmap")).to_dict()  # type: ignore[arg-type]
    assert data["name"] == "nmap"
    assert data["risk"] == "active"
    assert data["activity"] == "network"
    assert data["risk_explanation"]

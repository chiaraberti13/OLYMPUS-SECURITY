"""The maturity ladder, and the guard that stops it from overpromising."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.aegis.registry import implemented
from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.integrations import maturity as maturity_module
from olympus.integrations.capabilities import (
    Capability,
    CapabilityState,
    count_at_least,
    inventory,
    inventory_document,
)
from olympus.integrations.maturity import (
    DECLARED,
    LADDER,
    Maturity,
    MaturityRecord,
    at_least,
    rank,
    record_for,
    summary,
    verify_declarations,
)
from olympus.integrations.scanners import REGISTRY

runner = CliRunner()


# --------------------------------------------------------------------------- #
# The ladder itself
# --------------------------------------------------------------------------- #


def test_ladder_is_ordered_from_least_to_most_validated() -> None:
    assert LADDER == (
        Maturity.CATALOG_ONLY,
        Maturity.ADAPTER_READY,
        Maturity.OFFLINE_TESTED,
        Maturity.LIVE_TESTED,
        Maturity.PRODUCTION_READY,
    )
    assert [rank(stage) for stage in LADDER] == [0, 1, 2, 3, 4]


def test_at_least_compares_along_the_ladder() -> None:
    assert at_least(Maturity.LIVE_TESTED, Maturity.OFFLINE_TESTED) is True
    assert at_least(Maturity.LIVE_TESTED, Maturity.LIVE_TESTED) is True
    assert at_least(Maturity.OFFLINE_TESTED, Maturity.LIVE_TESTED) is False
    assert at_least(Maturity.CATALOG_ONLY, Maturity.ADAPTER_READY) is False


def test_undeclared_scanner_defaults_to_catalog_only() -> None:
    record = record_for("wpscan")
    assert record.stage is Maturity.CATALOG_ONLY
    assert record.evidence == ""
    assert "no native execution adapter" in record.blocker.lower()


# --------------------------------------------------------------------------- #
# The guard: the ledger must not claim more than the repository can prove
# --------------------------------------------------------------------------- #


def test_declared_ledger_matches_the_repository() -> None:
    """The one test that keeps the catalogue honest.

    If this fails, the ledger is claiming validation the repository cannot back
    up (or is understating an adapter that exists). Fix the claim or add the
    evidence — never the assertion.
    """
    assert verify_declarations() == []


def test_every_registered_adapter_is_declared() -> None:
    assert set(implemented()) <= set(DECLARED)


def test_nothing_claims_production_ready_yet() -> None:
    """The Definition of Done is open, so no adapter may claim its top rung."""
    assert summary()[Maturity.PRODUCTION_READY.value] == 0


def test_guard_catches_a_claim_without_an_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "wpscan",
        MaturityRecord("wpscan", Maturity.LIVE_TESTED, "docs/aegis-execution-evidence.md"),
    )
    assert any("no native adapter" in problem for problem in verify_declarations())


def test_guard_catches_a_claim_without_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "nmap",
        MaturityRecord("nmap", Maturity.LIVE_TESTED, ""),
    )
    assert any("without evidence" in problem for problem in verify_declarations())


def test_guard_catches_evidence_that_does_not_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "nmap",
        MaturityRecord("nmap", Maturity.LIVE_TESTED, "docs/does-not-exist.md"),
    )
    assert any("does not exist" in problem for problem in verify_declarations())


def test_guard_catches_offline_claim_without_a_parser_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``offline-tested`` means a regression fails the build; prove it."""
    monkeypatch.setattr(
        maturity_module,
        "parser_test_is_present",
        lambda name: name != "testssl",
    )
    assert any(
        "has no test_testssl_parser" in problem for problem in verify_declarations()
    )


def test_guard_catches_an_undeclared_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Understating the project is drift too, not a safe default."""
    trimmed = {name: rec for name, rec in DECLARED.items() if name != "nmap"}
    monkeypatch.setattr(maturity_module, "DECLARED", trimmed)
    assert any(
        "has a native adapter but no maturity declaration" in problem
        for problem in verify_declarations()
    )


def test_guard_catches_a_declaration_outside_the_catalogue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "not-a-scanner",
        MaturityRecord("not-a-scanner", Maturity.LIVE_TESTED, "README.md"),
    )
    assert any(
        "absent from the scanner catalogue" in problem
        for problem in verify_declarations()
    )


def test_guard_rejects_catalog_only_declarations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "wpscan",
        MaturityRecord("wpscan", Maturity.CATALOG_ONLY),
    )
    assert any("leave it out of DECLARED" in problem for problem in verify_declarations())


def test_guard_rejects_production_ready_with_an_open_blocker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "nmap",
        MaturityRecord(
            "nmap",
            Maturity.PRODUCTION_READY,
            "docs/aegis-execution-evidence.md",
            "SBOM still missing",
        ),
    )
    assert any(
        "production-ready while still recording a blocker" in problem
        for problem in verify_declarations()
    )


# --------------------------------------------------------------------------- #
# Summary and the capability inventory
# --------------------------------------------------------------------------- #


def test_summary_covers_the_whole_catalogue() -> None:
    counts = summary()
    assert set(counts) == {stage.value for stage in LADDER}
    assert sum(counts.values()) == len(REGISTRY)


def test_summary_reflects_the_repository_today() -> None:
    """The honest numbers, restated so a change to them is a deliberate act."""
    assert summary() == {
        "catalog-only": 11,
        "adapter-ready": 0,
        "offline-tested": 2,
        "live-tested": 11,
        "production-ready": 0,
    }


def test_maturity_and_readiness_are_independent_axes() -> None:
    """A live-tested engine on a host without its binary is still not ready."""
    capabilities = {item.name: item for item in inventory({})}
    nmap = capabilities["nmap"]
    assert nmap.maturity is Maturity.LIVE_TESTED
    if not nmap.available:
        assert nmap.state is CapabilityState.DEPENDENCY_MISSING
        assert nmap.ready is False


def test_catalog_only_engines_carry_a_blocker_and_no_evidence() -> None:
    for item in inventory({}):
        if item.maturity is Maturity.CATALOG_ONLY:
            assert item.evidence is None
            assert item.blocker


def test_capability_dict_exposes_the_maturity_axis() -> None:
    payload = Capability(
        name="nmap",
        category="network",
        purpose="p",
        kind="local-oss-binary",
        licence="GPL-2.0",
        adapted=True,
        available=True,
        state=CapabilityState.READY,
        maturity=Maturity.LIVE_TESTED,
        evidence="docs/aegis-execution-evidence.md",
        blocker="SBOM pending",
    ).to_dict()
    assert payload["maturity"] == "live-tested"
    assert payload["evidence"] == "docs/aegis-execution-evidence.md"
    assert payload["blocker"] == "SBOM pending"


def test_inventory_document_carries_the_histogram() -> None:
    document = inventory_document({})
    assert document["schema_version"] == "1.1.0"
    assert document["maturity"] == summary()
    assert document["catalogued"] == len(REGISTRY)


def test_count_at_least_matches_the_histogram() -> None:
    assert count_at_least(Maturity.LIVE_TESTED, {}) == 11
    assert count_at_least(Maturity.OFFLINE_TESTED, {}) == 13
    assert count_at_least(Maturity.ADAPTER_READY, {}) == len(implemented())
    assert count_at_least(Maturity.CATALOG_ONLY, {}) == len(REGISTRY)
    assert count_at_least(Maturity.PRODUCTION_READY, {}) == 0


# --------------------------------------------------------------------------- #
# olympus aegis capabilities
# --------------------------------------------------------------------------- #


def test_capabilities_reports_maturity_per_engine() -> None:
    result = runner.invoke(app, ["aegis", "capabilities"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    by_name = {item["name"]: item for item in document["capabilities"]}
    assert by_name["nmap"]["maturity"] == "live-tested"
    assert by_name["whatweb"]["maturity"] == "offline-tested"
    assert by_name["wpscan"]["maturity"] == "catalog-only"
    assert document["maturity"]["production-ready"] == 0


def test_capabilities_gate_passes_when_the_bar_is_met() -> None:
    result = runner.invoke(
        app, ["aegis", "capabilities", "--min-maturity", "live-tested", "--count", "11"]
    )
    assert result.exit_code == 0, result.output


def test_capabilities_gate_fails_when_the_bar_is_not_met() -> None:
    result = runner.invoke(
        app, ["aegis", "capabilities", "--min-maturity", "live-tested", "--count", "12"]
    )
    assert result.exit_code == int(ExitCode.NOT_AUTHORIZED)
    assert "11 integration(s) reach live-tested, 12 required" in result.output


def test_capabilities_gate_rejects_an_unknown_stage() -> None:
    result = runner.invoke(app, ["aegis", "capabilities", "--min-maturity", "shipped"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "unknown maturity stage" in result.output


def test_capabilities_reports_ledger_drift_as_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drift is a reporting bug, so it must not masquerade as a readiness result."""
    monkeypatch.setitem(
        maturity_module.DECLARED,
        "wpscan",
        MaturityRecord("wpscan", Maturity.LIVE_TESTED, "docs/aegis-execution-evidence.md"),
    )
    result = runner.invoke(app, ["aegis", "capabilities"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "maturity declaration drift" in result.output

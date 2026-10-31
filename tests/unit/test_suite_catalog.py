"""Unit tests for the honest suite-capability alignment catalogue."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.integrations import suite_catalog
from olympus.integrations.maturity import Maturity, MaturityRecord
from olympus.integrations.suite_catalog import (
    SUITE_CAPABILITIES,
    CoverageState,
    NativeCapability,
    SuiteCapability,
    catalog_document,
    coverage_of,
    verify_catalog,
)

runner = CliRunner()


def test_catalogue_is_internally_consistent() -> None:
    # The honesty gate: every engine exists and every native evidence file is real.
    assert verify_catalog() == []


def test_every_roadmap_capability_is_declared() -> None:
    declared = {capability.capability_id for capability in SUITE_CAPABILITIES}
    expected = {
        "website-scanner",
        "network-scanner",
        "ssl-scanner",
        "cms-scanner",
        "port-scanner",
        "subdomain-finder",
        "domain-finder",
        "password-auditor",
    }
    assert declared == expected


def test_catalog_document_shape_and_histogram() -> None:
    doc = catalog_document()
    assert doc["schema_name"] == "olympus.suite-capability-catalog"
    assert doc["schema_version"] == "1.0.0"
    capabilities = doc["capabilities"]
    assert isinstance(capabilities, list)
    histogram = doc["coverage"]
    assert isinstance(histogram, dict)
    assert sum(histogram.values()) == len(capabilities) == len(SUITE_CAPABILITIES)
    # Ordered by id for deterministic output.
    ids = [c["capability_id"] for c in capabilities]
    assert ids == sorted(ids)


def test_known_coverage_states_are_honest() -> None:
    states = {c["capability_id"]: c["coverage"] for c in catalog_document()["capabilities"]}
    # Proven engines / tested native modules -> present.
    assert states["website-scanner"] == "present"  # nuclei/sqlmap/... live-tested
    assert states["ssl-scanner"] == "present"  # testssl offline-tested
    assert states["port-scanner"] == "present"  # nmap live-tested
    assert states["subdomain-finder"] == "present"  # native CT discovery
    assert states["domain-finder"] == "present"  # native DNS/WHOIS
    # Catalogued-only or absent -> missing, never overstated.
    assert states["network-scanner"] == "missing"  # nessus/openvas catalog-only
    assert states["cms-scanner"] == "missing"  # wpscan catalog-only
    assert states["password-auditor"] == "missing"  # no module


def test_simulated_state_requires_a_bare_registered_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No engine currently sits at adapter-ready, so drive the SIMULATED branch with
    # a synthetic engine maturity and a capability that has no native backing.
    capability = SuiteCapability(
        capability_id="synthetic",
        title="Synthetic",
        summary="",
        modules=("themis",),
        engines=("nmap",),
    )
    monkeypatch.setattr(
        suite_catalog,
        "record_for",
        lambda name: MaturityRecord(name, Maturity.ADAPTER_READY, "", "unproven parser"),
    )
    assert coverage_of(capability) is CoverageState.SIMULATED


def test_native_capability_without_evidence_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    bogus = SuiteCapability(
        capability_id="bogus",
        title="Bogus",
        summary="",
        modules=("argus",),
        native=(NativeCapability("argus", "does not exist", "tests/unit/does_not_exist.py"),),
    )
    monkeypatch.setattr(suite_catalog, "SUITE_CAPABILITIES", (bogus,))
    problems = verify_catalog()
    assert any("native evidence missing" in problem for problem in problems)


def test_cli_catalog_command_emits_the_document() -> None:
    result = runner.invoke(app, ["catalog"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["schema_name"] == "olympus.suite-capability-catalog"
    assert len(doc["capabilities"]) == len(SUITE_CAPABILITIES)

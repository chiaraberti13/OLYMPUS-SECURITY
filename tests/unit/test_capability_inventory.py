"""Professional readiness inventory: catalogue presence is not executability."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus.cli import app
from olympus.integrations import capabilities
from olympus.integrations.scanners import by_name

runner = CliRunner()


def test_unadapted_binary_never_reports_ready(monkeypatch) -> None:
    spec = by_name("subfinder")
    assert spec is not None
    monkeypatch.setattr("olympus.integrations.scanners.shutil.which", lambda binary: binary)
    result = capabilities.inspect(spec, {})
    assert result.available is True
    assert result.adapted is False
    assert result.ready is False
    assert result.state is capabilities.CapabilityState.ADAPTER_MISSING


def test_api_configuration_does_not_replace_an_adapter() -> None:
    spec = by_name("nessus")
    assert spec is not None
    result = capabilities.inspect(
        spec,
        {"AEGIS_NESSUS_URL": "https://nessus.internal", "AEGIS_NESSUS_TOKEN": "set"},
    )
    assert result.available is True
    assert result.ready is False
    assert result.missing == ("olympus-adapter",)


def test_inventory_contract_counts_real_states() -> None:
    document = capabilities.inventory_document({})
    assert document["schema_name"] == "olympus.aegis-capability-inventory"
    assert document["catalogued"] == 24
    assert document["adapted"] == 13
    assert 0 <= document["ready"] <= document["adapted"]
    assert len(document["capabilities"]) == 24


def test_capabilities_cli_is_machine_readable() -> None:
    result = runner.invoke(app, ["aegis", "capabilities"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert document["catalogued"] == 24
    assert document["adapted"] == 13

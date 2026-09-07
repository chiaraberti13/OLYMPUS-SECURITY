"""The native CycloneDX SBOM generator and ``olympus core sbom``."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core import sbom

runner = CliRunner()


def test_normalize_follows_pep503() -> None:
    assert sbom.normalize("Typing_Extensions") == "typing-extensions"
    assert sbom.normalize("ruamel.yaml") == "ruamel-yaml"
    assert sbom.normalize("A--_.B") == "a-b"


def test_requirement_name_is_extracted_without_specifiers() -> None:
    assert sbom._requirement_name("pydantic>=2.6") == "pydantic"
    assert sbom._requirement_name("uvicorn[standard]>=0.27; extra == 'api'") == "uvicorn"
    assert sbom._requirement_name("") is None


def test_extra_marker_is_detected() -> None:
    assert sbom._required_extra("httpx>=0.27; extra == 'dev'") == "dev"
    assert sbom._required_extra("pydantic>=2.6") is None
    assert sbom._required_extra("foo; python_version < '3.11'") is None


def test_default_closure_excludes_extras_and_the_root() -> None:
    closure = sbom.dependency_closure()
    assert "olympus-security" not in closure
    # A plain install pulls pydantic; the dev/aegis-only tools must not appear.
    assert "pydantic" in closure
    assert "pytest" not in closure and "fastapi" not in closure
    # Deterministic ordering.
    assert closure == sorted(closure)


def test_requesting_an_extra_widens_the_closure() -> None:
    base = set(sbom.dependency_closure())
    widened = set(sbom.dependency_closure(extras=frozenset({"aegis"})))
    assert base <= widened  # extras only add


def test_component_for_an_installed_package_has_a_purl() -> None:
    component = sbom.component_for("pydantic")
    assert component is not None
    assert component["type"] == "library"
    assert component["purl"].startswith("pkg:pypi/pydantic@")
    assert component["purl"] == component["bom-ref"]
    assert component["version"]


def test_component_for_a_missing_package_is_none() -> None:
    assert sbom.component_for("definitely-not-installed-xyz") is None


def test_render_is_valid_cyclonedx() -> None:
    document = sbom.render_sbom(timestamp="2026-09-05T00:00:00Z", serial_number="urn:uuid:x")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"] == "urn:uuid:x"
    assert document["metadata"]["timestamp"] == "2026-09-05T00:00:00Z"
    root = document["metadata"]["component"]
    assert root["type"] == "application"
    assert root["name"] == "olympus-security"


def test_render_components_are_sorted_and_exclude_the_root() -> None:
    document = sbom.render_sbom()
    names = [c["name"] for c in document["components"]]
    assert names == sorted(names)
    assert "olympus-security" not in names
    assert all(c["purl"].startswith("pkg:pypi/") for c in document["components"])


def test_reproducible_render_omits_timestamp_and_serial() -> None:
    document = sbom.render_sbom()
    assert "serialNumber" not in document
    assert "timestamp" not in document.get("metadata", {})
    # Two reproducible renders are byte-for-byte identical.
    assert json.dumps(document, sort_keys=True) == json.dumps(
        sbom.render_sbom(), sort_keys=True
    )


def test_render_records_requested_extras_as_properties() -> None:
    document = sbom.render_sbom(extras=frozenset({"aegis"}))
    properties = document["metadata"].get("properties", [])
    assert {"name": "olympus:extra", "value": "aegis"} in properties


def test_requirements_lines_are_pinned_and_scoped() -> None:
    lines = sbom.requirements_lines()
    # Every line is a hard pin the scanner can resolve.
    assert all("==" in line for line in lines)
    names = {line.split("==", 1)[0] for line in lines}
    # Olympus's own runtime deps are present...
    assert "pydantic" in names
    # ...and the interpreter bootstrap that belongs to the env, not to Olympus,
    # is deliberately excluded so a vuln scan is not blamed on Olympus.
    assert "pip" not in names and "setuptools" not in names and "wheel" not in names
    assert "olympus-security" not in names


def test_requirements_lines_match_the_sbom_components() -> None:
    lines = sbom.requirements_lines()
    components = {c["name"]: c["version"] for c in sbom.render_sbom()["components"]}
    parsed = dict(line.split("==", 1) for line in lines)
    assert parsed == components


# --- CLI -------------------------------------------------------------------- #


def test_sbom_command_prints_valid_json() -> None:
    result = runner.invoke(app, ["core", "sbom", "--reproducible"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["bomFormat"] == "CycloneDX"
    assert "serialNumber" not in document


def test_sbom_command_stamps_serial_and_timestamp_by_default() -> None:
    result = runner.invoke(app, ["core", "sbom"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["serialNumber"].startswith("urn:uuid:")
    assert "timestamp" in document["metadata"]


def test_sbom_command_writes_a_file(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    destination = tmp_path / "nested" / "sbom.json"
    result = runner.invoke(
        app, ["core", "sbom", "--reproducible", "--output", str(destination)]
    )
    assert result.exit_code == 0, result.output
    assert destination.exists()
    assert json.loads(destination.read_text())["bomFormat"] == "CycloneDX"


def test_sbom_command_extra_widens_the_component_set() -> None:
    base = json.loads(runner.invoke(app, ["core", "sbom", "--reproducible"]).stdout)
    widened = json.loads(
        runner.invoke(app, ["core", "sbom", "--reproducible", "--extra", "aegis"]).stdout
    )
    assert len(widened["components"]) >= len(base["components"])

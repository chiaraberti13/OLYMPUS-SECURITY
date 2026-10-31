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
    # A plain install pulls pydantic; the dev/themis-only tools must not appear.
    assert "pydantic" in closure
    assert "pytest" not in closure and "fastapi" not in closure
    # Deterministic ordering.
    assert closure == sorted(closure)


def test_requesting_an_extra_widens_the_closure() -> None:
    base = set(sbom.dependency_closure())
    widened = set(sbom.dependency_closure(extras=frozenset({"themis"})))
    assert base <= widened  # extras only add


def test_requirement_extras_are_extracted_and_normalized() -> None:
    assert sbom._requirement_extras("markdown-it-py[linkify]>=2.1.0") == frozenset({"linkify"})
    assert sbom._requirement_extras("uvicorn[Standard,WebSockets]>=0.27") == frozenset(
        {"standard", "websockets"}
    )
    assert sbom._requirement_extras("pydantic>=2.6") == frozenset()


def test_closure_follows_extras_a_dependency_activates_on_its_target() -> None:
    # Regression (SEC-F-02): textual requires ``markdown-it-py[linkify]``, so the
    # linkify extra's own dependency ``linkify-it-py`` must be in the default
    # closure. Before the per-dependency extra fix it was dropped, leaving the
    # hash-lock and SBOM incomplete so ``pip install --require-hashes`` rejected
    # the constraints.
    closure = sbom.dependency_closure()
    assert "textual" in closure and "markdown-it-py" in closure
    assert "linkify-it-py" in closure


class _FakeDist:
    """Minimal stand-in exposing only ``requires`` for ``_direct_dependencies``."""

    def __init__(self, requires: list[str]) -> None:
        self.requires = requires


def test_direct_dependencies_marker_matrix() -> None:
    # extra-gated, environment-gated, unconditional, and a dependency that
    # itself requests an extra on its target.
    dist = _FakeDist(
        [
            "always-there>=1.0",
            "only-with-x>=1.0; extra == 'x'",
            "win-only>=1.0; sys_platform == 'win32'",
            "target[feature]>=1.0; extra == 'x'",
        ]
    )
    with_x = dict(sbom._direct_dependencies(dist, frozenset({"x"})))  # type: ignore[arg-type]
    assert with_x["always-there"] == frozenset()
    assert "only-with-x" in with_x
    assert with_x["target"] == frozenset({"feature"})  # per-dependency extra kept
    # The env-marker dependency has no extra gate, so it is surfaced here; the
    # closure then keeps it only if it is actually installed (installed-based
    # resolution), which is what makes platform/Python markers match the install.
    assert "win-only" in with_x

    without = dict(sbom._direct_dependencies(dist, frozenset()))  # type: ignore[arg-type]
    assert "always-there" in without and "win-only" in without
    assert "only-with-x" not in without  # inactive extra is not followed
    assert "target" not in without


def test_render_sbom_conforms_to_cyclonedx_1_5_structure() -> None:
    document = sbom.render_sbom(timestamp="2026-10-31T00:00:00Z", serial_number="urn:uuid:y")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert isinstance(document["version"], int)
    for component in document["components"]:
        assert component["type"] == "library"
        assert component["name"] and component["version"]
        assert component["purl"] == component["bom-ref"]
        assert component["purl"].startswith("pkg:pypi/")
        for licence in component.get("licenses", []):
            assert "license" in licence and "name" in licence["license"]


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
    assert json.dumps(document, sort_keys=True) == json.dumps(sbom.render_sbom(), sort_keys=True)


def test_render_records_requested_extras_as_properties() -> None:
    document = sbom.render_sbom(extras=frozenset({"themis"}))
    properties = document["metadata"].get("properties", [])
    assert {"name": "olympus:extra", "value": "themis"} in properties


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
    result = runner.invoke(app, ["core", "sbom", "--reproducible", "--output", str(destination)])
    assert result.exit_code == 0, result.output
    assert destination.exists()
    assert json.loads(destination.read_text())["bomFormat"] == "CycloneDX"


def test_sbom_command_extra_widens_the_component_set() -> None:
    base = json.loads(runner.invoke(app, ["core", "sbom", "--reproducible"]).stdout)
    widened = json.loads(
        runner.invoke(app, ["core", "sbom", "--reproducible", "--extra", "themis"]).stdout
    )
    assert len(widened["components"]) >= len(base["components"])

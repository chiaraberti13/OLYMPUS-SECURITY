"""The SBOM lists the engines and the template pin straight from the manifests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.sbom import render_sbom
from olympus.engines.loader import load_all, load_all_data
from olympus.engines.sbom import engine_components

pytestmark = pytest.mark.unit

_COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "firmware",
    "file",
    "data",
}


def _document() -> dict[str, object]:
    components, dependencies = engine_components()
    return render_sbom(extra_components=components, extra_dependencies=dependencies)


def test_every_engine_and_data_dependency_is_a_component() -> None:
    components, _ = engine_components()
    refs = {c["bom-ref"] for c in components}
    assert refs == {f"engine:{n}" for n in load_all()} | {f"data:{n}" for n in load_all_data()}
    assert len(refs) == len(components) == 25


def test_pins_come_from_the_manifests_not_from_a_second_list() -> None:
    by_ref = {c["bom-ref"]: c for c in engine_components()[0]}
    nuclei = by_ref["engine:nuclei"]
    assert nuclei["version"] == "v3.11.1"
    assert nuclei["purl"] == "pkg:golang/github.com/projectdiscovery/nuclei/v3@v3.11.1"
    templates = by_ref["data:nuclei-templates"]
    assert templates["type"] == "data" and templates["version"] == "v10.5.1"
    assert templates["purl"].endswith("@79fb682760ab3d5b0e22afbb44709353cbebf023")
    git = by_ref["engine:xsstrike"]
    assert git["purl"] == "pkg:github/s0md3v/xsstrike@65dd68ae9051ce7cecf3be23fbda6e329d8580af"
    assert {"name": "olympus:commit", "value": "65dd68ae9051ce7cecf3be23fbda6e329d8580af"} in git[
        "properties"
    ]
    assert by_ref["engine:wapiti"]["purl"] == "pkg:pypi/wapiti3@3.2.3"


def test_external_products_carry_no_invented_version() -> None:
    by_ref = {c["bom-ref"]: c for c in engine_components()[0]}
    for name in ("zap", "openvas", "nessus", "burp", "acunetix"):
        assert "version" not in by_ref[f"engine:{name}"]
        assert any(
            p["name"] == "olympus:requires-product" for p in by_ref[f"engine:{name}"]["properties"]
        )


def test_nuclei_depends_on_its_templates() -> None:
    _, dependencies = engine_components()
    assert dependencies == [{"ref": "engine:nuclei", "dependsOn": ["data:nuclei-templates"]}]


def test_the_document_is_a_valid_cyclonedx_shape_with_unique_refs() -> None:
    document = _document()
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    components = document["components"]
    assert isinstance(components, list)
    refs = [c["bom-ref"] for c in components]
    assert len(refs) == len(set(refs))
    assert {c["type"] for c in components} <= _COMPONENT_TYPES
    for component in components:
        assert component["name"] and component["bom-ref"]
    known = set(refs)
    for dependency in document["dependencies"]:  # type: ignore[attr-defined]
        assert dependency["ref"] in known and set(dependency["dependsOn"]) <= known


def test_the_document_is_deterministic() -> None:
    assert json.dumps(_document(), sort_keys=True) == json.dumps(_document(), sort_keys=True)


def test_a_clashing_bom_ref_is_refused() -> None:
    clash = {"type": "library", "bom-ref": "pkg:pypi/pydantic@0", "name": "x"}
    python_refs = [c["bom-ref"] for c in render_sbom()["components"]]
    clash["bom-ref"] = python_refs[0]
    with pytest.raises(ValueError, match="duplicate SBOM bom-ref"):
        render_sbom(extra_components=[clash])


def test_the_cli_flag_adds_the_engines_and_the_default_is_unchanged() -> None:
    runner = CliRunner()
    plain = runner.invoke(app, ["core", "sbom", "--reproducible"])
    engines = runner.invoke(app, ["core", "sbom", "--reproducible", "--engines"])
    assert plain.exit_code == 0 and engines.exit_code == 0
    plain_refs = {c["bom-ref"] for c in json.loads(plain.stdout)["components"]}
    engine_refs = {c["bom-ref"] for c in json.loads(engines.stdout)["components"]}
    assert not any(ref.startswith(("engine:", "data:")) for ref in plain_refs)
    assert engine_refs - plain_refs == {f"engine:{n}" for n in load_all()} | {
        f"data:{n}" for n in load_all_data()
    }
    assert "dependencies" not in json.loads(plain.stdout)

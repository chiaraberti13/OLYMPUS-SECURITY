"""``engine.toml`` schema, shipped manifests and their link to the real adapters."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from olympus.engines.loader import (
    ENGINES_ROOT,
    ManifestError,
    load_all,
    load_manifest,
    parse_manifest,
)
from olympus.engines.schema import MOBILE_REFERENCES
from olympus.integrations.maturity import Maturity, record_for
from olympus.integrations.scanners import by_name
from olympus.themis.base import ScannerAdapter

pytestmark = pytest.mark.unit

SHA = "65dd68ae9051ce7cecf3be23fbda6e329d8580af"

_BASE = """
[engine]
name = "demo"
category = "web"
upstream = "https://github.com/example/demo"
license = "MIT"
distribution = "go"
pinned_version = "v1.2.3"
update_policy = "minor"
presence_probe = ["demo", "-version"]
capability = "web.scan"
{engine_extra}
[engine.source]
module = "github.com/example/demo/cmd/demo"
{source_extra}
{adapter}
"""

_ADAPTER = """
[adapter]
entrypoint = "olympus.themis.adapters.nuclei:NucleiAdapter"
timeout_seconds = 600
resource_profile = "network-heavy"
"""


def _manifest(engine_extra: str = "", source_extra: str = "", adapter: str = _ADAPTER) -> str:
    return _BASE.format(engine_extra=engine_extra, source_extra=source_extra, adapter=adapter)


def test_a_complete_manifest_validates() -> None:
    manifest = parse_manifest(_manifest())
    assert manifest.engine.name == "demo"
    assert manifest.engine.mandatory is False
    assert manifest.engine.upstream_verified is False  # never assumed
    assert manifest.install_command() == "go install github.com/example/demo/cmd/demo@v1.2.3"


# --- rejected manifests ----------------------------------------------------- #
@pytest.mark.parametrize("pin", [*sorted(MOBILE_REFERENCES), "", "Latest", "^1.2", ">=1", "*"])
def test_moving_or_malformed_pins_are_rejected(pin: str) -> None:
    text = _manifest().replace('pinned_version = "v1.2.3"', f'pinned_version = "{pin}"')
    with pytest.raises(ManifestError, match="pinned_version"):
        parse_manifest(text)


def test_incomplete_manifest_reports_every_missing_field_in_both_forms() -> None:
    with pytest.raises(ManifestError) as caught:
        parse_manifest('[engine]\nname = "demo"\n')
    report = caught.value.report
    assert report is not None
    assert report.to_dict()["error"] == "schema_validation_error"
    fields = {".".join(str(p) for p in item["loc"]) for item in report.errors}
    assert {
        "engine.category",
        "engine.upstream",
        "engine.pinned_version",
        "engine.source",
    } <= fields
    assert "Olympus Schema Validation Error (olympus.engine-manifest)" in str(caught.value)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ManifestError, match="Extra inputs"):
        parse_manifest(_manifest(engine_extra='shell = "sh -c x"'))


@pytest.mark.parametrize(
    "probe",
    ['["/usr/bin/demo", "-v"]', '["demo", "-v; rm -rf /"]', '["demo", "a b"]', '["demo", "$(id)"]'],
)
def test_presence_probe_cannot_carry_paths_or_shell_syntax(probe: str) -> None:
    text = _manifest().replace('presence_probe = ["demo", "-version"]', f"presence_probe = {probe}")
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_mandatory_and_required_for_commands_are_mutually_exclusive() -> None:
    text = _manifest(engine_extra='mandatory = true\nrequired_for_commands = ["web.scan"]')
    with pytest.raises(ManifestError, match="either mandatory"):
        parse_manifest(text)


def test_mandatory_or_required_engine_must_have_an_adapter() -> None:
    with pytest.raises(ManifestError, match="mandatory engine must declare"):
        parse_manifest(_manifest(engine_extra="mandatory = true", adapter=""))
    with pytest.raises(ManifestError, match="required by commands must declare"):
        parse_manifest(_manifest(engine_extra='required_for_commands = ["web.scan"]', adapter=""))


def test_go_pin_must_be_a_version_tag() -> None:
    with pytest.raises(ManifestError, match="module version tag"):
        parse_manifest(_manifest().replace('"v1.2.3"', '"1.2.3"'))


def test_bad_adapter_entrypoint_shape_is_rejected() -> None:
    bad = _ADAPTER.replace("olympus.themis.adapters.nuclei:NucleiAdapter", "os.system")
    with pytest.raises(ManifestError, match="entrypoint"):
        parse_manifest(_manifest(adapter=bad))


@pytest.mark.parametrize(
    "source",
    [
        'repo = "https://github.com/e/d"\ncommit = "abc123"\ncheckout_path = "/opt/d"\n'
        'entry = "d.py"\nruntime = "python"',  # short sha
        'repo = "https://github.com/e/d"\ncommit = "'
        + SHA.upper()
        + '"\ncheckout_path = "/opt/d"\n'
        'entry = "d.py"\nruntime = "python"',  # not lowercase
        'repo = "https://github.com/e/d"\ncommit = "' + SHA + '"\ncheckout_path = "/opt/d"\n'
        'entry = "../d.py"\nruntime = "python"',  # path traversal
    ],
)
def test_git_distribution_requires_a_full_lowercase_commit_and_a_safe_entry(source: str) -> None:
    text = (
        _manifest(adapter="")
        .replace('distribution = "go"', 'distribution = "git"')
        .replace('module = "github.com/example/demo/cmd/demo"', source)
    )
    with pytest.raises(ManifestError):
        parse_manifest(text)


def test_git_distribution_requires_every_source_field() -> None:
    text = (
        _manifest(adapter="")
        .replace('distribution = "go"', 'distribution = "git"')
        .replace('module = "github.com/example/demo/cmd/demo"', 'repo = "https://github.com/e/d"')
    )
    with pytest.raises(ManifestError, match=r"requires source\.commit"):
        parse_manifest(text)


_API = """
[engine]
name = "burp"
category = "web"
upstream = "https://portswigger.net/burp"
license = "Commercial (PortSwigger)"
distribution = "api"
pinned_version = "2025.1"
update_policy = "manual"
presence_probe = ["burp", "--version"]
capability = "web.scan"
{engine_extra}
[engine.source]
requires_product = "PortSwigger Burp Suite Professional (commercial licence)"
{adapter}
"""


def test_api_engines_are_catalog_only_never_mandatory_never_adapted() -> None:
    ok = parse_manifest(_API.format(engine_extra="", adapter=""))
    assert ok.install_command() is None
    with pytest.raises(ManifestError, match="can never be required"):
        parse_manifest(_API.format(engine_extra="mandatory = true", adapter=_ADAPTER))
    with pytest.raises(ManifestError, match="stay catalog-only"):
        parse_manifest(_API.format(engine_extra="", adapter=_ADAPTER))


def test_install_command_is_derived_from_the_pin_for_every_distribution() -> None:
    def make(distribution: str, source: str, pin: str = "1.0") -> str:
        return (
            _manifest(adapter="")
            .replace('distribution = "go"', f'distribution = "{distribution}"')
            .replace('pinned_version = "v1.2.3"', f'pinned_version = "{pin}"')
            .replace('module = "github.com/example/demo/cmd/demo"', source)
        )

    assert (
        parse_manifest(make("pip", 'package = "demo"')).install_command()
        == "pip install 'demo==1.0'"
    )
    assert parse_manifest(make("gem", 'package = "demo"')).install_command() == (
        "gem install demo -v 1.0"
    )
    assert parse_manifest(make("apt", 'package = "demo"')).install_command() == (
        "apt-get install -y --no-install-recommends demo=1.0"
    )
    digest = "sha256:" + "a" * 64
    assert parse_manifest(
        make("docker", f'image = "example/demo"\ndigest = "{digest}"')
    ).install_command() == (f"docker pull example/demo@{digest}")
    git = parse_manifest(
        make(
            "git",
            'repo = "https://github.com/e/d"\n'
            f'commit = "{SHA}"\ncheckout_path = "/opt/d"\nentry = "d.py"\nruntime = "python"',
        )
    ).install_command()
    assert git is not None and SHA in git and "checkout --detach FETCH_HEAD" in git


# --- the manifests that ship with Olympus ---------------------------------- #
def _shipped() -> dict[str, Path]:
    return {p.parent.name: p for p in sorted(ENGINES_ROOT.glob("*/engine.toml"))}


def test_shipped_manifests_exist_and_all_load() -> None:
    assert load_all().keys() == _shipped().keys() != set()


@pytest.mark.parametrize("name", sorted(_shipped()))
def test_shipped_manifest_references_a_real_adapter_and_catalogued_engine(name: str) -> None:
    manifest = load_manifest(_shipped()[name])
    spec = by_name(name)
    assert spec is not None, f"{name} is not in the scanner catalogue"
    assert manifest.engine.category == spec.category
    assert manifest.engine.license == spec.licence
    if manifest.adapter is None:
        assert record_for(name).stage is Maturity.CATALOG_ONLY
        return
    module_name, _, class_name = manifest.adapter.entrypoint.partition(":")
    adapter_class = getattr(importlib.import_module(module_name), class_name)
    assert issubclass(adapter_class, ScannerAdapter)
    assert adapter_class.name == name
    assert adapter_class.binary == manifest.engine.presence_probe[0]
    assert manifest.adapter.timeout_seconds >= 1


def test_manifest_directory_must_match_engine_name(tmp_path: Path) -> None:
    folder = tmp_path / "wrongdir"
    folder.mkdir()
    (folder / "engine.toml").write_text(_manifest(adapter=""), encoding="utf-8")
    with pytest.raises(ManifestError, match="must equal its directory"):
        load_manifest(folder / "engine.toml")


def test_oversized_and_symlinked_manifests_are_refused(tmp_path: Path) -> None:
    folder = tmp_path / "demo"
    folder.mkdir()
    big = folder / "engine.toml"
    big.write_text("# " + "x" * 70_000, encoding="utf-8")
    with pytest.raises(ManifestError, match="cannot read"):
        load_manifest(big)
    real = tmp_path / "real.toml"
    real.write_text(_manifest(adapter=""), encoding="utf-8")
    link = tmp_path / "linked" / "engine.toml"
    link.parent.mkdir()
    link.symlink_to(real)
    with pytest.raises(ManifestError, match="symlink"):
        load_manifest(link)


def test_manifests_never_contain_secrets_or_command_strings() -> None:
    for path in _shipped().values():
        text = path.read_text(encoding="utf-8").lower()
        for forbidden in ("token", "password", "api_key", "secret", "sh -c", "shell"):
            assert forbidden not in text, f"{path}: contains {forbidden!r}"
        json.dumps(load_manifest(path).model_dump())  # serialisable, no objects

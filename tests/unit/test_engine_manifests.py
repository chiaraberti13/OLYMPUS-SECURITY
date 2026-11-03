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
from olympus.integrations.maturity import Maturity, at_least, record_for
from olympus.integrations.scanners import by_name
from olympus.themis.base import ScannerAdapter

pytestmark = pytest.mark.unit

SHA = "65dd68ae9051ce7cecf3be23fbda6e329d8580af"

_BASE = """
[engine]
name = "demo"
category = "web"
upstream = "https://github.com/example/demo"
language = "Go"
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
language = "Java (proprietario)"
license = "Commercial (PortSwigger)"
distribution = "api"
update_policy = "manual"
capability = "web.scan"
{engine_extra}
[engine.source]
requires_product = "PortSwigger Burp Suite Professional (commercial licence)"
env_vars = ["THEMIS_BURP_URL", "THEMIS_BURP_API_KEY"]
{adapter}
"""


def test_api_engines_are_catalog_only_never_mandatory_never_adapted() -> None:
    ok = parse_manifest(_API.format(engine_extra="", adapter=""))
    assert ok.install_command() is None
    with pytest.raises(ManifestError, match="can never be required"):
        parse_manifest(_API.format(engine_extra="mandatory = true", adapter=_ADAPTER))
    with pytest.raises(ManifestError, match="stay catalog-only"):
        parse_manifest(_API.format(engine_extra="", adapter=_ADAPTER))


def test_api_engine_has_no_pin_no_probe_and_only_env_var_names() -> None:
    no_names = _API.format(engine_extra="", adapter="").replace(
        'env_vars = ["THEMIS_BURP_URL", "THEMIS_BURP_API_KEY"]', ""
    )
    with pytest.raises(ManifestError, match="env var NAMES"):
        parse_manifest(no_names)
    with pytest.raises(ManifestError, match="no executable"):
        parse_manifest(_API.format(engine_extra='presence_probe = ["burp"]', adapter=""))
    with pytest.raises(ManifestError, match="String should match"):
        parse_manifest(
            _API.format(engine_extra="", adapter="").replace("THEMIS_BURP_URL", "secret-value-123")
        )
    # every other distribution must still pin and probe
    no_pin = _manifest(adapter="").replace('pinned_version = "v1.2.3"\n', "")
    with pytest.raises(ManifestError, match="requires pinned_version"):
        parse_manifest(no_pin)
    no_probe = _manifest(adapter="").replace('presence_probe = ["demo", "-version"]\n', "")
    with pytest.raises(ManifestError, match="requires presence_probe"):
        parse_manifest(no_probe)


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
        manifest = load_manifest(path)
        text = path.read_text(encoding="utf-8")
        # env var NAMES are allowed (the schema pins their shape); values never appear.
        for name in manifest.engine.source.env_vars:
            text = text.replace(name, "")
        text = text.lower()
        for forbidden in ("token", "password", "api_key", "secret", "sh -c", "shell"):
            assert forbidden not in text, f"{path}: contains {forbidden!r}"
        json.dumps(load_manifest(path).model_dump())  # serialisable, no objects


def _git_manifest(source_lines: str, probe: str = "demo") -> str:
    return (
        _manifest(adapter="")
        .replace('distribution = "go"', 'distribution = "git"')
        .replace('presence_probe = ["demo", "-version"]', f'presence_probe = ["{probe}", "-v"]')
        .replace(
            'module = "github.com/example/demo/cmd/demo"',
            f'repo = "https://github.com/e/d"\ncommit = "{SHA}"\ncheckout_path = "/opt/d"\n'
            + source_lines,
        )
    )


def test_git_engine_is_interpreted_xor_compiled() -> None:
    interpreted = 'entry = "d.py"\nruntime = "python"'
    compiled = 'build = "autotools"\nbuild_args = ["--without-zenmap", "--prefix=/usr/local"]'
    assert parse_manifest(_git_manifest(interpreted)).engine.source.runtime == "python"
    assert parse_manifest(_git_manifest(compiled)).engine.source.build == "autotools"
    for bad in ("", interpreted + "\n" + compiled, 'entry = "d.py"', 'runtime = "python"'):
        with pytest.raises(ManifestError, match=r"interpreted .* or compiled"):
            parse_manifest(_git_manifest(bad))


def test_compiled_git_install_command_runs_the_pinned_build() -> None:
    command = parse_manifest(
        _git_manifest('build = "autotools"\nbuild_args = ["--without-zenmap"]')
    ).install_command()
    assert command is not None
    assert command.endswith(
        "cd /opt/d && find . -name configure -type f -exec touch {} + "
        "&& ./configure --without-zenmap && make && make install"
    )


def test_interpreted_git_install_command_pins_packages_and_writes_a_launcher() -> None:
    command = parse_manifest(
        _git_manifest(
            'entry = "d.py"\nruntime = "python"\nruntime_packages = ["tld==0.13.2"]',
            probe="demo",
        )
    ).install_command()
    assert command is not None
    assert "pip install 'tld==0.13.2'" in command
    assert 'exec python /opt/d/d.py "$@"' in command
    assert "> /usr/local/bin/demo" in command


@pytest.mark.parametrize(
    "extra",
    [
        'runtime_packages = ["tld"]',  # not pinned
        'runtime_packages = ["tld>=0.13"]',  # range, not ==
        'build_args = ["--prefix=/x; rm -rf /"]',  # shell syntax
        'build_args = ["-O3"]',  # not a long option
    ],
)
def test_runtime_packages_and_build_args_must_be_exact_and_inert(extra: str) -> None:
    with pytest.raises(ManifestError):
        parse_manifest(_git_manifest('entry = "d.py"\nruntime = "python"\n' + extra))


# --- the catalogue as a whole ---------------------------------------------- #
def test_every_catalogued_engine_has_exactly_one_manifest() -> None:
    from olympus.integrations.scanners import REGISTRY

    assert set(_shipped()) == {spec.name for spec in REGISTRY}


def test_manifest_adapter_presence_matches_the_adapter_registry() -> None:
    from olympus.themis.registry import implemented

    for name, manifest in load_all().items():
        assert (manifest.adapter is not None) == (name in implemented()), name


def test_the_mandatory_set_is_the_core_path_and_changing_it_is_deliberate() -> None:
    """nmap/nuclei/httpx are the defaults of recommended_scanner, Smart Scan and Athena deep.

    ``mandatory`` means "baseline infrastructure every engine-using command assumes", not
    "engines we like". Widening this set must be a reviewed decision, hence this lock.
    """
    mandatory = {name for name, m in load_all().items() if m.engine.mandatory}
    assert mandatory == {"nmap", "nuclei", "httpx"}


def test_adapter_backed_manifests_are_not_catalog_only_and_vice_versa() -> None:
    for name, manifest in load_all().items():
        stage = record_for(name).stage
        assert (stage is Maturity.CATALOG_ONLY) == (manifest.adapter is None), name


def test_every_manifest_is_unverified_until_check_updates_says_otherwise() -> None:
    assert not [n for n, m in load_all().items() if m.engine.upstream_verified]


def test_api_engines_are_the_five_external_products() -> None:
    api = {n for n, m in load_all().items() if m.engine.distribution == "api"}
    assert api == {"zap", "openvas", "nessus", "burp", "acunetix"}
    for name in api:
        manifest = load_all()[name]
        assert manifest.engine.mandatory is False and manifest.adapter is None
        assert manifest.engine.source.requires_product


def test_pypi_packages_that_are_not_the_upstream_project_are_rejected() -> None:
    for package, fragment in (("commix", "Bhai4You"), ("theHarvester", "stale")):
        text = _manifest(adapter="").replace('distribution = "go"', 'distribution = "pip"')
        text = text.replace('module = "github.com/example/demo/cmd/demo"', f'package = "{package}"')
        with pytest.raises(ManifestError, match=fragment):
            parse_manifest(text.replace('"v1.2.3"', '"0.1"'))


def test_live_tested_engines_record_the_version_their_evidence_was_captured_on() -> None:
    for name, manifest in load_all().items():
        if at_least(record_for(name).stage, Maturity.LIVE_TESTED):
            assert manifest.engine.evidence_version, f"{name}: live-tested without evidence_version"


def test_estimated_adapter_values_are_marked_until_reviewed() -> None:
    unreviewed = sorted(n for n, m in load_all().items() if m.adapter and not m.adapter.reviewed)
    for name in unreviewed:
        text = _shipped()[name].read_text(encoding="utf-8")
        assert "reviewed = false" in text and "TODO(TOOLS-4)" in text, name
    assert _manifest().count("reviewed") == 0  # the schema default is "not reviewed"
    assert parse_manifest(_manifest()).adapter is not None
    assert parse_manifest(_manifest()).adapter.reviewed is False  # type: ignore[union-attr]


def test_a_tag_whose_code_prints_another_version_is_recorded_not_trusted() -> None:
    manifest = load_all()["xsstrike"]
    assert manifest.engine.pinned_version == "3.1.6"
    assert manifest.engine.reported_version == "3.1.5"
    assert manifest.engine.source.commit  # the commit, not the string, is the pin


def test_licences_with_extra_terms_are_conditional_in_the_registry() -> None:
    from olympus.integrations.scanners import by_name

    for name in ("nmap", "nikto"):
        spec = by_name(name)
        assert spec is not None
        assert spec.redistributable == "conditional"
        assert spec.redistribution == "conditional"
    gpl = by_name("sqlmap")
    assert gpl is not None and gpl.redistribution == "free"
    commercial = by_name("nessus")
    assert commercial is not None and commercial.redistribution == "no"


# --- data dependencies ------------------------------------------------------ #
_DATA = """
[data]
name = "tpl"
upstream = "https://github.com/example/tpl"
license = "MIT"
pinned_version = "v1.0.0"
update_policy = "manual"
used_by = ["nuclei"]

[data.source]
repo = "https://github.com/example/tpl"
commit = "{commit}"
checkout_path = "/opt/tpl"
"""


def _data(**changes: str) -> str:
    text = _DATA.format(commit=changes.pop("commit", SHA))
    for old, new in changes.items():
        text = text.replace(old, new)
    return text


def _load_data_text(tmp_path: Path, text: str, name: str = "tpl"):  # type: ignore[no-untyped-def]
    from olympus.engines.loader import load_data_manifest

    path = tmp_path / f"{name}.toml"
    path.write_text(text, encoding="utf-8")
    return load_data_manifest(path)


def test_a_data_dependency_is_pinned_like_an_engine(tmp_path: Path) -> None:
    manifest = _load_data_text(tmp_path, _data())
    assert manifest.data.source.commit == SHA
    assert SHA in manifest.install_command()
    assert manifest.data.upstream_verified is False
    for bad in ("latest", "main", "master"):
        with pytest.raises(ManifestError, match="exact version"):
            _load_data_text(tmp_path, _data(**{'"v1.0.0"': f'"{bad}"'}))
    with pytest.raises(ManifestError, match="40-hex"):
        _load_data_text(tmp_path, _data(commit="abc"))
    with pytest.raises(ManifestError, match=r"requires source\.commit"):
        _load_data_text(tmp_path, _data().replace(f'commit = "{SHA}"\n', ""))


def test_data_manifest_file_name_must_match_and_unknown_keys_fail(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="must equal the file name"):
        _load_data_text(tmp_path, _data(), name="other")
    with pytest.raises(ManifestError, match="Extra inputs"):
        _load_data_text(tmp_path, _data() + "\n[extra]\nx = 1\n")


def test_requires_data_and_used_by_agree_and_point_at_real_manifests() -> None:
    from olympus.engines.loader import load_all_data

    engines, data = load_all(), load_all_data()
    for name, manifest in engines.items():
        for needed in manifest.engine.requires_data:
            assert needed in data, f"{name}: requires_data {needed!r} has no _data manifest"
            assert name in data[needed].data.used_by, f"{needed}.used_by does not list {name}"
    for dep_name, dep in data.items():
        for user in dep.data.used_by:
            assert dep_name in engines[user].engine.requires_data, (
                f"{user} does not require {dep_name}"
            )
    assert engines["nuclei"].engine.requires_data == ["nuclei-templates"]

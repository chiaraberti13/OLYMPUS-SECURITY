"""An adapter's install hint is the pinned manifest command — never a moving reference.

Regression guard for the supply-chain defect where ``ScannerAdapter.install`` carried
hand-written strings (``go install …@latest`` for nuclei/httpx/katana/dalfox, the wrong
``pip install commix`` PyPI package) that contradicted the pinned ``engine.toml``. The hint
is now derived from the manifest (:func:`olympus.engines.loader.install_hint`), so what an
operator is shown to install a missing engine is exactly the version the build verifies.
"""

from __future__ import annotations

import re

import pytest

from olympus.engines.doctor import adapter_for
from olympus.engines.loader import install_hint, load_all
from olympus.engines.schema import MOBILE_REFERENCES
from olympus.integrations.scanners import REGISTRY

_MOVING = re.compile(r"@(" + "|".join(sorted(MOBILE_REFERENCES)) + r")(\b|$)")

_WITH_ADAPTER = [
    (name, manifest) for name, manifest in sorted(load_all().items()) if manifest.adapter
]
_IDS = [name for name, _ in _WITH_ADAPTER]

_SPECS_WITH_MANIFEST = [
    (spec.name, spec) for spec in REGISTRY if install_hint(spec.name) is not None
]
_SPEC_IDS = [name for name, _ in _SPECS_WITH_MANIFEST]


@pytest.mark.parametrize("name,manifest", _WITH_ADAPTER, ids=_IDS)
def test_adapter_install_hint_is_the_pinned_manifest_command(name, manifest):  # type: ignore[no-untyped-def]
    adapter = adapter_for(manifest)
    assert adapter is not None
    expected = manifest.install_command()
    # Every engine with an adapter is an installable artifact (never an api product).
    assert expected is not None
    # Single source of truth: the hint the operator sees cannot drift from the pin.
    assert adapter.install == expected == install_hint(name)


@pytest.mark.parametrize("name,manifest", _WITH_ADAPTER, ids=_IDS)
def test_adapter_install_hint_has_no_moving_or_wrong_reference(name, manifest):  # type: ignore[no-untyped-def]
    hint = adapter_for(manifest).install  # type: ignore[union-attr]
    assert not _MOVING.search(hint), f"{name}: moving reference in install hint: {hint}"
    # A bare ``pip install <name>`` installs whatever is latest on PyPI — and for commix
    # and theHarvester that is a different, third-party package (see NOT_UPSTREAM_ON_PYPI).
    if "pip install" in hint:
        assert "==" in hint, f"{name}: unpinned pip install: {hint}"
    if "go install" in hint:
        assert "@v" in hint, f"{name}: unpinned go install: {hint}"
    if "gem install" in hint:
        assert " -v " in hint, f"{name}: unpinned gem install: {hint}"


def test_mandatory_engine_install_hints_carry_their_exact_pin():
    manifests = load_all()
    for name in ("nuclei", "httpx", "nmap"):
        manifest = manifests[name]
        assert manifest.engine.mandatory, f"{name} is expected to be mandatory"
        adapter = adapter_for(manifest)
        assert adapter is not None
        # The install command embeds the exact pin: the version tag for a ``go`` engine,
        # the commit for one built from a ``git`` checkout (e.g. nmap).
        version, commit = manifest.engine.pinned_version, manifest.engine.source.commit
        assert (version and version in adapter.install) or (commit and commit in adapter.install)


@pytest.mark.parametrize("name,spec", _SPECS_WITH_MANIFEST, ids=_SPEC_IDS)
def test_catalogue_install_hint_is_pinned_and_not_a_wrong_package(name, spec):  # type: ignore[no-untyped-def]
    # The scanner catalogue (olympus themis scanners) must show the same pinned command
    # as the manifest — no unpinned or dependency-confusion install for an engine whose
    # PyPI name is a different project than its git upstream.
    assert spec.install == install_hint(name)
    assert not _MOVING.search(spec.install), (
        f"{name}: moving reference in catalogue: {spec.install}"
    )
    assert "pip install commix" not in spec.install
    assert "pip install theHarvester" not in spec.install


def test_commix_install_hint_is_the_git_project_not_the_pypi_package():
    # The regression this file guards: commix was suggested as ``pip install commix``,
    # which is an unrelated third-party package, not commixproject/commix.
    hint = install_hint("commix") or ""
    assert "commixproject/commix" in hint
    assert "pip install commix" not in hint

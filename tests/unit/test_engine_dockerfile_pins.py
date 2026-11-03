"""The scanner image must install exactly the versions the manifests pin.

A pin that only lives in ``engine.toml`` is cosmetic; this fails the build when the
Dockerfile and a manifest disagree (manifest -> Dockerfile direction). The reverse
direction (an install with no manifest) is asserted once every catalogued engine
has a manifest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.engines.loader import load_all
from olympus.engines.schema import EngineManifest
from olympus.integrations.scanners import by_name

pytestmark = pytest.mark.unit

DOCKERFILE = Path(__file__).parents[2] / "docker" / "Dockerfile.scanners"


def _expected_fragments(manifest: EngineManifest) -> list[str]:
    """Every pin a manifest declares that the Dockerfile must repeat verbatim."""
    engine, source = manifest.engine, manifest.engine.source
    match engine.distribution:
        case "go":
            return [f"{source.module}@{engine.pinned_version}"]
        case "git":
            fragments = [f"git_pin {source.repo} {source.commit} {source.checkout_path}"]
            fragments += source.build_args
            for item in source.runtime_packages:
                package, _, version = item.partition("==")
                if source.runtime == "ruby":
                    fragments.append(f"gem install --no-document {package} -v {version}")
                else:
                    fragments.append(f"'{item}'")
            return fragments
        case "pip":
            return [f"'{source.package}=={engine.pinned_version}'"]
        case "gem":
            return [f"gem install {source.package} -v {engine.pinned_version}"]
        case _:
            return []  # api engines are not installed by this image


@pytest.mark.parametrize("name", sorted(load_all()))
def test_dockerfile_installs_the_manifest_pin(name: str) -> None:
    manifest = load_all()[name]
    spec = by_name(name)
    assert spec is not None
    if not spec.in_scanner_image:
        pytest.skip(f"{name}: not shipped in the scanner image (see the TODOs in the Dockerfile)")
    text = DOCKERFILE.read_text(encoding="utf-8")
    for fragment in _expected_fragments(manifest):
        assert fragment in text, f"{name}: Dockerfile.scanners does not contain {fragment!r}"


def test_engines_not_shipped_in_the_image_are_documented_as_todo() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    from olympus.integrations.scanners import REGISTRY

    for spec in REGISTRY:
        if spec.binary is not None and not spec.in_scanner_image:
            assert spec.name in text.lower(), f"{spec.name}: absent from the image but undocumented"


def test_dockerfile_has_no_best_effort_installs_or_moving_references() -> None:
    lines = [
        line
        for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    ]
    code = "\n".join(lines)
    assert "|| true" not in code
    assert "@latest" not in code
    assert "--branch" not in code and "clone --depth 1" not in code  # HEAD of a branch
    assert 'SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]' in code
    assert "apt-get install" in code and "nmap=" not in code  # no apt-installed engine
    assert "GOTOOLCHAIN=go1.26" in code  # the Go toolchain is pinned too

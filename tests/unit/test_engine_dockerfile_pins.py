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
    """``in_scanner_image = False`` needs a ``TODO(TOOLS-4)`` line naming the engine.

    Otherwise someone can drop an engine from the Dockerfile and the inventory would
    keep saying nothing about why it is missing.
    """
    from olympus.integrations.scanners import REGISTRY

    todo_lines = [
        line.lower()
        for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if line.lstrip().startswith("#") and "TODO(TOOLS-4)" in line
    ]
    for spec in REGISTRY:
        if spec.binary is not None and not spec.in_scanner_image:
            assert any(spec.name in line for line in todo_lines), (
                f"{spec.name}: in_scanner_image=False but no TODO(TOOLS-4) names it"
            )


def test_go_toolchain_is_pinned_before_the_first_go_command_and_sumdb_stays_on() -> None:
    code = "\n".join(
        line
        for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )
    first_go = min(code.index(token) for token in ("go install", "go version", "go env"))
    assert code.index("GOTOOLCHAIN=go1.26") < first_go
    assert code.index("GOSUMDB=sum.golang.org") < first_go
    assert "GOSUMDB=off" not in code and "GONOSUMDB" not in code and "GOFLAGS" not in code
    assert "GOINSECURE" not in code


def test_image_ships_the_licence_notice_and_the_nmap_licence_text() -> None:
    code = DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY docker/NOTICE /NOTICE" in code
    assert "/opt/nmap/LICENSE" in code
    notice = (DOCKERFILE.parent / "NOTICE").read_text(encoding="utf-8")
    assert "Nmap Public Source License" in notice and "https://nmap.org/npsl/" in notice
    assert "nikto" in notice and "databases" in notice


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


def test_every_pin_in_the_dockerfile_belongs_to_a_manifest() -> None:
    """The reverse direction: an install nobody declared in an engine.toml is a bug."""
    import re

    text = DOCKERFILE.read_text(encoding="utf-8")
    manifests = load_all().values()
    commits = {m.engine.source.commit for m in manifests if m.engine.source.commit}
    for repo, commit, _path in re.findall(r"git_pin (\S+) ([0-9a-f]{40}) (\S+);", text):
        assert commit in commits, f"git_pin {repo} {commit} has no engine.toml"
    modules = {f"{m.engine.source.module}@{m.engine.pinned_version}" for m in manifests}
    for target in re.findall(r"go install (\S+)", text):
        assert target in modules, f"go install {target} has no engine.toml"
    pips = {f"{m.engine.source.package}=={m.engine.pinned_version}" for m in manifests}
    for pin in re.findall(r"'([A-Za-z0-9._-]+==[0-9][A-Za-z0-9._-]*)'", text):
        runtime = {p for m in manifests for p in m.engine.source.runtime_packages}
        assert pin in pips or pin in runtime, f"pip pin {pin} has no engine.toml"

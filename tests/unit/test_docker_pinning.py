"""Guard the supply-chain pinning of mandatory container images.

Roadmap §1.3 asks for Docker images pinned by digest and no ``@latest`` on the
mandatory components. This test keeps those pins from silently regressing to a
floating tag on a later edit — the same drift discipline used for the scanner
matrix and the maturity ledger.

The distinction the roadmap draws is deliberate and encoded here: the *mandatory*
components (the base image the scanner image builds from, the Redis broker the
stack requires) must be digest-pinned; the *best-effort* scanner installs keep
their ``|| true`` so one unavailable tool never fails the build, but must not
track ``@latest``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_DOCKERFILE_SCANNERS = _ROOT / "docker" / "Dockerfile.scanners"
_COMPOSE = _ROOT / "docker-compose.yml"

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_scanner_image_base_is_pinned_by_digest() -> None:
    from_lines = [ln for ln in _lines(_DOCKERFILE_SCANNERS) if ln.startswith("FROM ")]
    assert from_lines, "Dockerfile.scanners has no FROM line"
    for line in from_lines:
        assert _DIGEST.search(line), f"base image is not digest-pinned: {line!r}"
        assert ":latest" not in line


def test_redis_broker_is_pinned_by_digest() -> None:
    """The broker is a mandatory service, so its image must be digest-pinned."""
    redis_images = [
        ln for ln in _lines(_COMPOSE) if "image:" in ln and "redis" in ln
    ]
    assert redis_images, "no redis image line found in docker-compose.yml"
    for line in redis_images:
        assert _DIGEST.search(line), f"redis image is not digest-pinned: {line!r}"


def test_go_scanner_installs_are_version_pinned_not_latest() -> None:
    """Best-effort scanners keep ``|| true`` but must pin a version, not @latest."""
    go_lines = [ln for ln in _lines(_DOCKERFILE_SCANNERS) if "go install" in ln]
    assert go_lines, "no 'go install' lines found"
    for line in go_lines:
        assert "@latest" not in line, f"go install still tracks @latest: {line.strip()!r}"
        assert re.search(r"@v\d+\.\d+\.\d+", line), f"no pinned version in: {line.strip()!r}"


def test_best_effort_scanner_installs_keep_their_guard() -> None:
    """The design intent — one missing tool must not fail the build — is preserved."""
    go_lines = [ln for ln in _lines(_DOCKERFILE_SCANNERS) if "go install" in ln]
    for line in go_lines:
        assert "|| true" in line, f"best-effort guard removed from: {line.strip()!r}"


@pytest.mark.parametrize("path", [_DOCKERFILE_SCANNERS, _COMPOSE])
def test_pinning_files_exist(path: Path) -> None:
    assert path.is_file()


# --- Container hardening (roadmap §5.3) -------------------------------------- #
#
# Text-based guards (no YAML dependency, matching this file's style) so the
# runtime-safe compose hardening cannot silently regress.


def test_zap_requires_an_api_key_and_never_disables_it() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    assert "api.disablekey=true" not in text, "ZAP API key must not be disabled"
    assert "api.key=${AEGIS_ZAP_API_KEY" in text, "ZAP must require AEGIS_ZAP_API_KEY"


def test_core_services_drop_privileges_and_capabilities() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    assert "no-new-privileges:true" in text, "no-new-privileges must be set"
    assert "cap_drop" in text and '- "ALL"' in text, "capabilities must be dropped"
    # The shared hardening anchor is defined and applied.
    assert "x-hardening: &hardening" in text
    assert "<<: *hardening" in text


def test_compose_defines_a_dedicated_network() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    assert re.search(r"^networks:", text, re.MULTILINE), "no top-level networks block"
    assert "backend:" in text

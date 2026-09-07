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

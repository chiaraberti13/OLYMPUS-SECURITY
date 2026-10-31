"""Unit tests for Argus IP-scope enforcement (CIDR containment)."""

import json
from pathlib import Path

import pytest

from olympus.argus.ip_scope import (
    IpOutOfScopeError,
    IpScopeError,
    enforce_ip_scope,
    load_ip_scope,
)


def _write(path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "engagement": "demo",
        "allowed_networks": ["203.0.113.0/24", "2001:db8::/32"],
        "excluded_networks": ["203.0.113.5/32"],
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_covers_cidr_and_exclusions(tmp_path: Path) -> None:
    scope = load_ip_scope(_write(tmp_path / "s.json"))
    assert scope.covers("203.0.113.10") is True
    assert scope.covers("203.0.113.5") is False  # excluded
    assert scope.covers("198.51.100.1") is False  # not allowed
    assert scope.covers("2001:db8::1") is True


def test_covers_rejects_invalid_ip(tmp_path: Path) -> None:
    scope = load_ip_scope(_write(tmp_path / "s.json"))
    assert scope.covers("not-an-ip") is False


def test_load_missing(tmp_path: Path) -> None:
    with pytest.raises(IpScopeError, match="not found"):
        load_ip_scope(tmp_path / "nope.json")


def test_load_bad_cidr(tmp_path: Path) -> None:
    with pytest.raises(IpScopeError, match="invalid CIDR"):
        load_ip_scope(_write(tmp_path / "s.json", allowed_networks=["not-a-cidr"]))


def test_load_requires_networks(tmp_path: Path) -> None:
    with pytest.raises(IpScopeError, match="no allowed_networks"):
        load_ip_scope(_write(tmp_path / "s.json", allowed_networks=[]))


def test_enforce_blocks_and_logs(tmp_path: Path) -> None:
    scope_path = _write(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    with pytest.raises(IpOutOfScopeError):
        enforce_ip_scope("8.8.8.8", scope_path, log_path)
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["target"] == "8.8.8.8"


def test_enforce_allows(tmp_path: Path) -> None:
    scope_path = _write(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    scope = enforce_ip_scope("203.0.113.10", scope_path, log_path)
    assert scope.engagement == "demo"
    assert not log_path.exists()

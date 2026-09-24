"""Tests for the dedicated MAC/OUI authorization perimeter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.mac_scope import (
    MacOutOfScopeError,
    MacScopeError,
    enforce_mac_scope,
    load_mac_scope,
)


def _write_scope(path: Path, allowed: list[str], excluded: list[str] | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "engagement": "test",
                "allowed_ouis": allowed,
                "excluded_ouis": excluded or [],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_scope_normalizes_ouis_and_matches_mac(tmp_path: Path) -> None:
    scope = load_mac_scope(_write_scope(tmp_path / "scope.json", ["00:1a:2b"]))

    assert scope.allowed_ouis == ("001A2B",)
    assert scope.covers("00-1A-2B-3C-4D-5E")
    assert not scope.covers("00:11:22:33:44:55")


def test_excluded_oui_wins(tmp_path: Path) -> None:
    scope = load_mac_scope(_write_scope(tmp_path / "scope.json", ["00:1A:2B"], ["001A2B"]))

    assert not scope.covers("00:1A:2B:3C:4D:5E")


def test_invalid_scope_is_actionable(tmp_path: Path) -> None:
    path = _write_scope(tmp_path / "scope.json", ["invalid"])

    with pytest.raises(MacScopeError, match="invalid OUI"):
        load_mac_scope(path)


def test_blocked_mac_is_audited(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json", ["00:1A:2B"])
    audit_path = tmp_path / "blocked.log"

    with pytest.raises(MacOutOfScopeError):
        enforce_mac_scope("00:11:22:33:44:55", scope_path, audit_path)

    record = json.loads(audit_path.read_text(encoding="utf-8"))
    assert record["target"] == "00:11:22:33:44:55"
    assert record["action"] == "blocked_out_of_scope"

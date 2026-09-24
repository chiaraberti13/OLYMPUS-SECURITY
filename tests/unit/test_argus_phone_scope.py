"""Unit tests for Argus phone-number scope enforcement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.phone_scope import (
    PhoneOutOfScopeError,
    PhoneScope,
    PhoneScopeError,
    enforce_phone_scope,
    load_phone_scope,
)


def _write_scope(path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "engagement": "demo",
        "allowed_prefixes": ["+1650555", "+39"],
        "excluded_prefixes": [],
    }
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_covers_allows_prefix() -> None:
    scope = PhoneScope(engagement="e", allowed_prefixes=("+1650555",))
    assert scope.covers("+16505550123") is True
    assert scope.covers("+14155550123") is False


def test_covers_excludes_take_precedence() -> None:
    scope = PhoneScope(engagement="e", allowed_prefixes=("+39",), excluded_prefixes=("+3906",))
    assert scope.covers("+393331234567") is True
    assert scope.covers("+390612345678") is False


def test_load_scope_ok(tmp_path: Path) -> None:
    scope = load_phone_scope(_write_scope(tmp_path / "s.json"))
    assert scope.engagement == "demo"
    assert "+39" in scope.allowed_prefixes


def test_load_scope_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PhoneScopeError, match="not found"):
        load_phone_scope(tmp_path / "nope.json")


def test_load_scope_bad_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(PhoneScopeError, match="not valid JSON"):
        load_phone_scope(bad)


def test_load_scope_requires_allowed_prefixes(tmp_path: Path) -> None:
    empty = _write_scope(tmp_path / "e.json", allowed_prefixes=[])
    with pytest.raises(PhoneScopeError, match="no allowed_prefixes"):
        load_phone_scope(empty)


def test_enforce_blocks_and_logs(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    with pytest.raises(PhoneOutOfScopeError):
        enforce_phone_scope("+14155550123", scope_path, log_path)
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["target"] == "+14155550123"
    assert entry["action"] == "blocked_out_of_scope"


def test_enforce_allows_in_scope(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    scope = enforce_phone_scope("+16505550123", scope_path, log_path)
    assert scope.engagement == "demo"
    assert not log_path.exists()

"""Unit tests for Argus account-enumeration scope enforcement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.accounts_scope import (
    AccountOutOfScopeError,
    AccountScope,
    AccountScopeError,
    enforce_account_scope,
    load_account_scope,
)


def _write(path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {"engagement": "demo", "allowed_handles": ["olympus_demo"]}
    data.update(overrides)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_covers_case_insensitive() -> None:
    scope = AccountScope(engagement="e", allowed_handles=("Olympus_Demo",))
    assert scope.covers("olympus_demo") is True
    assert scope.covers("someone_else") is False


def test_load_ok(tmp_path: Path) -> None:
    scope = load_account_scope(_write(tmp_path / "s.json"))
    assert scope.engagement == "demo"


def test_load_missing(tmp_path: Path) -> None:
    with pytest.raises(AccountScopeError, match="not found"):
        load_account_scope(tmp_path / "nope.json")


def test_load_requires_handles(tmp_path: Path) -> None:
    with pytest.raises(AccountScopeError, match="no allowed_handles"):
        load_account_scope(_write(tmp_path / "e.json", allowed_handles=[]))


def test_load_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{nope", encoding="utf-8")
    with pytest.raises(AccountScopeError, match="not valid JSON"):
        load_account_scope(path)


def test_load_not_an_object(tmp_path: Path) -> None:
    path = tmp_path / "list.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(AccountScopeError, match="must contain a JSON object"):
        load_account_scope(path)


def test_load_missing_keys(tmp_path: Path) -> None:
    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"engagement": "x"}), encoding="utf-8")
    with pytest.raises(AccountScopeError, match="must define"):
        load_account_scope(path)


def test_enforce_blocks_and_logs(tmp_path: Path) -> None:
    scope_path = _write(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    with pytest.raises(AccountOutOfScopeError):
        enforce_account_scope("intruder", scope_path, log_path)
    entry = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert entry["target"] == "intruder"


def test_enforce_allows(tmp_path: Path) -> None:
    scope_path = _write(tmp_path / "s.json")
    log_path = tmp_path / "blocked.log"
    scope = enforce_account_scope("olympus_demo", scope_path, log_path)
    assert scope.engagement == "demo"
    assert not log_path.exists()

"""Unit tests for Argus scope enforcement (block + log out-of-scope targets)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.scope import (
    OutOfScopeError,
    ScopeError,
    enforce_scope,
    load_scope,
    log_blocked,
)


def _write_scope(path: Path, **overrides: object) -> Path:
    payload: dict[str, object] = {
        "engagement": "olympus-demo-corp-2026",
        "allowed_domains": ["olympusdemocorp.example"],
        "excluded_domains": ["out.olympusdemocorp.example"],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_scope_reads_valid_file(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    scope = load_scope(scope_path)

    assert scope.engagement == "olympus-demo-corp-2026"
    assert scope.allowed_domains == ("olympusdemocorp.example",)


def test_scope_covers_domain_and_subdomains(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))

    assert scope.covers("olympusdemocorp.example")
    assert scope.covers("mail.olympusdemocorp.example")
    assert not scope.covers("evil.com")


def test_scope_excluded_domain_wins_over_allowed(tmp_path: Path) -> None:
    scope = load_scope(_write_scope(tmp_path / "scope.json"))

    assert not scope.covers("out.olympusdemocorp.example")


def test_load_scope_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="not found"):
        load_scope(tmp_path / "missing.json")


def test_load_scope_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScopeError, match="not valid JSON"):
        load_scope(path)


def test_load_scope_missing_keys_raises(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "x"}), encoding="utf-8")
    with pytest.raises(ScopeError, match="allowed_domains"):
        load_scope(path)


def test_load_scope_empty_allowed_domains_raises(tmp_path: Path) -> None:
    path = _write_scope(tmp_path / "scope.json", allowed_domains=[])
    with pytest.raises(ScopeError, match="no allowed_domains"):
        load_scope(path)


def test_log_blocked_appends_json_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "blocked.log"
    log_blocked("evil.com", tmp_path / "scope.json", log_path)
    log_blocked("evil2.com", tmp_path / "scope.json", log_path)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["domain"] == "evil.com"
    assert first["action"] == "blocked_out_of_scope"


def test_enforce_scope_allows_in_scope_domain(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    scope = enforce_scope("olympusdemocorp.example", scope_path, log_path)

    assert scope.covers("olympusdemocorp.example")
    assert not log_path.exists()


def test_enforce_scope_blocks_and_logs_out_of_scope_domain(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path / "scope.json")
    log_path = tmp_path / "blocked.log"

    with pytest.raises(OutOfScopeError) as excinfo:
        enforce_scope("evil.com", scope_path, log_path)

    assert excinfo.value.domain == "evil.com"
    assert log_path.exists()
    entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert entry["domain"] == "evil.com"

"""Tests for Artemis URL scope enforcement without network activity."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis.scope import OutOfScopeError, ScopeError, enforce_scope
from olympus.cli import app

runner = CliRunner()


def _scope(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "allowed_origins": ["https://portal.olympusdemocorp.example:443"],
                "allowed_path_prefixes": ["/app"],
                "allowed_ip_networks": ["192.0.2.0/24", "2001:db8::/32"],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_scope_canonicalizes_and_authorizes_segment_path(tmp_path: Path) -> None:
    approved = enforce_scope(
        "HTTPS://PORTAL.OLYMPUSDEMOCORP.EXAMPLE/app/../app/login#fragment",
        _scope(tmp_path / "scope.json"),
        tmp_path / "blocked.log",
    )

    assert approved.url == "https://portal.olympusdemocorp.example/app/login"
    assert approved.origin == "https://portal.olympusdemocorp.example"


def test_scope_blocks_similar_path_and_redacts_query_from_log(tmp_path: Path) -> None:
    log = tmp_path / "blocked.log"
    with pytest.raises(OutOfScopeError):
        enforce_scope(
            "https://portal.olympusdemocorp.example/application?token=synthetic-secret",
            _scope(tmp_path / "scope.json"),
            log,
        )

    audit = log.read_text(encoding="utf-8")
    assert "application" in audit
    assert "token" not in audit
    assert "synthetic-secret" not in audit


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@portal.olympusdemocorp.example/app",
        "https://portal.olympusdemocorp.example/%2e%2e/admin",
        "https://portal.olympusdemocorp.example/app\\admin",
        "https://portal.olympusdemocorp.example/app\nadmin",
    ],
)
def test_scope_rejects_unsafe_or_invalid_urls(url: str, tmp_path: Path) -> None:
    with pytest.raises((ScopeError, OutOfScopeError)):
        enforce_scope(url, _scope(tmp_path / "scope.json"), tmp_path / "blocked.log")


def test_cli_block_and_demo_are_network_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = _scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"
    blocked = runner.invoke(
        app,
        [
            "artemis",
            "check-scope",
            "--url",
            "https://outside.example/app",
            "--scope",
            str(scope),
            "--log",
            str(log),
        ],
    )
    assert blocked.exit_code == 3
    assert "out of scope" in blocked.output

    authorized = runner.invoke(
        app,
        [
            "artemis",
            "check-scope",
            "--url",
            "https://portal.olympusdemocorp.example/app/login",
            "--scope",
            str(scope),
            "--log",
            str(log),
        ],
    )
    assert authorized.exit_code == 0
    assert "no network request performed" in authorized.stdout

"""Unit and CLI tests for Argus passive web recon."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.web import (
    WebReconError,
    build_web_asset,
    build_web_findings,
    export_web_intel,
    fetch_web,
    host_of,
    normalize_url,
)
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()


class _Http:
    def __init__(self, headers: dict[str, str] | None = None, raise_error: bool = False) -> None:
        self._headers = headers or {}
        self._raise = raise_error

    @classmethod
    def from_config(
        cls,
        *,
        min_interval: float | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: Callable[[str], tuple[str, ...]] | None = None,
    ) -> _Http:
        return cls({"Server": "nginx"})

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._raise:
            raise HttpRequestError("unreachable")
        return HttpResponse(status_code=200, headers=self._headers, body="")


def test_normalize_and_host() -> None:
    assert normalize_url("example.com").startswith("https://")
    assert host_of("http://example.com/path") == "example.com"


def test_host_of_invalid() -> None:
    with pytest.raises(WebReconError):
        host_of("http://")


def test_fetch_web_reports_headers() -> None:
    http = _Http({"Server": "nginx", "Content-Security-Policy": "default-src 'self'"})
    report = fetch_web("example.com", http)
    assert report.host == "example.com"
    assert report.server == "nginx"
    assert "Content-Security-Policy" in report.security_headers_present
    assert "X-Frame-Options" in report.security_headers_missing
    assert report.to_dict()["status_code"] == 200


def test_fetch_web_error() -> None:
    with pytest.raises(WebReconError):
        fetch_web("example.com", _Http(raise_error=True))


def test_build_asset_and_findings() -> None:
    report = fetch_web("example.com", _Http({"Server": "nginx"}))
    asset = build_web_asset(report)
    assert asset.metadata["server"] == "nginx"
    findings = build_web_findings(asset.asset_id, report)
    titles = {f.title for f in findings}
    assert any("security header" in t for t in titles)
    assert "Server banner disclosed" in titles


def test_no_server_banner_finding() -> None:
    all_headers = dict.fromkeys(
        (
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ),
        "x",
    )
    report = fetch_web("example.com", _Http(all_headers))
    assert build_web_findings("AST-1", report) == []


def test_export(tmp_path: Path) -> None:
    from olympus.argus.web import WebIntel

    report = fetch_web("example.com", _Http({"Server": "nginx"}))
    intel = WebIntel(report=report, asset=build_web_asset(report), findings=[])
    out = tmp_path / "web.json"
    export_web_intel(intel, out)
    assert json.loads(out.read_text())["report"]["host"] == "example.com"


def _scope(tmp_path: Path, domain: str = "example.com") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "t", "allowed_domains": [domain]}), encoding="utf-8")
    return path


def test_cli_in_scope_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    out = tmp_path / "web.json"
    result = runner.invoke(
        app,
        [
            "argus",
            "web",
            "--url",
            "https://example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
            "--output",
            str(out),
        ],
    )
    # Missing security headers -> findings -> exit code 1.
    assert result.exit_code == 1, result.output
    assert out.exists()


def test_cli_out_of_scope(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        [
            "argus",
            "web",
            "--url",
            "https://evil.test",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_cli_bad_url(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["argus", "web", "--url", "http://", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 2


def test_cli_scope_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["argus", "web", "--url", "https://example.com", "--scope", str(tmp_path / "no.json")]
    )
    assert result.exit_code == 2


class _BrokenHttp:
    @classmethod
    def from_config(
        cls,
        *,
        min_interval: float | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: Callable[[str], tuple[str, ...]] | None = None,
    ) -> _BrokenHttp:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        raise HttpRequestError("unreachable")


class _RedirectHttp:
    def __init__(self, redirect_validator: Callable[[str], None]) -> None:
        self._redirect_validator = redirect_validator

    @classmethod
    def from_config(
        cls,
        *,
        min_interval: float | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: Callable[[str], tuple[str, ...]] | None = None,
    ) -> _RedirectHttp:
        assert redirect_validator is not None
        return cls(redirect_validator)

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self._redirect_validator("http://127.0.0.1/admin")
        raise AssertionError("a rejected redirect must not be followed")


def test_cli_blocks_and_audits_out_of_scope_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _RedirectHttp)
    log = tmp_path / "redirect-blocked.log"

    result = runner.invoke(
        app,
        [
            "argus",
            "web",
            "--url",
            "https://example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
        ],
    )

    assert result.exit_code == 3
    assert "127.0.0.1" in log.read_text(encoding="utf-8")


def test_cli_unreachable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _BrokenHttp)
    result = runner.invoke(
        app, ["argus", "web", "--url", "https://example.com", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 4

"""CLI-level tests for `olympus artemis xss` (transport is stubbed)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.artemis.xss import MARKER
from olympus.cli import app

runner = CliRunner()

URL = "https://portal.olympusdemocorp.example/app/search?q=x"


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _ReflectingTransport:
    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        body = f"<html><h1>Results for {MARKER}</h1></html>".encode()
        return HttpResponse(url, 200, {"content-type": "text/html"}, body)


def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _ReflectingTransport)


def test_xss_requires_authorization() -> None:
    result = runner.invoke(app, ["artemis", "xss", "--url", URL])
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_xss_flags_reflected_param(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    out = tmp_path / "findings.json"
    # --param omitted: every query parameter (here 'q') is tested.
    result = runner.invoke(
        app, ["artemis", "xss", "--url", URL, "--i-am-authorized", "--output", str(out)]
    )
    # Uniform across every Artemis command: findings exit 1, not 0.
    assert result.exit_code == 1, result.output
    assert "status=findings" in result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_xss_probe_failure_exits_failed_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Broken:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del url, addresses, timeout, max_bytes
            raise HttpClientError("connection reset by peer")

    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Broken)
    out = tmp_path / "findings.json"

    result = runner.invoke(
        app, ["artemis", "xss", "--url", URL, "--i-am-authorized", "--output", str(out)]
    )

    assert result.exit_code == 6, result.output
    assert "status=failed" in result.output
    assert json.loads(out.read_text(encoding="utf-8")) == []


def test_xss_no_param_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    result = runner.invoke(
        app,
        [
            "artemis",
            "xss",
            "--url",
            "https://portal.olympusdemocorp.example/app/x",
            "--i-am-authorized",
        ],
    )
    assert result.exit_code == 2
    assert "no query parameter" in result.output

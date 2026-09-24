"""CLI-level tests for `olympus artemis metabase` (transport is stubbed)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.cli import app

runner = CliRunner()

URL = "https://metabase.olympusdemocorp.example"


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if url.endswith("/api/session/properties"):
            body = b'{"version": {"tag": "v0.60.10"}, "engine": "metabase"}'
            return HttpResponse(url, 200, {"content-type": "application/json"}, body)
        return HttpResponse(url, 405, {}, b"")


def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Transport)


def test_metabase_requires_authorization() -> None:
    result = runner.invoke(app, ["artemis", "metabase", "--url", URL])
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_metabase_flags_affected_instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app, ["artemis", "metabase", "--url", URL, "--i-am-authorized", "--output", str(out)]
    )
    assert result.exit_code == 1, result.output
    assert "status=findings" in result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert "CVE-2026-72898" in findings[0]["title"]


def test_metabase_unreachable_target_exits_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreachable instance must not exit 0 the way a patched one does."""

    class _Broken:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del url, addresses, timeout, max_bytes
            raise HttpClientError("no route to host")

    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Broken)

    result = runner.invoke(app, ["artemis", "metabase", "--url", URL, "--i-am-authorized"])

    assert result.exit_code == 6, result.output
    assert "status=failed" in result.output

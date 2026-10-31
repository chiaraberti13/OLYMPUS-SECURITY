"""Tests for Artemis passive technology fingerprinting (from a fetched response)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.fingerprint import (
    SIGNATURES,
    Fingerprint,
    fingerprint_response,
    fingerprints_to_findings,
)
from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.cli import app

runner = CliRunner()

URL = "https://portal.olympusdemocorp.example/app"


def _response(headers: dict[str, str], body: bytes = b"") -> HttpResponse:
    return HttpResponse(URL, 200, headers, body)


def test_identifies_server_and_version_from_headers() -> None:
    response = _response({"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2.1"})
    products = {fp.product: fp.version for fp in fingerprint_response(response)}
    assert products["nginx"] == "1.25.3"
    assert products["PHP"] == "8.2.1"


def test_identifies_cms_from_body_generator() -> None:
    body = b'<html><meta name="generator" content="WordPress 6.5.2"><div class="wp-content">'
    matches = fingerprint_response(_response({"Server": "Apache/2.4.58"}, body))
    products = {fp.product: fp.version for fp in matches}
    assert products["WordPress"] == "6.5.2"
    assert products["Apache httpd"] == "2.4.58"


def test_no_false_positive_on_empty_response() -> None:
    assert fingerprint_response(_response({}, b"")) == []


def test_waf_detected_without_version() -> None:
    matches = fingerprint_response(_response({"Server": "cloudflare"}))
    assert matches == [
        Fingerprint(
            product="Cloudflare",
            category="waf-cdn",
            version=None,
            evidence="matched on server",
            references=(),
        )
    ]


def test_every_signature_declares_at_least_one_marker() -> None:
    for sig in SIGNATURES:
        assert sig.header is not None or sig.body is not None, sig.product


def test_findings_are_informational_and_bound_to_asset() -> None:
    matches = fingerprint_response(_response({"Server": "nginx/1.25.3"}))
    findings = fingerprints_to_findings("AST-9", URL, matches)
    assert findings[0].severity.value == "info"
    assert findings[0].asset_id == "AST-9"
    assert "nginx 1.25.3" in findings[0].title


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        return HttpResponse(url, 200, {"Server": "nginx/1.25.3", "X-Powered-By": "Express"}, b"")


class _HostileTransport:
    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del url, addresses, timeout, max_bytes
        raise HttpClientError("reset\x1b[2J\nforged diagnostic")


def test_cli_fingerprint_reports_detected_stack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Transport)
    out = tmp_path / "fp.json"
    result = runner.invoke(
        app,
        [
            "artemis",
            "fingerprint",
            "--url",
            URL,
            "--i-am-authorized",
            "--output",
            str(out),
        ],
    )
    # Fingerprints are findings, so this exits 1 like every other Artemis command.
    assert result.exit_code == 1, result.output
    assert "status=findings" in result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    products = {f["title"] for f in findings}
    assert any("nginx" in p for p in products)
    assert any("Express" in p for p in products)


def test_cli_fingerprint_sanitizes_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _HostileTransport)
    result = runner.invoke(
        app,
        ["artemis", "fingerprint", "--url", URL, "--i-am-authorized"],
    )

    assert result.exit_code == 6, result.output
    assert "\x1b" not in result.output
    assert "\nforged diagnostic" not in result.output
    assert "fingerprint failed: reset[2J forged diagnostic" in result.output


def test_cli_fingerprint_blocks_out_of_scope(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "artemis",
            "fingerprint",
            "--url",
            "https://evil.example/app",
            "--i-am-authorized",
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )
    # An out-of-scope target is exit 3, never conflated with a usage error.
    assert result.exit_code == 3
    assert "out of scope" in result.output


def test_cli_fingerprint_requires_explicit_authorization() -> None:
    result = runner.invoke(app, ["artemis", "fingerprint", "--url", URL])
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output

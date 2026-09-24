from __future__ import annotations

import json
import urllib.request

from typer.testing import CliRunner

from olympus.cli import app


class _Response:
    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *args):  # type: ignore[no-untyped-def]
        return None

    def read(self) -> bytes:
        return b'{"job_id":"AEGIS-00000000000000000000000000000000"}'


def test_scan_client_submits_to_native_api(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: int):  # type: ignore[no-untyped-def]
        captured["request"] = request
        captured["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = CliRunner().invoke(
        app,
        [
            "aegis",
            "scan",
            "--scanner",
            "nmap",
            "--target",
            "example.com",
            "--kind",
            "domain",
            "--scope-id",
            "customer-1",
            "--i-am-authorized",
        ],
        env={"OLYMPUS_AEGIS_API_KEY": "k" * 32},
    )
    assert result.exit_code == 0, result.output
    request = captured["request"]
    assert isinstance(request, urllib.request.Request)
    assert request.full_url == "http://127.0.0.1:8443/api/v1/jobs"
    assert request.get_header("X-olympus-api-key") == "k" * 32
    assert json.loads(request.data or b"{}")["scope_id"] == "customer-1"
    assert captured["timeout"] == 15


def test_scan_client_requires_authorization_secret_and_remote_tls() -> None:
    runner = CliRunner()
    base = [
        "aegis",
        "scan",
        "--scanner",
        "nmap",
        "--target",
        "example.com",
        "--scope-id",
        "customer-1",
    ]
    denied = runner.invoke(app, base)
    assert denied.exit_code == 4
    missing = runner.invoke(app, [*base, "--i-am-authorized"])
    assert missing.exit_code == 2
    remote = runner.invoke(
        app,
        [*base, "--i-am-authorized", "--url", "http://api.example.com"],
        env={"OLYMPUS_AEGIS_API_KEY": "k" * 32},
    )
    assert remote.exit_code == 2
    assert "require HTTPS" in remote.output

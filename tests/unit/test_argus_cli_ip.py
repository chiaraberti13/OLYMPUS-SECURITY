"""CLI-level tests for `olympus argus ip`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.cli import app
from olympus.core.http import HttpResponse

runner = CliRunner()


class _GeoClient:
    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _GeoClient:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        body = json.dumps(
            {
                "success": True,
                "country": "Italy",
                "connection": {"org": "DemoVPN", "asn": 1},
                "security": {"proxy": True, "hosting": False},
            }
        )
        return HttpResponse(status_code=200, headers={}, body=body)


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "ip-scope.json"
    path.write_text(
        json.dumps({"engagement": "t", "allowed_networks": ["203.0.113.0/24"]}), encoding="utf-8"
    )
    return path


def test_ip_offline_in_scope(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["argus", "ip", "--ip", "203.0.113.10", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["asset"]["asset_type"] == "ip"


def test_ip_out_of_scope_blocks(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        ["argus", "ip", "--ip", "8.8.8.8", "--scope", str(_scope(tmp_path)), "--log", str(log)],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_ip_parse_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["argus", "ip", "--ip", "nope", "--scope", str(_scope(tmp_path))])
    assert result.exit_code == 2


def test_ip_requires_ip_or_input(tmp_path: Path) -> None:
    result = runner.invoke(app, ["argus", "ip", "--scope", str(_scope(tmp_path))])
    assert result.exit_code == 2
    assert "exactly one" in result.output


def test_ip_geo_requires_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["argus", "ip", "--ip", "203.0.113.10", "--scope", str(_scope(tmp_path)), "--geo"]
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_ip_geo_with_fake_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _GeoClient)
    result = runner.invoke(
        app,
        [
            "argus",
            "ip",
            "--ip",
            "203.0.113.10",
            "--scope",
            str(_scope(tmp_path)),
            "--geo",
            "--i-am-authorized",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["asset"]["metadata"]["country"] == "Italy"
    assert payload["geo"]["asn"] == "AS1"
    assert any("proxy/VPN" in f["title"] for f in payload["findings"])


def test_ip_batch_skips_invalid_and_out_of_scope(tmp_path: Path) -> None:
    ips = tmp_path / "ips.txt"
    ips.write_text("203.0.113.1\nnot-an-ip\n8.8.8.8\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "argus",
            "ip",
            "--input",
            str(ips),
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.find("[") : result.output.rfind("]") + 1])
    assert len(payload) == 1
    assert "skipping invalid IP" in result.output
    assert "skipping out-of-scope IP" in result.output

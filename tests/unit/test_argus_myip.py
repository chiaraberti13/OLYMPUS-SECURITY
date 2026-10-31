"""Unit and CLI tests for Argus public-IP discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.myip import MyIpError, build_result, discover, discover_public_ip, export_myip
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()


class _Http:
    def __init__(self, ip: str | None = "203.0.113.7", geo_ok: bool = True) -> None:
        self._ip = ip
        self._geo_ok = geo_ok

    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "ipwho.is" in url:
            if not self._geo_ok:
                raise HttpRequestError("geo down")
            body = json.dumps({"success": True, "country": "Nowhere"})
            return HttpResponse(status_code=200, headers={}, body=body)
        if self._ip is None:
            return HttpResponse(status_code=500, headers={}, body="")
        return HttpResponse(status_code=200, headers={}, body=json.dumps({"ip": self._ip}))


class _BrokenHttp:
    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _BrokenHttp:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        raise HttpRequestError("all down")


def test_discover_public_ip() -> None:
    assert discover_public_ip(_Http()) == "203.0.113.7"


def test_discover_public_ip_all_fail() -> None:
    with pytest.raises(MyIpError):
        discover_public_ip(_BrokenHttp())


def test_discover_public_ip_bad_json() -> None:
    class _BadJson:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            return HttpResponse(status_code=200, headers={}, body="not json")

    with pytest.raises(MyIpError):
        discover_public_ip(_BadJson())


def test_discover_without_geo() -> None:
    result = discover(_Http(), geolocate=False)
    assert result.public_ip == "203.0.113.7"
    assert result.intel is None
    assert result.to_dict()["intel"] is None


def test_build_result_without_geo_is_network_independent() -> None:
    result = build_result("203.0.113.7")

    assert result.public_ip == "203.0.113.7"
    assert result.intel is None


def test_discover_with_geo() -> None:
    result = discover(_Http(), geolocate=True)
    assert result.intel is not None
    assert result.intel.report.ip == "203.0.113.7"


def test_discover_with_geo_failure_still_returns() -> None:
    result = discover(_Http(geo_ok=False), geolocate=True)
    assert result.intel is not None  # classification survives geo failure


def test_export(tmp_path: Path) -> None:
    result = discover(_Http(), geolocate=False)
    out = tmp_path / "myip.json"
    export_myip(result, out)
    assert json.loads(out.read_text())["public_ip"] == "203.0.113.7"


def test_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    result = runner.invoke(app, ["argus", "myip"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["public_ip"] == "203.0.113.7"


def test_cli_geo_and_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    out = tmp_path / "myip.json"
    result = runner.invoke(app, ["argus", "myip", "--geo", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_cli_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _BrokenHttp)
    result = runner.invoke(app, ["argus", "myip"])
    assert result.exit_code == 4

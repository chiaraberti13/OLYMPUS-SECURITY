"""Unit and CLI tests for Argus RDAP/WHOIS lookups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.whois import (
    WhoisError,
    build_whois_asset,
    export_whois_report,
    lookup_domain,
)
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()

_RDAP_BODY = json.dumps(
    {
        "ldhName": "example.com",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Demo Registrar"]],
                ],
            }
        ],
        "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}],
        "secureDNS": {"delegationSigned": True},
    }
)


class _Http:
    def __init__(
        self, status: int = 200, body: str = _RDAP_BODY, raise_error: bool = False
    ) -> None:
        self._status = status
        self._body = body
        self._raise = raise_error

    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._raise:
            raise HttpRequestError("down")
        return HttpResponse(status_code=self._status, headers={}, body=self._body)


def test_lookup_domain_parses_record() -> None:
    report = lookup_domain("example.com", _Http())
    assert report.registrar == "Demo Registrar"
    assert report.registered is not None and report.registered.startswith("1995")
    assert report.expires is not None and report.expires.startswith("2027")
    assert report.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert report.dnssec is True
    assert report.to_dict()["status"] == ["active"]


def test_lookup_registrar_handle_fallback() -> None:
    body = json.dumps({"ldhName": "x.com", "entities": [{"roles": ["registrar"], "handle": "H1"}]})
    report = lookup_domain("x.com", _Http(body=body))
    assert report.registrar == "H1"


def test_lookup_not_found() -> None:
    with pytest.raises(WhoisError):
        lookup_domain("example.com", _Http(status=404))


def test_lookup_server_error() -> None:
    with pytest.raises(WhoisError):
        lookup_domain("example.com", _Http(status=500))


def test_lookup_non_json() -> None:
    with pytest.raises(WhoisError):
        lookup_domain("example.com", _Http(body="<html>"))


def test_lookup_network_error() -> None:
    with pytest.raises(WhoisError):
        lookup_domain("example.com", _Http(raise_error=True))


def test_build_asset() -> None:
    report = lookup_domain("example.com", _Http())
    asset = build_whois_asset(report)
    assert asset.metadata["registrar"] == "Demo Registrar"
    assert asset.metadata["dnssec"] == "true"


def test_export(tmp_path: Path) -> None:
    report = lookup_domain("example.com", _Http())
    out = tmp_path / "whois.json"
    export_whois_report(report, build_whois_asset(report), out)
    assert json.loads(out.read_text())["report"]["domain"] == "example.com"


def _scope(tmp_path: Path, domain: str = "example.com") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "t", "allowed_domains": [domain]}), encoding="utf-8")
    return path


def test_cli_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    out = tmp_path / "whois.json"
    result = runner.invoke(
        app,
        [
            "argus",
            "whois",
            "--domain",
            "example.com",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_cli_out_of_scope(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        [
            "argus",
            "whois",
            "--domain",
            "evil.test",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_cli_scope_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["argus", "whois", "--domain", "example.com", "--scope", str(tmp_path / "no.json")]
    )
    assert result.exit_code == 2


def test_cli_lookup_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _NotFound(_Http):
        @classmethod
        def from_config(cls, *, min_interval: float | None = None) -> _NotFound:
            return cls(status=404)

    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _NotFound)
    result = runner.invoke(
        app, ["argus", "whois", "--domain", "example.com", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 4

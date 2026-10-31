"""Unit and CLI tests for Argus MAC-address analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.mac import (
    MacIntel,
    MacParseError,
    analyze_mac,
    build_mac_asset,
    build_mac_findings,
    export_mac_intel,
    is_valid_mac,
    lookup_vendor,
)
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()


class _Http:
    def __init__(
        self, status: int = 200, body: str = "Cisco Systems", raise_error: bool = False
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


def test_is_valid_mac() -> None:
    assert is_valid_mac("aa:bb:cc:dd:ee:ff")
    assert is_valid_mac("AABBCCDDEEFF")
    assert not is_valid_mac("aa:bb:cc")


def test_analyze_universal_mac() -> None:
    report = analyze_mac("00:1a:2b:3c:4d:5e")
    assert report.mac == "00:1A:2B:3C:4D:5E"
    assert report.oui == "00:1A:2B"
    assert report.locally_administered is False
    assert report.multicast is False
    assert report.to_dict()["oui"] == "00:1A:2B"


def test_analyze_local_and_multicast_bits() -> None:
    report = analyze_mac("03-00-00-00-00-00")
    assert report.locally_administered is True
    assert report.multicast is True


def test_analyze_rejects_invalid() -> None:
    with pytest.raises(MacParseError):
        analyze_mac("zz")


def test_lookup_vendor_paths() -> None:
    report = analyze_mac("00:1a:2b:3c:4d:5e")
    assert lookup_vendor(report, _Http(status=200, body="Cisco")) == "Cisco"
    assert lookup_vendor(report, _Http(status=404, body="")) is None
    assert lookup_vendor(report, _Http(status=200, body="  ")) is None
    assert lookup_vendor(report, _Http(raise_error=True)) is None


def test_build_asset_and_findings() -> None:
    report = analyze_mac("02:00:00:00:00:01")
    asset = build_mac_asset(report, "Acme")
    assert asset.metadata["vendor"] == "Acme"
    findings = build_mac_findings(asset.asset_id, report)
    assert findings and findings[0].title == "Locally administered MAC address"


def test_no_finding_for_universal() -> None:
    report = analyze_mac("00:1a:2b:3c:4d:5e")
    assert build_mac_findings("AST-1", report) == []


def test_export(tmp_path: Path) -> None:
    report = analyze_mac("00:1a:2b:3c:4d:5e")
    intel = MacIntel(report=report, asset=build_mac_asset(report), vendor=None, findings=[])
    out = tmp_path / "mac.json"
    export_mac_intel(intel, out)
    assert json.loads(out.read_text())["report"]["mac"] == "00:1A:2B:3C:4D:5E"


def test_cli_offline() -> None:
    result = runner.invoke(app, ["argus", "mac", "--mac", "00:1a:2b:3c:4d:5e"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["report"]["oui"] == "00:1A:2B"


def test_cli_invalid() -> None:
    result = runner.invoke(app, ["argus", "mac", "--mac", "nope"])
    assert result.exit_code == 2


def test_cli_vendor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    out = tmp_path / "mac.json"
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps({"engagement": "test", "allowed_ouis": ["00:1A:2B"]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "argus",
            "mac",
            "--mac",
            "00:1a:2b:3c:4d:5e",
            "--vendor",
            "--i-am-authorized",
            "--scope",
            str(scope),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["vendor"] == "Cisco Systems"


def test_cli_vendor_requires_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)

    result = runner.invoke(app, ["argus", "mac", "--mac", "00:1a:2b:3c:4d:5e", "--vendor"])

    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_cli_vendor_blocks_out_of_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps({"engagement": "test", "allowed_ouis": ["00:1A:2B"]}),
        encoding="utf-8",
    )
    audit = tmp_path / "blocked.log"

    result = runner.invoke(
        app,
        [
            "argus",
            "mac",
            "--mac",
            "00:11:22:33:44:55",
            "--vendor",
            "--i-am-authorized",
            "--scope",
            str(scope),
            "--log",
            str(audit),
        ],
    )

    assert result.exit_code == 3
    assert "00:11:22:33:44:55" in audit.read_text(encoding="utf-8")

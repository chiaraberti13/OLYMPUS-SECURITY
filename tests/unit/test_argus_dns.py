"""Unit and CLI tests for Argus DoH DNS enumeration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.dns_records import (
    DnsRecordError,
    build_dns_asset,
    export_dns_report,
    normalize_domain,
    resolve_records,
)
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()


class _Http:
    """Cloudflare answers A/AAAA; Google is never needed."""

    def __init__(self, *, cloudflare_down: bool = False, both_down: bool = False) -> None:
        self._cf_down = cloudflare_down
        self._both_down = both_down

    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._both_down:
            raise HttpRequestError("down")
        is_cloudflare = "cloudflare" in url
        if is_cloudflare and self._cf_down:
            return HttpResponse(status_code=500, headers={}, body="")
        answer = []
        if "type=A&" in url or url.endswith("type=A"):
            answer = [{"data": "203.0.113.9"}]
        return HttpResponse(status_code=200, headers={}, body=json.dumps({"Answer": answer}))


def test_normalize_domain() -> None:
    assert normalize_domain("https://Example.com/path") == "example.com"
    with pytest.raises(DnsRecordError):
        normalize_domain("no-dot")


def test_resolve_records() -> None:
    report = resolve_records("example.com", _Http(), record_types=("A", "MX"))
    assert report.records["A"] == ["203.0.113.9"]
    assert "MX" not in report.records  # empty answers are omitted
    assert report.to_dict()["domain"] == "example.com"


def test_resolve_records_google_fallback() -> None:
    report = resolve_records("example.com", _Http(cloudflare_down=True), record_types=("A",))
    assert report.records["A"] == ["203.0.113.9"]


def test_resolve_records_all_providers_down() -> None:
    with pytest.raises(DnsRecordError):
        resolve_records("example.com", _Http(both_down=True), record_types=("A",))


def test_build_asset() -> None:
    report = resolve_records("example.com", _Http(), record_types=("A",))
    asset = build_dns_asset(report)
    assert "203.0.113.9" in asset.ip_addresses
    assert asset.metadata["record_types"] == "A"


def test_export(tmp_path: Path) -> None:
    report = resolve_records("example.com", _Http(), record_types=("A",))
    out = tmp_path / "dns.json"
    export_dns_report(report, build_dns_asset(report), out)
    assert json.loads(out.read_text())["report"]["domain"] == "example.com"


def _scope(tmp_path: Path, domain: str = "example.com") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "t", "allowed_domains": [domain]}), encoding="utf-8")
    return path


def test_cli_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    out = tmp_path / "dns.json"
    result = runner.invoke(
        app,
        [
            "argus",
            "dns",
            "--domain",
            "example.com",
            "--types",
            "A",
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


def test_cli_default_types(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    result = runner.invoke(
        app, ["argus", "dns", "--domain", "example.com", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 0, result.output


def test_cli_out_of_scope(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        [
            "argus",
            "dns",
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
        app, ["argus", "dns", "--domain", "example.com", "--scope", str(tmp_path / "no.json")]
    )
    assert result.exit_code == 2


def test_cli_provider_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Down(_Http):
        @classmethod
        def from_config(cls, *, min_interval: float | None = None) -> _Down:
            return cls(both_down=True)

    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Down)
    result = runner.invoke(
        app, ["argus", "dns", "--domain", "example.com", "--scope", str(_scope(tmp_path))]
    )
    assert result.exit_code == 4

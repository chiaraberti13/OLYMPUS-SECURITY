"""Unit and CLI tests for Argus email OSINT."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.email_osint import (
    EmailEnrichment,
    EmailParseError,
    analyze_email,
    build_email_asset,
    build_email_findings,
    enrich_email,
    export_email_intel,
    is_valid_email,
)
from olympus.argus.resolver import DnsResolutionError
from olympus.cli import app
from olympus.core.http import HttpRequestError, HttpResponse

runner = CliRunner()


class _Resolver:
    def __init__(self, records: list[str] | None = None, raise_error: bool = False) -> None:
        self._records = records or []
        self._raise = raise_error

    def resolve(self, name: str, record_type: str) -> list[str]:
        if self._raise:
            raise DnsResolutionError("boom")
        return self._records


class _Http:
    def __init__(self, status: int = 200, raise_error: bool = False) -> None:
        self._status = status
        self._raise = raise_error

    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._raise:
            raise HttpRequestError("network down")
        return HttpResponse(status_code=self._status, headers={}, body="")


def test_is_valid_email() -> None:
    assert is_valid_email("a@b.co")
    assert not is_valid_email("nope")
    assert not is_valid_email("a@b")


def test_analyze_email_parses_parts() -> None:
    report = analyze_email("  Alice@Example.COM ")
    assert report.email == "alice@example.com"
    assert report.local_part == "alice"
    assert report.domain == "example.com"
    assert report.gravatar_url.startswith("https://www.gravatar.com/avatar/")
    assert report.to_dict()["sha256"] == report.sha256


def test_analyze_email_rejects_invalid() -> None:
    with pytest.raises(EmailParseError):
        analyze_email("not-an-email")


def test_enrich_email_success() -> None:
    report = analyze_email("bob@example.com")
    enrichment = enrich_email(report, _Resolver(["10 mx.example.com"]), _Http(status=200))
    assert enrichment.domain_has_mx is True
    assert enrichment.gravatar_exists is True
    assert enrichment.to_dict()["gravatar_exists"] is True


def test_enrich_email_handles_failures() -> None:
    report = analyze_email("bob@example.com")
    enrichment = enrich_email(report, _Resolver(raise_error=True), _Http(raise_error=True))
    assert enrichment.domain_has_mx is None
    assert enrichment.gravatar_exists is None


def test_findings_flag_missing_mx_and_avatar() -> None:
    report = analyze_email("bob@example.com")
    asset = build_email_asset(report, EmailEnrichment(domain_has_mx=False, gravatar_exists=True))
    assert asset.metadata["domain_has_mx"] == "false"
    findings = build_email_findings(
        asset.asset_id, report, EmailEnrichment(domain_has_mx=False, gravatar_exists=True)
    )
    titles = {f.title for f in findings}
    assert "Email domain cannot receive mail" in titles
    assert "Public Gravatar avatar exists for the address" in titles


def test_findings_empty_without_enrichment() -> None:
    report = analyze_email("bob@example.com")
    assert build_email_findings("AST-1", report, None) == []


def test_export_email_intel(tmp_path: Path) -> None:
    report = analyze_email("bob@example.com")
    asset = build_email_asset(report)
    from olympus.argus.email_osint import EmailIntel

    intel = EmailIntel(report=report, asset=asset, enrichment=None, findings=[])
    out = tmp_path / "sub" / "email.json"
    export_email_intel(intel, out)
    assert json.loads(out.read_text())["report"]["email"] == "bob@example.com"


def _scope(tmp_path: Path, domain: str = "example.com") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"engagement": "t", "allowed_domains": [domain]}), encoding="utf-8")
    return path


def test_cli_offline_ok() -> None:
    result = runner.invoke(app, ["argus", "email", "--email", "a@b.co"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["report"]["domain"] == "b.co"


def test_cli_invalid_email() -> None:
    result = runner.invoke(app, ["argus", "email", "--email", "nope"])
    assert result.exit_code == 2


def test_cli_enrich_requires_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "email",
            "--email",
            "a@example.com",
            "--enrich",
            "--scope",
            str(_scope(tmp_path)),
        ],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_cli_enrich_out_of_scope(tmp_path: Path) -> None:
    log = tmp_path / "log"
    result = runner.invoke(
        app,
        [
            "argus",
            "email",
            "--email",
            "a@evil.test",
            "--enrich",
            "--i-am-authorized",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_cli_enrich_scope_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "email",
            "--email",
            "a@example.com",
            "--enrich",
            "--i-am-authorized",
            "--scope",
            str(tmp_path / "missing.json"),
        ],
    )
    assert result.exit_code == 2


def test_cli_enrich_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)
    monkeypatch.setattr(argus_cli, "DnspythonResolver", lambda: _Resolver(["10 mx"]))
    out = tmp_path / "email.json"
    result = runner.invoke(
        app,
        [
            "argus",
            "email",
            "--email",
            "a@example.com",
            "--enrich",
            "--i-am-authorized",
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

"""Tests for Argus CDN/WAF fronting detection + origin-leak self-assessment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.argus.fronting import (
    CDN_RANGES,
    assess_fronting,
    classify_ip,
    report_to_asset,
    report_to_findings,
)
from olympus.cli import app
from olympus.core.enums import Severity

runner = CliRunner()

DOMAIN = "olympusdemocorp.example"
CF_IP = "104.16.10.20"  # inside Cloudflare's published 104.16.0.0/13
ORIGIN_IP = "45.55.10.20"  # globally routable, outside every bundled CDN range


class _Resolver:
    """Offline resolver: apex is fronted, one CT subdomain leaks a bare origin."""

    def resolve(self, name: str, record_type: str) -> list[str]:
        lowered = name.lower()
        if lowered == DOMAIN and record_type == "A":
            return [CF_IP]
        if lowered == f"origin.{DOMAIN}" and record_type == "A":
            return [ORIGIN_IP]
        if lowered == f"cdn.{DOMAIN}" and record_type == "A":
            return [CF_IP]
        return []


class _CtClient:
    def discover(self, domain: str) -> list[str]:
        return [f"origin.{domain}", f"cdn.{domain}", domain]


def test_classify_ip_matches_known_cdn_and_rejects_others() -> None:
    assert classify_ip(CF_IP) == "Cloudflare"
    assert classify_ip(ORIGIN_IP) is None
    assert classify_ip("not-an-ip") is None


def test_cdn_ranges_are_valid_networks() -> None:
    import ipaddress

    for cidrs in CDN_RANGES.values():
        for cidr in cidrs:
            ipaddress.ip_network(cidr)  # must not raise


def test_assess_detects_fronting_and_flags_only_the_leak() -> None:
    report = assess_fronting(DOMAIN, _Resolver(), _CtClient())

    assert report.fronted is True
    assert report.providers == ("Cloudflare",)
    # cdn.* stays inside Cloudflare and is NOT a leak; origin.* is the only leak.
    assert [leak.ip for leak in report.origin_leaks] == [ORIGIN_IP]
    assert report.origin_leaks[0].source == f"origin.{DOMAIN}"


def test_no_leak_scan_when_apex_is_not_fronted() -> None:
    class _Direct:
        def resolve(self, name: str, record_type: str) -> list[str]:
            return [ORIGIN_IP] if name.lower() == DOMAIN and record_type == "A" else []

    report = assess_fronting(DOMAIN, _Direct(), _CtClient())
    assert report.fronted is False
    assert report.origin_leaks == ()  # CT subdomains are never resolved when not fronted


def test_private_ips_are_never_reported_as_leaks() -> None:
    class _PrivateLeak:
        def resolve(self, name: str, record_type: str) -> list[str]:
            if name.lower() == DOMAIN and record_type == "A":
                return [CF_IP]
            if name.lower() == f"origin.{DOMAIN}" and record_type == "A":
                return ["10.0.0.5"]  # RFC1918, not a real exposure
            return []

    report = assess_fronting(DOMAIN, _PrivateLeak(), _CtClient())
    assert report.fronted is True
    assert report.origin_leaks == ()


def test_findings_carry_severities_and_asset_metadata() -> None:
    report = assess_fronting(DOMAIN, _Resolver(), _CtClient())
    asset = report_to_asset(report, "AST-1")
    findings = report_to_findings(report, "AST-1")

    assert asset.metadata["fronted"] == "true"
    assert "Cloudflare" in asset.metadata["cdn_providers"]
    severities = {f.severity for f in findings}
    assert Severity.INFO in severities  # fronting note
    assert Severity.MEDIUM in severities  # origin leak
    assert all(f.asset_id == "AST-1" for f in findings)


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps({"engagement": "olympus-demo-corp-2026", "allowed_domains": [DOMAIN]}),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def _stub(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "DnspythonResolver", _Resolver)
    monkeypatch.setattr(argus_cli, "CrtShClient", _CtClient)


def test_cli_fronting_flags_leak_with_exit_1(tmp_path: Path, _stub: None) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    output = tmp_path / "fronting.json"
    result = runner.invoke(
        app,
        [
            "argus",
            "fronting",
            "--domain",
            DOMAIN,
            "--scope",
            str(scope),
            "--log",
            str(tmp_path / "blocked.log"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 1, result.output  # a leak was found
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["fronted"] is True
    assert payload["cdn_providers"] == ["Cloudflare"]
    assert any("origin-IP leak" in f["title"] for f in payload["findings"])


def test_cli_fronting_blocks_out_of_scope(tmp_path: Path, _stub: None) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"
    result = runner.invoke(
        app,
        [
            "argus",
            "fronting",
            "--domain",
            "evil.example",
            "--scope",
            str(scope),
            "--log",
            str(log),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()  # the blocked attempt is audited

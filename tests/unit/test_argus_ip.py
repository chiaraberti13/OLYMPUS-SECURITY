"""Unit tests for Argus IP OSINT (offline core + geolocation adapter)."""

import json

import pytest

from olympus.argus.ip_osint import (
    IpApiClient,
    IpGeo,
    IpGeoError,
    IpParseError,
    IpWhoisClient,
    analyze_ip,
    build_ip_asset,
    build_ip_findings,
)
from olympus.core.enums import AssetType, Severity
from olympus.core.http import HttpRequestError, HttpResponse


class _FakeClient:
    def __init__(self, *, body: str = "", error: bool = False, status: int = 200) -> None:
        self._body = body
        self._error = error
        self._status = status
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        if self._error:
            raise HttpRequestError("boom")
        return HttpResponse(status_code=self._status, headers={}, body=self._body)


def test_analyze_global_ipv4() -> None:
    report = analyze_ip("1.1.1.1")
    assert report.version == 4
    assert report.is_global is True
    assert report.kind == "global"


def test_analyze_private_and_loopback() -> None:
    assert analyze_ip("10.0.0.1").kind == "private"
    assert analyze_ip("127.0.0.1").kind == "loopback"
    assert analyze_ip("::1").kind == "loopback"


def test_analyze_invalid_raises() -> None:
    with pytest.raises(IpParseError):
        analyze_ip("not-an-ip")


def test_build_asset_carries_geo_metadata() -> None:
    report = analyze_ip("1.1.1.1")
    geo = IpGeo(country="Australia", isp="Cloudflare", asn="AS13335")
    asset = build_ip_asset(report, geo)
    assert asset.asset_type is AssetType.IP
    assert asset.metadata["country"] == "Australia"
    assert asset.metadata["asn"] == "AS13335"


def test_findings_flag_non_global() -> None:
    findings = build_ip_findings("AST-1", analyze_ip("10.0.0.1"))
    assert findings[0].severity is Severity.INFO
    assert "Non-routable" in findings[0].title


def test_findings_flag_proxy_hosting() -> None:
    report = analyze_ip("1.1.1.1")
    geo = IpGeo(org="DemoVPN", is_proxy=True, is_hosting=True, asn="AS1")
    findings = build_ip_findings("AST-1", report, geo)
    assert any("proxy/VPN, hosting" in f.title for f in findings)


def test_geolocate_success() -> None:
    body = json.dumps(
        {
            "success": True,
            "country": "Italy",
            "region": "Lazio",
            "city": "Rome",
            "connection": {"isp": "DemoISP", "org": "DemoOrg", "asn": 64500},
            "security": {"proxy": False, "hosting": True},
        }
    )
    http = _FakeClient(body=body)
    geo = IpWhoisClient(http).geolocate("1.1.1.1")
    assert geo.country == "Italy"
    assert geo.asn == "AS64500"
    assert geo.is_hosting is True
    assert http.calls == ["https://ipwho.is/1.1.1.1"]
    assert IpApiClient is IpWhoisClient


def test_geolocate_status_fail_raises() -> None:
    body = json.dumps({"success": False, "message": "reserved range"})
    with pytest.raises(IpGeoError, match="reserved range"):
        IpWhoisClient(_FakeClient(body=body)).geolocate("10.0.0.1")


def test_geolocate_bad_json_raises() -> None:
    with pytest.raises(IpGeoError, match="non-JSON"):
        IpWhoisClient(_FakeClient(body="<html>")).geolocate("1.1.1.1")


def test_geolocate_network_error_wrapped() -> None:
    with pytest.raises(IpGeoError, match="request failed"):
        IpWhoisClient(_FakeClient(error=True)).geolocate("1.1.1.1")


def test_geolocate_non_success_http_is_explicit() -> None:
    with pytest.raises(IpGeoError, match="HTTP 429"):
        IpWhoisClient(_FakeClient(body="{}", status=429)).geolocate("1.1.1.1")

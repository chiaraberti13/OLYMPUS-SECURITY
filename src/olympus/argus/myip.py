"""Discover the operator's own public IP address.

Unlike the other Argus lookups, ``myip`` concerns the operator's *own* egress
address rather than a third-party target, so no engagement scope applies. It
asks a small set of public "what is my IP" providers through the shared
injected :class:`~olympus.core.http.HttpClient` (offline in tests) and returns
the first address any provider reports. Optional geolocation reuses the Argus
IP-OSINT path to classify and, if requested, enrich that address.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from olympus.argus.ip_osint import (
    IpGeo,
    IpGeoError,
    IpIntel,
    IpWhoisClient,
    analyze_ip,
    build_ip_asset,
    build_ip_findings,
)
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError

#: Public providers that return a JSON body containing an ``ip`` field.
PROVIDERS = (
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://api64.ipify.org?format=json",
)


class MyIpError(RuntimeError):
    """Raised when no provider could report the public IP address."""


def discover_public_ip(http: HttpClient, providers: tuple[str, ...] = PROVIDERS) -> str:
    """Return the operator's public IP from the first responsive provider."""
    for url in providers:
        try:
            response = http.get(url)
        except HttpRequestError:
            continue
        if response.status_code != 200:
            continue
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("ip"):
            return str(data["ip"])
    raise MyIpError("could not determine public IP from any provider")


@dataclass(frozen=True)
class MyIpResult:
    """The discovered public IP and optional geo/asset/finding enrichment."""

    public_ip: str
    intel: IpIntel | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the result."""
        return {
            "public_ip": self.public_ip,
            "intel": self.intel.to_dict() if self.intel else None,
        }


def build_result(public_ip: str, geo_http: HttpClient | None = None) -> MyIpResult:
    """Build the result for a discovered address, optionally enriching it."""
    if geo_http is None:
        return MyIpResult(public_ip=public_ip)

    report = analyze_ip(public_ip)
    geo: IpGeo | None = None
    try:
        geo = IpWhoisClient(geo_http).geolocate(report.ip)
    except IpGeoError:
        geo = None
    asset = build_ip_asset(report, geo)
    findings = build_ip_findings(asset.asset_id, report, geo)
    intel = IpIntel(report=report, asset=asset, geo=geo, findings=findings)
    return MyIpResult(public_ip=public_ip, intel=intel)


def discover(http: HttpClient, *, geolocate: bool = False) -> MyIpResult:
    """Backward-compatible discovery using one HTTP adapter for both stages."""
    public_ip = discover_public_ip(http)
    return build_result(public_ip, http if geolocate else None)


def export_myip(result: MyIpResult, path: Path) -> None:
    """Write a ``myip`` result as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(result.to_dict(), indent=2, sort_keys=True), mode=0o600
    )

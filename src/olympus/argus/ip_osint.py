"""IP-address OSINT for Argus: offline classification + opt-in geolocation.

The offline core validates and classifies an IP entirely with the standard
library — no network, no key. Optional geolocation/ASN enrichment (which does
call a third party) is layered on top behind a protocol, so tests inject an
offline double. This is the coherent, non-destructive slice of the GhostTrack
concept: passive intelligence on an address, never active probing of the host.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import quote

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset, Finding


class IpParseError(ValueError):
    """Raised when the input is not a valid IP address."""


class IpGeoError(RuntimeError):
    """Raised when a geolocation lookup fails (network, bad payload...)."""


@dataclass(frozen=True)
class IpReport:
    """Offline classification of a single IP address."""

    ip: str
    version: int
    is_global: bool
    is_private: bool
    kind: str  # global | private | loopback | link_local | multicast | reserved | unspecified

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "ip": self.ip,
            "version": self.version,
            "is_global": self.is_global,
            "is_private": self.is_private,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class IpGeo:
    """Geolocation/ASN enrichment for an IP address."""

    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_proxy: bool = False
    is_hosting: bool = False


class IpGeoClient(Protocol):
    """Anything able to geolocate an IP address."""

    def geolocate(self, ip: str) -> IpGeo:
        """Return geolocation for ``ip`` (raises :class:`IpGeoError` on failure)."""
        ...


class IpWhoisClient:
    """Real, keyless geolocation via the encrypted ipwho.is endpoint."""

    _ENDPOINT = "https://ipwho.is"

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def geolocate(self, ip: str) -> IpGeo:
        """Geolocate ``ip`` and normalize the documented nested response."""
        try:
            response = self._client.get(f"{self._ENDPOINT}/{quote(ip)}")
        except HttpRequestError as exc:
            raise IpGeoError(f"geolocation request failed: {exc}") from exc
        if response.status_code != 200:
            raise IpGeoError(f"geolocation returned HTTP {response.status_code}")
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise IpGeoError(f"geolocation returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise IpGeoError("geolocation returned an unexpected payload")
        if data.get("success") is not True:
            raise IpGeoError(f"geolocation failed: {data.get('message', 'unknown error')}")
        connection = data.get("connection")
        if not isinstance(connection, dict):
            connection = {}
        security = data.get("security")
        if not isinstance(security, dict):
            security = {}
        asn_value = str(connection.get("asn", ""))
        if asn_value and not asn_value.upper().startswith("AS"):
            asn_value = f"AS{asn_value}"
        return IpGeo(
            country=str(data.get("country", "")),
            region=str(data.get("region", "")),
            city=str(data.get("city", "")),
            isp=str(connection.get("isp", "")),
            org=str(connection.get("org", "")),
            asn=asn_value,
            is_proxy=bool(
                security.get("proxy", False)
                or security.get("vpn", False)
                or security.get("tor", False)
            ),
            is_hosting=bool(security.get("hosting", False)),
        )


# Compatibility for callers importing the historical class name. The runtime
# provider is ipwho.is; no request is sent to the former plaintext endpoint.
IpApiClient = IpWhoisClient


def analyze_ip(raw_ip: str) -> IpReport:
    """Validate and classify ``raw_ip`` entirely offline."""
    try:
        address = ipaddress.ip_address(raw_ip.strip())
    except ValueError as exc:
        raise IpParseError(f"not a valid IP address: {raw_ip!r}") from exc

    if address.is_loopback:
        kind = "loopback"
    elif address.is_link_local:
        kind = "link_local"
    elif address.is_multicast:
        kind = "multicast"
    elif address.is_unspecified:
        kind = "unspecified"
    elif address.is_private:
        kind = "private"
    elif address.is_global:
        kind = "global"
    else:
        kind = "reserved"

    return IpReport(
        ip=str(address),
        version=address.version,
        is_global=address.is_global,
        is_private=address.is_private,
        kind=kind,
    )


def build_ip_asset(report: IpReport, geo: IpGeo | None = None) -> Asset:
    """Convert an :class:`IpReport` (+ optional geo) into a `core.Asset`."""
    metadata: dict[str, str] = {"version": str(report.version), "kind": report.kind}
    if geo is not None:
        for key, value in (
            ("country", geo.country), ("region", geo.region), ("city", geo.city),
            ("isp", geo.isp), ("org", geo.org), ("asn", geo.asn),
        ):
            if value:
                metadata[key] = value
    return Asset(
        asset_type=AssetType.IP,
        hostname=report.ip,
        ip_addresses=[report.ip],
        source=Source.ARGUS,
        tags=["argus", "ip-osint"],
        metadata=metadata,
    )


def build_ip_findings(asset_id: str, report: IpReport, geo: IpGeo | None = None) -> list[Finding]:
    """Derive findings from the offline report plus any opt-in geo data."""
    findings: list[Finding] = []
    if not report.is_global:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title=f"Non-routable IP ({report.kind})",
                description="The address is not a globally routable public IP.",
                severity=Severity.INFO,
                evidence=[f"kind={report.kind}", f"ip={report.ip}"],
            )
        )
    if geo is not None and (geo.is_proxy or geo.is_hosting):
        labels = ", ".join(
            label for label, flag in (("proxy/VPN", geo.is_proxy), ("hosting", geo.is_hosting))
            if flag
        )
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title=f"IP flagged as {labels}",
                description=(
                    f"Third-party intelligence classifies this address as {labels} "
                    f"({geo.org or geo.isp or 'unknown network'}), relevant when triaging "
                    "connections during an authorized investigation."
                ),
                severity=Severity.LOW,
                evidence=[f"asn={geo.asn}", f"proxy={geo.is_proxy}", f"hosting={geo.is_hosting}"],
            )
        )
    return findings


@dataclass(frozen=True)
class IpIntel:
    """Bundle of everything Argus learned about one IP, for export."""

    report: IpReport
    asset: Asset
    geo: IpGeo | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "report": self.report.to_dict(),
            "asset": json.loads(self.asset.model_dump_json()),
            "geo": (
                {
                    "country": self.geo.country,
                    "region": self.geo.region,
                    "city": self.geo.city,
                    "isp": self.geo.isp,
                    "org": self.geo.org,
                    "asn": self.geo.asn,
                    "is_proxy": self.geo.is_proxy,
                    "is_hosting": self.geo.is_hosting,
                }
                if self.geo is not None
                else None
            ),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_ip_intel(intel: IpIntel, path: Path) -> None:
    """Write an IP-intel bundle (report + asset + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )

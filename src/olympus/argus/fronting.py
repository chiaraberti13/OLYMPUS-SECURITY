"""Passive CDN/WAF fronting detection and origin-leak self-assessment.

Inspired by CloudFail's premise — a misconfigured domain can leak the origin
IP that hides behind a CDN/WAF — but rebuilt as a strictly *defensive* check.
It answers one question for an **authorized** domain: "is this domain fronted
by a CDN, and does any public record leak an IP that sits outside that CDN's
ranges?"

Unlike the tool that inspired it, this module:

* uses only passive, public data (DNS answers and Certificate Transparency
  subdomains that Argus already collects) — it never brute-forces guessed
  subdomains, never queries origin-exposing databases, and never uses Tor or
  any other evasion;
* never connects to a discovered candidate origin — it only *reports* the
  leak so the owner can fix the misconfiguration.

The bundled CDN ranges are a curated, published subset (not exhaustive); an
IP outside them is reported as a *candidate* leak to review, never as proof.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from olympus.argus.ct import CertificateTransparencyClient
from olympus.argus.resolver import DnsResolver
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Asset, Finding

# Curated, published CDN/WAF network ranges (a maintained subset, not
# exhaustive). Sourced from each provider's public IP-range documentation.
CDN_RANGES: dict[str, tuple[str, ...]] = {
    "Cloudflare": (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ),
    "Fastly": (
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "146.75.0.0/16",
        "151.101.0.0/16",
        "199.232.0.0/16",
    ),
    "Amazon CloudFront": (
        "13.32.0.0/15",
        "52.84.0.0/15",
        "54.182.0.0/16",
        "54.192.0.0/16",
        "204.246.164.0/22",
        "205.251.192.0/19",
    ),
    "Akamai": (
        "23.0.0.0/12",
        "23.192.0.0/11",
        "104.64.0.0/10",
        "184.24.0.0/13",
        "2.16.0.0/13",
    ),
}


def _networks() -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Return the flattened (provider, network) list, parsed once per call."""
    parsed: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for provider, cidrs in CDN_RANGES.items():
        for cidr in cidrs:
            parsed.append((provider, ipaddress.ip_network(cidr)))
    return parsed


def classify_ip(ip: str) -> str | None:
    """Return the CDN provider that owns ``ip``, or ``None`` if none does."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, network in _networks():
        if address.version == network.version and address in network:
            return provider
    return None


def _is_public(ip: str) -> bool:
    """Return ``True`` for a globally routable address (skip private/reserved)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@dataclass(frozen=True)
class OriginLeak:
    """A public IP found outside every known CDN range while the apex is fronted."""

    ip: str
    source: str  # the record/subdomain the IP was found on


@dataclass(frozen=True)
class FrontingReport:
    """Result of a passive fronting/origin-leak assessment for one domain."""

    domain: str
    providers: tuple[str, ...] = ()
    apex_ips: tuple[str, ...] = ()
    origin_leaks: tuple[OriginLeak, ...] = ()
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def fronted(self) -> bool:
        """Return ``True`` if the apex resolves into a known CDN/WAF range."""
        return bool(self.providers)


def assess_fronting(
    domain: str,
    resolver: DnsResolver,
    ct_client: CertificateTransparencyClient | None = None,
    *,
    max_subdomains: int = 50,
) -> FrontingReport:
    """Passively assess CDN fronting and candidate origin leaks for ``domain``.

    Resolves the apex A/AAAA records and classifies them against known CDN
    ranges. When the apex is fronted, each Certificate-Transparency subdomain
    (already public, never guessed) is resolved once; any globally routable
    address outside every known CDN range is reported as a *candidate* origin
    leak. ``max_subdomains`` bounds the passive fan-out for politeness.
    """
    apex_ips = tuple(resolver.resolve(domain, "A") + resolver.resolve(domain, "AAAA"))
    providers = tuple(sorted({p for ip in apex_ips if (p := classify_ip(ip)) is not None}))

    leaks: list[OriginLeak] = []
    if providers and ct_client is not None:
        subdomains = [s for s in ct_client.discover(domain) if s != domain][:max_subdomains]
        seen: set[str] = set()
        for subdomain in subdomains:
            for ip in resolver.resolve(subdomain, "A") + resolver.resolve(subdomain, "AAAA"):
                if ip in seen:
                    continue
                seen.add(ip)
                if _is_public(ip) and classify_ip(ip) is None:
                    leaks.append(OriginLeak(ip=ip, source=subdomain))

    return FrontingReport(
        domain=domain,
        providers=providers,
        apex_ips=apex_ips,
        origin_leaks=tuple(leaks),
    )


def report_to_asset(report: FrontingReport, asset_id: str) -> Asset:
    """Build a ``core.Asset`` describing the assessed domain."""
    return Asset(
        asset_id=asset_id,
        asset_type=AssetType.DOMAIN,
        hostname=report.domain,
        source=Source.ARGUS,
        ip_addresses=list(report.apex_ips),
        tags=["fronting", *(p.lower().replace(" ", "-") for p in report.providers)],
        metadata={
            "fronted": "true" if report.fronted else "false",
            "cdn_providers": ", ".join(report.providers) if report.providers else "none",
        },
    )


def report_to_findings(report: FrontingReport, asset_id: str) -> list[Finding]:
    """Derive findings: an informational fronting note plus any origin leaks."""
    findings: list[Finding] = []
    if report.fronted:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title=f"Domain fronted by {', '.join(report.providers)}",
                description=(
                    f"{report.domain} resolves into published CDN/WAF ranges "
                    f"({', '.join(report.providers)}), so the origin is not directly exposed "
                    "on the apex record."
                ),
                severity=Severity.INFO,
                evidence=[f"apex A/AAAA: {', '.join(report.apex_ips)}"],
            )
        )
    for leak in report.origin_leaks:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Candidate origin-IP leak behind CDN/WAF",
                description=(
                    f"Subdomain {leak.source} resolves to {leak.ip}, a public address outside "
                    "every known CDN/WAF range while the apex is fronted. Review whether this "
                    "record exposes the protected origin."
                ),
                severity=Severity.MEDIUM,
                evidence=[f"{leak.source} -> {leak.ip}"],
                remediation=(
                    "Route the leaking subdomain through the same CDN/WAF, or restrict the "
                    "origin firewall to accept traffic only from the CDN's published ranges."
                ),
                references=["https://developers.cloudflare.com/fundamentals/get-started/"],
            )
        )
    return findings


def export_fronting(
    report: FrontingReport, asset: Asset, findings: list[Finding], output: Path
) -> None:
    """Write the fronting asset + findings atomically as a versioned JSON document."""
    payload = {
        "schema_name": "olympus.argus-fronting",
        "schema_version": "1.0.0",
        "domain": report.domain,
        "fronted": report.fronted,
        "cdn_providers": list(report.providers),
        "asset": asset.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    atomic_write_text(
        output, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=0o600
    )

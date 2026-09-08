"""Domain registration intelligence for Argus over RDAP.

RDAP (Registration Data Access Protocol) is the structured successor to WHOIS.
Argus queries ``rdap.org``, which redirects to the authoritative registry,
through the shared injected :class:`~olympus.core.http.HttpClient` — no key,
offline in tests. It returns the registrar, key lifecycle dates, name servers,
status flags, and DNSSEC delegation.

The lookup resolves the target's registration data, so the caller must enforce
the engagement scope (see :func:`olympus.argus.scope.enforce_scope`) before
invoking :func:`lookup_domain`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from olympus.argus.dns_records import normalize_domain
from olympus.core.enums import AssetType, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset

_RDAP_URL = "https://rdap.org/domain/{domain}"

#: The only host an RDAP lookup ever contacts (see ``RESOLVER_HOSTS``).
RDAP_HOSTS = ("rdap.org",)


class WhoisError(RuntimeError):
    """Raised when the registry lookup fails or the domain is not registered."""


def _extract_events(events: list[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for event in events or []:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str) and isinstance(date, str):
            out[action] = date
    return out


def _extract_registrar(entities: list[Any]) -> str | None:
    for entity in entities or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    return str(field[3])
        handle = entity.get("handle")
        return str(handle) if handle is not None else None
    return None


@dataclass(frozen=True)
class WhoisReport:
    """RDAP registration data for a single domain."""

    domain: str
    registrar: str | None
    status: list[str]
    registered: str | None
    expires: str | None
    last_changed: str | None
    nameservers: list[str]
    dnssec: bool | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "status": self.status,
            "registered": self.registered,
            "expires": self.expires,
            "last_changed": self.last_changed,
            "nameservers": self.nameservers,
            "dnssec": self.dnssec,
        }


def lookup_domain(raw_domain: str, http: HttpClient) -> WhoisReport:
    """Query RDAP for ``raw_domain`` and normalize the registration record."""
    domain = normalize_domain(raw_domain)
    try:
        response = http.get(
            _RDAP_URL.format(domain=quote(domain)),
            headers={"Accept": "application/rdap+json"},
        )
    except HttpRequestError as exc:
        raise WhoisError(f"RDAP request failed for {domain}: {exc}") from exc

    if response.status_code == 404:
        raise WhoisError(f"domain not found or not registered: {domain}")
    if response.status_code != 200:
        raise WhoisError(f"registry returned status {response.status_code} for {domain}")
    try:
        data = json.loads(response.body)
    except json.JSONDecodeError as exc:
        raise WhoisError(f"registry returned a non-JSON response for {domain}") from exc
    if not isinstance(data, dict):
        raise WhoisError(f"registry returned an unexpected payload for {domain}")

    events = _extract_events(data.get("events", []))
    nameservers = [
        str(ns["ldhName"])
        for ns in data.get("nameservers", []) or []
        if isinstance(ns, dict) and ns.get("ldhName")
    ]
    secure_dns = data.get("secureDNS")
    dnssec = secure_dns.get("delegationSigned") if isinstance(secure_dns, dict) else None
    status = [str(item) for item in data.get("status", []) or []]
    return WhoisReport(
        domain=str(data.get("ldhName", domain)),
        registrar=_extract_registrar(data.get("entities", [])),
        status=status,
        registered=events.get("registration"),
        expires=events.get("expiration"),
        last_changed=events.get("last changed") or events.get("last update of RDAP database"),
        nameservers=nameservers,
        dnssec=dnssec if isinstance(dnssec, bool) else None,
    )


def build_whois_asset(report: WhoisReport) -> Asset:
    """Convert a :class:`WhoisReport` into a ``core.Asset``."""
    metadata: dict[str, str] = {}
    if report.registrar:
        metadata["registrar"] = report.registrar
    if report.expires:
        metadata["expires"] = report.expires
    if report.dnssec is not None:
        metadata["dnssec"] = str(report.dnssec).lower()
    return Asset(
        asset_type=AssetType.DOMAIN,
        hostname=report.domain,
        source=Source.ARGUS,
        tags=["argus", "whois", "rdap"],
        metadata=metadata,
    )


def export_whois_report(report: WhoisReport, asset: Asset, path: Path) -> None:
    """Write a WHOIS report (registration + asset) as JSON to ``path``."""
    payload = {"report": report.to_dict(), "asset": json.loads(asset.model_dump_json())}
    atomic_write_text(
        path, json.dumps(payload, indent=2, sort_keys=True), mode=0o600
    )

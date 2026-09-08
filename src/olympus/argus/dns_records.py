"""DNS record enumeration for Argus over DNS-over-HTTPS (DoH).

Queries Cloudflare's DoH JSON API with a Google fallback through the shared
injected :class:`~olympus.core.http.HttpClient`, so the lookup needs no extra
resolver dependency, works where UDP/53 is blocked, and stays offline in
tests. It resolves the record types commonly used in infrastructure mapping.

The lookup actively resolves the target's zone, so the caller must enforce the
engagement scope (see :func:`olympus.argus.scope.enforce_scope`) before
invoking :func:`resolve_records`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from olympus.core.enums import AssetType, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset

_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
_GOOGLE = "https://dns.google/resolve"

#: The only hosts a DoH lookup ever contacts. Exported so callers can pin the
#: transport to them instead of trusting whatever a URL happens to say.
RESOLVER_HOSTS = ("cloudflare-dns.com", "dns.google")

#: Record types queried by default, in a stable order.
RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


class DnsRecordError(RuntimeError):
    """Raised when no provider returns any answer for the domain."""


def normalize_domain(raw_domain: str) -> str:
    """Return the bare domain of ``raw_domain`` (strip any scheme/path)."""
    domain = raw_domain.strip().lower().strip(".")
    if "//" in domain:
        domain = domain.split("//", 1)[1]
    domain = domain.split("/", 1)[0]
    if "." not in domain or " " in domain:
        raise DnsRecordError(f"{raw_domain!r} does not look like a domain name")
    return domain


def _query(http: HttpClient, base: str, domain: str, record_type: str) -> list[str] | None:
    """Return the answer data for one record type, or ``None`` on provider error."""
    url = f"{base}?name={quote(domain)}&type={quote(record_type)}"
    try:
        response = http.get(url, headers={"Accept": "application/dns-json"})
    except HttpRequestError:
        return None
    if response.status_code != 200:
        return None
    try:
        data = json.loads(response.body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    answers: list[str] = []
    for answer in data.get("Answer", []) or []:
        if isinstance(answer, dict) and answer.get("data") is not None:
            answers.append(str(answer["data"]))
    return answers


@dataclass(frozen=True)
class DnsRecordReport:
    """DoH-resolved records for a single domain."""

    domain: str
    records: dict[str, list[str]]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {"domain": self.domain, "records": self.records}


def resolve_records(
    raw_domain: str,
    http: HttpClient,
    record_types: tuple[str, ...] = RECORD_TYPES,
) -> DnsRecordReport:
    """Resolve ``record_types`` for ``raw_domain`` via DoH (Cloudflare, then Google)."""
    domain = normalize_domain(raw_domain)
    records: dict[str, list[str]] = {}
    reachable = False
    for record_type in record_types:
        answers = _query(http, _CLOUDFLARE, domain, record_type)
        if answers is None:
            answers = _query(http, _GOOGLE, domain, record_type)
        if answers is None:
            continue
        reachable = True
        if answers:
            records[record_type] = answers
    if not reachable:
        raise DnsRecordError(f"no DoH provider could be reached for {domain}")
    return DnsRecordReport(domain=domain, records=records)


def build_dns_asset(report: DnsRecordReport) -> Asset:
    """Convert a :class:`DnsRecordReport` into a ``core.Asset``."""
    ip_addresses = [*report.records.get("A", []), *report.records.get("AAAA", [])]
    return Asset(
        asset_type=AssetType.DOMAIN,
        hostname=report.domain,
        ip_addresses=ip_addresses,
        source=Source.ARGUS,
        tags=["argus", "dns"],
        metadata={"record_types": ",".join(sorted(report.records))},
    )


def export_dns_report(report: DnsRecordReport, asset: Asset, path: Path) -> None:
    """Write a DNS report (records + asset) as JSON to ``path``."""
    payload = {"report": report.to_dict(), "asset": json.loads(asset.model_dump_json())}
    atomic_write_text(
        path, json.dumps(payload, indent=2, sort_keys=True), mode=0o600
    )

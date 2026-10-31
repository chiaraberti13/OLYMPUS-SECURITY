"""Passive DNS reconnaissance.

Resolves A/AAAA/MX/TXT records for a domain and derives its SPF/DMARC email
security posture. Purely passive: only standard DNS queries, no active
probing of the target's infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from olympus.argus.ct import CertificateTransparencyClient
from olympus.argus.resolver import DnsResolver


@dataclass(frozen=True)
class DomainRecon:
    """Passive DNS snapshot of a single domain at a point in time."""

    domain: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    subdomains: list[str] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this recon snapshot."""
        return {
            "domain": self.domain,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "mx_records": self.mx_records,
            "txt_records": self.txt_records,
            "spf": self.spf,
            "dmarc": self.dmarc,
            "subdomains": self.subdomains,
            "scanned_at": self.scanned_at.isoformat(),
        }


def _find_spf(txt_records: list[str]) -> str | None:
    """Return the SPF record among ``txt_records``, if any."""
    for record in txt_records:
        if record.strip().lower().startswith("v=spf1"):
            return record
    return None


def _find_dmarc(dmarc_txt_records: list[str]) -> str | None:
    """Return the DMARC record among ``_dmarc`` TXT answers, if any."""
    for record in dmarc_txt_records:
        if record.strip().lower().startswith("v=dmarc1"):
            return record
    return None


def scan_domain(
    domain: str,
    resolver: DnsResolver,
    ct_client: CertificateTransparencyClient | None = None,
) -> DomainRecon:
    """Run a passive DNS/MX/SPF/DMARC recon pass against ``domain``."""
    a_records = resolver.resolve(domain, "A")
    aaaa_records = resolver.resolve(domain, "AAAA")
    mx_records = resolver.resolve(domain, "MX")
    txt_records = resolver.resolve(domain, "TXT")
    dmarc_txt_records = resolver.resolve(f"_dmarc.{domain}", "TXT")

    return DomainRecon(
        domain=domain,
        a_records=a_records,
        aaaa_records=aaaa_records,
        mx_records=mx_records,
        txt_records=txt_records,
        spf=_find_spf(txt_records),
        dmarc=_find_dmarc(dmarc_txt_records),
        subdomains=ct_client.discover(domain) if ct_client is not None else [],
    )

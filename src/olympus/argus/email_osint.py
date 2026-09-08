"""Passive, privacy-respecting email OSINT for Argus.

The offline core validates an address, splits its parts, and derives the
public Gravatar URL from the address hash — no network, no key. Opt-in
enrichment layers two passive checks on top, both behind injected ports so
tests stay offline and deterministic:

* whether the domain can receive mail at all (an MX lookup through the shared
  :class:`~olympus.argus.resolver.DnsResolver`);
* whether a public Gravatar avatar actually exists for the address (an HTTP
  ``GET`` through the shared :class:`~olympus.core.http.HttpClient`).

It deliberately never probes a mailbox over SMTP or queries a breach database:
those are active or credentialed techniques out of scope for a passive module.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from olympus.argus.resolver import DnsResolutionError, DnsResolver
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset, Finding

#: Pragmatic, deliberately conservative address syntax check.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: Gravatar's public avatar endpoint; ``d=404`` makes "no avatar" observable.
_GRAVATAR_URL = "https://www.gravatar.com/avatar/{md5}?d=404"


class EmailParseError(ValueError):
    """Raised when the input is not a syntactically valid email address."""


def is_valid_email(value: str) -> bool:
    """Return ``True`` if ``value`` is a syntactically plausible email address."""
    return bool(_EMAIL_RE.match(value.strip()))


@dataclass(frozen=True)
class EmailReport:
    """Offline analysis of a single email address."""

    email: str
    local_part: str
    domain: str
    md5: str
    sha256: str
    gravatar_url: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "email": self.email,
            "local_part": self.local_part,
            "domain": self.domain,
            "md5": self.md5,
            "sha256": self.sha256,
            "gravatar_url": self.gravatar_url,
        }


@dataclass(frozen=True)
class EmailEnrichment:
    """Opt-in passive enrichment: mail deliverability and avatar presence."""

    domain_has_mx: bool | None = None
    gravatar_exists: bool | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the enrichment."""
        return {"domain_has_mx": self.domain_has_mx, "gravatar_exists": self.gravatar_exists}


def analyze_email(raw_email: str) -> EmailReport:
    """Validate ``raw_email`` and derive its offline attributes."""
    email = raw_email.strip().lower()
    if not is_valid_email(email):
        raise EmailParseError(f"not a valid email address: {raw_email!r}")
    local, _, domain = email.partition("@")
    # Gravatar keys avatars on the MD5 of the address; it is not used as a
    # security primitive here, only to reproduce the public avatar URL.
    md5 = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324
    sha256 = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return EmailReport(
        email=email,
        local_part=local,
        domain=domain,
        md5=md5,
        sha256=sha256,
        gravatar_url=_GRAVATAR_URL.format(md5=md5),
    )


def enrich_email(
    report: EmailReport,
    resolver: DnsResolver,
    http: HttpClient,
) -> EmailEnrichment:
    """Run the two passive, opt-in checks for ``report`` (best effort)."""
    try:
        domain_has_mx: bool | None = bool(resolver.resolve(report.domain, "MX"))
    except DnsResolutionError:
        domain_has_mx = None

    try:
        response = http.get(report.gravatar_url)
        gravatar_exists: bool | None = response.status_code == 200
    except HttpRequestError:
        gravatar_exists = None

    return EmailEnrichment(domain_has_mx=domain_has_mx, gravatar_exists=gravatar_exists)


def build_email_asset(report: EmailReport, enrichment: EmailEnrichment | None = None) -> Asset:
    """Convert an :class:`EmailReport` (+ optional enrichment) into a ``core.Asset``."""
    metadata: dict[str, str] = {"domain": report.domain, "sha256": report.sha256}
    if enrichment is not None:
        if enrichment.domain_has_mx is not None:
            metadata["domain_has_mx"] = str(enrichment.domain_has_mx).lower()
        if enrichment.gravatar_exists is not None:
            metadata["gravatar_exists"] = str(enrichment.gravatar_exists).lower()
    return Asset(
        asset_type=AssetType.ACCOUNT,
        hostname=report.email,
        source=Source.ARGUS,
        tags=["argus", "email-osint"],
        metadata=metadata,
    )


def build_email_findings(
    asset_id: str,
    report: EmailReport,
    enrichment: EmailEnrichment | None = None,
) -> list[Finding]:
    """Derive findings from the enrichment (none from the offline report alone)."""
    findings: list[Finding] = []
    if enrichment is not None and enrichment.domain_has_mx is False:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Email domain cannot receive mail",
                description=(
                    f"The domain {report.domain!r} publishes no MX records, so the address "
                    "cannot currently receive email. This may indicate a typo, a parked "
                    "domain, or a disposable address."
                ),
                severity=Severity.INFO,
                evidence=[f"domain={report.domain}", "mx=absent"],
            )
        )
    if enrichment is not None and enrichment.gravatar_exists:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Public Gravatar avatar exists for the address",
                description=(
                    "A public Gravatar avatar is registered for this address, confirming the "
                    "address is in use and linking it to a public profile image."
                ),
                severity=Severity.INFO,
                evidence=[f"gravatar_url={report.gravatar_url}"],
            )
        )
    return findings


@dataclass(frozen=True)
class EmailIntel:
    """Bundle of everything Argus learned about one email address, for export."""

    report: EmailReport
    asset: Asset
    enrichment: EmailEnrichment | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "report": self.report.to_dict(),
            "enrichment": self.enrichment.to_dict() if self.enrichment else None,
            "asset": json.loads(self.asset.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_email_intel(intel: EmailIntel, path: Path) -> None:
    """Write an email-intel bundle (report + asset + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )

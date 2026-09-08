"""Account (username) enumeration across a curated set of public sites.

Given a handle, Argus checks a small, well-known site list for a public
profile and, optionally, extracts public profile metadata (avatar, bio,
follower count) already visible on the page. Each hit becomes a
`core.Asset` (``AssetType.ACCOUNT``) plus a summary `core.Finding`.

Deliberate safety choices (unlike the source tool this concept comes from):
- One honest HTTP GET per site through the injectable
  :class:`~olympus.core.http.HttpClient`. **No** TLS-fingerprint
  impersonation, **no** proxy rotation, **no** anti-bot evasion — Olympus
  performs transparent, authorized testing only.
- The site list is a declarative, reviewable config, not code.
"""

from __future__ import annotations

import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset, Finding


class SiteRegistryError(Exception):
    """Raised when the site registry file is missing, unreadable or invalid."""


class SiteSpec(BaseModel):
    """Declarative check for one site: how to build the URL and read presence."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    url_template: str = Field(min_length=1)
    present_status: list[int] = Field(default_factory=lambda: [200])
    absent_status: list[int] = Field(default_factory=lambda: [404])
    present_body: str | None = None
    absent_body: str | None = None
    # field name -> regex with one capturing group, run against the page body.
    metadata_patterns: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class SiteCheck:
    """Outcome of probing one site for a handle."""

    name: str
    url: str
    exists: bool | None  # True / False / None (indeterminate)
    status_code: int | None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AccountScanResult:
    """All per-site outcomes for a single handle."""

    handle: str
    checks: list[SiteCheck] = field(default_factory=list)

    def existing(self) -> list[SiteCheck]:
        """Return only the sites where the handle was found."""
        return [check for check in self.checks if check.exists is True]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the scan."""
        return {
            "handle": self.handle,
            "checks": [
                {
                    "name": check.name,
                    "url": check.url,
                    "exists": check.exists,
                    "status_code": check.status_code,
                    "metadata": check.metadata,
                }
                for check in self.checks
            ],
        }


def load_site_registry(path: Path) -> list[SiteSpec]:
    """Load and validate the JSON site registry (a list of site specs)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SiteRegistryError(f"site registry not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SiteRegistryError(f"site registry could not be read: {path} ({exc})") from exc
    if not isinstance(raw, list):
        raise SiteRegistryError(f"site registry {path} must contain a JSON array")
    try:
        specs = [SiteSpec.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise SiteRegistryError(f"site registry {path} failed validation: {exc}") from exc
    for spec in specs:
        _validate_site_template(spec, path)
    return specs


def validate_public_site_url(url: str) -> None:
    """Reject non-HTTPS, credential-bearing, or local/private registry destinations."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise SiteRegistryError(f"site URL must use HTTPS: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise SiteRegistryError(f"site URL must not contain credentials: {url!r}")
    if not parsed.hostname:
        raise SiteRegistryError(f"site URL has no hostname: {url!r}")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise SiteRegistryError(f"site URL resolves to a local hostname: {url!r}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise SiteRegistryError(f"site URL must not target a non-public IP: {url!r}")


def _validate_site_template(spec: SiteSpec, path: Path | None = None) -> None:
    if spec.url_template.count("{username}") != 1:
        location = f" in {path}" if path is not None else ""
        raise SiteRegistryError(
            f"site {spec.name!r}{location} must contain exactly one '{{username}}' placeholder"
        )
    authority = spec.url_template.split("://", 1)[-1].split("/", 1)[0]
    if "{username}" in authority:
        raise SiteRegistryError(
            f"site {spec.name!r} must place '{{username}}' in the path or query, not hostname"
        )
    validate_public_site_url(spec.url_template.format(username="olympus_probe"))


def _extract_metadata(spec: SiteSpec, body: str) -> dict[str, str]:
    """Pull declared public metadata fields out of a page body via regex."""
    metadata: dict[str, str] = {}
    for field_name, pattern in spec.metadata_patterns.items():
        match = re.search(pattern, body)
        if match and match.groups():
            metadata[field_name] = match.group(1).strip()
    return metadata


def check_site(
    handle: str, spec: SiteSpec, client: HttpClient, *, want_metadata: bool = False
) -> SiteCheck:
    """Probe a single site for ``handle`` and classify presence."""
    _validate_site_template(spec)
    url = spec.url_template.format(username=quote(handle, safe=""))
    validate_public_site_url(url)
    try:
        response = client.get(url)
    except HttpRequestError:
        return SiteCheck(name=spec.name, url=url, exists=None, status_code=None)

    status = response.status_code
    body = response.body

    present = status in spec.present_status
    if spec.present_body is not None:
        present = present and spec.present_body in body
    absent = status in spec.absent_status or (
        spec.absent_body is not None and spec.absent_body in body
    )

    exists: bool | None
    if present and not absent:
        exists = True
    elif absent:
        exists = False
    else:
        exists = None

    metadata = _extract_metadata(spec, body) if (exists and want_metadata) else {}
    return SiteCheck(name=spec.name, url=url, exists=exists, status_code=status, metadata=metadata)


def enumerate_accounts(
    handle: str,
    specs: list[SiteSpec],
    client: HttpClient,
    *,
    want_metadata: bool = False,
    concurrency: int = 1,
) -> AccountScanResult:
    """Run every site check for ``handle`` and collect the results.

    With ``concurrency > 1`` the (I/O-bound) per-site checks run in a thread
    pool; results keep the site-registry order regardless.
    """
    if concurrency <= 1 or len(specs) <= 1:
        checks = [check_site(handle, spec, client, want_metadata=want_metadata) for spec in specs]
        return AccountScanResult(handle=handle, checks=checks)

    workers = min(concurrency, len(specs))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        checks = list(
            pool.map(
                lambda spec: check_site(handle, spec, client, want_metadata=want_metadata), specs
            )
        )
    return AccountScanResult(handle=handle, checks=checks)


def build_account_assets(result: AccountScanResult) -> list[Asset]:
    """One `core.Asset` (``AssetType.ACCOUNT``) per discovered profile."""
    assets: list[Asset] = []
    for check in result.existing():
        metadata = {"site": check.name, "handle": result.handle, **check.metadata}
        assets.append(
            Asset(
                asset_type=AssetType.ACCOUNT,
                hostname=check.url,
                source=Source.ARGUS,
                tags=["argus", "account-enumeration"],
                metadata=metadata,
            )
        )
    return assets


def build_account_finding(asset_id: str, result: AccountScanResult) -> Finding | None:
    """Summarize where the handle exists as one `core.Finding` (or ``None``)."""
    hits = result.existing()
    if not hits:
        return None
    return Finding(
        asset_id=asset_id,
        source=Source.ARGUS,
        title=f"Handle '{result.handle}' found on {len(hits)} site(s)",
        description=(
            "The handle resolves to a public profile on multiple platforms, expanding the "
            "OSINT footprint available for an authorized social-engineering assessment."
        ),
        severity=Severity.LOW if len(hits) < 3 else Severity.MEDIUM,
        evidence=[f"{check.name}: {check.url}" for check in hits],
        remediation=(
            "If these accounts belong to the target organization's staff, advise minimizing "
            "reuse of a single identifiable handle across platforms."
        ),
    )


@dataclass(frozen=True)
class AccountIntel:
    """Bundle of the scan plus derived assets/findings, for export."""

    result: AccountScanResult
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "scan": self.result.to_dict(),
            "assets": [json.loads(a.model_dump_json()) for a in self.assets],
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_account_intel(intel: AccountIntel, path: Path) -> None:
    """Write an account-intel bundle (scan + assets + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )

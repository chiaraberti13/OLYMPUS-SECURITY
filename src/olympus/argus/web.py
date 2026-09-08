"""Passive HTTP reconnaissance for Argus.

Fetches an authorized target URL once and reports its response posture without
any intrusive probing: the final URL after redirects, the status, disclosed
technology banners, and which common security headers are present or missing.
The HTTP transport is injected through the shared
:class:`~olympus.core.http.HttpClient`, so tests run offline and the request
carries Olympus's honest, fixed ``User-Agent``.

Because a fetch actively connects to the target, the caller must enforce the
engagement scope (see :func:`olympus.argus.scope.enforce_scope`) before
invoking :func:`fetch_web`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpAddressPolicyError, HttpClient, HttpRequestError
from olympus.core.models import Asset, Finding

#: Security response headers Argus checks for on every fetch.
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

#: Technology/infrastructure banners worth recording when disclosed.
TECH_HEADERS = ("Server", "X-Powered-By", "Via", "X-AspNet-Version")


class WebReconError(RuntimeError):
    """Raised when the target cannot be reached or the URL is unusable."""


class WebPolicyBlockedError(WebReconError):
    """Raised when the connect-time scope/SSRF policy refused a destination.

    Distinct from a plain unreachable host: it means the target (or a redirect
    hop, or a rebound DNS answer) pointed somewhere Olympus is not allowed to
    connect to, and the caller should report a policy block rather than a
    network failure.
    """


def normalize_url(raw_url: str) -> str:
    """Return ``raw_url`` with an explicit scheme (defaulting to HTTPS)."""
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    return url


def host_of(raw_url: str) -> str:
    """Return the hostname of ``raw_url`` (used for scope enforcement)."""
    parsed = urlparse(normalize_url(raw_url))
    if not parsed.hostname:
        raise WebReconError(f"could not determine a host for {raw_url!r}")
    return parsed.hostname


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


@dataclass(frozen=True)
class WebReport:
    """Passive HTTP posture of a single target URL."""

    url: str
    host: str
    status_code: int
    server: str | None
    tech_headers: dict[str, str]
    security_headers_present: dict[str, str]
    security_headers_missing: list[str]
    content_type: str | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "url": self.url,
            "host": self.host,
            "status_code": self.status_code,
            "server": self.server,
            "tech_headers": self.tech_headers,
            "security_headers_present": self.security_headers_present,
            "security_headers_missing": self.security_headers_missing,
            "content_type": self.content_type,
        }


def fetch_web(raw_url: str, http: HttpClient) -> WebReport:
    """Fetch ``raw_url`` once and summarize its passive HTTP posture."""
    url = normalize_url(raw_url)
    host = host_of(url)
    try:
        response = http.get(url)
    except HttpAddressPolicyError as exc:
        raise WebPolicyBlockedError(f"destination refused by policy for {url}: {exc}") from exc
    except HttpRequestError as exc:
        raise WebReconError(f"could not reach {url}: {exc}") from exc

    lowered = _headers_lower(response.headers)
    present = {name: lowered[name.lower()] for name in SECURITY_HEADERS if name.lower() in lowered}
    missing = [name for name in SECURITY_HEADERS if name.lower() not in lowered]
    tech = {name: lowered[name.lower()] for name in TECH_HEADERS if name.lower() in lowered}
    return WebReport(
        url=url,
        host=host,
        status_code=response.status_code,
        server=lowered.get("server"),
        tech_headers=tech,
        security_headers_present=present,
        security_headers_missing=missing,
        content_type=lowered.get("content-type"),
    )


def build_web_asset(report: WebReport) -> Asset:
    """Convert a :class:`WebReport` into a ``core.Asset``."""
    metadata: dict[str, str] = {"status_code": str(report.status_code)}
    if report.server:
        metadata["server"] = report.server
    if report.content_type:
        metadata["content_type"] = report.content_type
    return Asset(
        asset_type=AssetType.WEB_SERVER,
        hostname=report.host,
        source=Source.ARGUS,
        tags=["argus", "web-recon"],
        metadata=metadata,
    )


def build_web_findings(asset_id: str, report: WebReport) -> list[Finding]:
    """Derive findings for missing security headers and disclosed banners."""
    findings: list[Finding] = []
    if report.security_headers_missing:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title=f"{len(report.security_headers_missing)} security header(s) missing",
                description=(
                    "The response omits recommended security headers, leaving the site more "
                    "exposed to clickjacking, MIME sniffing, or transport downgrade depending "
                    "on which headers are absent."
                ),
                severity=Severity.LOW,
                evidence=[f"missing={name}" for name in report.security_headers_missing],
                remediation="Add the missing security response headers at the edge or origin.",
            )
        )
    if report.server:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Server banner disclosed",
                description=(
                    "The target discloses its server software in the 'Server' response header, "
                    "which can help an attacker fingerprint known vulnerabilities."
                ),
                severity=Severity.INFO,
                evidence=[f"server={report.server}"],
                remediation="Suppress or genericize the 'Server' response header.",
            )
        )
    return findings


@dataclass(frozen=True)
class WebIntel:
    """Bundle of everything Argus learned about one target URL, for export."""

    report: WebReport
    asset: Asset
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "report": self.report.to_dict(),
            "asset": json.loads(self.asset.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_web_intel(intel: WebIntel, path: Path) -> None:
    """Write a web-intel bundle (report + asset + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )

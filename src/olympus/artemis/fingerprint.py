"""Passive technology fingerprinting from an already-fetched HTTP response.

Inspired by dismap's asset-identification premise (match response headers and
body against a signature database to name the product/technology behind a
service), reimplemented to stay within Artemis's minimal, non-intrusive
footprint: it fingerprints only the response Artemis **already** fetched
through the scope-safe, DNS-pinned transport. It sends **no** extra requests
to guessed paths and computes no favicon probes, so no new traffic reaches the
target beyond the single authorized GET. Matches become informational
``core.Finding`` records that enrich the attack-surface inventory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from olympus.artemis.http import HttpResponse
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding


@dataclass(frozen=True)
class Signature:
    """One fingerprint rule: header and/or body markers for a product."""

    product: str
    category: str  # web-server | waf-cdn | cms | framework | app | language
    header: tuple[str, str] | None = None  # (header name lower-cased, substring, lower-cased)
    body: str | None = None  # case-sensitive substring expected in the body
    version_pattern: str | None = None  # regex with group(1) = version, applied to header+body
    references: tuple[str, ...] = ()


# Curated signature set covering common web servers, CDNs/WAFs, CMS, frameworks
# and app platforms. Every marker is one that appears in a normal base-URL
# response — no custom endpoints are probed.
SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "nginx", "web-server", header=("server", "nginx"), version_pattern=r"nginx/(\d[\w.]*)"
    ),
    Signature(
        "Apache httpd",
        "web-server",
        header=("server", "apache"),
        version_pattern=r"Apache/(\d[\w.]*)",
    ),
    Signature(
        "Microsoft IIS",
        "web-server",
        header=("server", "microsoft-iis"),
        version_pattern=r"Microsoft-IIS/(\d[\w.]*)",
    ),
    Signature("Caddy", "web-server", header=("server", "caddy")),
    Signature("Cloudflare", "waf-cdn", header=("server", "cloudflare")),
    Signature("Fastly", "waf-cdn", header=("x-served-by", "cache-")),
    Signature("Amazon CloudFront", "waf-cdn", header=("via", "cloudfront")),
    Signature("Akamai", "waf-cdn", header=("server", "akamaighost")),
    Signature("Sucuri WAF", "waf-cdn", header=("x-sucuri-id", "")),
    Signature("PHP", "language", header=("x-powered-by", "php"), version_pattern=r"PHP/(\d[\w.]*)"),
    Signature(
        "ASP.NET",
        "framework",
        header=("x-powered-by", "asp.net"),
        version_pattern=r"ASP\.NET(?:\s+Version:?\s*(\d[\w.]*))?",
    ),
    Signature("Express", "framework", header=("x-powered-by", "express")),
    Signature(
        "WordPress",
        "cms",
        body="wp-content",
        version_pattern=r'name="generator" content="WordPress (\d[\w.]*)"',
    ),
    Signature("Drupal", "cms", header=("x-generator", "drupal"), version_pattern=r"Drupal (\d+)"),
    Signature(
        "Joomla", "cms", body='content="Joomla!', version_pattern=r'content="Joomla! (\d[\w.]*)'
    ),
    Signature("Django", "framework", body="csrfmiddlewaretoken"),
    Signature("Laravel", "framework", header=("set-cookie", "laravel_session")),
    Signature(
        "Jenkins", "app", header=("x-jenkins", ""), version_pattern=r"x-jenkins:\s*(\d[\w.]*)"
    ),
    Signature("GitLab", "app", header=("x-gitlab-feature-category", "")),
    Signature("Grafana", "app", body="grafanaBootData"),
    Signature("Kibana", "app", header=("kbn-name", "")),
    Signature("phpMyAdmin", "app", body="phpMyAdmin"),
    Signature(
        "Apache Tomcat", "app", body="Apache Tomcat", version_pattern=r"Apache Tomcat/(\d[\w.]*)"
    ),
    Signature("Atlassian Jira", "app", header=("x-arequestid", "")),
    Signature("Atlassian Confluence", "app", body='name="confluence-'),
    Signature("Metabase", "app", body="Metabase"),
)


@dataclass(frozen=True)
class Fingerprint:
    """One matched technology, optionally with an extracted version."""

    product: str
    category: str
    version: str | None = None
    evidence: str = ""
    references: tuple[str, ...] = field(default=())


def _header_haystack(response: HttpResponse) -> str:
    """Return a lower-cased ``name: value`` block of every response header."""
    return "\n".join(f"{name.lower()}: {value.lower()}" for name, value in response.headers.items())


def _matches(signature: Signature, header_block: str, body: str) -> bool:
    """Return ``True`` if every marker the signature declares is present."""
    if signature.header is not None:
        name, needle = signature.header
        line_prefix = f"{name}:"
        header_line = next(
            (line for line in header_block.splitlines() if line.startswith(line_prefix)), None
        )
        if header_line is None:
            return False
        if needle and needle not in header_line:
            return False
    if signature.body is not None and signature.body not in body:
        return False
    return signature.header is not None or signature.body is not None


def fingerprint_response(response: HttpResponse) -> list[Fingerprint]:
    """Match a fetched response against the signature set, newest evidence first."""
    body = response.body.decode("utf-8", errors="replace")
    header_block = _header_haystack(response)
    combined = f"{header_block}\n{body}"
    results: list[Fingerprint] = []
    for signature in SIGNATURES:
        if not _matches(signature, header_block, body):
            continue
        version: str | None = None
        if signature.version_pattern is not None:
            match = re.search(signature.version_pattern, combined, re.IGNORECASE)
            if match is not None and match.lastindex:
                version = match.group(1)
        evidence = signature.header[0] if signature.header is not None else "response body"
        results.append(
            Fingerprint(
                product=signature.product,
                category=signature.category,
                version=version,
                evidence=f"matched on {evidence}",
                references=signature.references,
            )
        )
    return results


def fingerprints_to_findings(
    asset_id: str, url: str, fingerprints: list[Fingerprint]
) -> list[Finding]:
    """Turn technology matches into informational attack-surface findings."""
    findings: list[Finding] = []
    for fp in fingerprints:
        version = f" {fp.version}" if fp.version else ""
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARTEMIS,
                title=f"Technology detected: {fp.product}{version}",
                description=(
                    f"{url} exposes {fp.product}{version} ({fp.category}). Passive fingerprint "
                    "from the fetched response headers/body; no extra requests were sent."
                ),
                severity=Severity.INFO,
                evidence=[fp.evidence],
                references=list(fp.references),
            )
        )
    return findings

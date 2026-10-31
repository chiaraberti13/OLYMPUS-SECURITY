"""Non-exploitative detection of Metabase instances vulnerable to CVE-2026-72898.

The Metabase advisory GHSA-vwf4-m7j8-wcjf describes an unauthenticated SQL
injection in ``/api/session/reset_password``. This check only *fingerprints*
exposure — it reads the public version from ``/api/session/properties`` and
notes whether the vulnerable endpoint is reachable — going through Artemis's
scope-safe, DNS-pinned :func:`fetch_scoped` transport. It **never** sends a
SQL injection payload: Olympus reports the risk, it does not exploit it.

"No finding" here has three very different causes — the endpoint answered and
the version is patched, the host is not Metabase at all, or the check never
reached the host. The report distinguishes them so a failed check cannot be
mistaken for a clean one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from olympus.artemis.content import classify_fetch_error
from olympus.artemis.http import HttpClientError, Resolver, Transport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.core.coverage import Coverage, CoverageTracker, FailureKind, RunStatus
from olympus.core.enums import Severity, Source
from olympus.core.execution import ExecutionPolicy
from olympus.core.models import Finding

CVE_ID = "CVE-2026-72898"
ADVISORY_URL = "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf"

# Metabase release line -> (highest affected release, first patched version).
_AFFECTED: dict[int, tuple[int, str]] = {
    58: (23, "58.24"),
    59: (20, "59.21"),
    60: (16, "60.17"),
    61: (10, "61.11"),
    62: (8, "62.9"),
    63: (3, "63.5"),
}

_VERSION_RE = re.compile(r"v?(?:[01]\.)?(\d+)\.(\d+)")


def _parse_line_release(tag: str) -> tuple[int, int] | None:
    """Parse a Metabase version tag (e.g. ``v0.60.16``) into ``(line, release)``."""
    match = _VERSION_RE.match(tag.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def _extract_version_tag(body: str) -> str | None:
    """Return the Metabase version tag from a ``/api/session/properties`` body."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "version" not in data:
        return None
    version = data["version"]
    if isinstance(version, dict):
        tag = version.get("tag")
        return str(tag) if tag is not None else None
    return str(version)


@dataclass(frozen=True)
class MetabaseReport:
    """The findings of one Metabase check plus what the check could reach."""

    findings: tuple[Finding, ...] = ()
    coverage: Coverage = field(default_factory=Coverage)
    #: Set when the host answered but is not a Metabase instance.
    identified: bool = False

    @property
    def status(self) -> RunStatus:
        """Whether this check can speak for the target at all."""
        return self.coverage.status(len(self.findings))


@dataclass(frozen=True)
class _Fetch:
    """One scoped GET outcome: a response, or the reason there is none."""

    status: int | None = None
    body: str = ""
    failure: FailureKind | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        """Whether a response was received (of any status)."""
        return self.failure is None


def _get_status(
    url: str,
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    policy: ExecutionPolicy,
) -> _Fetch:
    """Scoped GET of ``url``, reporting the failure reason instead of swallowing it."""
    try:
        result = fetch_scoped(url, scope_path, log_path, resolver, transport, policy=policy)
    except (HttpClientError, ScopeError, OutOfScopeError, ValueError) as exc:
        return _Fetch(failure=classify_fetch_error(exc), detail=str(exc))
    return _Fetch(
        status=result.response.status,
        body=result.response.body.decode("utf-8", errors="replace"),
    )


def detect_metabase(
    asset_id: str,
    base_url: str,
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    *,
    policy: ExecutionPolicy,
) -> MetabaseReport:
    """Fingerprint a possible Metabase instance and flag CVE-2026-72898 exposure."""
    base = base_url.rstrip("/")
    # One unit is planned up front: the properties endpoint that identifies the
    # instance. The vulnerable endpoint is only planned once there is an
    # instance to check, so "not Metabase" stays full coverage rather than half.
    tracker = CoverageTracker(1)

    properties = _get_status(
        f"{base}/api/session/properties", scope_path, log_path, resolver, transport, policy
    )
    if not properties.ok:
        tracker.fail(
            properties.failure or FailureKind.ERROR,
            f"/api/session/properties: {properties.detail}",
        )
        return MetabaseReport(coverage=tracker.build())
    tracker.complete()

    version_tag = _extract_version_tag(properties.body) if properties.status == 200 else None
    if version_tag is None:
        # A real answer: this host responded and is not a Metabase instance.
        return MetabaseReport(coverage=tracker.build())

    tracker.plan(1)
    reset = _get_status(
        f"{base}/api/session/reset_password", scope_path, log_path, resolver, transport, policy
    )
    evidence = [f"version={version_tag}", "GET /api/session/properties -> 200"]
    if reset.ok:
        tracker.complete()
        evidence.append(f"GET /api/session/reset_password -> {reset.status}")
    else:
        tracker.fail(
            reset.failure or FailureKind.ERROR,
            f"/api/session/reset_password: {reset.detail}",
        )

    findings = _findings_for(asset_id, version_tag, evidence)
    return MetabaseReport(tuple(findings), tracker.build(), identified=True)


def _findings_for(asset_id: str, version_tag: str, evidence: list[str]) -> list[Finding]:
    """Return the CVE finding for an affected version, or the exposure notice."""
    line_release = _parse_line_release(version_tag)
    if line_release is not None and line_release[0] in _AFFECTED:
        highest_affected, patched = _AFFECTED[line_release[0]]
        if line_release[1] <= highest_affected:
            return [
                Finding(
                    asset_id=asset_id,
                    source=Source.ARTEMIS,
                    title=f"Metabase vulnerable to {CVE_ID} (unauthenticated SQL injection)",
                    description=(
                        f"The instance reports version {version_tag}, within the range "
                        f"affected by {CVE_ID}: an unauthenticated attacker can inject SQL via "
                        "/api/session/reset_password to read credentials and escalate to admin."
                    ),
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    evidence=evidence,
                    remediation=f"Upgrade Metabase to {patched} or later; until then block the "
                    "/api/session/reset_password endpoint at the network edge.",
                    references=[ADVISORY_URL],
                )
            ]
    return [
        Finding(
            asset_id=asset_id,
            source=Source.ARTEMIS,
            title="Metabase instance exposed — verify version against CVE-2026-72898",
            description=(
                f"A Metabase instance was fingerprinted (version {version_tag}). Confirm it is "
                f"not within the range affected by {CVE_ID}."
            ),
            severity=Severity.LOW,
            evidence=evidence,
            remediation=f"Confirm the version is patched (see {ADVISORY_URL}).",
            references=[ADVISORY_URL],
        )
    ]

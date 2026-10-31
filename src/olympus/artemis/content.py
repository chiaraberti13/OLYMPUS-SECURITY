"""Authorized web content/directory discovery for Artemis.

A real, working content-discovery engine (the technique behind gobuster /
dirsearch / dirb): it requests a list of candidate paths under an authorized
base URL and reports which ones exist, so an operator can map the hidden
attack surface of a target they are **authorized** to test — and practise the
technique against a lab.

Safety is structural, not cosmetic:

* every candidate URL is re-checked against the Artemis scope before the
  request, so discovery can only ever touch authorized origins and path
  prefixes (out-of-scope candidates are blocked and audited);
* requests go through the DNS-pinned :func:`fetch_scoped` transport, are
  GET-only and bounded (timeout + max body), and never send a payload — this
  is discovery, not exploitation;
* it is rate-limited (with jitter) and capped, so it is not a stress/flood
  tool, and it stops at one overall deadline rather than per-request timeouts
  that add up.

Discovered paths become ``core.Finding`` records; a curated set of
sensitive names (``.git``, ``.env``, backups, admin panels…) is raised to
``LOW`` with remediation, everything else stays informational.

Candidates that could not be checked are **counted, not dropped**. A run whose
requests all failed used to return an empty list that reads exactly like "this
target has nothing hidden"; it now reports ``FAILED`` coverage with the reason,
so an operator can tell "nothing is there" from "we never looked".
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from olympus.artemis.http import HttpClientError, Resolver, Transport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.core.coverage import Coverage, CoverageTracker, FailureKind, RunStatus
from olympus.core.enums import Severity, Source
from olympus.core.execution import (
    Cancellation,
    CancellationRequested,
    Deadline,
    ExecutionPolicy,
    NeverCancelled,
    RandomSource,
    interruptible_sleep,
)
from olympus.core.models import Finding

# Response statuses that mean "this path exists / is worth reporting".
_INTERESTING_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403, 405})

# Substrings that, when present in a discovered path, indicate a sensitive
# exposure worth escalating above a plain informational hit.
_SENSITIVE_MARKERS = (
    ".git",
    ".svn",
    ".env",
    ".htpasswd",
    "backup",
    "dump",
    "config",
    "admin",
    "phpinfo",
    "wp-admin",
    "id_rsa",
    ".bak",
    ".sql",
)

_MAX_WORDS = 5000


class WordlistError(RuntimeError):
    """Raised when a wordlist file is missing, unreadable or empty."""


@dataclass(frozen=True)
class DiscoveredPath:
    """One candidate path that returned an interesting status."""

    path: str
    url: str
    status: int
    length: int

    @property
    def sensitive(self) -> bool:
        """Return ``True`` if the path name matches a sensitive marker."""
        lowered = self.path.lower()
        return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def load_wordlist(path: Path) -> list[str]:
    """Load a newline-delimited wordlist, skipping blanks/comments, deduped and capped."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WordlistError(f"wordlist could not be read: {path} ({exc})") from exc
    words: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        candidate = line.strip().lstrip("/")
        if not candidate or candidate.startswith("#") or candidate in seen:
            continue
        seen.add(candidate)
        words.append(candidate)
        if len(words) >= _MAX_WORDS:
            break
    if not words:
        raise WordlistError(f"wordlist {path} contains no usable entries")
    return words


def _candidate_url(base_url: str, word: str) -> str:
    """Join ``base_url`` and ``word`` with exactly one separating slash."""
    return f"{base_url.rstrip('/')}/{word}"


@dataclass(frozen=True)
class ContentDiscoveryReport:
    """Everything one discovery run found, and everything it could not check."""

    discovered: tuple[DiscoveredPath, ...] = ()
    coverage: Coverage = field(default_factory=Coverage)

    @property
    def status(self) -> RunStatus:
        """How much of the wordlist this run can actually speak for."""
        return self.coverage.status(len(self.discovered))


def classify_fetch_error(exc: Exception) -> FailureKind:
    """Map a scoped-fetch failure onto the shared coverage vocabulary."""
    if isinstance(exc, OutOfScopeError):
        return FailureKind.SCOPE_DENIED
    if isinstance(exc, ScopeError):
        return FailureKind.POLICY_DENIED
    if isinstance(exc, HttpClientError):
        message = str(exc).lower()
        if "dns" in message or "resolution" in message:
            return FailureKind.DNS_FAILURE
        if "timed out" in message or "timeout" in message:
            return FailureKind.TIMEOUT
        if "limit" in message or "exceeds" in message or "too large" in message:
            return FailureKind.LIMIT_EXCEEDED
        if "redirect" in message or "decoded" in message:
            return FailureKind.PROTOCOL_ERROR
        return FailureKind.TRANSPORT_ERROR
    return FailureKind.ERROR


def discover_content(
    base_url: str,
    words: list[str],
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    *,
    policy: ExecutionPolicy,
    max_bytes: int = 1_000_000,
    cancellation: Cancellation | None = None,
    random_source: RandomSource | None = None,
) -> ContentDiscoveryReport:
    """Request each candidate path under ``base_url`` and report what was learned.

    Every candidate is accounted for: one that returned a status is
    ``completed``, one whose request failed is ``failed`` with the reason, and
    one the run never reached — because the deadline ran out — is ``skipped``.
    ``min_interval_seconds`` throttles requests for politeness and
    ``jitter_ratio`` spreads that pacing so the traffic is not a metronome.
    """
    policy.require_authorization("Artemis content discovery")
    token = cancellation or NeverCancelled()
    deadline = Deadline(policy.deadline_seconds)
    tracker = CoverageTracker(len(words))
    discovered: list[DiscoveredPath] = []

    for index, word in enumerate(words):
        if token.is_cancelled():
            tracker.skip(FailureKind.CANCELLED, "cancelled", units=len(words) - index)
            raise CancellationRequested("operation cancelled")
        if not _wait_for_turn(index, policy, token, deadline, random_source):
            remaining = len(words) - index
            if token.is_cancelled():
                tracker.skip(FailureKind.CANCELLED, "cancelled", units=remaining)
                raise CancellationRequested("operation cancelled")
            tracker.skip(FailureKind.DEADLINE_EXCEEDED, "run deadline reached", units=remaining)
            break
        url = _candidate_url(base_url, word)
        request_policy = replace(policy, deadline_seconds=max(0.05, deadline.remaining))
        try:
            result = fetch_scoped(
                url,
                scope_path,
                log_path,
                resolver,
                transport,
                max_bytes=max_bytes,
                policy=request_policy,
                cancellation=token,
            )
        except (HttpClientError, ScopeError, OutOfScopeError, ValueError) as exc:
            tracker.fail(classify_fetch_error(exc), f"/{word}: {exc}")
            continue
        tracker.complete()
        if result.response.status in _INTERESTING_STATUSES:
            discovered.append(
                DiscoveredPath(
                    path=word,
                    url=result.response.url,
                    status=result.response.status,
                    length=len(result.response.body),
                )
            )
    return ContentDiscoveryReport(tuple(discovered), tracker.build())


def _wait_for_turn(
    index: int,
    policy: ExecutionPolicy,
    token: Cancellation,
    deadline: Deadline,
    random_source: RandomSource | None,
) -> bool:
    """Honor the jittered rate limit; return whether there is still time to request."""
    if index > 0:
        wait = policy.next_interval(random_source)
        if wait > 0.0 and not interruptible_sleep(wait, token, deadline):
            return False
    return deadline.remaining >= 0.05


def discoveries_to_findings(asset_id: str, discovered: Sequence[DiscoveredPath]) -> list[Finding]:
    """Turn discovered paths into findings; sensitive names are raised to LOW."""
    findings: list[Finding] = []
    for item in discovered:
        sensitive = item.sensitive
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARTEMIS,
                title=(
                    f"Sensitive path exposed: /{item.path} (HTTP {item.status})"
                    if sensitive
                    else f"Path discovered: /{item.path} (HTTP {item.status})"
                ),
                description=(
                    f"{item.url} returned HTTP {item.status} ({item.length} bytes) to an "
                    "authorized content-discovery request."
                ),
                severity=Severity.LOW if sensitive else Severity.INFO,
                evidence=[f"GET {item.url} -> {item.status}"],
                remediation=(
                    "Remove or access-restrict this resource if it is not meant to be public."
                    if sensitive
                    else ""
                ),
            )
        )
    return findings

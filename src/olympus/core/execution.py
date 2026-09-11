"""Shared authorization, resource, cancellation, retry, and audit policy.

Scope syntax remains owned by each module (domain suffix, CIDR, E.164, OUI,
handle, or URL+resolved address). This module standardizes when checks happen
and the bounded execution/redaction behavior around those dedicated gates.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_TIMEOUT_SECONDS = 3600.0
MAX_DEADLINE_SECONDS = 86_400.0
MAX_CONCURRENCY = 64
MAX_RETRIES = 5
MAX_BACKOFF_SECONDS = 60.0
MAX_MIN_INTERVAL_SECONDS = 60.0
MAX_JITTER_RATIO = 1.0

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
)


class ExecutionPolicyError(ValueError):
    """Raised when shared execution settings are missing, ambiguous, or unsafe."""


class AuthorizationRequiredError(PermissionError):
    """Raised before work when a policy lacks explicit authorization."""


class CancellationRequested(RuntimeError):
    """Raised when cooperative work observes a cancellation request."""


class Cancellation(Protocol):
    """Minimal cooperative cancellation port shared by workers/adapters."""

    def is_cancelled(self) -> bool:
        """Return whether cancellation was requested."""
        ...


class NeverCancelled:
    """Default cancellation token for bounded synchronous operations."""

    def is_cancelled(self) -> bool:
        return False


class CancellationToken:
    """Thread-safe mutable cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Request cancellation; repeated calls are idempotent."""
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


#: Returns a float in ``[0, 1)``. Injectable so tests can pin jitter.
RandomSource = Callable[[], float]

#: Jitter is not a secret, but a system source costs nothing here and keeps
#: the module free of a seeded global generator that a caller could disturb.
default_random_source: RandomSource = secrets.SystemRandom().random


@dataclass(frozen=True)
class ExecutionPolicy:
    """Validated resource and authorization policy for one operation."""

    authorized: bool = False
    approval_reference: str | None = None
    timeout_seconds: float = 10.0
    deadline_seconds: float = 600.0
    max_concurrency: int = 1
    retries: int = 0
    backoff_seconds: float = 0.5
    min_interval_seconds: float = 0.0
    jitter_ratio: float = 0.0

    def __post_init__(self) -> None:
        if not 0.05 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ExecutionPolicyError(
                f"timeout_seconds must be between 0.05 and {MAX_TIMEOUT_SECONDS:g}"
            )
        if not 0.05 <= self.deadline_seconds <= MAX_DEADLINE_SECONDS:
            raise ExecutionPolicyError(
                f"deadline_seconds must be between 0.05 and {MAX_DEADLINE_SECONDS:g}"
            )
        if not 1 <= self.max_concurrency <= MAX_CONCURRENCY:
            raise ExecutionPolicyError(f"max_concurrency must be between 1 and {MAX_CONCURRENCY}")
        if not 0 <= self.retries <= MAX_RETRIES:
            raise ExecutionPolicyError(f"retries must be between 0 and {MAX_RETRIES}")
        if not 0.0 <= self.backoff_seconds <= MAX_BACKOFF_SECONDS:
            raise ExecutionPolicyError(
                f"backoff_seconds must be between 0 and {MAX_BACKOFF_SECONDS:g}"
            )
        if not 0.0 <= self.min_interval_seconds <= MAX_MIN_INTERVAL_SECONDS:
            raise ExecutionPolicyError(
                f"min_interval_seconds must be between 0 and {MAX_MIN_INTERVAL_SECONDS:g}"
            )
        if not 0.0 <= self.jitter_ratio <= MAX_JITTER_RATIO:
            raise ExecutionPolicyError(f"jitter_ratio must be between 0 and {MAX_JITTER_RATIO:g}")
        if self.approval_reference is not None and not self.approval_reference.strip():
            raise ExecutionPolicyError("approval_reference must not be blank")

    def require_authorization(self, operation: str) -> None:
        """Refuse an operation before its scope gate or adapter can run."""
        if not self.authorized:
            raise AuthorizationRequiredError(
                f"{operation} requires explicit documented authorization"
            )

    def authorize_target(
        self, operation: str, target: str, scope_authorizer: Callable[[str], object]
    ) -> None:
        """Require authorization, then invoke the module's dedicated scope gate."""
        self.require_authorization(operation)
        scope_authorizer(target)

    def check_cancellation(self, cancellation: Cancellation) -> None:
        """Raise a stable exception when cooperative cancellation is requested."""
        if cancellation.is_cancelled():
            raise CancellationRequested("operation cancelled")

    def next_interval(self, random_source: RandomSource | None = None) -> float:
        """Return the next throttle wait, with symmetric jitter applied.

        Without jitter a paced scanner sends a request on a perfectly regular
        tick, which is both trivially fingerprintable and prone to landing in
        lockstep with another client. The wait is spread over
        ``±jitter_ratio`` of the configured interval and never goes negative.
        """
        if self.min_interval_seconds <= 0.0:
            return 0.0
        if self.jitter_ratio <= 0.0:
            return self.min_interval_seconds
        draw = (random_source or default_random_source)()
        offset = (draw * 2.0 - 1.0) * self.jitter_ratio
        return max(0.0, self.min_interval_seconds * (1.0 + offset))

    def next_backoff(self, attempt: int, random_source: RandomSource | None = None) -> float:
        """Return the wait before retry ``attempt`` (1-based), jittered and capped.

        The base is an exponential backoff from ``backoff_seconds``, bounded by
        ``MAX_BACKOFF_SECONDS`` so a large retry budget cannot turn into an
        unbounded sleep, and by the policy's own deadline elsewhere.
        """
        if attempt < 1:
            raise ExecutionPolicyError("attempt must be 1 or greater")
        base = min(self.backoff_seconds * (2.0 ** (attempt - 1)), MAX_BACKOFF_SECONDS)
        if base <= 0.0 or self.jitter_ratio <= 0.0:
            return base
        draw = (random_source or default_random_source)()
        offset = (draw * 2.0 - 1.0) * self.jitter_ratio
        return max(0.0, min(base * (1.0 + offset), MAX_BACKOFF_SECONDS))


class Deadline:
    """A monotonic overall budget shared by every unit of one run.

    Modules used to add up per-request timeouts, which lets a long run drift
    far past what the operator asked for. A deadline is taken once, at the
    start, and every unit asks it how much time is actually left.
    """

    def __init__(self, seconds: float) -> None:
        if seconds <= 0.0:
            raise ExecutionPolicyError("deadline seconds must be positive")
        self._expiry = time.monotonic() + seconds

    @property
    def remaining(self) -> float:
        """Seconds left before the budget is spent; never negative."""
        return max(0.0, self._expiry - time.monotonic())

    @property
    def expired(self) -> bool:
        """Whether the budget is spent."""
        return self.remaining <= 0.0

    def slice_for(self, requested: float) -> float:
        """Return ``requested`` capped by whatever budget is still left."""
        return min(requested, self.remaining)


#: Longest uninterrupted sleep taken while waiting; a cancellation request is
#: observed at least this often even during a long rate-limit wait.
CANCELLATION_POLL_SECONDS = 0.05


def interruptible_sleep(
    seconds: float,
    cancellation: Cancellation | None = None,
    deadline: Deadline | None = None,
) -> bool:
    """Sleep in cancellation-sized slices; return whether the full wait elapsed.

    Returns ``False`` as soon as cancellation is requested or the run deadline
    is spent, so a caller can stop instead of finishing a wait nobody is
    waiting for any more.
    """
    if seconds <= 0.0:
        return True
    token = cancellation or NeverCancelled()
    end = time.monotonic() + seconds
    while True:
        if token.is_cancelled():
            return False
        if deadline is not None and deadline.expired:
            return False
        left = end - time.monotonic()
        if left <= 0.0:
            return True
        time.sleep(min(left, CANCELLATION_POLL_SECONDS))


def _sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def redact_url(value: str) -> str:
    """Redact sensitive query values while preserving a URL's useful shape."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    query = urlencode(
        [
            (key, "[REDACTED]" if _sensitive_key(key) else item)
            for key, item in parse_qsl(parsed.query)
        ],
        doseq=True,
    )
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    redacted = urlunsplit(
        (parsed.scheme, f"{hostname}{port}", parsed.path, query, parsed.fragment)
    )
    # Audit logs and job records are read by people and matched by policy
    # checks, so keep the sentinel legible rather than percent-encoded.
    return redacted.replace("%5BREDACTED%5D", "[REDACTED]")


#: A URL embedded in free text (an error message, scanner output, a log line).
_URL_IN_TEXT = re.compile(r"https?://[^\s\]\[<>\"']+")


def redact_text(value: str) -> str:
    """Redact the secret-bearing query parameters of every URL inside free text.

    ``redact_url`` only rewrites a string that *is* a URL. Most secrets leak
    inside a sentence, so anything human-readable that is persisted or printed
    goes through this instead.
    """
    return _URL_IN_TEXT.sub(lambda match: redact_url(match.group(0)), value)


def _redact_value(item: Any) -> Any:
    """Redact one metadata value by shape: mapping, list, or URL-bearing string.

    A URL query secret must be redacted wherever it sits — a direct value, an
    element of a list, or an element of a nested list — not only when it is the
    immediate value of a key. A string that is not a URL and anything that is
    not a mapping/list/string are returned unchanged.
    """
    if isinstance(item, Mapping):
        return redact_mapping(item)
    if isinstance(item, list):
        return [_redact_value(entry) for entry in item]
    if isinstance(item, str):
        return redact_url(item)
    return item


def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively redact secret-bearing keys and URL query parameters."""
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        redacted[key] = "[REDACTED]" if _sensitive_key(key) else _redact_value(item)
    return redacted


@dataclass(frozen=True)
class StructuredAuditRecord:
    """Redacted JSON audit record shared by application and worker surfaces."""

    timestamp: str
    execution_id: str
    action: str
    outcome: str
    target: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the redacted serialization; raw metadata is never exposed."""
        target = redact_url(self.target) if self.target is not None else None
        return {
            "timestamp": self.timestamp,
            "execution_id": self.execution_id,
            "action": self.action,
            "outcome": self.outcome,
            "target": target,
            "metadata": redact_mapping(self.metadata),
        }

    def to_json(self) -> str:
        """Return deterministic one-line JSON suitable for append-only logs."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def append_structured_audit(path: Path, record: StructuredAuditRecord) -> None:
    """Append one redacted record through an owner-only no-follow descriptor."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (record.to_json() + "\n").encode("utf-8")
    if len(content) > 1_000_000:
        raise ValueError("structured audit record exceeds the 1000000 byte limit")
    if path.is_symlink():
        raise OSError(f"structured audit path must not be a symlink: {path}")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"structured audit path must be a regular file: {path}")
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("structured audit append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

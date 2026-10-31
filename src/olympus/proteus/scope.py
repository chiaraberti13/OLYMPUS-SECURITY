"""Scope enforcement for authorized Proteus awareness simulations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from olympus.core.execution import StructuredAuditRecord, append_structured_audit

_LOCAL_PART = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ProteusScopeError(ValueError):
    """Raised when scope data or a scoped value is malformed."""


class ProteusOutOfScopeError(PermissionError):
    """Raised when a simulation target is outside the loaded scope."""

    def __init__(self, value: str, scope_path: Path) -> None:
        super().__init__(f"{value!r} is out of scope ({scope_path})")
        self.email = value  # compatibility for existing email-target callers
        self.value = value
        self.scope_path = scope_path


def _normalize_domain(value: str) -> str:
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ProteusScopeError(f"invalid domain: {value!r}") from exc
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
    ):
        raise ProteusScopeError(f"invalid domain: {value!r}")
    return domain


def normalize_email(value: str) -> str:
    """Return one conservative mailbox form suitable for scope comparison."""
    candidate = value.strip()
    if len(candidate) > 254 or candidate.count("@") != 1:
        raise ProteusScopeError(f"invalid email address: {value!r}")
    local, domain = candidate.rsplit("@", 1)
    if (
        not local
        or len(local) > 64
        or not _LOCAL_PART.fullmatch(local)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise ProteusScopeError(f"invalid email address: {value!r}")
    return f"{local}@{_normalize_domain(domain)}"


def normalize_landing_url(value: str) -> str:
    """Validate and canonicalize an HTTPS training URL without credentials."""
    if any(character in value for character in "\r\n\t"):
        raise ProteusScopeError("landing URL contains control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProteusScopeError(f"invalid landing URL: {exc}") from exc
    if parsed.scheme.lower() != "https" or parsed.hostname is None:
        raise ProteusScopeError("landing URL must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ProteusScopeError("landing URL must not contain credentials")
    hostname = _normalize_domain(parsed.hostname)
    authority = hostname if port in {None, 443} else f"{hostname}:{port}"
    return urlunsplit(("https", authority, parsed.path or "/", parsed.query, parsed.fragment))


def landing_origin(value: str) -> str:
    """Return the canonical origin of a validated training URL."""
    parsed = urlsplit(normalize_landing_url(value))
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


@dataclass(frozen=True)
class ProteusScope:
    """Authorized recipient/sender domains and training-page origins."""

    engagement: str
    allowed_domains: tuple[str, ...]
    allowed_landing_origins: tuple[str, ...]

    def covers(self, email: str) -> bool:
        """Return whether an email is syntactically valid and domain-authorized."""
        try:
            domain = normalize_email(email).rsplit("@", 1)[1]
        except ProteusScopeError:
            return False
        return domain in self.allowed_domains

    def covers_landing_url(self, url: str) -> bool:
        """Return whether a valid HTTPS landing URL uses an authorized origin."""
        try:
            origin = landing_origin(url)
        except ProteusScopeError:
            return False
        return origin in self.allowed_landing_origins


def load_scope(path: Path) -> ProteusScope:
    """Load and strictly validate recipient domains and landing origins."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProteusScopeError(f"scope file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProteusScopeError(f"scope file could not be read: {path} ({exc})") from exc
    if not isinstance(raw, dict):
        raise ProteusScopeError(f"scope file {path} must contain a JSON object")
    expected = {"engagement", "allowed_domains", "allowed_landing_origins"}
    if set(raw) != expected:
        raise ProteusScopeError(f"scope file {path} must define exactly {sorted(expected)}")
    engagement = raw["engagement"]
    domains = raw["allowed_domains"]
    origins = raw["allowed_landing_origins"]
    if not isinstance(engagement, str) or not engagement.strip():
        raise ProteusScopeError("scope engagement must be a non-blank string")
    if (
        not isinstance(domains, list)
        or not domains
        or not all(isinstance(item, str) for item in domains)
    ):
        raise ProteusScopeError("scope allowed_domains must be a non-empty string array")
    if (
        not isinstance(origins, list)
        or not origins
        or not all(isinstance(item, str) for item in origins)
    ):
        raise ProteusScopeError("scope allowed_landing_origins must be a non-empty string array")
    normalized_domains = tuple(dict.fromkeys(_normalize_domain(item) for item in domains))
    normalized_origins: list[str] = []
    for item in origins:
        normalized = normalize_landing_url(item)
        parsed = urlsplit(normalized)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ProteusScopeError("allowed_landing_origins entries must contain an origin only")
        normalized_origins.append(landing_origin(normalized))
    return ProteusScope(
        engagement=engagement.strip(),
        allowed_domains=normalized_domains,
        allowed_landing_origins=tuple(dict.fromkeys(normalized_origins)),
    )


def log_blocked(value: str, scope_path: Path, log_path: Path, reason: str) -> None:
    """Append a structured denial without persisting a recipient address."""
    safe_target = value.rsplit("@", 1)[-1].lower() if "@" in value else None
    append_structured_audit(
        log_path,
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=str(uuid4()),
            action="proteus.blocked_out_of_scope",
            outcome="blocked",
            target=safe_target,
            metadata={
                "reason": reason,
                "scope_file": str(scope_path),
                "target_sha256": hashlib.sha256(value.strip().lower().encode()).hexdigest(),
            },
        ),
    )


def enforce_scope(email: str, scope_path: Path, log_path: Path) -> ProteusScope:
    """Require a valid recipient/sender domain and audit denials without email PII."""
    scope = load_scope(scope_path)
    if not scope.covers(email):
        log_blocked(email, scope_path, log_path, "email_domain_not_allowed")
        raise ProteusOutOfScopeError(email, scope_path)
    return scope


def enforce_landing_scope(url: str, scope_path: Path, log_path: Path) -> ProteusScope:
    """Require an explicitly allowed HTTPS training origin."""
    scope = load_scope(scope_path)
    if not scope.covers_landing_url(url):
        safe_value = landing_origin(url)
        log_blocked(safe_value, scope_path, log_path, "landing_origin_not_allowed")
        raise ProteusOutOfScopeError(safe_value, scope_path)
    return scope

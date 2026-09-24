"""API identities for the AEGIS control plane: scopes, rotation, revocation.

One shared API key is a single point of compromise with no way to tell callers
apart, no way to give a dashboard read-only access, and no way to take a leaked
credential out of circulation without breaking every client at once. This module
replaces it with a small, file-backed identity register:

* **Many identities.** Each has an id, a scope set, an optional expiry, and its
  own rate limit.
* **Secrets are never stored.** Only the SHA-256 of a high-entropy token is
  persisted; the token itself is shown once, when it is generated.
* **Rotation has an overlap window.** A rotated identity keeps its previous
  secret valid for a bounded period, so clients can be updated without an
  outage — and the old secret stops working on its own.
* **Revocation is immediate and fail-closed.** A revoked or expired identity
  authenticates nothing, and an unreadable or malformed register authenticates
  nothing either.

The register is a versioned contract (``olympus.aegis-api-identities``) written
owner-only and atomically, so a half-written file can never be observed.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from olympus.core.contracts import validate_contract_header
from olympus.core.fileio import atomic_write_text, read_regular_text

MAX_REGISTER_BYTES = 1_000_000
MIN_SECRET_CHARACTERS = 32
DEFAULT_RATE_LIMIT_PER_MINUTE = 120
MAX_RATE_LIMIT_PER_MINUTE = 100_000
MAX_OVERLAP_SECONDS = 7 * 24 * 3_600

IDENTITY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

#: Every permission the API understands. A scope names one capability, so a
#: read-only dashboard cannot queue a scan and a submitter cannot cancel one.
SCOPES: tuple[str, ...] = (
    "capabilities:read",
    "jobs:read",
    "jobs:write",
    "jobs:cancel",
)


class IdentityError(ValueError):
    """Raised when an identity register or one of its entries is invalid."""


def hash_secret(secret: str) -> str:
    """Return the stored form of a credential: its SHA-256, never the secret."""
    if len(secret) < MIN_SECRET_CHARACTERS:
        raise IdentityError(f"API secrets must contain at least {MIN_SECRET_CHARACTERS} characters")
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_secret() -> str:
    """Return a fresh high-entropy credential (shown once, stored hashed)."""
    return secrets.token_urlsafe(32)


class ApiIdentity(BaseModel):
    """One credential: who is calling, what they may do, and until when."""

    model_config = ConfigDict(extra="forbid")

    identity_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    secret_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scopes: list[str] = Field(min_length=1, max_length=len(SCOPES))
    created_at: datetime
    #: Previous secret, still accepted until ``previous_valid_until``.
    previous_secret_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    previous_valid_until: datetime | None = None
    rotated_at: datetime | None = None
    not_after: datetime | None = None
    revoked: bool = False
    revoked_at: datetime | None = None
    rate_limit_per_minute: int = Field(
        default=DEFAULT_RATE_LIMIT_PER_MINUTE, ge=1, le=MAX_RATE_LIMIT_PER_MINUTE
    )

    def validated_scopes(self) -> tuple[str, ...]:
        """Return the scope set, refusing any permission the API does not define."""
        unknown = sorted(set(self.scopes) - set(SCOPES))
        if unknown:
            raise IdentityError(f"unknown API scopes: {', '.join(unknown)}")
        return tuple(sorted(set(self.scopes)))

    def usable_at(self, moment: datetime) -> bool:
        """True when this identity may authenticate at ``moment``."""
        if self.revoked:
            return False
        return self.not_after is None or moment < self.not_after

    def matches(self, presented_hash: str, moment: datetime) -> bool:
        """Compare a presented credential against the current or rotating secret."""
        if secrets.compare_digest(self.secret_sha256, presented_hash):
            return True
        if self.previous_secret_sha256 is None or self.previous_valid_until is None:
            return False
        if moment >= self.previous_valid_until:
            return False
        return secrets.compare_digest(self.previous_secret_sha256, presented_hash)


class IdentityRegister(BaseModel):
    """The versioned, persisted set of API identities."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-api-identities"] = "olympus.aegis-api-identities"
    schema_version: Literal["1.0.0"] = "1.0.0"
    identities: list[ApiIdentity] = Field(default_factory=list, max_length=1_000)

    def validate_entries(self) -> IdentityRegister:
        """Reject duplicate ids and unknown scopes before the register is used."""
        seen: set[str] = set()
        for identity in self.identities:
            if identity.identity_id in seen:
                raise IdentityError(f"duplicate API identity: {identity.identity_id}")
            seen.add(identity.identity_id)
            identity.validated_scopes()
        return self

    def find(self, identity_id: str) -> ApiIdentity | None:
        return next((item for item in self.identities if item.identity_id == identity_id), None)

    def authenticate(self, presented: str, *, moment: datetime | None = None) -> ApiIdentity:
        """Return the identity a presented credential belongs to.

        Every candidate is compared even after a match is found, so the answer
        does not depend on the register's order.
        """
        now = moment or datetime.now(UTC)
        if len(presented) < MIN_SECRET_CHARACTERS:
            raise IdentityError("presented credential is too short to be an API secret")
        digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
        matched: ApiIdentity | None = None
        for identity in self.identities:
            if identity.matches(digest, now) and identity.usable_at(now) and matched is None:
                matched = identity
        if matched is None:
            raise IdentityError("no usable API identity matches the presented credential")
        return matched

    def public_view(self) -> list[dict[str, object]]:
        """Return the register without any credential material."""
        return [
            {
                "identity_id": identity.identity_id,
                "scopes": list(identity.validated_scopes()),
                "created_at": identity.created_at.isoformat(),
                "rotated_at": identity.rotated_at.isoformat() if identity.rotated_at else None,
                "not_after": identity.not_after.isoformat() if identity.not_after else None,
                "revoked": identity.revoked,
                "rate_limit_per_minute": identity.rate_limit_per_minute,
                "rotation_overlap_until": (
                    identity.previous_valid_until.isoformat()
                    if identity.previous_valid_until
                    else None
                ),
            }
            for identity in self.identities
        ]


def load_register(path: Path) -> IdentityRegister:
    """Load and validate the identity register; any problem is fail-closed."""
    raw = read_regular_text(path, max_bytes=MAX_REGISTER_BYTES, label="AEGIS identity register")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IdentityError(f"invalid AEGIS identity register JSON: {exc.msg}") from exc
    validate_contract_header(document, schema_name="olympus.aegis-api-identities")
    return IdentityRegister.model_validate(document).validate_entries()


def save_register(path: Path, register: IdentityRegister) -> None:
    """Write the register atomically, owner-only: it holds credential hashes."""
    register.validate_entries()
    atomic_write_text(path, register.model_dump_json(indent=2) + "\n", mode=0o600)


def add_identity(
    register: IdentityRegister,
    *,
    identity_id: str,
    scopes: Iterable[str],
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE,
    expires_in_days: int | None = None,
) -> tuple[IdentityRegister, str]:
    """Add one identity, returning the register and the secret to hand over once."""
    if not IDENTITY_ID_PATTERN.fullmatch(identity_id):
        raise IdentityError(
            "identity_id must be 1-64 characters of lowercase letters, digits, '_', '.' or '-'"
        )
    if register.find(identity_id) is not None:
        raise IdentityError(f"API identity already exists: {identity_id}")
    now = datetime.now(UTC)
    secret = generate_secret()
    identity = ApiIdentity(
        identity_id=identity_id,
        secret_sha256=hash_secret(secret),
        scopes=sorted(set(scopes)),
        created_at=now,
        not_after=now + timedelta(days=expires_in_days) if expires_in_days else None,
        rate_limit_per_minute=rate_limit_per_minute,
    )
    identity.validated_scopes()
    updated = register.model_copy(update={"identities": [*register.identities, identity]})
    return updated.validate_entries(), secret


def rotate_identity(
    register: IdentityRegister, identity_id: str, *, overlap_seconds: int = 300
) -> tuple[IdentityRegister, str]:
    """Issue a new secret, keeping the previous one valid for a bounded overlap."""
    if not 0 <= overlap_seconds <= MAX_OVERLAP_SECONDS:
        raise IdentityError(f"overlap_seconds must be between 0 and {MAX_OVERLAP_SECONDS}")
    identity = _require(register, identity_id)
    now = datetime.now(UTC)
    secret = generate_secret()
    rotated = identity.model_copy(
        update={
            "secret_sha256": hash_secret(secret),
            "previous_secret_sha256": identity.secret_sha256 if overlap_seconds else None,
            "previous_valid_until": (
                now + timedelta(seconds=overlap_seconds) if overlap_seconds else None
            ),
            "rotated_at": now,
        }
    )
    return _replace(register, rotated), secret


def revoke_identity(register: IdentityRegister, identity_id: str) -> IdentityRegister:
    """Revoke an identity, including any secret still inside its rotation window."""
    identity = _require(register, identity_id)
    revoked = identity.model_copy(
        update={
            "revoked": True,
            "revoked_at": datetime.now(UTC),
            "previous_secret_sha256": None,
            "previous_valid_until": None,
        }
    )
    return _replace(register, revoked)


def _require(register: IdentityRegister, identity_id: str) -> ApiIdentity:
    identity = register.find(identity_id)
    if identity is None:
        raise IdentityError(f"unknown API identity: {identity_id}")
    return identity


def _replace(register: IdentityRegister, identity: ApiIdentity) -> IdentityRegister:
    identities = [
        identity if item.identity_id == identity.identity_id else item
        for item in register.identities
    ]
    return register.model_copy(update={"identities": identities}).validate_entries()


class RateLimiter:
    """Per-identity sliding-window request limiter.

    In-process by design: it bounds one server's exposure to a runaway or
    stolen credential. It is not a distributed quota, and the API documentation
    says so rather than implying a guarantee several replicas cannot give.
    """

    def __init__(self, window_seconds: float = 60.0, max_tracked_identities: int = 10_000):
        self._window = window_seconds
        self._max_tracked = max_tracked_identities
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, identity_id: str, limit: int, *, now: float | None = None) -> float | None:
        """Record one request; return seconds to wait when the limit is exceeded."""
        moment = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.get(identity_id)
            if hits is None:
                if len(self._hits) >= self._max_tracked:
                    self._evict(moment)
                hits = self._hits.setdefault(identity_id, deque())
            while hits and hits[0] <= moment - self._window:
                hits.popleft()
            if len(hits) >= limit:
                return max(0.0, self._window - (moment - hits[0]))
            hits.append(moment)
            return None

    def _evict(self, moment: float) -> None:
        """Drop windows that hold nothing, so an attacker cannot grow the map."""
        for key in [
            key for key, hits in self._hits.items() if not hits or hits[-1] <= moment - self._window
        ]:
            del self._hits[key]

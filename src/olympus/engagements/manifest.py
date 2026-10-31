"""Versioned, signed authorization manifests for active engagements (SEC-C).

The contract is deliberately independent of execution adapters. Callers must
pin the approver's public key and pass the operation's target, technique and
clock reading to :meth:`SignedEngagementManifest.authorize`; a valid signature
alone is not authorization for every operation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from olympus.core.ids import new_id
from olympus.core.models import EngagementScope, OlympusModel, is_canonical_engagement_id
from olympus.core.signing import SigningError, sign, verify
from olympus.integrations.activity import RiskClass, risk_within

_TECHNIQUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


class ManifestAuthorizationError(ValueError):
    """Raised when a valid manifest does not authorize the requested operation."""


class ManifestVerificationError(ValueError):
    """Raised when a manifest signature, digest, or trusted key is invalid."""


class ManifestRevocationError(ManifestAuthorizationError):
    """Raised when an otherwise-valid manifest has been revoked and must not be reused."""


class EngagementManifest(OlympusModel):
    """Immutable authorization boundary for one time-limited engagement."""

    schema_name: Literal["olympus.engagement-manifest"] = "olympus.engagement-manifest"
    manifest_id: str = Field(default_factory=lambda: new_id("manifest"))
    engagement_id: str
    client: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    approver: str = Field(min_length=1, max_length=200)
    contract_id: str = Field(min_length=1, max_length=200)
    scope: EngagementScope
    valid_from: datetime
    expires_at: datetime
    allowed_techniques: tuple[str, ...] = Field(min_length=1, max_length=128)
    #: Optional ceiling on how intrusive an authorized operation may be (SEC-G).
    #: When set, an operation whose risk class exceeds it is refused even if its
    #: technique is listed — so an ``intrusive`` capability runs only when the
    #: manifest explicitly raises the ceiling to ``intrusive``. Left unset (the
    #: default), the risk gate is not applied and only technique/scope/time bound
    #: the operation; the field is omitted from the signed bytes when unset, so it
    #: is a backward-compatible, additive extension that never invalidates an
    #: existing signature.
    allowed_risk: RiskClass | None = None
    max_targets: int = Field(default=1, ge=1, le=10_000)
    max_concurrency: int = Field(default=1, ge=1, le=64)
    max_runtime_seconds: int = Field(default=300, ge=1, le=86_400)

    @field_validator("engagement_id")
    @classmethod
    def _validate_engagement_id(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not is_canonical_engagement_id(cleaned):
            raise ValueError("engagement_id must use ENG-YYYY-NNNNN format")
        return cleaned

    @field_validator("allowed_techniques")
    @classmethod
    def _validate_techniques(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({item.strip() for item in value}))
        if not normalized or any(_TECHNIQUE_RE.fullmatch(item) is None for item in normalized):
            raise ValueError("allowed_techniques must contain valid, non-empty identifiers")
        return normalized

    @model_validator(mode="after")
    def _validate_window(self) -> EngagementManifest:
        if self.valid_from.tzinfo is None or self.valid_from.utcoffset() is None:
            raise ValueError("valid_from must include a timezone")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        if self.valid_from >= self.expires_at:
            raise ValueError("expires_at must be later than valid_from")
        return self

    def canonical_json(self) -> str:
        """Return the deterministic JSON bytes that are covered by the signature.

        ``exclude_none`` keeps additive optional fields (e.g. ``allowed_risk``) out
        of the signed bytes when unset, so a manifest signed before such a field
        existed produces identical bytes and its signature still verifies.
        """
        return json.dumps(
            self.model_dump(mode="json", exclude_none=True), sort_keys=True, separators=(",", ":")
        )

    def digest(self) -> str:
        """Return the SHA-256 digest of the canonical manifest."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def authorizes(
        self, *, target: str, technique: str, now: datetime, risk: RiskClass | None = None
    ) -> bool:
        """Check time window, exact technique, normalized host scope and risk ceiling.

        When both ``risk`` (the operation's class) and this manifest's
        ``allowed_risk`` ceiling are set, the operation is authorized only if its
        risk is within that ceiling, so an intrusive capability runs only under a
        manifest that explicitly permits it. A missing ceiling or a missing
        operation risk leaves the behaviour unchanged (technique/scope/time only).
        """
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must include a timezone")
        instant = now.astimezone(UTC)
        if (
            self.allowed_risk is not None
            and risk is not None
            and not risk_within(risk, self.allowed_risk)
        ):
            return False
        return (
            self.valid_from.astimezone(UTC) <= instant < self.expires_at.astimezone(UTC)
            and technique in self.allowed_techniques
            and self.scope.covers(target)
        )


class SignedEngagementManifest(OlympusModel):
    """A manifest plus its detached Ed25519 signature and pinned digest."""

    schema_name: Literal["olympus.signed-engagement-manifest"] = (
        "olympus.signed-engagement-manifest"
    )
    manifest: EngagementManifest
    manifest_sha256: str = Field(pattern=_DIGEST_RE.pattern)
    signature_envelope: str = Field(min_length=1, max_length=10_000)

    @classmethod
    def sign_manifest(
        cls, manifest: EngagementManifest, *, private_key_pem: str
    ) -> SignedEngagementManifest:
        """Sign canonical manifest content using Olympus's vetted Ed25519 wrapper."""
        signature = sign(manifest.canonical_json().encode("utf-8"), private_key_pem)
        return cls(
            manifest=manifest,
            manifest_sha256=manifest.digest(),
            signature_envelope=signature,
        )

    def authorize(
        self,
        *,
        trusted_public_key_pem: str,
        target: str,
        technique: str,
        now: datetime,
        revoked: Collection[str] = (),
        risk: RiskClass | None = None,
    ) -> EngagementManifest:
        """Verify signature and enforce the requested operation's manifest bounds.

        ``revoked`` is the operator's revocation list: a manifest is rejected when
        any of its identifiers — the signed digest, the ``manifest_id`` or the
        ``engagement_id`` — appears in it, so a revoked authorization cannot be
        reused even while still inside its time window. Revocation is checked only
        after signature and digest verification, so it never masks a tampered or
        unsigned manifest.
        """
        self.verify_signature(trusted_public_key_pem=trusted_public_key_pem)
        if (
            not isinstance(revoked, Collection)
            or isinstance(revoked, str)
            or any(
                not isinstance(identifier, str) or not identifier.strip() for identifier in revoked
            )
        ):
            raise ManifestAuthorizationError(
                "revocation identifiers must be supplied as a collection of non-empty strings"
            )
        identifiers = {self.manifest_sha256, self.manifest.manifest_id, self.manifest.engagement_id}
        if identifiers & set(revoked):
            raise ManifestRevocationError(
                "manifest has been revoked and cannot authorize operations"
            )
        if not self.manifest.authorizes(target=target, technique=technique, now=now, risk=risk):
            raise ManifestAuthorizationError(
                "manifest does not authorize this target, technique, time, or risk class"
            )
        return self.manifest

    def verify_signature(self, *, trusted_public_key_pem: str) -> None:
        """Verify content integrity and the signature against a pinned public key."""
        if self.manifest.digest() != self.manifest_sha256:
            raise ManifestVerificationError("manifest digest does not match its signed content")
        try:
            signature_valid = verify(
                self.manifest.canonical_json().encode("utf-8"),
                self.signature_envelope,
                public_pem=trusted_public_key_pem,
            )
        except SigningError as exc:
            raise ManifestVerificationError("manifest signature verification failed") from exc
        if not signature_valid:
            raise ManifestVerificationError("manifest signature is invalid")

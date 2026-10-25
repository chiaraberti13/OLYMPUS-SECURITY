"""Offline-first OIDC bearer verification for the Themis control plane.

The verifier deliberately performs no discovery or network access. Operators
pin an issuer, audience and a local JWKS file; key updates are therefore an
explicit deployment operation with an auditable artifact.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import jwt

from olympus.core.fileio import read_regular_text

MAX_JWKS_BYTES = 1_000_000
MAX_KEYS = 64
MAX_TOKEN_BYTES = 16 * 1024
ALLOWED_ALGORITHMS = ("RS256", "ES256", "EdDSA")


class OidcError(ValueError):
    """Raised when pinned OIDC configuration or a bearer token is invalid."""


class OidcVerifier:
    """Verify JWT access tokens against an explicitly pinned local JWKS."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_path: Path,
        max_token_lifetime_seconds: int = 3_600,
    ) -> None:
        parsed = urlsplit(issuer)
        if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            raise OidcError("OIDC issuer must be an absolute HTTPS URL without query or fragment")
        if not audience or len(audience) > 256:
            raise OidcError("OIDC audience must contain 1-256 characters")
        if not 60 <= max_token_lifetime_seconds <= 86_400:
            raise OidcError("OIDC maximum token lifetime must be between 60 and 86400 seconds")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.max_token_lifetime_seconds = max_token_lifetime_seconds
        self._keys = self._load_keys(jwks_path)

    @staticmethod
    def _load_keys(path: Path) -> dict[str, jwt.PyJWK]:
        raw = read_regular_text(path, max_bytes=MAX_JWKS_BYTES, label="OIDC JWKS")
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OidcError(f"invalid OIDC JWKS JSON: {exc.msg}") from exc
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
            raise OidcError(f"OIDC JWKS must contain 1-{MAX_KEYS} keys")
        loaded: dict[str, jwt.PyJWK] = {}
        for item in keys:
            if not isinstance(item, dict):
                raise OidcError("OIDC JWKS keys must be objects")
            kid = item.get("kid")
            algorithm = item.get("alg")
            if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
                raise OidcError("every OIDC JWK needs a bounded kid")
            if kid in loaded:
                raise OidcError(f"duplicate OIDC JWK kid: {kid}")
            if algorithm not in ALLOWED_ALGORITHMS or item.get("use", "sig") != "sig":
                raise OidcError("OIDC JWK must be a signing key with an allowed asymmetric alg")
            try:
                loaded[kid] = jwt.PyJWK.from_dict(item, algorithm=algorithm)
            except (jwt.PyJWKError, ValueError, TypeError) as exc:
                raise OidcError(f"invalid OIDC JWK {kid}") from exc
        return loaded

    def verify(self, token: str, *, moment: datetime | None = None) -> str:
        """Return the stable subject after signature and claim validation."""
        try:
            token_size = len(token.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise OidcError("OIDC bearer token is not valid UTF-8") from exc
        if not token or token_size > MAX_TOKEN_BYTES:
            raise OidcError("OIDC bearer token is empty or too large")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OidcError("invalid OIDC bearer header") from exc
        kid = header.get("kid")
        algorithm = header.get("alg")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None or algorithm not in ALLOWED_ALGORITHMS or algorithm != key.algorithm_name:
            raise OidcError("OIDC bearer key or algorithm is not trusted")
        now = moment or datetime.now(UTC)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=[algorithm],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                leeway=0,
            )
        except jwt.PyJWTError as exc:
            raise OidcError("OIDC bearer signature or claims are invalid") from exc
        subject = claims.get("sub")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        if not isinstance(subject, str) or not subject or len(subject) > 128:
            raise OidcError("OIDC subject is missing or invalid")
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, (int, float))
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
        ):
            raise OidcError("OIDC token timestamps are invalid")
        lifetime = float(expires_at) - float(issued_at)
        if lifetime <= 0 or lifetime > self.max_token_lifetime_seconds:
            raise OidcError("OIDC token lifetime exceeds the configured bound")
        if float(issued_at) > now.timestamp():
            raise OidcError("OIDC token was issued in the future")
        return subject

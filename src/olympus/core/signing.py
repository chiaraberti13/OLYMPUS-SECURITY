"""Ed25519 detached signatures for third-party verifiable provenance.

HMAC (see :mod:`olympus.minerva.custody`) proves integrity to anyone who holds
the *shared secret* — it cannot give an outside auditor independent assurance,
because verifying requires the same key that could have signed. Ed25519 closes
that: the operator signs with a **private** key, and anyone can verify with the
**public** key alone. That makes it the right tool for provenance on artifacts a
third party must trust — a custody ledger, an evidence file, an SBOM, a report.

This is a thin, safe wrapper over the vetted ``cryptography`` library — never
hand-rolled. A signature is a self-describing JSON envelope:

    {"scheme": "olympus.sig.v1", "algorithm": "Ed25519",
     "public_key": "<PEM>", "signature": "<base64>"}

The public key travels inside the envelope for convenience, but verification is
**pinned**: :func:`verify` requires the caller to supply the public key they
trust and rejects the signature unless the embedded key matches it. Without that
pin an attacker could re-sign tampered data with their own keypair and swap the
embedded key, so an unpinned "valid signature" would be meaningless.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_SCHEME = "olympus.sig.v1"
SIGNATURE_ALGORITHM = "Ed25519"


class SigningError(ValueError):
    """Raised when a key is invalid, or a signature fails to verify."""


def generate_keypair() -> tuple[str, str]:
    """Return a fresh ``(private_pem, public_pem)`` Ed25519 keypair as PEM text.

    The private key is unencrypted PKCS#8 PEM — write it to an owner-only file and
    protect it; the public key is safe to distribute to verifiers.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def _load_private(private_pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(f"invalid Ed25519 private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private key is not an Ed25519 key")
    return key


def _load_public(public_pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise SigningError(f"invalid Ed25519 public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("public key is not an Ed25519 key")
    return key


def _public_pem_of(private_key: Ed25519PrivateKey) -> str:
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _raw_public(public_pem: str) -> bytes:
    return _load_public(public_pem).public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def sign(data: bytes, private_pem: str) -> str:
    """Sign ``data`` with an Ed25519 private key; return a JSON signature envelope."""
    private_key = _load_private(private_pem)
    signature = private_key.sign(data)
    envelope = {
        "scheme": SIGNATURE_SCHEME,
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key": _public_pem_of(private_key),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def verify(data: bytes, envelope_text: str, *, public_pem: str) -> bool:
    """Verify a signature envelope against ``data`` and a **trusted** public key.

    Returns ``True`` only when the envelope's embedded public key matches
    ``public_pem`` (the key the caller trusts) *and* the signature is valid for
    ``data``. Raises :class:`SigningError` on a malformed envelope or a key/scheme
    mismatch; returns ``False`` only for a well-formed-but-invalid signature.
    """
    try:
        envelope: Any = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise SigningError(f"invalid signature envelope: {exc.msg}") from exc
    if not isinstance(envelope, dict) or envelope.get("scheme") != SIGNATURE_SCHEME:
        raise SigningError("not an Olympus signature envelope")
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise SigningError(f"unsupported signature algorithm: {envelope.get('algorithm')!r}")
    embedded = envelope.get("public_key")
    if not isinstance(embedded, str):
        raise SigningError("signature envelope has no public_key")
    if _raw_public(embedded) != _raw_public(public_pem):
        raise SigningError(
            "signature was made by a different key than the trusted public key"
        )
    try:
        signature = base64.b64decode(str(envelope["signature"]))
    except (KeyError, ValueError) as exc:
        raise SigningError(f"malformed signature envelope: {exc}") from exc
    try:
        _load_public(public_pem).verify(signature, data)
    except InvalidSignature:
        return False
    return True

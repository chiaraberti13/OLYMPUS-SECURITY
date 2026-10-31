"""At-rest authenticated encryption policy for finding data (ROADMAP ``SEC-E``).

Findings are sensitive: they record a target's exposed vulnerabilities, software
versions and reachable hosts. This module is the **single source** of the finding
encryption-key policy — its environment-variable name, its minimum length and how
it is resolved through the :class:`~olympus.core.secrets.SecretProvider` port
(``SEC-D``) — shared by every place findings are persisted at rest:

* the append-only lifecycle **transition store** (per record), and
* the immutable finding/asset JSON **bundles** that producers (scanners, Athena)
  emit and the CLI and Web UI consume.

The cryptography itself is delegated to :mod:`olympus.core.crypto` (Fernet over
an scrypt-derived key — authenticated, vetted, never hand-rolled). The key is
*separable* from the data: it lives only in the operator's environment or keyring
and never travels inside the ciphertext envelope.

Reads are **fail-closed**: an encrypted document presented without a key, with a
wrong key, or with a tampered ciphertext raises rather than returning partial or
guessed plaintext. Plaintext (legacy, unencrypted) documents keep reading
unchanged, so enabling encryption never strands already-written bundles.
"""

from __future__ import annotations

import json

from pydantic import SecretStr

from olympus.core.crypto import ENCRYPTION_SCHEME, CryptoError, decrypt_to_text, encrypt_text
from olympus.core.secrets import SecretProvider, resolve_secret

#: Environment variable holding the symmetric key that protects findings at rest.
#: One key unlocks every finding artifact an operator stores, so the lifecycle
#: store and the bundle path deliberately share it rather than minting two.
FINDINGS_ENCRYPTION_KEY_ENV = "OLYMPUS_FINDINGS_ENCRYPTION_KEY"

#: Minimum operator key length. scrypt stretches the key, but a short passphrase
#: is still weak, so it is refused loudly at load time rather than silently used.
MIN_ENCRYPTION_KEY_LENGTH = 32


class FindingsEncryptionError(ValueError):
    """Raised when the finding-at-rest key is misconfigured or decryption fails."""


def load_findings_encryption_key(provider: SecretProvider | None = None) -> SecretStr | None:
    """Return the configured findings key, or ``None`` when none is set.

    Resolves through the ``SecretProvider`` port (the process environment by
    default). A key shorter than :data:`MIN_ENCRYPTION_KEY_LENGTH` is rejected so
    a weak key cannot be adopted by accident.
    """
    key = resolve_secret(FINDINGS_ENCRYPTION_KEY_ENV, provider=provider)
    if key is not None and len(key.get_secret_value()) < MIN_ENCRYPTION_KEY_LENGTH:
        raise FindingsEncryptionError(
            f"{FINDINGS_ENCRYPTION_KEY_ENV} must contain at least "
            f"{MIN_ENCRYPTION_KEY_LENGTH} characters"
        )
    return key


def is_encryption_envelope(raw: object) -> bool:
    """Return whether an already-parsed JSON value is an Olympus encryption envelope.

    A structural probe (not a decrypt): callers that have parsed a document once
    use it to decide whether to decrypt, so a plaintext bundle whose own data
    happens to mention a scheme string is never mistaken for an envelope — only a
    top-level object carrying this exact ``scheme`` qualifies.
    """
    return isinstance(raw, dict) and raw.get("scheme") == ENCRYPTION_SCHEME


def encrypt_findings_document(plaintext: str, *, provider: SecretProvider | None = None) -> str:
    """Encrypt a finding/asset document into a self-describing envelope string.

    Fail-closed: encryption requires a configured key, so a caller can never
    believe it wrote protected data when no key was set.
    """
    key = load_findings_encryption_key(provider)
    if key is None:
        raise FindingsEncryptionError(
            f"encrypting finding data requires {FINDINGS_ENCRYPTION_KEY_ENV}"
        )
    return encrypt_text(plaintext, key.get_secret_value())


def decrypt_findings_document(
    envelope_text: str,
    *,
    provider: SecretProvider | None = None,
    max_bytes: int | None = None,
) -> str:
    """Decrypt an envelope produced by :func:`encrypt_findings_document`.

    Fail-closed on every error path: a missing key, a wrong key, a tampered
    ciphertext, or decrypted plaintext larger than ``max_bytes`` all raise
    :class:`FindingsEncryptionError` instead of yielding partial data.
    """
    key = load_findings_encryption_key(provider)
    if key is None:
        raise FindingsEncryptionError(
            f"decrypting finding data requires {FINDINGS_ENCRYPTION_KEY_ENV}"
        )
    try:
        plaintext = decrypt_to_text(envelope_text, key.get_secret_value())
    except CryptoError as exc:
        raise FindingsEncryptionError(
            "finding decryption failed: wrong key or corrupted data"
        ) from exc
    if max_bytes is not None and len(plaintext.encode("utf-8")) > max_bytes:
        raise FindingsEncryptionError("decrypted finding data exceeds the size limit")
    return plaintext


def looks_encrypted(text: str) -> bool:
    """Return whether raw ``text`` parses to an Olympus encryption envelope.

    Convenience for callers that hold only the file text (and have not parsed it):
    invalid JSON is simply not an envelope.
    """
    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False
    return is_encryption_envelope(raw)

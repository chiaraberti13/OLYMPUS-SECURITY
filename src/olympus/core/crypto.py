"""Authenticated symmetric encryption for sensitive data at rest.

This is a thin, safe wrapper over a vetted library — never hand-rolled crypto.
It uses **Fernet** (AES-128 in CBC with an HMAC-SHA256 authentication tag, from
``cryptography``) with a per-message key derived from an operator passphrase via
**scrypt**. Authentication means a tampered or truncated ciphertext is rejected
on decrypt rather than silently mis-decrypted, and the random per-message salt
means the same plaintext under the same passphrase encrypts differently each
time.

The output is a self-describing JSON envelope (so the parameters travel with the
data and a future scheme can be told apart), safe to write as text:

    {"scheme": "olympus.enc.v1", "kdf": "scrypt",
     "n": 32768, "r": 8, "p": 1, "salt": "<b64>", "ciphertext": "<fernet token>"}

The passphrase is never stored; only the salt is. A wrong passphrase, or any
corruption, raises :class:`CryptoError`.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ENCRYPTION_SCHEME = "olympus.enc.v1"

#: scrypt work factors. n must be a power of two; these are a sensible
#: interactive-use default (~tens of ms) and are recorded in the envelope so
#: decryption uses whatever the ciphertext was produced with.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH = 32
_SALT_BYTES = 16

#: Hard ceilings on the KDF parameters accepted from an (untrusted) envelope, so
#: a hostile document cannot turn decryption into a memory bomb. scrypt uses
#: roughly 128 * n * r bytes; the product cap below bounds that to ~1 GiB, and
#: n must additionally be a power of two (scrypt requires it).
_MAX_SCRYPT_N = 2**21
_MAX_SCRYPT_R = 32
_MAX_SCRYPT_P = 16
_MAX_SCRYPT_MEMORY = 1024 * 1024 * 1024  # 128 * n * r ceiling
_MAX_SALT_BYTES = 1024


class CryptoError(ValueError):
    """Raised when decryption fails (wrong passphrase or corrupted data)."""


def _validate_passphrase(passphrase: str) -> bytes:
    if not passphrase or len(passphrase) < 1:
        raise CryptoError("passphrase must not be empty")
    return passphrase.encode("utf-8")


def _validate_kdf_params(n: int, r: int, p: int, salt: bytes) -> None:
    """Reject KDF parameters that are unsafe or a memory-exhaustion vector.

    Called on the values read from an untrusted envelope before any scrypt work,
    so a hostile document cannot make decryption allocate unbounded memory.
    """
    if not (1 <= r <= _MAX_SCRYPT_R and 1 <= p <= _MAX_SCRYPT_P):
        raise CryptoError("encryption envelope has out-of-range KDF parameters")
    if n < 2 or n > _MAX_SCRYPT_N or (n & (n - 1)) != 0:
        raise CryptoError("encryption envelope has an invalid scrypt n (must be a power of two)")
    if 128 * n * r > _MAX_SCRYPT_MEMORY:
        raise CryptoError("encryption envelope requests too much KDF memory")
    if not 1 <= len(salt) <= _MAX_SALT_BYTES:
        raise CryptoError("encryption envelope has an out-of-range salt")


def _derive_fernet_key(passphrase: bytes, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LENGTH, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(passphrase))


def encrypt_bytes(plaintext: bytes, passphrase: str) -> str:
    """Encrypt ``plaintext`` under ``passphrase`` into a JSON envelope string."""
    secret = _validate_passphrase(passphrase)
    salt = _random_salt()
    key = _derive_fernet_key(secret, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    token = Fernet(key).encrypt(plaintext)
    envelope = {
        "scheme": ENCRYPTION_SCHEME,
        "kdf": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": token.decode("ascii"),
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


def decrypt_to_bytes(envelope_text: str, passphrase: str) -> bytes:
    """Decrypt a JSON envelope produced by :func:`encrypt_bytes`."""
    secret = _validate_passphrase(passphrase)
    try:
        envelope: Any = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        raise CryptoError(f"invalid encryption envelope: {exc.msg}") from exc
    if not isinstance(envelope, dict) or envelope.get("scheme") != ENCRYPTION_SCHEME:
        raise CryptoError("not an Olympus encryption envelope")
    try:
        salt = base64.b64decode(envelope["salt"])
        token = str(envelope["ciphertext"]).encode("ascii")
        n = int(envelope["n"])
        r = int(envelope["r"])
        p = int(envelope["p"])
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError(f"malformed encryption envelope: {exc}") from exc
    _validate_kdf_params(n, r, p, salt)
    key = _derive_fernet_key(secret, salt, n=n, r=r, p=p)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise CryptoError("decryption failed: wrong passphrase or corrupted data") from exc


def encrypt_text(plaintext: str, passphrase: str) -> str:
    """Encrypt UTF-8 text into a JSON envelope string."""
    return encrypt_bytes(plaintext.encode("utf-8"), passphrase)


def decrypt_to_text(envelope_text: str, passphrase: str) -> str:
    """Decrypt a JSON envelope to UTF-8 text."""
    try:
        return decrypt_to_bytes(envelope_text, passphrase).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("decrypted data is not valid UTF-8") from exc


def _random_salt() -> bytes:
    import os

    return os.urandom(_SALT_BYTES)

"""Authenticated, bounded storage for sensitive Minerva evidence artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from olympus.core.crypto import CryptoError, decrypt_to_bytes, encrypt_bytes
from olympus.core.evidence import DEFAULT_MAX_ARTIFACT_BYTES, evidence_from_bytes
from olympus.core.fileio import (
    atomic_write_bytes,
    atomic_write_text,
    ensure_write_target,
    read_regular_bytes,
    read_regular_text,
)
from olympus.core.models import Evidence
from olympus.core.retention import secure_delete
from olympus.core.secrets import SecretProvider, resolve_secret

EVIDENCE_ENCRYPTION_KEY_ENV = "OLYMPUS_EVIDENCE_ENCRYPTION_KEY"
PROTECTED_EVIDENCE_VERSION = "olympus.minerva.protected-evidence.v1"
DEFAULT_MAX_PROTECTED_BYTES = 400 * 1024 * 1024
_MAGIC = b"OLYMPUS-EVIDENCE\x00\x01"
_MAX_HEADER_BYTES = 64 * 1024
_MIN_SECRET_LENGTH = 32


class ProtectedEvidenceError(ValueError):
    """Raised when a protected evidence package is invalid or cannot be verified."""


class _ProtectedMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["olympus.minerva.protected-evidence.v1"] = (
        "olympus.minerva.protected-evidence.v1"
    )
    evidence: Evidence
    content_length: int = Field(ge=0, le=DEFAULT_MAX_ARTIFACT_BYTES)


class EvidenceDeletionReceipt(BaseModel):
    """Minimal receipt proving which verified package preceded source deletion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.evidence-deletion-receipt"] = "olympus.evidence-deletion-receipt"
    evidence_id: str
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    protected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    bytes_removed: int = Field(ge=0)
    storage_erasure_guaranteed: Literal[False] = False
    limitation: str = (
        "File overwrite/unlink cannot guarantee erasure from snapshots, backups, "
        "copy-on-write filesystems, SSD wear levelling, or replicas."
    )


def load_evidence_encryption_key(*, provider: SecretProvider | None = None) -> str:
    """Resolve the runtime encryption secret, failing closed on weak/missing values."""
    secret = resolve_secret(EVIDENCE_ENCRYPTION_KEY_ENV, provider=provider)
    if secret is None:
        raise ProtectedEvidenceError(f"{EVIDENCE_ENCRYPTION_KEY_ENV} is required")
    value = secret.get_secret_value()
    if len(value) < _MIN_SECRET_LENGTH:
        raise ProtectedEvidenceError(
            f"{EVIDENCE_ENCRYPTION_KEY_ENV} must contain at least {_MIN_SECRET_LENGTH} characters"
        )
    return value


def _pack(metadata: _ProtectedMetadata, content: bytes) -> bytes:
    header = metadata.model_dump_json().encode("utf-8")
    if not 1 <= len(header) <= _MAX_HEADER_BYTES:
        raise ProtectedEvidenceError("protected evidence metadata exceeds the allowed size")
    return _MAGIC + len(header).to_bytes(4, "big") + header + content


def _unpack(payload: bytes) -> tuple[_ProtectedMetadata, bytes]:
    prefix = len(_MAGIC) + 4
    if len(payload) < prefix or payload[: len(_MAGIC)] != _MAGIC:
        raise ProtectedEvidenceError("invalid protected evidence framing")
    header_length = int.from_bytes(payload[len(_MAGIC) : prefix], "big")
    if not 1 <= header_length <= _MAX_HEADER_BYTES or len(payload) < prefix + header_length:
        raise ProtectedEvidenceError("invalid protected evidence metadata length")
    try:
        metadata = _ProtectedMetadata.model_validate_json(payload[prefix : prefix + header_length])
    except ValueError as exc:
        raise ProtectedEvidenceError("invalid protected evidence metadata") from exc
    content = payload[prefix + header_length :]
    if len(content) != metadata.content_length:
        raise ProtectedEvidenceError("protected evidence content length mismatch")
    digest = hashlib.sha256(content).hexdigest()
    if digest != metadata.evidence.sha256.lower():
        raise ProtectedEvidenceError("protected evidence digest mismatch")
    return metadata, content


def load_protected_evidence(
    protected: Path,
    *,
    provider: SecretProvider | None = None,
    max_bytes: int = DEFAULT_MAX_PROTECTED_BYTES,
) -> tuple[Evidence, bytes]:
    """Authenticate, decrypt and validate one bounded protected evidence package."""
    envelope = read_regular_text(protected, max_bytes=max_bytes, label="protected evidence")
    try:
        plaintext = decrypt_to_bytes(envelope, load_evidence_encryption_key(provider=provider))
    except CryptoError as exc:
        raise ProtectedEvidenceError(str(exc)) from exc
    metadata, content = _unpack(plaintext)
    return metadata.evidence, content


def protect_evidence(
    artifact: Path,
    output: Path,
    *,
    evidence_type: str,
    uri: str | None = None,
    provider: SecretProvider | None = None,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    overwrite: bool = False,
    delete_source: bool = False,
    receipt_path: Path | None = None,
) -> Evidence:
    """Encrypt evidence and optionally remove its source after round-trip verification."""
    if artifact.resolve() == output.resolve():
        raise ProtectedEvidenceError("source and protected output must be different files")
    if receipt_path is not None and not delete_source:
        raise ProtectedEvidenceError("a deletion receipt requires delete_source=True")
    if receipt_path is not None and receipt_path.resolve() in {
        artifact.resolve(),
        output.resolve(),
    }:
        raise ProtectedEvidenceError("receipt, source and protected output must be different files")
    ensure_write_target(output, overwrite=overwrite)
    if receipt_path is not None:
        ensure_write_target(receipt_path, overwrite=overwrite)
    content = read_regular_bytes(artifact, max_bytes=max_bytes, label="evidence artifact")
    evidence = evidence_from_bytes(
        content,
        evidence_type=evidence_type,
        uri=uri if uri is not None else artifact.resolve().as_uri(),
    )
    metadata = _ProtectedMetadata(evidence=evidence, content_length=len(content))
    envelope = encrypt_bytes(
        _pack(metadata, content), load_evidence_encryption_key(provider=provider)
    )
    atomic_write_text(output, envelope, mode=0o600, overwrite=overwrite)

    # A source is removed only after the published ciphertext can be independently
    # authenticated and produces the exact captured bytes again.
    verified_evidence, verified_content = load_protected_evidence(output, provider=provider)
    if verified_evidence != evidence or verified_content != content:
        raise ProtectedEvidenceError("protected evidence round-trip verification failed")
    if delete_source:
        protected_bytes = read_regular_bytes(
            output, max_bytes=DEFAULT_MAX_PROTECTED_BYTES, label="protected evidence"
        )
        removed = secure_delete(artifact)
        if receipt_path is not None:
            receipt = EvidenceDeletionReceipt(
                evidence_id=evidence.evidence_id,
                evidence_sha256=evidence.sha256.lower(),
                protected_sha256=hashlib.sha256(protected_bytes).hexdigest(),
                bytes_removed=removed,
            )
            atomic_write_text(
                receipt_path,
                json.dumps(receipt.model_dump(), indent=2, sort_keys=True) + "\n",
                mode=0o600,
                overwrite=overwrite,
            )
    return evidence


def restore_evidence(
    protected: Path,
    output: Path,
    *,
    provider: SecretProvider | None = None,
    max_bytes: int = DEFAULT_MAX_PROTECTED_BYTES,
    overwrite: bool = False,
) -> Evidence:
    """Restore authenticated plaintext with owner-only permissions."""
    if protected.resolve() == output.resolve():
        raise ProtectedEvidenceError("protected input and restored output must be different files")
    ensure_write_target(output, overwrite=overwrite)
    evidence, content = load_protected_evidence(protected, provider=provider, max_bytes=max_bytes)
    atomic_write_bytes(output, content, mode=0o600, overwrite=overwrite)
    return evidence


__all__ = [
    "DEFAULT_MAX_PROTECTED_BYTES",
    "EVIDENCE_ENCRYPTION_KEY_ENV",
    "EvidenceDeletionReceipt",
    "ProtectedEvidenceError",
    "load_evidence_encryption_key",
    "load_protected_evidence",
    "protect_evidence",
    "restore_evidence",
]

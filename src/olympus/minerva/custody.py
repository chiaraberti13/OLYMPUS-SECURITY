"""Tamper-evident, evidence-anchored chain of custody for DFIR material."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.core.models import Evidence
from olympus.core.secrets import SecretProvider, resolve_secret
from olympus.minerva.provenance import AcquisitionProvenance as AcquisitionProvenance

try:  # pragma: no cover - exercised on POSIX; fallback is for Windows
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None  # type: ignore[assignment]

GENESIS_HASH = "0" * 64
CUSTODY_SCHEMA_NAME = "olympus.custody"
CUSTODY_SCHEMA_VERSION = "3.0.0"
SIGNED_CUSTODY_VERSION = "3.1.0"
ED25519_SIGNED_CUSTODY_VERSION = "3.2.0"
UNATTRIBUTED_CUSTODY_VERSION = "2.0.0"
UNATTRIBUTED_SIGNED_CUSTODY_VERSION = "2.1.0"
UNATTRIBUTED_ED25519_SIGNED_CUSTODY_VERSION = "2.2.0"
LEGACY_CUSTODY_VERSION = "1.0.0"
DEFAULT_MAX_LEDGER_BYTES = 50_000_000
DEFAULT_MAX_ENTRIES = 100_000
_PROCESS_LOCK = threading.RLock()

#: HMAC algorithm used to sign a 3.1.0 ledger, and the env var carrying the key.
CUSTODY_HMAC_ALGORITHM: Literal["HMAC-SHA256"] = "HMAC-SHA256"
CUSTODY_KEY_ENV = "OLYMPUS_CUSTODY_HMAC_KEY"

#: Ed25519 signs a 3.2.0 ledger with an *asymmetric* key, so a third party can
#: verify the chain with only the public key — exactly what a court-grade chain
#: of custody needs (``SEC-E``). The private key is a secret (resolved through the
#: ``SecretProvider`` seam); the public key is not and is read plainly.
CUSTODY_ED25519_ALGORITHM: Literal["Ed25519"] = "Ed25519"
CUSTODY_ED25519_PRIVATE_KEY_ENV = "OLYMPUS_CUSTODY_ED25519_PRIVATE_KEY"
CUSTODY_ED25519_PUBLIC_KEY_ENV = "OLYMPUS_CUSTODY_ED25519_PUBLIC_KEY"


class CustodyAction(StrEnum):
    """Allowed evidence custody transitions."""

    COLLECTED = "collected"
    TRANSFERRED = "transferred"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"


class _EntryBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1)
    evidence_id: str = Field(pattern=r"^EVD-\d{4}-\d{5}$")
    action: CustodyAction
    actor: str = Field(min_length=1, max_length=200)
    occurred_at: datetime
    previous_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    entry_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("actor")
    @classmethod
    def _safe_actor(cls, value: str) -> str:
        if value != value.strip() or any(character in value for character in "\r\n\x00"):
            raise ValueError("actor must be trimmed single-line text without NUL")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value.astimezone(UTC)


class CustodyEntry(_EntryBase):
    """One immutable custody event anchored to the evidence digest."""

    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    acquisition: AcquisitionProvenance | None = None

    @field_validator("evidence_sha256")
    @classmethod
    def _lowercase_digest(cls, value: str) -> str:
        if value != value.lower():
            raise ValueError("evidence_sha256 must be lowercase")
        return value


class LegacyCustodyEntry(_EntryBase):
    """Read-only v1 entry; the format did not anchor an evidence digest."""


CustodyRecord = CustodyEntry | LegacyCustodyEntry


class _CustodyLedgerV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.custody"]
    schema_version: Literal["2.0.0", "3.0.0"]
    entries: list[CustodyEntry]


class _CustodyLedgerV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.custody"]
    schema_version: Literal["1.0.0"]
    entries: list[LegacyCustodyEntry]


class CustodySignature(BaseModel):
    """HMAC over the ledger head, binding the whole chain and its length.

    The signature covers ``entry_count`` and ``head_hash`` (the last entry's
    ``entry_hash``, which already chains in every prior entry). An attacker who
    rewrites the ledger can recompute every ``entry_hash`` and a consistent head,
    but cannot recompute this value without the key; dropping entries changes the
    count and head, so a truncation invalidates it too. These are exactly the two
    attacks a bare hash chain cannot catch on its own.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["HMAC-SHA256"]
    entry_count: int = Field(ge=1)
    head_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    value: str = Field(pattern=r"^[a-f0-9]{64}$")


class _CustodyLedgerV2Signed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.custody"]
    schema_version: Literal["2.1.0", "3.1.0"]
    entries: list[CustodyEntry]
    signature: CustodySignature


class CustodyEd25519Signature(BaseModel):
    """Ed25519 signature over the ledger head, verifiable by a third party.

    Unlike the HMAC signature, verification needs only the ``public_key`` carried
    here (and an out-of-band trust anchor to compare it against), never the secret
    signing key. It commits to ``entry_count`` and ``head_hash`` for the same
    reasons as :class:`CustodySignature`, so truncation and rewrite are caught.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: Literal["Ed25519"]
    entry_count: int = Field(ge=1)
    head_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    #: Raw 32-byte Ed25519 public key, hex-encoded (64 chars).
    public_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    #: Raw 64-byte Ed25519 signature, hex-encoded (128 chars).
    value: str = Field(pattern=r"^[a-f0-9]{128}$")


class _CustodyLedgerV2Ed25519Signed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.custody"]
    schema_version: Literal["2.2.0", "3.2.0"]
    entries: list[CustodyEntry]
    signature: CustodyEd25519Signature


class CustodyIntegrityError(ValueError):
    """Raised when a ledger is malformed or its hash/state chain is invalid."""


class CustodyKeyError(ValueError):
    """Raised when a signing key is required but absent, or malformed."""


@dataclass(frozen=True)
class LedgerInspection:
    entries: tuple[CustodyRecord, ...]
    schema_version: str
    evidence_anchored: bool
    signed: bool = False
    signature_verified: bool = False
    #: ``"HMAC-SHA256"``, ``"Ed25519"`` or ``None`` for an unsigned ledger.
    signature_algorithm: str | None = None


def _entry_hash(
    sequence: int,
    evidence_id: str,
    evidence_sha256: str,
    action: CustodyAction,
    actor: str,
    occurred_at: datetime,
    previous_hash: str,
    acquisition: AcquisitionProvenance | None = None,
) -> str:
    payload: dict[str, Any] = {
        "action": action.value,
        "actor": actor,
        "evidence_id": evidence_id,
        "evidence_sha256": evidence_sha256,
        "occurred_at": occurred_at.astimezone(UTC).isoformat(),
        "previous_hash": previous_hash,
        "sequence": sequence,
    }
    if acquisition is not None:
        payload["acquisition"] = acquisition.model_dump(mode="json")
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _legacy_entry_hash(entry: LegacyCustodyEntry) -> str:
    payload = {
        "action": entry.action.value,
        "actor": entry.actor,
        "evidence_id": entry.evidence_id,
        "occurred_at": entry.occurred_at.astimezone(UTC).isoformat(),
        "previous_hash": entry.previous_hash,
        "sequence": entry.sequence,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_custody_key(env: dict[str, str] | None = None) -> bytes | None:
    """Return the HMAC signing key from the environment, or ``None`` if unset.

    The key is read from ``OLYMPUS_CUSTODY_HMAC_KEY`` as UTF-8 text (a
    passphrase). An empty or whitespace-only value is treated as unset so a
    blank export does not silently produce a weak key.
    """
    source = env if env is not None else os.environ
    raw = source.get(CUSTODY_KEY_ENV, "").strip()
    return raw.encode("utf-8") if raw else None


def _signature_payload(entry_count: int, head_hash: str, schema_version: str) -> bytes:
    """Canonical bytes the HMAC is computed over."""
    payload = {
        "algorithm": CUSTODY_HMAC_ALGORITHM,
        "entry_count": entry_count,
        "head_hash": head_hash,
        "schema_name": CUSTODY_SCHEMA_NAME,
        "schema_version": schema_version,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _compute_signature(key: bytes, entry_count: int, head_hash: str, schema_version: str) -> str:
    return hmac.new(
        key, _signature_payload(entry_count, head_hash, schema_version), hashlib.sha256
    ).hexdigest()


def _sign_entries(
    key: bytes, entries: list[CustodyEntry], schema_version: str = SIGNED_CUSTODY_VERSION
) -> CustodySignature:
    head_hash = entries[-1].entry_hash
    return CustodySignature(
        algorithm=CUSTODY_HMAC_ALGORITHM,
        entry_count=len(entries),
        head_hash=head_hash,
        value=_compute_signature(key, len(entries), head_hash, schema_version),
    )


def verify_signature(
    key: bytes,
    entries: list[CustodyEntry],
    signature: CustodySignature,
    schema_version: str = SIGNED_CUSTODY_VERSION,
) -> None:
    """Raise :class:`CustodyIntegrityError` if the HMAC or its commitments fail.

    The chain must already be verified (:func:`verify_entries`) so ``entries`` is
    the real, ordered history; this then binds the operator's key to that exact
    history and length.
    """
    if signature.entry_count != len(entries):
        raise CustodyIntegrityError(
            f"signature commits to {signature.entry_count} entries but the ledger has "
            f"{len(entries)} (a truncation or an inserted entry)"
        )
    if signature.head_hash != entries[-1].entry_hash:
        raise CustodyIntegrityError("signature head_hash does not match the ledger head")
    expected = _compute_signature(key, len(entries), entries[-1].entry_hash, schema_version)
    if not hmac.compare_digest(expected, signature.value):
        raise CustodyIntegrityError(
            "custody signature mismatch: wrong key or the ledger was rewritten"
        )


def _ed25519_signature_payload(entry_count: int, head_hash: str, schema_version: str) -> bytes:
    """Canonical bytes the Ed25519 signature is computed over."""
    payload = {
        "algorithm": CUSTODY_ED25519_ALGORITHM,
        "entry_count": entry_count,
        "head_hash": head_hash,
        "schema_name": CUSTODY_SCHEMA_NAME,
        "schema_version": schema_version,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign_entries_ed25519(
    private_key: Ed25519PrivateKey,
    entries: list[CustodyEntry],
    schema_version: str = ED25519_SIGNED_CUSTODY_VERSION,
) -> CustodyEd25519Signature:
    head_hash = entries[-1].entry_hash
    signature = private_key.sign(
        _ed25519_signature_payload(len(entries), head_hash, schema_version)
    )
    public_key = private_key.public_key().public_bytes_raw()
    return CustodyEd25519Signature(
        algorithm=CUSTODY_ED25519_ALGORITHM,
        entry_count=len(entries),
        head_hash=head_hash,
        public_key=public_key.hex(),
        value=signature.hex(),
    )


def verify_ed25519_signature(
    public_key: Ed25519PublicKey,
    entries: list[CustodyEntry],
    signature: CustodyEd25519Signature,
    schema_version: str = ED25519_SIGNED_CUSTODY_VERSION,
) -> None:
    """Raise :class:`CustodyIntegrityError` if the Ed25519 signature fails.

    Verification needs only ``public_key`` — a third party with the published key
    can prove the chain, its length and its head were not altered, without any
    secret. The caller's ``public_key`` is the trust anchor: the key embedded in
    the ledger must equal it, so an attacker cannot re-sign a rewritten ledger
    with their own key and have it accepted.
    """
    if signature.entry_count != len(entries):
        raise CustodyIntegrityError(
            f"signature commits to {signature.entry_count} entries but the ledger has "
            f"{len(entries)} (a truncation or an inserted entry)"
        )
    if signature.head_hash != entries[-1].entry_hash:
        raise CustodyIntegrityError("signature head_hash does not match the ledger head")
    anchor = public_key.public_bytes_raw().hex()
    if not hmac.compare_digest(anchor, signature.public_key):
        raise CustodyIntegrityError(
            "custody signature public key does not match the expected signer"
        )
    try:
        public_key.verify(
            bytes.fromhex(signature.value),
            _ed25519_signature_payload(len(entries), entries[-1].entry_hash, schema_version),
        )
    except InvalidSignature as exc:
        raise CustodyIntegrityError(
            "custody Ed25519 signature mismatch: wrong key or the ledger was rewritten"
        ) from exc


def load_custody_ed25519_private_key(
    *, env: dict[str, str] | None = None, provider: SecretProvider | None = None
) -> Ed25519PrivateKey | None:
    """Return the Ed25519 signing key from ``OLYMPUS_CUSTODY_ED25519_PRIVATE_KEY``.

    The value is a hex-encoded raw 32-byte seed, resolved through the
    :class:`~olympus.core.secrets.SecretProvider` seam (``SEC-D``) because it is a
    secret. ``None`` when unset; a malformed value raises :class:`CustodyKeyError`.
    """
    if env is not None:
        raw = env.get(CUSTODY_ED25519_PRIVATE_KEY_ENV, "").strip()
    else:
        secret = resolve_secret(CUSTODY_ED25519_PRIVATE_KEY_ENV, provider=provider)
        raw = secret.get_secret_value() if secret is not None else ""
    if not raw:
        return None
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
    except (ValueError, TypeError) as exc:
        raise CustodyKeyError(
            f"{CUSTODY_ED25519_PRIVATE_KEY_ENV} must be a hex-encoded 32-byte Ed25519 key"
        ) from exc


def load_custody_ed25519_public_key(env: dict[str, str] | None = None) -> Ed25519PublicKey | None:
    """Return the Ed25519 verification key from ``OLYMPUS_CUSTODY_ED25519_PUBLIC_KEY``.

    A hex-encoded raw 32-byte public key (not a secret, read plainly). ``None``
    when unset; a malformed value raises :class:`CustodyKeyError`.
    """
    source = env if env is not None else os.environ
    raw = source.get(CUSTODY_ED25519_PUBLIC_KEY_ENV, "").strip()
    if not raw:
        return None
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))
    except (ValueError, TypeError) as exc:
        raise CustodyKeyError(
            f"{CUSTODY_ED25519_PUBLIC_KEY_ENV} must be a hex-encoded 32-byte Ed25519 public key"
        ) from exc


def verify_entries(
    entries: list[CustodyEntry],
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    progress_check: Callable[[], None] | None = None,
    require_acquisition: bool = False,
    allow_acquisition: bool = True,
) -> None:
    """Validate ordering, timestamps, hashes, digests and per-evidence state."""
    _validate_entry_limit(max_entries)
    if not entries:
        raise CustodyIntegrityError("custody ledger must contain at least one entry")
    if len(entries) > max_entries:
        raise CustodyIntegrityError(f"custody ledger exceeds the {max_entries} entry limit")
    previous_hash = GENESIS_HASH
    previous_time: datetime | None = None
    states: dict[str, CustodyAction] = {}
    digests: dict[str, str] = {}
    for expected_sequence, entry in enumerate(entries, 1):
        if progress_check is not None:
            progress_check()
        expected_hash = _entry_hash(
            entry.sequence,
            entry.evidence_id,
            entry.evidence_sha256,
            entry.action,
            entry.actor,
            entry.occurred_at,
            entry.previous_hash,
            entry.acquisition,
        )
        if entry.sequence != expected_sequence:
            raise CustodyIntegrityError("custody sequence is not contiguous")
        if entry.previous_hash != previous_hash or entry.entry_hash != expected_hash:
            raise CustodyIntegrityError(f"custody hash mismatch at sequence {entry.sequence}")
        if previous_time is not None and entry.occurred_at < previous_time:
            raise CustodyIntegrityError("custody timestamps are not monotonic")
        prior_action = states.get(entry.evidence_id)
        prior_digest = digests.get(entry.evidence_id)
        if prior_digest is not None and prior_digest != entry.evidence_sha256:
            raise CustodyIntegrityError(
                f"evidence digest changed for {entry.evidence_id} at sequence {entry.sequence}"
            )
        if prior_action is None and entry.action is not CustodyAction.COLLECTED:
            raise CustodyIntegrityError(
                f"first custody action for {entry.evidence_id} must be collected"
            )
        if not allow_acquisition and entry.acquisition is not None:
            raise CustodyIntegrityError("custody 2.x entries cannot contain acquisition provenance")
        if prior_action is None and require_acquisition and entry.acquisition is None:
            raise CustodyIntegrityError(
                f"first custody entry for {entry.evidence_id} requires acquisition provenance"
            )
        if prior_action is not None and entry.acquisition is not None:
            raise CustodyIntegrityError(
                f"acquisition provenance is only valid on the first entry for {entry.evidence_id}"
            )
        if prior_action is not None and entry.action is CustodyAction.COLLECTED:
            raise CustodyIntegrityError(
                f"evidence {entry.evidence_id} was collected more than once"
            )
        if prior_action is CustodyAction.ARCHIVED:
            raise CustodyIntegrityError(f"archived evidence {entry.evidence_id} cannot transition")
        states[entry.evidence_id] = entry.action
        digests[entry.evidence_id] = entry.evidence_sha256
        previous_hash = entry.entry_hash
        previous_time = entry.occurred_at


def _verify_legacy_entries(
    entries: list[LegacyCustodyEntry],
    *,
    max_entries: int,
    progress_check: Callable[[], None] | None,
) -> None:
    _validate_entry_limit(max_entries)
    if not entries:
        raise CustodyIntegrityError("custody ledger must contain at least one entry")
    if len(entries) > max_entries:
        raise CustodyIntegrityError(f"custody ledger exceeds the {max_entries} entry limit")
    previous_hash = GENESIS_HASH
    previous_time: datetime | None = None
    for expected_sequence, entry in enumerate(entries, 1):
        if progress_check is not None:
            progress_check()
        if entry.sequence != expected_sequence:
            raise CustodyIntegrityError("custody sequence is not contiguous")
        if entry.previous_hash != previous_hash or entry.entry_hash != _legacy_entry_hash(entry):
            raise CustodyIntegrityError(f"custody hash mismatch at sequence {entry.sequence}")
        if previous_time is not None and entry.occurred_at < previous_time:
            raise CustodyIntegrityError("custody timestamps are not monotonic")
        previous_hash = entry.entry_hash
        previous_time = entry.occurred_at


def inspect_ledger(
    path: Path,
    *,
    missing_ok: bool = False,
    max_bytes: int = DEFAULT_MAX_LEDGER_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    progress_check: Callable[[], None] | None = None,
    key: bytes | None = None,
    ed25519_public_key: Ed25519PublicKey | None = None,
) -> LedgerInspection:
    """Load and verify a 3.x ledger or a compatible read-only/legacy ledger.

    When the matching key is given and the ledger is signed, the signature is
    verified — a truncation or a full rewrite is caught here. For an Ed25519 ledger
    this is the Ed25519 ``ed25519_public_key`` (third-party verification); for a
    HMAC ledger it is the HMAC ``key``. When the ledger is signed but the key is
    absent, the chain is still verified and the result reports ``signed=True,
    signature_verified=False`` so a caller can refuse to trust it.
    """
    if not path.exists():
        if missing_ok:
            return LedgerInspection((), CUSTODY_SCHEMA_VERSION, True)
        raise CustodyIntegrityError(f"custody ledger does not exist: {path}")
    try:
        payload: Any = json.loads(
            read_regular_text(path, max_bytes=max_bytes, label="custody ledger")
        )
        if not isinstance(payload, dict) or payload.get("schema_name") != CUSTODY_SCHEMA_NAME:
            raise CustodyIntegrityError("invalid custody schema_name")
        version = payload.get("schema_version")
        if version in {
            ED25519_SIGNED_CUSTODY_VERSION,
            UNATTRIBUTED_ED25519_SIGNED_CUSTODY_VERSION,
        }:
            ed_signed = _CustodyLedgerV2Ed25519Signed.model_validate(payload)
            if not ed_signed.entries:
                raise CustodyIntegrityError("custody ledger must contain at least one entry")
            attributed = version == ED25519_SIGNED_CUSTODY_VERSION
            verify_entries(
                ed_signed.entries,
                max_entries=max_entries,
                progress_check=progress_check,
                require_acquisition=attributed,
                allow_acquisition=attributed,
            )
            verified = False
            if ed25519_public_key is not None:
                verify_ed25519_signature(
                    ed25519_public_key,
                    ed_signed.entries,
                    ed_signed.signature,
                    schema_version=version,
                )
                verified = True
            return LedgerInspection(
                tuple(ed_signed.entries),
                version,
                True,
                signed=True,
                signature_verified=verified,
                signature_algorithm=CUSTODY_ED25519_ALGORITHM,
            )
        if version in {SIGNED_CUSTODY_VERSION, UNATTRIBUTED_SIGNED_CUSTODY_VERSION}:
            signed = _CustodyLedgerV2Signed.model_validate(payload)
            if not signed.entries:
                raise CustodyIntegrityError("custody ledger must contain at least one entry")
            attributed = version == SIGNED_CUSTODY_VERSION
            verify_entries(
                signed.entries,
                max_entries=max_entries,
                progress_check=progress_check,
                require_acquisition=attributed,
                allow_acquisition=attributed,
            )
            verified = False
            if key is not None:
                verify_signature(key, signed.entries, signed.signature, schema_version=version)
                verified = True
            return LedgerInspection(
                tuple(signed.entries),
                version,
                True,
                signed=True,
                signature_verified=verified,
                signature_algorithm=CUSTODY_HMAC_ALGORITHM,
            )
        if version in {CUSTODY_SCHEMA_VERSION, UNATTRIBUTED_CUSTODY_VERSION}:
            document = _CustodyLedgerV2.model_validate(payload)
            if not document.entries:
                raise CustodyIntegrityError("custody ledger must contain at least one entry")
            attributed = version == CUSTODY_SCHEMA_VERSION
            verify_entries(
                document.entries,
                max_entries=max_entries,
                progress_check=progress_check,
                require_acquisition=attributed,
                allow_acquisition=attributed,
            )
            return LedgerInspection(tuple(document.entries), version, True)
        if version == LEGACY_CUSTODY_VERSION:
            legacy = _CustodyLedgerV1.model_validate(payload)
            if not legacy.entries:
                raise CustodyIntegrityError("custody ledger must contain at least one entry")
            _verify_legacy_entries(
                legacy.entries, max_entries=max_entries, progress_check=progress_check
            )
            return LedgerInspection(tuple(legacy.entries), version, False)
        raise CustodyIntegrityError(
            f"unsupported custody version {version!r}; supported: "
            f"{ED25519_SIGNED_CUSTODY_VERSION}, {SIGNED_CUSTODY_VERSION}, "
            f"{CUSTODY_SCHEMA_VERSION}, legacy 2.x "
            f"(and read-only {LEGACY_CUSTODY_VERSION})"
        )
    except json.JSONDecodeError as exc:
        raise CustodyIntegrityError(f"invalid custody JSON: {exc.msg}") from exc
    except ValidationError as exc:
        raise CustodyIntegrityError(f"invalid custody document: {exc}") from exc


def load_ledger(
    path: Path,
    *,
    missing_ok: bool = False,
    max_bytes: int = DEFAULT_MAX_LEDGER_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    progress_check: Callable[[], None] | None = None,
    key: bytes | None = None,
) -> list[CustodyRecord]:
    """Compatibility facade returning records from a fully verified ledger."""
    return list(
        inspect_ledger(
            path,
            missing_ok=missing_ok,
            max_bytes=max_bytes,
            max_entries=max_entries,
            progress_check=progress_check,
            key=key,
        ).entries
    )


def append_entry(
    ledger: Path,
    evidence: Evidence,
    action: CustodyAction,
    actor: str,
    occurred_at: datetime | None = None,
    *,
    max_ledger_bytes: int = DEFAULT_MAX_LEDGER_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    progress_check: Callable[[], None] | None = None,
    key: bytes | None = None,
    ed25519_private_key: Ed25519PrivateKey | None = None,
    acquisition: AcquisitionProvenance | None = None,
) -> CustodyEntry:
    """Verify, lock and append one event, then durably replace the ledger.

    The ledger is written with the strongest key provided: ``ed25519_private_key``
    produces a third-party-verifiable 3.2.0 ledger (``SEC-E``); otherwise an HMAC
    ``key`` produces a 3.1.0 ledger; otherwise an unsigned 3.0.0 ledger. An
    existing signed ledger is verified against the matching key before the append
    and, if that verification cannot be done (key absent), the append is refused
    (:class:`CustodyKeyError`) — appending would otherwise strip the signature.
    """
    if progress_check is not None:
        progress_check()
    with _ledger_lock(ledger, progress_check):
        inspection = inspect_ledger(
            ledger,
            missing_ok=True,
            max_bytes=max_ledger_bytes,
            max_entries=max_entries,
            progress_check=progress_check,
            key=key,
            ed25519_public_key=(
                ed25519_private_key.public_key() if ed25519_private_key is not None else None
            ),
        )
        if not inspection.evidence_anchored:
            raise CustodyIntegrityError(
                "legacy custody 1.0.0 is read-only because it does not anchor evidence digests; "
                "preserve it and start a 3.0.0 ledger"
            )
        if inspection.signed and not inspection.signature_verified:
            required_env = (
                CUSTODY_ED25519_PRIVATE_KEY_ENV
                if inspection.signature_algorithm == CUSTODY_ED25519_ALGORITHM
                else CUSTODY_KEY_ENV
            )
            raise CustodyKeyError(
                f"custody ledger is signed ({inspection.signature_algorithm}); "
                f"set {required_env} to append or verify it"
            )
        entries = [entry for entry in inspection.entries if isinstance(entry, CustodyEntry)]
        if len(entries) >= max_entries:
            raise CustodyIntegrityError(f"custody ledger reached the {max_entries} entry limit")
        timestamp = _normalize_timestamp(occurred_at or datetime.now(UTC))
        sequence = len(entries) + 1
        previous_hash = entries[-1].entry_hash if entries else GENESIS_HASH
        digest = evidence.sha256.lower()
        prior_entry = next(
            (item for item in entries if item.evidence_id == evidence.evidence_id), None
        )
        if prior_entry is None and action is not CustodyAction.COLLECTED:
            raise CustodyIntegrityError(
                f"first custody action for {evidence.evidence_id} must be collected"
            )
        if prior_entry is None and acquisition is None:
            raise CustodyIntegrityError(
                f"first custody entry for {evidence.evidence_id} requires acquisition provenance"
            )
        if prior_entry is not None and acquisition is not None:
            raise CustodyIntegrityError(
                "acquisition provenance is only valid on the first entry for "
                f"{evidence.evidence_id}"
            )
        entry = CustodyEntry(
            sequence=sequence,
            evidence_id=evidence.evidence_id,
            evidence_sha256=digest,
            action=action,
            actor=actor,
            occurred_at=timestamp,
            previous_hash=previous_hash,
            acquisition=acquisition,
            entry_hash=_entry_hash(
                sequence,
                evidence.evidence_id,
                digest,
                action,
                actor,
                timestamp,
                previous_hash,
                acquisition,
            ),
        )
        entries.append(entry)
        attributed = any(item.acquisition is not None for item in entries)
        verify_entries(
            entries,
            max_entries=max_entries,
            progress_check=progress_check,
            require_acquisition=attributed,
            allow_acquisition=attributed,
        )
        if ed25519_private_key is not None:
            version = (
                ED25519_SIGNED_CUSTODY_VERSION
                if attributed
                else UNATTRIBUTED_ED25519_SIGNED_CUSTODY_VERSION
            )
            ed_signature = _sign_entries_ed25519(
                ed25519_private_key, entries, schema_version=version
            )
            payload = {
                "schema_name": CUSTODY_SCHEMA_NAME,
                "schema_version": version,
                "entries": [item.model_dump(mode="json") for item in entries],
                "signature": ed_signature.model_dump(mode="json"),
            }
        elif key is not None:
            version = SIGNED_CUSTODY_VERSION if attributed else UNATTRIBUTED_SIGNED_CUSTODY_VERSION
            signature = _sign_entries(key, entries, schema_version=version)
            payload = {
                "schema_name": CUSTODY_SCHEMA_NAME,
                "schema_version": version,
                "entries": [item.model_dump(mode="json") for item in entries],
                "signature": signature.model_dump(mode="json"),
            }
        else:
            version = CUSTODY_SCHEMA_VERSION if attributed else UNATTRIBUTED_CUSTODY_VERSION
            payload = {
                "schema_name": CUSTODY_SCHEMA_NAME,
                "schema_version": version,
                "entries": [item.model_dump(mode="json") for item in entries],
            }
        content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if len(content.encode("utf-8")) > max_ledger_bytes:
            raise CustodyIntegrityError(
                f"custody ledger would exceed the {max_ledger_bytes} byte limit"
            )
        atomic_write_text(ledger, content, mode=0o600)
        return entry


def _validate_entry_limit(max_entries: int) -> None:
    if not 1 <= max_entries <= 1_000_000:
        raise ValueError("max_entries must be between 1 and 1000000")


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CustodyIntegrityError("custody timestamp must include a timezone")
    return value.astimezone(UTC)


@contextmanager
def _ledger_lock(ledger: Path, progress_check: Callable[[], None] | None) -> Iterator[None]:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    lock_path = ledger.with_name(f".{ledger.name}.lock")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | nofollow, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"custody lock must be a regular file: {lock_path}")
        if _fcntl is None:
            with _PROCESS_LOCK:
                yield
            return
        while True:
            try:
                _fcntl.flock(descriptor, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if progress_check is not None:
                    progress_check()
                time.sleep(0.01)
        try:
            yield
        finally:
            _fcntl.flock(descriptor, _fcntl.LOCK_UN)
    finally:
        os.close(descriptor)

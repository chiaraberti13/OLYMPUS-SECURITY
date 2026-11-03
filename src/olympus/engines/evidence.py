"""Signed evidence manifest for one engine run.

For every run the platform can say, verifiably, *what ran and what it saw*: which engine
(at which pinned and detected version, from which manifest), which data dependencies (e.g.
the nuclei template commit), the command line that was executed (redacted), the scope it
was allowed to touch, how it ended, and the SHA-256 of the engine's raw output. The
manifest is signed with Ed25519 (:mod:`olympus.core.signing`), so a third party holding
only the public key can check it; the raw output itself is never embedded.

A manifest is only produced when it can be signed: unsigned evidence is not "weaker
evidence", it is evidence anyone could forge, so the application refuses to start a run
that asked for evidence without a signer (fail-closed).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from olympus.core.execution import redact_url, safe_terminal_text
from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.core.models import OlympusModel
from olympus.core.signing import SigningError, sign, verify
from olympus.engines.loader import (
    DATA_ROOT,
    ENGINES_ROOT,
    ManifestError,
    load_all_data,
    manifest_for,
)
from olympus.themis.model import ScanRequest, ScanResult

SIGNING_KEY_VARIABLE = "OLYMPUS_EVIDENCE_SIGNING_KEY_FILE"
MAX_KEY_BYTES = 16 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024

#: Takes the canonical bytes of a manifest and returns a signature envelope (JSON text).
Signer = Callable[[bytes], str]

_SHA256 = r"^[a-f0-9]{64}$"


class EvidenceError(RuntimeError):
    """Evidence cannot be produced or verified."""


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceEngine(_Part):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    detected_version: str | None = Field(default=None, max_length=500)
    pinned_version: str | None = None
    distribution: str
    source_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    #: SHA-256 of the engine.toml this run was governed by.
    manifest_sha256: str = Field(pattern=_SHA256)


class EvidenceData(_Part):
    name: str
    pinned_version: str
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    manifest_sha256: str = Field(pattern=_SHA256)


class EvidenceScope(_Part):
    target: str = Field(max_length=2_048)
    target_kind: str
    allowed_hosts: list[str]
    allowed_domains: list[str]
    allowed_cidrs: list[str]
    #: SHA-256 of the three allow-lists above, so the exact scope is pinned.
    scope_sha256: str = Field(pattern=_SHA256)


class EvidenceAuthorization(_Part):
    job_id: str | None = None
    manifest_sha256: str | None = Field(default=None, pattern=_SHA256)
    lab_policy_sha256: str | None = Field(default=None, pattern=_SHA256)


class EvidenceOutcome(_Part):
    state: str
    exit_code: int | None = None
    termination_cause: str | None = None
    partial: bool = False
    partial_reason: str | None = Field(default=None, max_length=1_000)
    finding_count: int = Field(ge=0)
    duration_seconds: float = Field(ge=0)


class EvidenceOutputs(_Part):
    """Digests of the RAW stdout/stderr. The output itself is never stored here."""

    stdout_sha256: str = Field(pattern=_SHA256)
    stderr_sha256: str = Field(pattern=_SHA256)
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)


class EngineRunEvidence(OlympusModel):
    schema_name: Literal["olympus.engine-run-evidence"] = "olympus.engine-run-evidence"
    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: str = Field(min_length=1, max_length=80)
    created_at: datetime
    engine: EvidenceEngine
    data_dependencies: list[EvidenceData] = Field(default_factory=list, max_length=8)
    #: The executed command line, already redacted. Empty when no process was started.
    command: list[str] = Field(default_factory=list, max_length=64)
    scope: EvidenceScope
    authorization: EvidenceAuthorization
    outcome: EvidenceOutcome
    outputs: EvidenceOutputs | None = None


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(evidence: EngineRunEvidence) -> bytes:
    """The exact bytes that are signed: sorted keys, no whitespace, UTF-8."""
    document = evidence.model_dump(mode="json")
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def evidence_sha256(evidence: EngineRunEvidence) -> str:
    return hashlib.sha256(canonical_bytes(evidence)).hexdigest()


def build_evidence(
    *,
    run_id: str,
    result: ScanResult,
    request: ScanRequest,
    lab_policy_sha256: str | None = None,
    now: datetime | None = None,
) -> EngineRunEvidence:
    """Describe one finished run; raises :class:`EvidenceError` for an unmanifested engine."""
    try:
        manifest = manifest_for(result.scanner)
    except (ManifestError, OSError) as exc:
        raise EvidenceError(f"no engine manifest for {result.scanner!r}: {exc}") from exc
    engine = manifest.engine
    scope_document = json.dumps(
        {
            "allowed_hosts": list(request.allowed),
            "allowed_domains": list(request.allowed_domains),
            "allowed_cidrs": list(request.allowed_cidrs),
        },
        sort_keys=True,
    )
    available = load_all_data()
    data = [
        EvidenceData(
            name=name,
            pinned_version=available[name].data.pinned_version,
            commit=str(available[name].data.source.commit),
            manifest_sha256=_sha256_file(DATA_ROOT / f"{name}.toml"),
        )
        for name in engine.requires_data
    ]
    digests = result.output_digests
    return EngineRunEvidence(
        run_id=run_id,
        created_at=now or datetime.now(UTC),
        engine=EvidenceEngine(
            name=engine.name,
            detected_version=safe_terminal_text(result.version) if result.version else None,
            pinned_version=engine.pinned_version,
            distribution=engine.distribution,
            source_commit=engine.source.commit,
            manifest_sha256=_sha256_file(ENGINES_ROOT / engine.name / "engine.toml"),
        ),
        data_dependencies=data,
        command=list(result.argv),
        scope=EvidenceScope(
            target=redact_url(request.target),
            target_kind=request.target_kind,
            allowed_hosts=list(request.allowed),
            allowed_domains=list(request.allowed_domains),
            allowed_cidrs=list(request.allowed_cidrs),
            scope_sha256=hashlib.sha256(scope_document.encode("utf-8")).hexdigest(),
        ),
        authorization=EvidenceAuthorization(
            job_id=result.job_id,
            manifest_sha256=result.manifest_sha256,
            lab_policy_sha256=lab_policy_sha256,
        ),
        outcome=EvidenceOutcome(
            state=result.state.value,
            exit_code=result.exit_code,
            termination_cause=(
                str(result.termination.cause) if result.termination is not None else None
            ),
            partial=result.partial,
            partial_reason=result.partial_reason,
            finding_count=len(result.findings),
            duration_seconds=round(result.duration_seconds, 3),
        ),
        outputs=(
            EvidenceOutputs(
                stdout_sha256=digests.stdout_sha256,
                stderr_sha256=digests.stderr_sha256,
                stdout_bytes=digests.stdout_bytes,
                stderr_bytes=digests.stderr_bytes,
            )
            if digests is not None
            else None
        ),
    )


def signature_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


def write_signed(evidence: EngineRunEvidence, signer: Signer, path: Path) -> str:
    """Write ``path`` (the manifest) and ``path.sig``; return the manifest's SHA-256."""
    envelope = signer(canonical_bytes(evidence))
    atomic_write_text(
        path, json.dumps(evidence.model_dump(mode="json"), indent=2) + "\n", mode=0o600
    )
    atomic_write_text(signature_path(path), envelope, mode=0o600)
    return evidence_sha256(evidence)


def verify_signed(path: Path, *, public_pem: str) -> EngineRunEvidence:
    """Load ``path`` and its signature; return the evidence only if the signature is valid."""
    try:
        text = read_regular_text(path, max_bytes=MAX_EVIDENCE_BYTES, label="evidence manifest")
        envelope = read_regular_text(
            signature_path(path), max_bytes=MAX_EVIDENCE_BYTES, label="evidence signature"
        )
        evidence = EngineRunEvidence.model_validate_json(text)
        valid = verify(canonical_bytes(evidence), envelope, public_pem=public_pem)
    except (OSError, ValueError, ValidationError, SigningError) as exc:
        raise EvidenceError(f"evidence cannot be verified: {exc}") from exc
    if not valid:
        raise EvidenceError("evidence signature is invalid: the manifest was altered")
    return evidence


def signer_from_environment(environment: dict[str, str] | None = None) -> Signer:
    """Build a signer from ``OLYMPUS_EVIDENCE_SIGNING_KEY_FILE`` (a path, never the key itself)."""
    env = os.environ if environment is None else environment
    location = env.get(SIGNING_KEY_VARIABLE, "").strip()
    if not location:
        raise EvidenceError(
            f"signed evidence needs {SIGNING_KEY_VARIABLE} to name an Ed25519 private key file"
        )
    try:
        private_pem = read_regular_text(
            Path(location), max_bytes=MAX_KEY_BYTES, label="signing key"
        )
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"cannot read the evidence signing key: {exc}") from exc

    def signer(data: bytes) -> str:
        try:
            return sign(data, private_pem)
        except SigningError as exc:
            raise EvidenceError(f"cannot sign evidence: {exc}") from exc

    return signer

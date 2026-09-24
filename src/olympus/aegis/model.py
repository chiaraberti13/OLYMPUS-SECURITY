"""Strict request and versioned result contracts for AEGIS native execution."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from olympus.aegis.runner import TerminationReport
from olympus.aegis.states import ExecutionState
from olympus.core.execution import Cancellation, NeverCancelled, redact_url
from olympus.core.models import Asset, Finding

MAX_RAW_EVIDENCE = 200_000
DEFAULT_MAX_PROCESS_OUTPUT_BYTES = 5_000_000
DEFAULT_MAX_FINDINGS = 10_000


@dataclass(frozen=True)
class ScanRequest:
    """A single validated request to run one scanner against one target."""

    scanner: str
    target: str
    target_kind: str = "host"
    allowed: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    resolved_addresses: tuple[str, ...] = ()
    timeout_seconds: float = 300.0
    deadline_seconds: float = 600.0
    max_output_bytes: int = DEFAULT_MAX_PROCESS_OUTPUT_BYTES
    max_findings: int = DEFAULT_MAX_FINDINGS
    authorized: bool = False
    live_enabled: bool = False
    simulate: bool = False
    cancellation: Cancellation = field(default_factory=NeverCancelled, repr=False, compare=False)

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", self.scanner) is None:
            raise ValueError("scanner must contain 1-64 lowercase letters, digits, or hyphens")
        if self.target_kind not in {"host", "domain", "url"}:
            raise ValueError("target_kind must be host, domain, or url")
        if not 1 <= len(self.target) <= 2_048 or any(
            character in self.target for character in "\r\n\x00"
        ):
            raise ValueError("target must contain 1-2048 characters without CR/LF/NUL")
        if (
            len(self.allowed) > 1_024
            or len(self.allowed_domains) > 1_024
            or len(self.allowed_cidrs) > 1_024
        ):
            raise ValueError("scope lists must each contain at most 1024 entries")
        if not 0.05 <= self.timeout_seconds <= 3_600:
            raise ValueError("timeout_seconds must be between 0.05 and 3600")
        if not 0.05 <= self.deadline_seconds <= 86_400:
            raise ValueError("deadline_seconds must be between 0.05 and 86400")
        if not 1 <= self.max_output_bytes <= 100_000_000:
            raise ValueError("max_output_bytes must be between 1 and 100000000")
        if not 1 <= self.max_findings <= 100_000:
            raise ValueError("max_findings must be between 1 and 100000")


@dataclass(frozen=True)
class Dependency:
    """What a scanner needs to run for real (shown on UNAVAILABLE)."""

    executable: str | None
    install: str
    version_expected: str
    diagnostic: str

    def to_dict(self) -> dict[str, object]:
        return {
            "executable": self.executable,
            "install": self.install,
            "version_expected": self.version_expected,
            "diagnostic": self.diagnostic,
        }


class AegisResultDocument(BaseModel):
    """Persistable output consumed by CLI, API, workers, databases and reports."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-result"] = "olympus.aegis-result"
    # 1.1.0 adds the optional `termination` object; every 1.0.0 field is
    # unchanged, so a 1.0.0 reader still understands a 1.1.0 document.
    schema_version: Literal["1.1.0"] = "1.1.0"
    scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    state: ExecutionState
    real_execution: bool
    target: str = Field(min_length=1, max_length=2_048)
    resolved_addresses: list[str] = Field(default_factory=list, max_length=256)
    version: str | None = Field(default=None, max_length=500)
    finding_count: int = Field(ge=0, le=100_000)
    asset_count: int = Field(ge=0, le=100_000)
    findings: list[Finding] = Field(default_factory=list, max_length=100_000)
    assets: list[Asset] = Field(default_factory=list, max_length=100_000)
    raw_evidence: str = Field(default="", max_length=MAX_RAW_EVIDENCE)
    raw_evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error: str | None = Field(default=None, max_length=2_000)
    dependency: dict[str, object] | None = None
    exit_code: int | None = None
    #: Structured reason the scanner process ended: timeout, cancellation,
    #: output budget, a kernel-enforced resource limit, or a clean exit.
    termination: dict[str, object] | None = None
    duration_seconds: float = Field(ge=0, le=86_400)

    @model_validator(mode="after")
    def _consistent_state(self) -> AegisResultDocument:
        if self.finding_count != len(self.findings) or self.asset_count != len(self.assets):
            raise ValueError("result counters must match nested contracts")
        if self.real_execution != (self.state is ExecutionState.LIVE):
            raise ValueError("real_execution must be true only for live results")
        if self.state not in {ExecutionState.LIVE, ExecutionState.SIMULATION} and (
            self.findings or self.assets
        ):
            raise ValueError("non-live/non-simulation states must not carry assets or findings")
        return self


@dataclass(frozen=True)
class ScanResult:
    """The domain outcome of one scanner invocation."""

    scanner: str
    state: ExecutionState
    target: str
    resolved_addresses: tuple[str, ...] = ()
    version: str | None = None
    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    raw_evidence: str = ""
    error: str | None = None
    dependency: Dependency | None = None
    exit_code: int | None = None
    termination: TerminationReport | None = None
    duration_seconds: float = 0.0

    def to_document(self) -> AegisResultDocument:
        """Validate and return the canonical versioned result document."""
        evidence = self.raw_evidence[:MAX_RAW_EVIDENCE]
        evidence_digest = hashlib.sha256(evidence.encode()).hexdigest() if evidence else None
        return AegisResultDocument(
            scanner=self.scanner,
            state=self.state,
            real_execution=self.state is ExecutionState.LIVE,
            target=redact_url(self.target),
            resolved_addresses=list(self.resolved_addresses),
            version=self.version[:500] if self.version else None,
            finding_count=len(self.findings),
            asset_count=len(self.assets),
            findings=self.findings,
            assets=self.assets,
            raw_evidence=evidence,
            raw_evidence_sha256=evidence_digest,
            error=self.error[:2_000] if self.error else None,
            dependency=self.dependency.to_dict() if self.dependency else None,
            exit_code=self.exit_code,
            termination=self.termination.to_dict() if self.termination else None,
            duration_seconds=round(self.duration_seconds, 3),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict JSON-compatible representation."""
        return self.to_document().model_dump(mode="json")

"""Immutable, versioned domain contracts for Athena assessment plans.

An :class:`AssessmentPlan` is the durable, validated description of *what*
Athena should assess and *within which limits*. It is framework- and
I/O-free: it validates itself with Pydantic (the project's data-contract
library), rejects unknown fields, and exposes a stable canonical digest so a
changed plan always produces a new identity rather than mutating history.

Credentials, provider tokens, and arbitrary command strings are deliberately
not representable here — a plan references authorization, it never carries
secrets.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from olympus.core.contracts import validate_contract_header
from olympus.core.migrations import migrate_document
from olympus.core.models import Asset, Finding, ScanJob

# Resource-safety defaults (a safeguard against runtime resource exhaustion, not
# a development constraint). These are intentionally generous and can be raised
# freely — they exist only to keep a single plan from exhausting the host by
# accident, and are not a limit on how many features/scanners/modules the
# project may have.
MAX_CONCURRENCY = 16
MAX_PER_JOB_TIMEOUT_SECONDS = 900
MAX_OVERALL_DEADLINE_SECONDS = 7200
MAX_RETRIES = 5
MAX_TARGETS = 256
MAX_RETENTION_DAYS = 3650

TargetKind = Literal["domain", "url"]


class PlanValidationError(ValueError):
    """Raised when plan input cannot be turned into a valid :class:`AssessmentPlan`."""


class ResultValidationError(ValueError):
    """Raised when a stored Athena result violates its versioned contract."""


class _StrictModel(BaseModel):
    """Base contract: reject unknown fields, freeze instances after creation."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(_StrictModel):
    """A single normalized assessment target."""

    kind: TargetKind
    value: str = Field(min_length=1)

    @field_validator("value")
    @classmethod
    def _normalize(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized or " " in normalized:
            raise ValueError("target value must be non-empty and contain no spaces")
        return normalized


class AuthorizationContext(_StrictModel):
    """Immutable authorization reference — never credentials."""

    engagement_id: str = Field(min_length=1)
    approval_reference: str = Field(min_length=1)
    confirmed: bool

    @field_validator("confirmed")
    @classmethod
    def _must_be_confirmed(cls, value: bool) -> bool:
        if not value:
            raise ValueError("authorization.confirmed must be true to run an assessment")
        return value


class ExecutionLimits(_StrictModel):
    """Bounded resource limits, clamped to safe maxima at validation time."""

    concurrency: int = Field(default=2, ge=1, le=MAX_CONCURRENCY)
    per_job_timeout_seconds: int = Field(default=60, ge=1, le=MAX_PER_JOB_TIMEOUT_SECONDS)
    overall_deadline_seconds: int = Field(default=600, ge=1, le=MAX_OVERALL_DEADLINE_SECONDS)
    max_retries: int = Field(default=1, ge=0, le=MAX_RETRIES)


class OutputPolicy(_StrictModel):
    """How and how long assessment results are retained."""

    retention_days: int = Field(default=30, ge=1, le=MAX_RETENTION_DAYS)
    report_formats: tuple[Literal["json", "markdown"], ...] = ("json",)


class ScopeReference(_StrictModel):
    """The engagement perimeter the plan authorizes, embedded for digesting."""

    allowed_domains: tuple[str, ...] = Field(min_length=1)

    @field_validator("allowed_domains")
    @classmethod
    def _normalize(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(domain.strip().lower().rstrip(".") for domain in value)

    def covers(self, host: str) -> bool:
        """Return ``True`` if ``host`` equals or is a subdomain of an allowed domain."""
        target = host.strip().lower().rstrip(".")
        return any(
            target == allowed or target.endswith(f".{allowed}") for allowed in self.allowed_domains
        )


class AssessmentPlan(_StrictModel):
    """The complete, immutable description of one assessment."""

    schema_name: Literal["olympus.athena.plan"] = "olympus.athena.plan"
    schema_version: Literal["1.0.0"] = "1.0.0"
    engagement_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    targets: tuple[Target, ...] = Field(min_length=1, max_length=MAX_TARGETS)
    adapters: tuple[str, ...] = Field(min_length=1)
    scope: ScopeReference
    authorization: AuthorizationContext
    limits: ExecutionLimits = ExecutionLimits()
    output: OutputPolicy = OutputPolicy()

    @field_validator("adapters")
    @classmethod
    def _unique_adapters(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("adapters must be unique")
        return value

    @model_validator(mode="after")
    def _engagement_matches_authorization(self) -> AssessmentPlan:
        if self.engagement_id != self.authorization.engagement_id:
            raise ValueError("plan engagement_id must match authorization.engagement_id")
        return self

    def canonical_json(self) -> str:
        """Return the deterministic JSON encoding used for digesting and storage."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Return the SHA-256 digest of the plan's canonical encoding."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def scope_digest(self) -> str:
        """Return the SHA-256 digest of the embedded scope reference."""
        payload = json.dumps(
            self.scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AssessmentResult(_StrictModel):
    """Normalized, versioned output from one Athena scan job."""

    schema_name: Literal["olympus.athena.result"] = "olympus.athena.result"
    schema_version: Literal["1.0.0"] = "1.0.0"
    assessment_id: str = Field(min_length=1)
    job: ScanJob
    assets: tuple[Asset, ...] = ()
    findings: tuple[Finding, ...] = ()

    def canonical_json(self) -> str:
        """Return a deterministic storage encoding."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def load_plan(raw: object) -> AssessmentPlan:
    """Validate ``raw`` (already-parsed JSON) into an :class:`AssessmentPlan`.

    Raises :class:`PlanValidationError` with an actionable message on any
    structural or semantic problem; never guesses missing or ambiguous fields.
    """
    if not isinstance(raw, dict):
        raise PlanValidationError("plan must be a JSON object")
    try:
        candidate = migrate_document(
            raw, schema_name="olympus.athena.plan", current_version="1.0.0"
        )
        validate_contract_header(candidate, schema_name="olympus.athena.plan")
        return AssessmentPlan.model_validate(candidate)
    except ValueError as exc:
        raise PlanValidationError(str(exc)) from exc


def load_result(raw: object) -> AssessmentResult:
    """Validate a stored job result and its nested shared contracts."""
    if not isinstance(raw, dict):
        raise ResultValidationError("assessment result must be a JSON object")
    try:
        validate_contract_header(raw, schema_name="olympus.athena.result")
        return AssessmentResult.model_validate(raw)
    except ValueError as exc:
        raise ResultValidationError(str(exc)) from exc

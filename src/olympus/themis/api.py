"""Authenticated native HTTP API for the Themis control plane.

Every request is attributed: it authenticates one named identity, is checked
against that identity's scopes and rate limit, carries a request id that is
echoed back to the caller, and is recorded in the redacted audit log.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from olympus import __version__
from olympus.apollo.application import ApolloApplicationService
from olympus.apollo.engine import evaluate_stream
from olympus.apollo.rules import DetectionRule
from olympus.athena.application.profiles import (
    ScanProfile,
    UnknownProfileError,
    get_profile,
)
from olympus.athena.application.profiles import profiles as scan_profiles
from olympus.athena.application.registry import active_adapters
from olympus.athena.domain.contracts import AssessmentPlan, Target
from olympus.core.execution import StructuredAuditRecord, append_structured_audit
from olympus.core.models import Alert, Engagement, Event
from olympus.core.observability import Correlation, Observability, observability_from_config
from olympus.engagements.manifest import (
    ManifestAuthorizationError,
    ManifestVerificationError,
    SignedEngagementManifest,
)
from olympus.engagements.resolve import (
    EngagementStoreError,
    engagement_covers,
    load_engagements,
    require_engagement,
)
from olympus.engagements.store import SqliteEngagementStore
from olympus.integrations.capabilities import inventory_document
from olympus.metis.extraction import (
    MAX_EXTRACTION_BYTES,
    ExtractionResult,
    extract_from_source,
)
from olympus.metis.models import IndicatorType
from olympus.minerva.custody import (
    CUSTODY_ED25519_PUBLIC_KEY_ENV,
    DEFAULT_MAX_ENTRIES,
    CustodyIntegrityError,
    CustodyRecord,
    LedgerInspection,
    inspect_ledger_text,
    load_custody_ed25519_public_key,
)
from olympus.themis.concurrency import RequestConcurrencyGate, RequestLease
from olympus.themis.identity import (
    SCOPES,
    ApiIdentity,
    IdentityError,
    IdentityRegister,
    RateLimiter,
    hash_secret,
    load_register,
)
from olympus.themis.jobs import (
    MAX_ATTEMPTS_LIMIT,
    IdempotencyConflict,
    JobState,
    ThemisJob,
    ThemisJobStore,
)
from olympus.themis.oidc import OidcError, OidcVerifier

MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_CONCURRENT_REQUESTS = 64
MAX_CONCURRENT_REQUESTS_LIMIT = 4_096
DEFAULT_API_KEY_SCOPES = ("capabilities:read",)
_API_KEY_HEADER = APIKeyHeader(name="X-Olympus-API-Key", auto_error=False)
_BEARER_HEADER = HTTPBearer(auto_error=False)

#: A caller-supplied trace identifier is echoed, so it must be inert text.
_TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class ApiSettings:
    """Server-owned settings; secrets and filesystem roots never enter requests."""

    database: Path
    scope_directory: Path
    #: Single shared credential. Kept for single-operator deployments; by
    #: default it can only inspect capabilities. Additional scopes must be
    #: explicitly granted, or managed as named identities instead.
    api_key: str = ""
    api_key_scopes: tuple[str, ...] = DEFAULT_API_KEY_SCOPES
    #: Register of named identities with their own scopes, expiry and limits.
    identities_path: Path | None = None
    #: Optional offline-first OIDC trust tuple. All values are required
    #: together; JWKS discovery and remote fetching are deliberately disabled.
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_path: Path | None = None
    #: Where each authenticated request is recorded, redacted.
    audit_path: Path | None = None
    #: The shared engagement database (ROADMAP ``WEB-B``). When set, engagements
    #: are readable over the API/Web and a submission may be scope-checked
    #: against one; when ``None`` those routes report the feature is not
    #: configured rather than silently pretending there are no engagements.
    engagements_database: Path | None = None
    #: Directory of ``core.Finding`` JSON bundles the Web UI reviews (ROADMAP
    #: ``WEB-C``). When set, the browser can browse, filter and triage findings
    #: produced by any module; when ``None`` the findings pages report the
    #: feature is not configured rather than pretending there are no findings.
    #: The bundles are read-only producer artifacts — the lifecycle lives in the
    #: append-only transition store below, never by rewriting them.
    findings_directory: Path | None = None
    #: Directory of ``core.Finding`` JSON bundles from an *earlier* run, used as
    #: the baseline for the Web UI scan-diff (ROADMAP ``WEB-I``). When set, the
    #: browser can compare the current findings against this baseline (new /
    #: resolved / persistent); when ``None`` the diff page reports the feature is
    #: not configured. Read-only producer artifacts, like ``findings_directory``.
    baseline_findings_directory: Path | None = None
    #: The append-only finding lifecycle store
    #: (:class:`~olympus.findings.store.SqliteFindingTransitionStore`). When set,
    #: a browser triage decision is recorded here with who/when/from→to/why, and
    #: the effective status of a finding is folded from this history over the
    #: bundle's base status. Without it, the Web UI shows findings read-only.
    findings_database: Path | None = None
    #: Directory of ``core.Incident`` JSON documents the Web dashboard summarises
    #: (ROADMAP ``WEB-G`` incident widget). When set, a ``incidents:read`` identity
    #: sees an incidents-by-status widget; when ``None`` the widget is simply
    #: absent. Read-only private producer artifacts, exactly as
    #: :func:`olympus.minerva.triage.export_incident` writes them — never a store.
    incidents_directory: Path | None = None
    #: Server-owned Apollo rule pack exposed through the typed API and Web UI.
    #: Requests may supply normalized events, never filesystem paths or rules.
    apollo_rules_directory: Path | None = None
    #: Optional hex-encoded raw 32-byte Ed25519 *public* key (not a secret) used
    #: to verify the signature of an Ed25519-signed custody ledger submitted to
    #: the Minerva verification API/Web. When ``None`` the hash chain is still
    #: verified and a signed ledger is reported ``signature_verified=False`` so a
    #: caller refuses to trust it; the key never signs, only verifies.
    minerva_custody_public_key_hex: str | None = None
    #: Pinned Ed25519 approver key. When configured, every API/Web job submission
    #: must carry a signed manifest and is rejected unless it authorizes the
    #: exact engagement, scanner, target and current time.
    trusted_manifest_public_key_pem: str | None = None
    #: Bound in-flight ASGI requests across API/Web processes sharing this job
    #: database; excess work is rejected rather than queued without bounds.
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS

    def validate(self) -> None:
        if (
            isinstance(self.max_concurrent_requests, bool)
            or not isinstance(self.max_concurrent_requests, int)
            or not 1 <= self.max_concurrent_requests <= MAX_CONCURRENT_REQUESTS_LIMIT
        ):
            raise ValueError(
                "Themis API max_concurrent_requests must be an integer between 1 and "
                f"{MAX_CONCURRENT_REQUESTS_LIMIT}"
            )
        oidc_values = (self.oidc_issuer, self.oidc_audience, self.oidc_jwks_path)
        if any(value is not None for value in oidc_values) and not all(
            value is not None for value in oidc_values
        ):
            raise ValueError("OIDC issuer, audience and local JWKS must be configured together")
        if self.oidc_issuer is not None and self.identities_path is None:
            raise ValueError("OIDC requires a local identity register for authorization")
        if not self.api_key and self.identities_path is None:
            raise ValueError("Themis API needs either an API key or an identity register")
        if self.api_key and len(self.api_key) < 32:
            raise ValueError("Themis API key must contain at least 32 characters")
        if self.api_key:
            if not isinstance(self.api_key_scopes, tuple) or not self.api_key_scopes:
                raise ValueError("Themis API key must have at least one explicitly granted scope")
            if any(not isinstance(scope, str) for scope in self.api_key_scopes):
                raise ValueError("Themis API key scopes must be strings")
            unknown_scopes = sorted(set(self.api_key_scopes) - set(SCOPES))
            if unknown_scopes:
                raise ValueError(f"unknown Themis API key scopes: {', '.join(unknown_scopes)}")
        if self.identities_path is not None:
            # Fail at startup rather than on the first request.
            load_register(self.identities_path)
        if self.oidc_issuer is not None:
            assert self.oidc_audience is not None  # noqa: S101 - all-or-none validation
            assert self.oidc_jwks_path is not None  # noqa: S101 - all-or-none validation
            OidcVerifier(
                issuer=self.oidc_issuer,
                audience=self.oidc_audience,
                jwks_path=self.oidc_jwks_path,
            )
        if self.trusted_manifest_public_key_pem is not None:
            if not self.trusted_manifest_public_key_pem.strip():
                raise ValueError("Themis trusted manifest public key must not be empty")
            if self.engagements_database is None:
                raise ValueError("Themis signed manifests require an engagement database")
        if self.minerva_custody_public_key_hex is not None:
            # Fail at startup on a malformed verification key rather than on the
            # first ledger submission; reuses the canonical hex loader.
            load_custody_ed25519_public_key(
                env={CUSTODY_ED25519_PUBLIC_KEY_ENV: self.minerva_custody_public_key_hex}
            )
        if self.scope_directory.is_symlink():
            raise ValueError("Themis scope directory must be an existing non-symlink directory")
        root = self.scope_directory.resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError("Themis scope directory must be an existing non-symlink directory")
        for label, directory in (
            ("findings", self.findings_directory),
            ("baseline findings", self.baseline_findings_directory),
            ("incidents", self.incidents_directory),
            ("Apollo rules", self.apollo_rules_directory),
        ):
            if directory is None:
                continue
            if directory.is_symlink():
                raise ValueError(
                    f"Themis {label} directory must be an existing non-symlink directory"
                )
            resolved = directory.resolve()
            missing = not resolved.exists() or not resolved.is_dir()
            if missing:
                raise ValueError(
                    f"Themis {label} directory must be an existing non-symlink directory"
                )


class _RegisterSource:
    """Serve the current identity register, re-reading it when the file changes.

    Rotation and revocation take effect without a restart. Any problem reading
    or validating the register authenticates nobody: a register that cannot be
    trusted is not a reason to keep honouring credentials it may have revoked.
    """

    def __init__(self, settings: ApiSettings) -> None:
        self._path = settings.identities_path
        self._static: IdentityRegister | None = None
        if settings.api_key:
            self._static = IdentityRegister(
                identities=[
                    ApiIdentity(
                        identity_id="default",
                        secret_sha256=hash_secret(settings.api_key),
                        scopes=list(settings.api_key_scopes),
                        created_at=datetime.now(UTC),
                    )
                ]
            )
        self._cache: tuple[tuple[int, int, int], IdentityRegister] | None = None

    def current(self) -> IdentityRegister:
        if self._path is None:
            assert self._static is not None  # noqa: S101 - guaranteed by ApiSettings.validate
            return self._static
        try:
            status_result = self._path.stat()
            stamp = (status_result.st_mtime_ns, status_result.st_size, status_result.st_ino)
        except OSError as exc:
            raise IdentityError(f"identity register is unreadable: {exc}") from exc
        if self._cache is not None and self._cache[0] == stamp:
            return self._cache[1]
        register = load_register(self._path)
        if self._static is not None:
            register = register.model_copy(
                update={"identities": [*self._static.identities, *register.identities]}
            ).validate_entries()
        self._cache = (stamp, register)
        return register


@dataclass(frozen=True)
class Caller:
    """The authenticated identity behind one request."""

    identity_id: str
    scopes: tuple[str, ...]


class JobSubmission(BaseModel):
    """Bounded request body for one authorized job."""

    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    target: str = Field(min_length=1, max_length=2_048)
    target_kind: Literal["host", "domain", "url"] = "host"
    scope_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    authorized: bool
    #: Optional engagement this job belongs to (ROADMAP ``WEB-B``). When set, the
    #: server resolves it from the shared engagement store and enforces that the
    #: target falls inside the engagement's authorized perimeter before queueing.
    engagement_id: str | None = Field(default=None, pattern=r"^ENG-\d{4}-\d{5}$")
    signed_manifest: SignedEngagementManifest | None = None
    #: Resubmitting the same key returns the job that already exists instead of
    #: queueing a second scan of the same target.
    idempotency_key: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    max_attempts: int = Field(default=1, ge=1, le=MAX_ATTEMPTS_LIMIT)


class EngagementList(BaseModel):
    """The engagements visible over the API, newest first."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.themis-engagement-list"] = "olympus.themis-engagement-list"
    schema_version: Literal["1.0.0"] = "1.0.0"
    count: int
    engagements: list[Engagement]


class JobList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.themis-job-list"] = "olympus.themis-job-list"
    # The list version tracks its embedded olympus.themis-job contract.
    schema_version: Literal["3.0.0"] = "3.0.0"
    count: int
    jobs: list[ThemisJob]


class ApolloRuleList(BaseModel):
    """Versioned projection of the configured, validated Apollo rule pack."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.apollo-rule-list"] = "olympus.apollo-rule-list"
    schema_version: Literal["1.0.0"] = "1.0.0"
    count: int
    rules: list[DetectionRule]


class ApolloEvaluationRequest(BaseModel):
    """Bounded normalized telemetry submitted for offline detection evaluation."""

    model_config = ConfigDict(extra="forbid")

    events: list[Event] = Field(min_length=1, max_length=500)


class ApolloEvaluationResult(BaseModel):
    """Versioned Apollo evaluation result shared by API clients and the Web UI."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.apollo-evaluation"] = "olympus.apollo-evaluation"
    schema_version: Literal["1.0.0"] = "1.0.0"
    rule_count: int
    event_count: int
    alert_count: int
    alerts: list[Alert]


class MinervaLedgerVerificationRequest(BaseModel):
    """A custody ledger document submitted for offline integrity verification.

    The ledger is the exact JSON object produced by Minerva custody
    (``olympus.custody``). It is verified in memory: no filesystem path, no key
    and no evidence payload is ever accepted from the caller.
    """

    model_config = ConfigDict(extra="forbid")

    ledger: dict[str, object] = Field(
        description="The olympus.custody ledger document to verify, as a JSON object.",
    )


class MinervaLedgerEntryView(BaseModel):
    """Normalized, bounded projection of one verified custody entry."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    evidence_id: str
    evidence_sha256: str | None = None
    action: str
    actor: str
    occurred_at: datetime
    previous_hash: str
    entry_hash: str


class MinervaLedgerVerification(BaseModel):
    """Versioned Minerva custody verification result for API and Web clients.

    The hash chain is always verified (a non-error result means it held). The
    signature is verified only when the server is configured with the matching
    Ed25519 verification key and the ledger is signed; otherwise a signed ledger
    reports ``signature_verified=false`` so the caller refuses to trust it.
    """

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.minerva-ledger-verification"] = (
        "olympus.minerva-ledger-verification"
    )
    schema_version: Literal["1.0.0"] = "1.0.0"
    #: Always ``true`` on a success response (the chain verification raised
    #: otherwise); present so clients can assert on it explicitly.
    chain_verified: bool = True
    #: Schema version of the verified ledger document (e.g. ``"3.2.0"``).
    ledger_schema_version: str
    entry_count: int
    #: ``true`` when every entry anchors an evidence SHA-256 (3.x ledgers); a
    #: read-only legacy 1.x ledger reports ``false``.
    evidence_anchored: bool
    signed: bool
    signature_verified: bool
    #: ``"HMAC-SHA256"``, ``"Ed25519"`` or ``null`` for an unsigned ledger.
    signature_algorithm: str | None = None
    entries: list[MinervaLedgerEntryView]


def _entry_view(record: CustodyRecord) -> MinervaLedgerEntryView:
    return MinervaLedgerEntryView(
        sequence=record.sequence,
        evidence_id=record.evidence_id,
        evidence_sha256=getattr(record, "evidence_sha256", None),
        action=record.action.value,
        actor=record.actor,
        occurred_at=record.occurred_at,
        previous_hash=record.previous_hash,
        entry_hash=record.entry_hash,
    )


def _ledger_verification(inspection: LedgerInspection) -> MinervaLedgerVerification:
    return MinervaLedgerVerification(
        ledger_schema_version=inspection.schema_version,
        entry_count=len(inspection.entries),
        evidence_anchored=inspection.evidence_anchored,
        signed=inspection.signed,
        signature_verified=inspection.signature_verified,
        signature_algorithm=inspection.signature_algorithm,
        entries=[_entry_view(record) for record in inspection.entries],
    )


class MetisExtractionRequest(BaseModel):
    """Bounded raw threat-intel submitted for offline, network-free IOC extraction."""

    model_config = ConfigDict(extra="forbid")

    source_format: Literal["text", "stix", "misp"] = "text"
    text: str = Field(min_length=1, max_length=MAX_EXTRACTION_BYTES)


class MetisIndicator(BaseModel):
    """A normalized IOC projected for API clients and the Web UI (type + value)."""

    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    value: str


class MetisSkippedItem(BaseModel):
    """An input element deliberately not imported, with the honest reason."""

    model_config = ConfigDict(extra="forbid")

    value: str
    reason: str


class MetisExtractionResult(BaseModel):
    """Versioned Metis extraction result shared by API clients and the Web UI."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.metis-extraction"] = "olympus.metis-extraction"
    schema_version: Literal["1.0.0"] = "1.0.0"
    source_format: str
    indicator_count: int
    skipped_count: int
    indicators: list[MetisIndicator]
    skipped: list[MetisSkippedItem]


def _metis_result_model(result: ExtractionResult) -> MetisExtractionResult:
    """Project the offline extraction core onto the versioned API/Web contract."""
    return MetisExtractionResult(
        source_format=result.source_format,
        indicator_count=len(result.indicators),
        skipped_count=len(result.skipped),
        indicators=[
            MetisIndicator(indicator_type=item.indicator_type, value=item.value)
            for item in result.indicators
        ],
        skipped=[MetisSkippedItem(value=item.value, reason=item.reason) for item in result.skipped],
    )


#: Upper bounds for an Athena plan request. They keep a single request small and
#: bounded; the domain contract enforces its own stricter maxima on top.
MAX_ATHENA_TARGETS = 64
MAX_ATHENA_DOMAINS = 64


class AthenaProfileView(BaseModel):
    """A target-free scan profile projected for API clients and the Web UI."""

    model_config = ConfigDict(extra="forbid")

    profile_id: str
    title: str
    summary: str
    adapters: list[str]
    active_adapters: list[str]
    #: ``true`` when the profile runs at least one adapter that actively probes a
    #: target (so it requires active-scan authorization for the engagement).
    active: bool


class AthenaProfileList(BaseModel):
    """Versioned list of the named scan profiles Athena can build plans from."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.athena-profile-list"] = "olympus.athena-profile-list"
    schema_version: Literal["1.0.0"] = "1.0.0"
    profiles: list[AthenaProfileView]


class AthenaPlanTarget(BaseModel):
    """One authorized assessment target (``domain`` or ``url``)."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["domain", "url"]
    value: str = Field(min_length=1, max_length=2048)


class AthenaPlanRequest(BaseModel):
    """Engagement inputs that turn a named profile into a validated plan.

    No target is ever assumed and ``confirmed`` must be set explicitly: a profile
    never self-authorizes a run, so an unconfirmed request fails validation (422)
    rather than yielding a silently runnable plan. Building a plan is a pure,
    offline, network-free computation — it produces a signable document, it does
    not execute anything.
    """

    model_config = ConfigDict(extra="forbid")

    profile: Literal["light", "deep"]
    engagement_id: str = Field(min_length=1, max_length=256)
    approval_reference: str = Field(min_length=1, max_length=256)
    targets: list[AthenaPlanTarget] = Field(min_length=1, max_length=MAX_ATHENA_TARGETS)
    allowed_domains: list[str] = Field(min_length=1, max_length=MAX_ATHENA_DOMAINS)
    name: str | None = Field(default=None, max_length=256)
    confirmed: bool = False
    report_formats: list[Literal["json", "markdown", "html", "pdf"]] | None = None


class AthenaPlanView(BaseModel):
    """Versioned, bounded projection of a built Athena plan for API and Web."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.athena-plan"] = "olympus.athena-plan"
    schema_version: Literal["1.0.0"] = "1.0.0"
    profile_id: str
    name: str
    engagement_id: str
    adapters: list[str]
    active: bool
    targets: list[AthenaPlanTarget]
    allowed_domains: list[str]
    report_formats: list[str]
    #: Always ``true`` on a success response: the plan contract rejects an
    #: unconfirmed authorization, so a returned plan is always confirmed.
    authorized: bool
    plan_digest: str
    scope_digest: str
    limits: dict[str, int]
    #: The full canonical plan document, indented and ready to run with
    #: ``olympus athena run`` (authorization reference, never a secret).
    plan_json: str


def _athena_profile_view(profile: ScanProfile) -> AthenaProfileView:
    active = set(active_adapters())
    return AthenaProfileView(
        profile_id=profile.profile_id,
        title=profile.title,
        summary=profile.summary,
        adapters=list(profile.adapters),
        active_adapters=sorted(name for name in profile.adapters if name in active),
        active=profile.active,
    )


def _athena_plan_view(plan: AssessmentPlan, profile: ScanProfile) -> AthenaPlanView:
    return AthenaPlanView(
        profile_id=profile.profile_id,
        name=plan.name,
        engagement_id=plan.engagement_id,
        adapters=list(plan.adapters),
        active=profile.active,
        targets=[AthenaPlanTarget(kind=item.kind, value=item.value) for item in plan.targets],
        allowed_domains=list(plan.scope.allowed_domains),
        report_formats=list(plan.output.report_formats),
        authorized=plan.authorization.confirmed,
        plan_digest=plan.digest(),
        scope_digest=plan.scope_digest(),
        limits=plan.limits.model_dump(mode="json"),
        plan_json=json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True),
    )


async def _renew_request_lease(gate: RequestConcurrencyGate, lease: RequestLease) -> None:
    """Keep a request lease alive until its middleware cancels this task."""
    while True:
        await asyncio.sleep(gate.heartbeat_seconds)
        if not await asyncio.to_thread(gate.renew, lease):
            return


def create_app(settings: ApiSettings, observability: Observability | None = None) -> FastAPI:
    """Build a fail-closed Themis API around the canonical durable job store."""
    settings.validate()
    owns_telemetry = observability is None
    telemetry = observability or observability_from_config()
    store = ThemisJobStore(settings.database)
    store.initialize()
    scope_root = settings.scope_directory.resolve()
    registers = _RegisterSource(settings)
    oidc: OidcVerifier | None = None
    if settings.oidc_issuer is not None:
        assert settings.oidc_audience is not None  # noqa: S101 - validated above
        assert settings.oidc_jwks_path is not None  # noqa: S101 - validated above
        oidc = OidcVerifier(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            jwks_path=settings.oidc_jwks_path,
        )
    limiter = RateLimiter()
    concurrency = RequestConcurrencyGate(settings.database, settings.max_concurrent_requests)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        try:
            yield
        finally:
            if owns_telemetry:
                telemetry.shutdown()

    app = FastAPI(
        title="Olympus Themis API",
        version=__version__,
        description="Authorized specialist-engine orchestration and evidence lifecycle.",
        lifespan=lifespan,
    )

    def authenticated(required_scope: str) -> Caller:
        """Return the caller if the credential is usable and carries the scope."""

        async def dependency(
            request: Request,
            supplied: Annotated[str | None, Depends(_API_KEY_HEADER)],
            bearer: Annotated[HTTPAuthorizationCredentials | None, Depends(_BEARER_HEADER)],
        ) -> Caller:
            try:
                if supplied and bearer is not None:
                    raise IdentityError("multiple authentication mechanisms supplied")
                register = registers.current()
                if bearer is not None:
                    if oidc is None or bearer.scheme.lower() != "bearer":
                        raise IdentityError("OIDC bearer authentication is not configured")
                    identity = register.authenticate_oidc_subject(oidc.verify(bearer.credentials))
                    request.state.authentication_method = "oidc"
                else:
                    identity = register.authenticate(supplied or "")
                    request.state.authentication_method = "api-key"
            except (IdentityError, OidcError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="missing or invalid API credential",
                    headers={"WWW-Authenticate": "ApiKey, Bearer"},
                ) from exc
            caller = Caller(identity.identity_id, identity.validated_scopes())
            request.state.identity_id = caller.identity_id
            if required_scope not in caller.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"identity is not granted the {required_scope} scope",
                )
            wait = limiter.check(caller.identity_id, identity.rate_limit_per_minute)
            if wait is not None:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="rate limit exceeded for this API identity",
                    headers={"Retry-After": str(max(1, math.ceil(wait)))},
                )
            return caller

        # FastAPI resolves the dependency into a Caller at request time.
        return cast(Caller, Depends(dependency))

    reads_capabilities = authenticated("capabilities:read")
    reads_jobs = authenticated("jobs:read")
    writes_jobs = authenticated("jobs:write")
    cancels_jobs = authenticated("jobs:cancel")
    reads_engagements = authenticated("engagements:read")
    reads_apollo = authenticated("apollo:read")
    runs_apollo = authenticated("apollo:run")
    reads_metis = authenticated("metis:read")
    reads_athena = authenticated("athena:read")
    reads_minerva = authenticated("minerva:read")
    minerva_public_key = (
        load_custody_ed25519_public_key(
            env={CUSTODY_ED25519_PUBLIC_KEY_ENV: settings.minerva_custody_public_key_hex}
        )
        if settings.minerva_custody_public_key_hex is not None
        else None
    )

    def _apollo_rules() -> tuple[DetectionRule, ...]:
        directory = settings.apollo_rules_directory
        if directory is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Apollo rule pack is not configured on this server",
            )
        try:
            return ApolloApplicationService().list_rules(directory)
        except (OSError, TimeoutError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Apollo rule pack is unavailable or invalid",
            ) from exc

    @app.middleware("http")
    async def accountability(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Give every request an id, echo it back, and record what it did."""
        started_at = time.monotonic()
        request_id = _trace_id(request.headers.get("x-request-id"), "req")
        correlation_id = _trace_id(request.headers.get("x-correlation-id"), "cor")
        request.state.request_id = request_id
        response: Response | None = None
        try:
            with telemetry.span("themis.api.request"):
                response = await call_next(request)
        finally:
            route_object = request.scope.get("route")
            route = getattr(route_object, "path", "unmatched")
            telemetry.api_request(
                "themis",
                request.method,
                route,
                response.status_code if response is not None else 500,
                time.monotonic() - started_at,
            )
        assert response is not None  # noqa: S101 - call_next returned without raising
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = correlation_id
        if settings.audit_path is not None:
            append_structured_audit(
                settings.audit_path,
                StructuredAuditRecord(
                    timestamp=datetime.now(UTC).isoformat(),
                    execution_id=request_id,
                    action=f"themis.api {request.method} {request.url.path}",
                    outcome=str(response.status_code),
                    metadata={
                        "identity": getattr(request.state, "identity_id", "anonymous"),
                        "authentication_method": getattr(
                            request.state, "authentication_method", "none"
                        ),
                        "correlation_id": correlation_id,
                        "status": response.status_code,
                    },
                ),
            )
        return response

    @app.middleware("http")
    async def security_boundary(request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
                too_large = declared_length < 0 or declared_length > MAX_REQUEST_BYTES
            except ValueError:
                too_large = True
            if too_large:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})

        # Content-Length is optional and cannot be trusted. Consume the ASGI body
        # stream incrementally, stop at the first byte above the limit, then cache
        # only the bounded body for FastAPI's downstream parser.
        bounded_body = bytearray()
        async for chunk in request.stream():
            if len(bounded_body) + len(chunk) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})
            bounded_body.extend(chunk)
        request._body = bytes(bounded_body)

        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.middleware("http")
    async def concurrency_boundary(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Bound in-flight requests before buffering their bodies or dispatching them."""
        started_at = time.monotonic()
        request_id = _trace_id(request.headers.get("x-request-id"), "req")
        correlation_id = _trace_id(request.headers.get("x-correlation-id"), "cor")
        lease = concurrency.try_acquire()
        if lease is None:
            telemetry.api_request(
                "themis", request.method, "overloaded", 503, time.monotonic() - started_at
            )
            if settings.audit_path is not None:
                append_structured_audit(
                    settings.audit_path,
                    StructuredAuditRecord(
                        timestamp=datetime.now(UTC).isoformat(),
                        execution_id=request_id,
                        action=f"themis.api {request.method} request-overload",
                        outcome="503",
                        metadata={"identity": "anonymous", "correlation_id": correlation_id},
                    ),
                )
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Themis API concurrency limit reached"},
                headers={
                    "Retry-After": "1",
                    "X-Request-ID": request_id,
                    "X-Correlation-ID": correlation_id,
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                },
            )
        heartbeat = asyncio.create_task(_renew_request_lease(concurrency, lease))
        try:
            return await call_next(request)
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
            await asyncio.to_thread(concurrency.release, lease)

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {
            "schema_name": "olympus.health",
            "schema_version": "1.0.0",
            "service": "themis",
            "status": "ok",
            "version": __version__,
        }

    @app.get("/ready", tags=["operations"])
    def ready(caller: Caller = reads_capabilities) -> dict[str, object]:
        store.initialize()
        return {
            "schema_name": "olympus.themis-readiness",
            "schema_version": "1.0.0",
            "status": "ready",
            "control_plane": True,
            "capabilities": inventory_document(),
        }

    @app.get("/metrics", include_in_schema=False)
    def metrics(caller: Caller = reads_capabilities) -> Response:
        payload = telemetry.prometheus_payload()
        if payload is None:
            raise HTTPException(status_code=404, detail="Prometheus metrics are not enabled")
        content, content_type = payload
        return Response(content=content, headers={"Content-Type": content_type})

    @app.get("/api/v1/capabilities", tags=["capabilities"])
    def capabilities(caller: Caller = reads_capabilities) -> dict[str, object]:
        return inventory_document()

    @app.get(
        "/api/v1/apollo/rules",
        response_model=ApolloRuleList,
        tags=["apollo"],
    )
    def apollo_rules(caller: Caller = reads_apollo) -> ApolloRuleList:
        rules = _apollo_rules()
        return ApolloRuleList(count=len(rules), rules=list(rules))

    @app.post(
        "/api/v1/apollo/evaluate",
        response_model=ApolloEvaluationResult,
        tags=["apollo"],
    )
    def apollo_evaluate(
        body: ApolloEvaluationRequest, caller: Caller = runs_apollo
    ) -> ApolloEvaluationResult:
        rules = _apollo_rules()
        try:
            alerts = evaluate_stream(list(rules), body.events, max_evaluations=500_000)
        except (TimeoutError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return ApolloEvaluationResult(
            rule_count=len(rules),
            event_count=len(body.events),
            alert_count=len(alerts),
            alerts=alerts,
        )

    @app.post(
        "/api/v1/minerva/verify-ledger",
        response_model=MinervaLedgerVerification,
        tags=["minerva"],
    )
    def minerva_verify_ledger(
        body: MinervaLedgerVerificationRequest, caller: Caller = reads_minerva
    ) -> MinervaLedgerVerification:
        try:
            text = json.dumps(body.ledger, separators=(",", ":"))
        except (TypeError, ValueError) as exc:  # pragma: no cover - JSON came from JSON
            raise HTTPException(status_code=422, detail="ledger is not serializable") from exc
        try:
            inspection = inspect_ledger_text(
                text,
                max_entries=DEFAULT_MAX_ENTRIES,
                ed25519_public_key=minerva_public_key,
            )
        except CustodyIntegrityError as exc:
            # A broken chain, a bad schema, or a signature mismatch on a signed
            # ledger all surface here: the document is present and parseable but
            # fails to verify, so the caller must not trust it.
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _ledger_verification(inspection)

    @app.post(
        "/api/v1/metis/extract",
        response_model=MetisExtractionResult,
        tags=["metis"],
    )
    def metis_extract(
        body: MetisExtractionRequest, caller: Caller = reads_metis
    ) -> MetisExtractionResult:
        """Extract IOCs from free text, a STIX bundle or a MISP event, offline.

        Parsing and normalization are local and deterministic; no network access,
        collection or enrichment is performed. Unparsed or unmapped input is
        returned in ``skipped`` with a reason, never silently dropped.
        """
        try:
            result = extract_from_source(body.source_format, body.text)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _metis_result_model(result)

    @app.get(
        "/api/v1/athena/profiles",
        response_model=AthenaProfileList,
        tags=["athena"],
    )
    def athena_profiles(caller: Caller = reads_athena) -> AthenaProfileList:
        """List the named, target-free scan profiles Athena can build plans from.

        A profile only chooses which already-registered adapters run and with
        which safe limits; it carries no target and performs no network access.
        """
        return AthenaProfileList(
            profiles=[_athena_profile_view(profile) for profile in scan_profiles()]
        )

    @app.post(
        "/api/v1/athena/plan",
        response_model=AthenaPlanView,
        tags=["athena"],
    )
    def athena_plan(body: AthenaPlanRequest, caller: Caller = reads_athena) -> AthenaPlanView:
        """Build a validated, signable assessment plan from a named profile, offline.

        The profile supplies adapters and safe limits; the caller supplies the
        authorized target(s), engagement scope and authorization reference.
        Building a plan is a pure, deterministic computation: it produces a plan
        document, it never executes a scan. ``confirmed`` must be true — a profile
        never self-authorizes a run — so an unconfirmed or out-of-shape request is
        rejected with 422 rather than yielding a silently runnable plan.
        """
        try:
            selected = get_profile(body.profile)
            targets = tuple(Target(kind=item.kind, value=item.value) for item in body.targets)
            plan = selected.build_plan(
                engagement_id=body.engagement_id,
                approval_reference=body.approval_reference,
                targets=targets,
                allowed_domains=tuple(body.allowed_domains),
                name=body.name,
                confirmed=body.confirmed,
                report_formats=tuple(body.report_formats) if body.report_formats else None,
            )
        except UnknownProfileError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ValueError as exc:
            # Pydantic ValidationError (a ValueError subclass) and the contract's
            # own ValueError both land here: an unconfirmed authorization, an
            # out-of-shape target, an empty scope or an unknown report format.
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _athena_plan_view(plan, selected)

    @app.get(
        "/api/v1/engagements",
        response_model=EngagementList,
        tags=["engagements"],
    )
    def list_engagements(caller: Caller = reads_engagements) -> EngagementList:
        database = _require_engagements_database(settings)
        try:
            engagements = load_engagements(database)
        except EngagementStoreError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return EngagementList(count=len(engagements), engagements=engagements)

    @app.get(
        "/api/v1/engagements/{engagement_id}",
        response_model=Engagement,
        tags=["engagements"],
    )
    def get_engagement(engagement_id: str, caller: Caller = reads_engagements) -> Engagement:
        database = _require_engagements_database(settings)
        try:
            return require_engagement(database, engagement_id)
        except EngagementStoreError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/api/v1/jobs",
        response_model=ThemisJob,
        status_code=status.HTTP_201_CREATED,
        tags=["jobs"],
    )
    def submit(body: JobSubmission, caller: Caller = writes_jobs) -> ThemisJob:
        if not body.authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="documented authorization must be confirmed",
            )
        if body.engagement_id is not None:
            _enforce_engagement_scope(
                settings.engagements_database,
                body.engagement_id,
                body.target,
                body.target_kind,
            )
        manifest_sha256 = authorize_submission_manifest(settings, body)
        scope_path = _registered_scope(scope_root, body.scope_id)
        try:
            job = store.submit(
                scanner=body.scanner,
                target=body.target,
                target_kind=body.target_kind,
                scope_path=scope_path,
                authorized=True,
                manifest_sha256=manifest_sha256,
                idempotency_key=body.idempotency_key,
                max_attempts=body.max_attempts,
            )
            with telemetry.span("themis.job.queued", Correlation(job_id=job.job_id)):
                return job
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/jobs",
        response_model=JobList,
        tags=["jobs"],
    )
    def list_jobs(
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
        state_filter: Annotated[JobState | None, Query(alias="state")] = None,
        caller: Caller = reads_jobs,
    ) -> JobList:
        jobs = store.list(limit=limit, state=state_filter)
        return JobList(count=len(jobs), jobs=jobs)

    @app.get(
        "/api/v1/jobs/{job_id}",
        response_model=ThemisJob,
        tags=["jobs"],
    )
    def get_job(job_id: str, caller: Caller = reads_jobs) -> ThemisJob:
        return _get(store, job_id)

    @app.post(
        "/api/v1/jobs/{job_id}/cancel",
        response_model=ThemisJob,
        tags=["jobs"],
    )
    def cancel_job(job_id: str, caller: Caller = cancels_jobs) -> ThemisJob:
        try:
            return store.cancel(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=exc.args[0]) from exc

    return app


def _trace_id(supplied: str | None, prefix: str) -> str:
    """Return the caller's trace id when it is inert text, else a fresh one."""
    if supplied is not None and _TRACE_ID.fullmatch(supplied):
        return supplied
    return f"{prefix}-{uuid4().hex}"


def _require_engagements_database(settings: ApiSettings) -> Path:
    """Return the configured engagement database, or report the feature is off.

    When no engagement store is wired, the honest answer is "not configured"
    (503), never an empty list that would imply there are simply no engagements.
    """
    if settings.engagements_database is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="engagement store is not configured on this server",
        )
    return settings.engagements_database


def _enforce_engagement_scope(
    database: Path | None, engagement_id: str, target: str, target_kind: str
) -> None:
    """Reject a submission whose target falls outside the engagement's scope."""
    if database is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="engagement_id was supplied but no engagement store is configured",
        )
    try:
        engagement = require_engagement(database, engagement_id)
    except EngagementStoreError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not engagement_covers(engagement, target, target_kind):
        raise HTTPException(
            status_code=422,
            detail="target is outside the engagement scope",
        )


def authorize_submission_manifest(settings: ApiSettings, body: JobSubmission) -> str | None:
    """Verify and bind the configured signed authorization, fail-closed."""
    trusted_key = settings.trusted_manifest_public_key_pem
    if trusted_key is None:
        if body.signed_manifest is not None:
            raise HTTPException(
                status_code=400,
                detail="signed manifest supplied but no trusted approver key is configured",
            )
        return None
    if body.signed_manifest is None:
        raise HTTPException(status_code=403, detail="a signed engagement manifest is required")
    if body.engagement_id is None:
        raise HTTPException(status_code=422, detail="signed manifest requires engagement_id")
    if body.signed_manifest.manifest.engagement_id != body.engagement_id:
        raise HTTPException(status_code=422, detail="manifest engagement does not match submission")
    database = _require_engagements_database(settings)
    store = SqliteEngagementStore(database)
    try:
        store.authorize_and_save_manifest(
            body.signed_manifest,
            trusted_public_key_pem=trusted_key,
            target=body.target,
            technique=body.scanner,
            now=datetime.now(UTC),
        )
    except (ManifestAuthorizationError, ManifestVerificationError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    finally:
        store.close()
    return body.signed_manifest.manifest_sha256


def _registered_scope(root: Path, scope_id: str) -> Path:
    unresolved = root / f"{scope_id}.json"
    if unresolved.is_symlink():
        raise HTTPException(status_code=404, detail="registered scope not found")
    candidate = unresolved.resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="invalid scope identifier")
    if not candidate.exists() or not candidate.is_file() or candidate.is_symlink():
        raise HTTPException(status_code=404, detail="registered scope not found")
    return candidate


def _get(store: ThemisJobStore, job_id: str) -> ThemisJob:
    try:
        return store.get(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=exc.args[0]) from exc

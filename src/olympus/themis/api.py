"""Authenticated native HTTP API for the THEMIS control plane.

Every request is attributed: it authenticates one named identity, is checked
against that identity's scopes and rate limit, carries a request id that is
echoed back to the caller, and is recorded in the redacted audit log.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from olympus import __version__
from olympus.core.execution import StructuredAuditRecord, append_structured_audit
from olympus.core.observability import Correlation, Observability, observability_from_config
from olympus.integrations.capabilities import inventory_document
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

MAX_REQUEST_BYTES = 64 * 1024
_API_KEY_HEADER = APIKeyHeader(name="X-Olympus-API-Key", auto_error=False)

#: A caller-supplied trace identifier is echoed, so it must be inert text.
_TRACE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class ApiSettings:
    """Server-owned settings; secrets and filesystem roots never enter requests."""

    database: Path
    scope_directory: Path
    #: Single shared credential. Kept for single-operator deployments; it
    #: becomes an implicit identity holding every scope.
    api_key: str = ""
    #: Register of named identities with their own scopes, expiry and limits.
    identities_path: Path | None = None
    #: Where each authenticated request is recorded, redacted.
    audit_path: Path | None = None

    def validate(self) -> None:
        if not self.api_key and self.identities_path is None:
            raise ValueError("THEMIS API needs either an API key or an identity register")
        if self.api_key and len(self.api_key) < 32:
            raise ValueError("THEMIS API key must contain at least 32 characters")
        if self.identities_path is not None:
            # Fail at startup rather than on the first request.
            load_register(self.identities_path)
        root = self.scope_directory.resolve()
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise ValueError("THEMIS scope directory must be an existing non-symlink directory")


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
                        scopes=list(SCOPES),
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
    #: Resubmitting the same key returns the job that already exists instead of
    #: queueing a second scan of the same target.
    idempotency_key: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
    )
    max_attempts: int = Field(default=1, ge=1, le=MAX_ATTEMPTS_LIMIT)


class JobList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.aegis-job-list"] = "olympus.aegis-job-list"
    # 2.0.0 tracks the embedded olympus.aegis-job contract, which replaced
    # `scope_path` with `scope_name`.
    schema_version: Literal["2.0.0"] = "2.0.0"
    count: int
    jobs: list[ThemisJob]


def create_app(settings: ApiSettings, observability: Observability | None = None) -> FastAPI:
    """Build a fail-closed THEMIS API around the canonical durable job store."""
    settings.validate()
    owns_telemetry = observability is None
    telemetry = observability or observability_from_config()
    store = ThemisJobStore(settings.database)
    store.initialize()
    scope_root = settings.scope_directory.resolve()
    registers = _RegisterSource(settings)
    limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        try:
            yield
        finally:
            if owns_telemetry:
                telemetry.shutdown()

    app = FastAPI(
        title="Olympus THEMIS API",
        version=__version__,
        description="Authorized specialist-engine orchestration and evidence lifecycle.",
        lifespan=lifespan,
    )

    def authenticated(required_scope: str) -> Caller:
        """Return the caller if the credential is usable and carries the scope."""

        async def dependency(
            request: Request,
            supplied: Annotated[str | None, Depends(_API_KEY_HEADER)],
        ) -> Caller:
            try:
                identity = registers.current().authenticate(supplied or "")
            except IdentityError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="missing or invalid API credential",
                    headers={"WWW-Authenticate": "ApiKey"},
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
            "schema_name": "olympus.aegis-readiness",
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
        scope_path = _registered_scope(scope_root, body.scope_id)
        try:
            job = store.submit(
                scanner=body.scanner,
                target=body.target,
                target_kind=body.target_kind,
                scope_path=scope_path,
                authorized=True,
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

"""Native THEMIS web control plane (FastAPI + Jinja2 + server-sent events).

CLI, TUI, API and Web are different interfaces over the *same* core use cases.
This module adds a browser interface on top of the authenticated THEMIS API
without duplicating any security logic: it drives the identical
:class:`~olympus.themis.jobs.ThemisJobStore`, the identical registered-scope
resolution and the identical redacted audit trail, so a job started from the
browser is indistinguishable — by policy and by audit — from one started on the
command line.

There is no ``POST /run-command`` and no arbitrary shell: the browser only ever
submits a typed request (``scanner``/``target``/``scope``) that the server
translates into the same scope- and policy-gated execution the CLI performs.

Hardening (all :data:`ROADMAP` ``WEB-A`` **P0**):

* authentication is a signed, ``HttpOnly`` + ``Secure`` + ``SameSite=Strict``
  session cookie minted only from a valid API credential;
* every state-changing form carries a synchroniser CSRF token bound to the
  session, checked in constant time;
* a restrictive Content-Security-Policy with **no inline script or style**
  (scripts and styles are same-origin static files) plus the API's security
  headers and bounded request body;
* all target-influenced text is stripped of terminal control sequences and
  URL secrets before rendering, and Jinja2 autoescaping defuses HTML
  (``SEC-H``).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, cast

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from olympus import __version__
from olympus.core.execution import (
    StructuredAuditRecord,
    append_structured_audit,
    redact_text,
)
from olympus.core.models import Engagement
from olympus.core.observability import Correlation, Observability, observability_from_config
from olympus.engagements.resolve import (
    EngagementStoreError,
    engagement_covers,
    load_engagements,
    require_engagement,
)
from olympus.integrations.capabilities import Capability, CapabilityState, inventory
from olympus.themis.api import (
    MAX_REQUEST_BYTES,
    ApiSettings,
    JobSubmission,
    _registered_scope,
    _RegisterSource,
    _trace_id,
)
from olympus.themis.identity import IdentityError, RateLimiter
from olympus.themis.jobs import (
    TERMINAL_STATES,
    IdempotencyConflict,
    JobState,
    ThemisJob,
    ThemisJobStore,
)

#: Where bundled templates and static assets live, next to this module.
_PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = _PACKAGE_ROOT / "web_templates"
STATIC_DIR = _PACKAGE_ROOT / "web_static"

SESSION_COOKIE = "olympus_session"
#: A browser session is deliberately short-lived; it is re-minted on login.
SESSION_TTL_SECONDS = 8 * 60 * 60
#: Control bytes a hostile target could smuggle into a banner, hostname or
#: scanner error to corrupt the operator's terminal or forge a log line.
_CONTROL_CHARACTERS = "".join(
    chr(code)
    for code in range(0x00, 0xA0)
    if code < 0x09 or (0x0B <= code <= 0x1F) or code == 0x7F or 0x80 <= code <= 0x9F
)
_CONTROL_TABLE = {ord(character): None for character in _CONTROL_CHARACTERS}

#: Human labels for the job lifecycle. Sub-phases the store does not record
#: (parsing/normalising) are not invented here: an honest state never implies
#: coverage the worker has not reported.
_STATE_LABELS: dict[JobState, str] = {
    JobState.QUEUED: "Queued",
    JobState.RUNNING: "Running",
    JobState.SUCCEEDED: "Completed",
    JobState.PARTIAL: "Partial — nothing ran",
    JobState.FAILED: "Failed",
    JobState.TIMED_OUT: "Timed out",
    JobState.CANCELLED: "Cancelled",
    JobState.POLICY_DENIED: "Policy denied",
}


@dataclass(frozen=True)
class WebSession:
    """The authenticated identity behind one browser session."""

    identity_id: str
    nonce: str
    scopes: tuple[str, ...]


def _safe(text: str) -> str:
    """Render target-influenced text safely: no control bytes, URL secrets redacted.

    Control bytes are stripped first so a smuggled escape cannot split a URL away
    from the redactor, then URL query secrets are redacted. Jinja2 autoescaping
    then neutralises any HTML before it reaches the page.
    """
    return redact_text(text.translate(_CONTROL_TABLE)).strip()


def _present_job(job: ThemisJob) -> dict[str, object]:
    """Project one job into a redacted, interface-agnostic view for the UI."""
    result = job.result if isinstance(job.result, dict) else None
    finding_count = result.get("finding_count") if result else None
    return {
        "job_id": job.job_id,
        "scanner": job.scanner,
        "target": _safe(job.target),
        "target_kind": job.target_kind,
        "scope_name": job.scope_name,
        "state": job.state.value,
        "state_label": _STATE_LABELS.get(job.state, job.state.value),
        "is_terminal": job.state in TERMINAL_STATES,
        "attempts": job.attempts,
        "max_attempts": job.max_attempts,
        "created_at": job.created_at.isoformat(),
        "updated_at": job.updated_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "error": _safe(job.error) if job.error else None,
        "finding_count": finding_count if isinstance(finding_count, int) else None,
    }


def _present_engagement(engagement: Engagement) -> dict[str, object]:
    """Project one engagement into a redacted, interface-agnostic view.

    Scope entries, name and client originate from the operator, not a target,
    but they still pass through :func:`_safe` so the engagement list cannot be
    used to smuggle control bytes into the operator's terminal or page.
    """
    return {
        "engagement_id": engagement.engagement_id,
        "name": _safe(engagement.name),
        "client": _safe(engagement.client),
        "status": engagement.status.value,
        "included": [_safe(entry) for entry in engagement.scope.included],
        "excluded": [_safe(entry) for entry in engagement.scope.excluded],
        "authorization_reference": _safe(engagement.authorization_reference),
        "tags": [_safe(tag) for tag in engagement.tags],
        "digest": engagement.digest(),
        "created_at": engagement.created_at.isoformat(),
        "updated_at": engagement.updated_at.isoformat(),
    }


#: Human, non-alarming labels for each operational readiness state. The state
#: itself is computed by the capability system, never by the GUI, so the page
#: cannot make a non-adapted scanner look executable.
_CAPABILITY_STATE_LABELS: dict[CapabilityState, str] = {
    CapabilityState.READY: "Ready",
    CapabilityState.ADAPTER_MISSING: "No Olympus adapter",
    CapabilityState.DEPENDENCY_MISSING: "Engine not installed",
    CapabilityState.CONFIGURATION_MISSING: "Not configured",
}


def _present_capability(capability: Capability) -> dict[str, object]:
    """Project one capability record into an interface-agnostic view for the UI.

    Every field is taken verbatim from the capability/registry system
    (:func:`olympus.integrations.capabilities.inventory`) — the same source the
    CLI (``olympus themis capabilities``) and the API (``/api/v1/capabilities``)
    read. Nothing is hardcoded in the GUI, so an engine that is catalogued but
    not adapted is shown with its honest state and never as runnable.
    """
    return {
        "name": capability.name,
        "category": capability.category,
        "purpose": capability.purpose,
        "kind": capability.kind,
        "licence": capability.licence,
        "adapted": capability.adapted,
        "available": capability.available,
        "ready": capability.ready,
        "state": capability.state.value,
        "state_label": _CAPABILITY_STATE_LABELS.get(capability.state, capability.state.value),
        "missing": list(capability.missing),
        "maturity": capability.maturity.value,
        "evidence": capability.evidence,
        "blocker": capability.blocker,
    }


def create_web_app(settings: ApiSettings, observability: Observability | None = None) -> FastAPI:
    """Build the fail-closed native web control plane over the canonical store."""
    settings.validate()
    if not TEMPLATES_DIR.is_dir() or not STATIC_DIR.is_dir():  # pragma: no cover - packaging
        raise RuntimeError("THEMIS web assets are missing from the installation")

    owns_telemetry = observability is None
    telemetry = observability or observability_from_config()
    store = ThemisJobStore(settings.database)
    store.initialize()
    scope_root = settings.scope_directory.resolve()
    registers = _RegisterSource(settings)
    limiter = RateLimiter()
    # A per-process secret: restarting the server invalidates every session,
    # which is the safe default. It never leaves the process.
    session_secret = secrets.token_bytes(32)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        try:
            yield
        finally:
            if owns_telemetry:
                telemetry.shutdown()

    app = FastAPI(
        title="Olympus THEMIS Web",
        version=__version__,
        description="Browser control plane over the authenticated THEMIS API.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _sign(payload: str) -> str:
        mac = hmac.new(session_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}.{mac}"

    def _unsign(token: str) -> str | None:
        payload, separator, mac = token.rpartition(".")
        if not separator or not payload or not mac:
            return None
        expected = hmac.new(session_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return None
        return payload

    def _csrf_token(nonce: str) -> str:
        return hmac.new(session_secret, f"csrf:{nonce}".encode(), hashlib.sha256).hexdigest()

    def _mint_session_cookie(identity_id: str) -> tuple[str, str]:
        nonce = secrets.token_urlsafe(16)
        expiry = int(time.time()) + SESSION_TTL_SECONDS
        return _sign(f"{identity_id}:{expiry}:{nonce}"), nonce

    def _load_session(request: Request) -> WebSession | None:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        payload = _unsign(token)
        if payload is None:
            return None
        identity_id, _, remainder = payload.partition(":")
        expiry_text, _, nonce = remainder.partition(":")
        if not identity_id or not expiry_text or not nonce:
            return None
        try:
            expiry = int(expiry_text)
        except ValueError:
            return None
        now = datetime.now(UTC)
        if expiry < int(now.timestamp()):
            return None
        identity = registers.current().find(identity_id)
        if identity is None or not identity.usable_at(now):
            # Revocation and expiry take effect without waiting for the cookie.
            return None
        return WebSession(identity_id, nonce, identity.validated_scopes())

    def _require_session(request: Request) -> WebSession:
        session = _load_session(request)
        if session is None:
            raise _Redirect("/login")
        request.state.identity_id = session.identity_id
        return session

    def requires(scope: str) -> WebSession:
        def dependency(request: Request) -> WebSession:
            session = _require_session(request)
            if scope not in session.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"session identity is not granted the {scope} scope",
                )
            return session

        # FastAPI resolves the dependency into a WebSession at request time.
        return cast(WebSession, Depends(dependency))

    reads_jobs = requires("jobs:read")
    writes_jobs = requires("jobs:write")
    cancels_jobs = requires("jobs:cancel")
    reads_engagements = requires("engagements:read")
    reads_capabilities = requires("capabilities:read")
    engagements_database = settings.engagements_database

    def _check_csrf(session: WebSession, supplied: str | None) -> None:
        if supplied is None or not hmac.compare_digest(supplied, _csrf_token(session.nonce)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")

    def _rate_limit(session: WebSession) -> None:
        identity = registers.current().find(session.identity_id)
        limit = identity.rate_limit_per_minute if identity is not None else 60
        if limiter.check(session.identity_id, limit) is not None:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limit exceeded for this identity",
            )

    @app.exception_handler(_Redirect)
    async def _redirect_handler(request: Request, exc: _Redirect) -> Response:
        del request
        return RedirectResponse(exc.location, status_code=status.HTTP_303_SEE_OTHER)

    @app.middleware("http")
    async def accountability(request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Give every request an id, echo it, and record it in the redacted audit."""
        started_at = time.monotonic()
        request_id = _trace_id(request.headers.get("x-request-id"), "web")
        request.state.request_id = request_id
        response: Response | None = None
        try:
            with telemetry.span("themis.web.request"):
                response = await call_next(request)
        finally:
            route_object = request.scope.get("route")
            route = getattr(route_object, "path", "unmatched")
            telemetry.api_request(
                "themis-web",
                request.method,
                route,
                response.status_code if response is not None else 500,
                time.monotonic() - started_at,
            )
        assert response is not None  # noqa: S101 - call_next returned without raising
        response.headers["X-Request-ID"] = request_id
        if settings.audit_path is not None:
            append_structured_audit(
                settings.audit_path,
                StructuredAuditRecord(
                    timestamp=datetime.now(UTC).isoformat(),
                    execution_id=request_id,
                    action=f"themis.web {request.method} {request.url.path}",
                    outcome=str(response.status_code),
                    metadata={
                        "identity": getattr(request.state, "identity_id", "anonymous"),
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
                declared = int(content_length)
                too_large = declared < 0 or declared > MAX_REQUEST_BYTES
            except ValueError:
                too_large = True
            if too_large:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})
        bounded = bytearray()
        async for chunk in request.stream():
            if len(bounded) + len(chunk) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})
            bounded.extend(chunk)
        request._body = bytes(bounded)

        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    def _page(request: Request, name: str, context: dict[str, object], code: int = 200) -> Response:
        payload: dict[str, object] = {"version": __version__, **context}
        return templates.TemplateResponse(request, name, payload, status_code=code)

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"service": "themis-web", "status": "ok", "version": __version__}

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    def login_form(request: Request) -> Response:
        if _load_session(request) is not None:
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        return _page(request, "login.html", {"error": None})

    @app.post("/login", include_in_schema=False)
    def login(
        request: Request,
        api_key: Annotated[str, Form()],
    ) -> Response:
        # Throttle credential guessing with a shared bucket before any check.
        if limiter.check("web:login", 60) is not None:
            return _page(
                request, "login.html", {"error": "Too many attempts; wait a minute."}, code=429
            )
        try:
            identity = registers.current().authenticate(api_key)
        except IdentityError:
            return _page(request, "login.html", {"error": "Invalid credential."}, code=401)
        token, _ = _mint_session_cookie(identity.identity_id)
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            secure=True,
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/logout", include_in_schema=False)
    def logout(request: Request) -> Response:
        session = _load_session(request)
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        if session is not None:
            response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard(request: Request, session: WebSession = reads_jobs) -> Response:
        jobs = store.list(limit=200)
        histogram: dict[str, int] = {}
        for job in jobs:
            histogram[job.state.value] = histogram.get(job.state.value, 0) + 1
        recent = [_present_job(job) for job in jobs[:10]]
        return _page(
            request,
            "dashboard.html",
            {
                "identity_id": session.identity_id,
                "scopes": session.scopes,
                "total": len(jobs),
                "histogram": histogram,
                "recent": recent,
                "csrf_token": _csrf_token(session.nonce),
            },
        )

    @app.get("/jobs", response_class=HTMLResponse, include_in_schema=False)
    def jobs_page(request: Request, session: WebSession = reads_jobs) -> Response:
        jobs = [_present_job(job) for job in store.list(limit=200)]
        return _page(
            request,
            "jobs.html",
            {"jobs": jobs, "csrf_token": _csrf_token(session.nonce)},
        )

    def _engagement_options() -> list[dict[str, str]]:
        """Offer the operator the engagements they can scope a scan to.

        Best-effort: a missing or unreadable store simply offers no engagements
        (the engagement field stays optional) rather than failing the form.
        """
        if engagements_database is None:
            return []
        try:
            engagements = load_engagements(engagements_database)
        except (EngagementStoreError, OSError):
            return []
        return [
            {"engagement_id": item.engagement_id, "name": _safe(item.name)} for item in engagements
        ]

    @app.get("/engagements", response_class=HTMLResponse, include_in_schema=False)
    def engagements_page(request: Request, session: WebSession = reads_engagements) -> Response:
        if engagements_database is None:
            return _page(request, "engagements.html", {"configured": False, "engagements": []})
        try:
            engagements = [
                _present_engagement(item) for item in load_engagements(engagements_database)
            ]
        except (EngagementStoreError, OSError):
            engagements = []
        return _page(
            request,
            "engagements.html",
            {"configured": True, "engagements": engagements},
        )

    @app.get("/engagements/{engagement_id}", response_class=HTMLResponse, include_in_schema=False)
    def engagement_detail(
        request: Request, engagement_id: str, session: WebSession = reads_engagements
    ) -> Response:
        if engagements_database is None:
            return _page(request, "engagements.html", {"configured": False, "engagements": []})
        try:
            engagement = require_engagement(engagements_database, engagement_id)
        except EngagementStoreError:
            return _page(request, "not_found.html", {"job_id": _safe(engagement_id)}, code=404)
        return _page(
            request,
            "engagement_detail.html",
            {"engagement": _present_engagement(engagement)},
        )

    @app.get("/tools", response_class=HTMLResponse, include_in_schema=False)
    def tools_page(request: Request, session: WebSession = reads_capabilities) -> Response:
        """Render the tool catalogue straight from the real capability inventory.

        The page is a faithful projection of
        :func:`olympus.integrations.capabilities.inventory`; it never hardcodes a
        tool list, so it reflects exactly what THEMIS has adapted, what is
        installed/configured on this host, and what is therefore runnable.
        """
        del session
        capabilities = [_present_capability(item) for item in inventory()]
        summary = {
            "catalogued": len(capabilities),
            "adapted": sum(1 for item in capabilities if item["adapted"]),
            "available": sum(1 for item in capabilities if item["available"]),
            "ready": sum(1 for item in capabilities if item["ready"]),
        }
        return _page(
            request,
            "tools.html",
            {"capabilities": capabilities, "summary": summary},
        )

    @app.get("/assessments/new", response_class=HTMLResponse, include_in_schema=False)
    def new_assessment(request: Request, session: WebSession = writes_jobs) -> Response:
        return _page(
            request,
            "new_assessment.html",
            {
                "error": None,
                "form": {},
                "engagements": _engagement_options(),
                "csrf_token": _csrf_token(session.nonce),
            },
        )

    @app.post("/jobs", include_in_schema=False)
    def submit_job(
        request: Request,
        scanner: Annotated[str, Form()],
        target: Annotated[str, Form()],
        scope_id: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
        target_kind: Annotated[str, Form()] = "host",
        authorized: Annotated[str | None, Form()] = None,
        engagement_id: Annotated[str | None, Form()] = None,
        idempotency_key: Annotated[str | None, Form()] = None,
        max_attempts: Annotated[int, Form()] = 1,
        session: WebSession = writes_jobs,
    ) -> Response:
        _check_csrf(session, csrf_token)
        _rate_limit(session)
        form = {
            "scanner": scanner,
            "target": target,
            "scope_id": scope_id,
            "engagement_id": engagement_id or "",
        }

        def _error(message: str, code: int = 400) -> Response:
            return _page(
                request,
                "new_assessment.html",
                {
                    "error": message,
                    "form": form,
                    "engagements": _engagement_options(),
                    "csrf_token": _csrf_token(session.nonce),
                },
                code=code,
            )

        is_authorized = (authorized or "").strip().lower() in {"on", "true", "1", "yes"}
        if not is_authorized:
            return _error("Documented authorization must be confirmed before an active scan.")
        chosen_engagement = (engagement_id or "").strip() or None
        try:
            submission = JobSubmission(
                scanner=scanner,
                target=target,
                target_kind=target_kind,  # type: ignore[arg-type]
                scope_id=scope_id,
                authorized=True,
                engagement_id=chosen_engagement,
                idempotency_key=(idempotency_key or None),
                max_attempts=max_attempts,
            )
        except ValidationError:
            return _error("The request is not valid; check scanner, target and scope.", code=422)
        if submission.engagement_id is not None:
            if engagements_database is None:
                return _error("No engagement store is configured on this server.", code=400)
            try:
                engagement = require_engagement(engagements_database, submission.engagement_id)
            except EngagementStoreError:
                return _error("The selected engagement does not exist.", code=404)
            if not engagement_covers(engagement, submission.target, submission.target_kind):
                return _error("That target is outside the selected engagement's scope.", code=422)
        try:
            scope_path = _registered_scope(scope_root, submission.scope_id)
        except HTTPException as exc:
            return _error(f"Scope rejected: {exc.detail}", code=exc.status_code)
        try:
            job = store.submit(
                scanner=submission.scanner,
                target=submission.target,
                target_kind=submission.target_kind,
                scope_path=scope_path,
                authorized=True,
                idempotency_key=submission.idempotency_key,
                max_attempts=submission.max_attempts,
            )
        except IdempotencyConflict as exc:
            return _error(f"Idempotency key already used for a different request: {exc}", code=409)
        except ValueError as exc:
            return _error(f"Rejected: {exc}", code=422)
        with telemetry.span("themis.job.queued", Correlation(job_id=job.job_id)):
            return RedirectResponse(f"/jobs/{job.job_id}", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse, include_in_schema=False)
    def job_detail(request: Request, job_id: str, session: WebSession = reads_jobs) -> Response:
        try:
            job = store.get(job_id)
        except KeyError:
            return _page(request, "not_found.html", {"job_id": _safe(job_id)}, code=404)
        return _page(
            request,
            "job_detail.html",
            {
                "job": _present_job(job),
                "can_cancel": "jobs:cancel" in session.scopes,
                "csrf_token": _csrf_token(session.nonce),
            },
        )

    @app.post("/jobs/{job_id}/cancel", include_in_schema=False)
    def cancel_job(
        request: Request,
        job_id: str,
        csrf_token: Annotated[str, Form()],
        session: WebSession = cancels_jobs,
    ) -> Response:
        _check_csrf(session, csrf_token)
        try:
            store.cancel(job_id)
        except KeyError:
            return _page(request, "not_found.html", {"job_id": _safe(job_id)}, code=404)
        return RedirectResponse(f"/jobs/{job_id}", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/jobs/{job_id}/events", include_in_schema=False)
    def job_events(job_id: str, session: WebSession = reads_jobs) -> Response:
        del session

        async def stream() -> AsyncIterator[str]:
            last_state: str | None = None
            # Bounded so a never-finishing job cannot hold the connection open
            # forever; the client reconnects with EventSource if it needs more.
            for _ in range(600):
                try:
                    job = store.get(job_id)
                except KeyError:
                    yield "event: error\ndata: job not found\n\n"
                    return
                view = _present_job(job)
                if view["state"] != last_state:
                    last_state = str(view["state"])
                    payload = (
                        f'{{"state": "{view["state"]}", '
                        f'"label": "{view["state_label"]}", '
                        f'"terminal": {str(view["is_terminal"]).lower()}}}'
                    )
                    yield f"event: state\ndata: {payload}\n\n"
                if view["is_terminal"]:
                    yield "event: end\ndata: terminal\n\n"
                    return
                await asyncio.sleep(0.5)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return app


class _Redirect(Exception):
    """Internal signal that an unauthenticated page request must go to login."""

    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location

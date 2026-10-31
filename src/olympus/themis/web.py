"""Native Themis web control plane (FastAPI + Jinja2 + server-sent events).

CLI, TUI, API and Web are different interfaces over the *same* core use cases.
This module adds a browser interface on top of the authenticated Themis API
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
import json
import re
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, cast
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from olympus import __version__
from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.execution import (
    StructuredAuditRecord,
    append_structured_audit,
    safe_terminal_text,
)
from olympus.core.finding_lifecycle import (
    SUPPRESSED_STATUSES,
    FindingTransitionError,
    allowed_transitions,
    record_transition,
)
from olympus.core.models import Engagement, Finding, Incident
from olympus.core.observability import Correlation, Observability, observability_from_config
from olympus.engagements.manifest import SignedEngagementManifest
from olympus.engagements.resolve import (
    EngagementStoreError,
    engagement_covers,
    load_engagements,
    require_engagement,
)
from olympus.findings.store import (
    FindingTransitionStoreError,
    SqliteFindingTransitionStore,
)
from olympus.integrations.activity import (
    ACTIVITY_CATALOGUE,
    RISK_EXPLANATION,
    ActivityType,
    RiskClass,
    activity_info,
    profile,
    recommended_scanner,
    scanners_for_activity,
)
from olympus.integrations.capabilities import Capability, CapabilityState, inventory
from olympus.integrations.smartscan import (
    OBJECTIVE_SUMMARY,
    ScanObjective,
    SmartScanPlan,
    objectives,
    propose_pipeline,
)
from olympus.minerva.triage import incident_status_breakdown, load_incidents
from olympus.themis.api import (
    MAX_REQUEST_BYTES,
    ApiSettings,
    JobSubmission,
    _registered_scope,
    _RegisterSource,
    _renew_request_lease,
    _trace_id,
    authorize_submission_manifest,
)
from olympus.themis.concurrency import RequestConcurrencyGate
from olympus.themis.identity import IdentityError, RateLimiter
from olympus.themis.jobs import (
    TERMINAL_STATES,
    IdempotencyConflict,
    JobState,
    ThemisJob,
    ThemisJobStore,
)
from olympus.vulcan.aggregate import (
    AggregationError,
    asset_breakdown,
    load_findings,
    severity_breakdown,
    source_breakdown,
)
from olympus.vulcan.compare import diff_findings
from olympus.vulcan.evidence_view import build_finding_evidence_view
from olympus.vulcan.report import (
    ReportSection,
    build_report_model,
    render_report_csv,
    render_report_html,
    render_report_markdown,
)
from olympus.vulcan.sarif import findings_to_sarif
from olympus.vulcan.search import FindingFilter, search_findings
from olympus.vulcan.view import FindingView, rank_by_risk

#: Where bundled templates and static assets live, next to this module.
_PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = _PACKAGE_ROOT / "web_templates"
STATIC_DIR = _PACKAGE_ROOT / "web_static"

SESSION_COOKIE = "olympus_session"
#: A browser session is deliberately short-lived; it is re-minted on login.
SESSION_TTL_SECONDS = 8 * 60 * 60
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
    """Render target-influenced text safely for a one-line web field.

    URL secrets and control characters are defanged centrally; Jinja2
    autoescaping then neutralises HTML before it reaches the page.
    """
    return safe_terminal_text(text)


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
        "distribution": capability.distribution,
        "version": capability.version,
    }


#: Short, non-alarming label per risk class for badges in the guided flow.
_RISK_LABELS: dict[RiskClass, str] = {
    RiskClass.PASSIVE: "Passive",
    RiskClass.ACTIVE: "Active",
    RiskClass.INTRUSIVE: "Intrusive",
    RiskClass.DESTRUCTIVE_PROHIBITED: "Prohibited",
}


def _native_activities() -> list[dict[str, str]]:
    """Return the activities that run as a Themis job, for the run form select."""
    return [
        {"value": info.activity.value, "title": info.title, "summary": info.summary}
        for info in ACTIVITY_CATALOGUE
        if info.themis_native
    ]


def _other_activities() -> list[dict[str, str]]:
    """Return the activities handled by other modules, surfaced honestly with a hint."""
    return [
        {
            "title": info.title,
            "summary": info.summary,
            "cli_hint": info.cli_hint or "",
        }
        for info in ACTIVITY_CATALOGUE
        if not info.themis_native
    ]


def _scanner_choices(ready: set[str]) -> list[dict[str, object]]:
    """Project every scanner into a guided-flow choice tagged with readiness.

    Activity and risk come from :mod:`olympus.integrations.activity`; readiness
    comes from the capability inventory. The GUI never decides either, so a
    non-adapted or uninstalled scanner is shown but honestly marked not-ready.
    """
    choices: list[dict[str, object]] = []
    for info in ACTIVITY_CATALOGUE:
        if not info.themis_native:
            continue
        for item in scanners_for_activity(info.activity):
            choices.append(
                {
                    "name": item.name,
                    "activity": item.activity.value,
                    "risk": item.risk.value,
                    "risk_label": _RISK_LABELS[item.risk],
                    "summary": item.summary,
                    "ready": item.name in ready,
                }
            )
    return choices


def _ready_scanner_names() -> set[str]:
    """Return the set of scanners that are runnable (adapted and available) here."""
    return {item.name for item in inventory() if item.ready}


#: Human labels for each severity, for a badge in the findings view.
_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}
#: Human labels for each lifecycle status (ROADMAP ``WEB-C``). The workflow and
#: its legal transitions are owned by :mod:`olympus.core.finding_lifecycle`; the
#: page only renders these labels, it never decides what a transition means.
_FINDING_STATUS_LABELS: dict[FindingStatus, str] = {
    FindingStatus.NEW: "New",
    FindingStatus.TRIAGED: "Triaged",
    FindingStatus.CONFIRMED: "Confirmed",
    FindingStatus.FALSE_POSITIVE: "False positive",
    FindingStatus.ACCEPTED: "Accepted risk",
    FindingStatus.IN_REMEDIATION: "In remediation",
    FindingStatus.CLOSED: "Closed",
}


class _FindingsUnavailable(Exception):
    """A findings bundle could not be read; the detail is already a safe string."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _as_finding_status(value: str) -> FindingStatus | None:
    """Parse a status filter value, returning ``None`` for anything unrecognised."""
    try:
        return FindingStatus(value)
    except ValueError:
        return None


def _as_severity(value: str) -> Severity | None:
    """Parse a severity filter value, returning ``None`` for anything unrecognised."""
    try:
        return Severity(value)
    except ValueError:
        return None


def _as_source(value: str) -> Source | None:
    """Parse a source filter value, returning ``None`` for anything unrecognised."""
    try:
        return Source(value)
    except ValueError:
        return None


def _present_finding_row(view: FindingView) -> dict[str, object]:
    """Project one finding into a redacted, interface-agnostic list row.

    The compact cells come from :meth:`FindingView.row` (the single tested place
    that renders list columns), so the browser shows the same risk, severity,
    status, asset, source, CVE and KEV values as the CLI and never re-derives
    them. ``title``/``asset`` are already terminal-safe from the view.
    """
    finding = view.finding
    row = view.row()
    return {
        "finding_id": finding.finding_id,
        "risk": row["risk"],
        "severity": finding.severity.value,
        "severity_label": _SEVERITY_LABELS.get(finding.severity, finding.severity.value),
        "status": finding.status.value,
        "status_label": _FINDING_STATUS_LABELS.get(finding.status, finding.status.value),
        "title": row["title"],
        "asset": row["asset"],
        "source": finding.source.value,
        "cve": row["cve"],
        "kev": finding.kev,
    }


def _finding_filter_from_params(
    *,
    status_filter: str,
    severity: str,
    source: str,
    text: str,
    kev_only: str,
    has_cve: str,
    min_risk: str,
    engagement: str = "",
    tag: str = "",
    asset: str = "",
) -> tuple[FindingFilter, dict[str, str]]:
    """Build a :class:`FindingFilter` from raw query params, plus an echo dict.

    The single place the browser turns filter query parameters into the shared
    filter, so the findings list and the exported report narrow a finding set
    *identically* — a report is always exactly what the filtered table showed.
    Unrecognised enum values and an out-of-range risk simply do not constrain.
    ``tag`` is a comma-separated list; a finding must carry **all** of the tags
    (case-insensitive), exactly as the CLI ``--tag`` repeated option does.
    """
    status_value = _as_finding_status(status_filter)
    source_value = _as_source(source)
    min_severity = _as_severity(severity)
    try:
        min_risk_value: float | None = float(min_risk) if min_risk.strip() else None
    except ValueError:
        min_risk_value = None
    if min_risk_value is not None and not 0.0 <= min_risk_value <= 100.0:
        min_risk_value = None
    tags = frozenset(part.strip() for part in tag.split(",") if part.strip())
    query = FindingFilter(
        statuses=frozenset({status_value}) if status_value is not None else frozenset(),
        sources=frozenset({source_value}) if source_value is not None else frozenset(),
        min_severity=min_severity,
        engagement_id=engagement.strip() or None,
        asset_id=asset.strip() or None,
        kev_only=bool(kev_only),
        has_cve=True if has_cve else None,
        tags=tags,
        text=text.strip(),
        min_risk_score=min_risk_value,
    )
    echo = {
        "status": status_filter,
        "severity": severity,
        "source": source,
        "engagement": engagement,
        "asset": asset,
        "tag": tag,
        "text": text,
        "kev_only": "on" if kev_only else "",
        "has_cve": "on" if has_cve else "",
        "min_risk": min_risk,
    }
    return query, echo


def _finding_filter_options() -> dict[str, list[dict[str, str]]]:
    """Offer the selectable filter values, drawn from the real contract enums."""
    return {
        "statuses": [
            {"value": status.value, "label": _FINDING_STATUS_LABELS[status]}
            for status in FindingStatus
        ],
        "severities": [
            {"value": severity.value, "label": _SEVERITY_LABELS[severity]}
            # Critical-first mirrors the risk ordering operators think in.
            for severity in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            )
        ],
        "sources": [{"value": source.value, "label": source.value} for source in Source],
    }


def create_web_app(settings: ApiSettings, observability: Observability | None = None) -> FastAPI:
    """Build the fail-closed native web control plane over the canonical store."""
    settings.validate()
    if not TEMPLATES_DIR.is_dir() or not STATIC_DIR.is_dir():  # pragma: no cover - packaging
        raise RuntimeError("Themis web assets are missing from the installation")

    owns_telemetry = observability is None
    telemetry = observability or observability_from_config()
    store = ThemisJobStore(settings.database)
    store.initialize()
    scope_root = settings.scope_directory.resolve()
    registers = _RegisterSource(settings)
    limiter = RateLimiter()
    concurrency = RequestConcurrencyGate(settings.database, settings.max_concurrent_requests)
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
        title="Olympus Themis Web",
        version=__version__,
        description="Browser control plane over the authenticated Themis API.",
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
    reads_findings = requires("findings:read")
    writes_findings = requires("findings:write")
    engagements_database = settings.engagements_database
    findings_directory = settings.findings_directory
    findings_database = settings.findings_database
    baseline_findings_directory = settings.baseline_findings_directory
    incidents_directory = settings.incidents_directory

    def _load_findings_from(directory: Path) -> list[Finding]:
        """Load every ``*.json`` finding bundle in ``directory``, bounded.

        The bundles are the same read-only producer artifacts the CLI consumes
        (``olympus vulcan findings``), loaded through the identical strict,
        bounded :func:`load_findings`. A bundle that cannot be read or parsed
        raises :class:`_FindingsUnavailable` so the page is honest about a broken
        input rather than silently showing fewer findings than exist.
        """
        root = directory.resolve()
        if not root.is_dir():
            raise _FindingsUnavailable("the findings directory is unavailable")
        try:
            paths = sorted(path for path in root.glob("*.json") if path.is_file())
        except OSError as exc:
            raise _FindingsUnavailable("the findings directory could not be read") from exc
        if not paths:
            return []
        try:
            return load_findings(paths)
        except AggregationError as exc:
            raise _FindingsUnavailable(_safe(str(exc))) from exc
        except OSError as exc:
            raise _FindingsUnavailable("a findings bundle could not be read") from exc

    def _load_findings_catalogue() -> list[Finding]:
        """Load the configured current-findings directory (see :func:`_load_findings_from`)."""
        assert findings_directory is not None  # noqa: S101 - callers guard on configuration
        return _load_findings_from(findings_directory)

    def _load_incidents_catalogue() -> list[Incident] | None:
        """Load the configured incident directory, or ``None`` when unreadable.

        Each file is a read-only ``olympus.incident`` document produced by
        ``olympus minerva triage`` (:func:`load_incidents`). A missing, broken or
        malformed directory returns ``None`` so the dashboard honestly omits the
        incident widget rather than inventing a count.
        """
        assert incidents_directory is not None  # noqa: S101 - callers guard on configuration
        root = incidents_directory.resolve()
        if not root.is_dir():
            return None
        try:
            paths = sorted(path for path in root.glob("*.json") if path.is_file())
            return load_incidents(paths)
        except (OSError, ValueError):
            return None

    def _open_transition_store() -> SqliteFindingTransitionStore | None:
        """Open the append-only lifecycle store, or ``None`` when not configured."""
        if findings_database is None:
            return None
        return SqliteFindingTransitionStore(findings_database)

    def _effective_finding(finding: Finding, store: SqliteFindingTransitionStore | None) -> Finding:
        """Return ``finding`` with its *current* status folded from recorded history.

        The bundle carries the status at production time; the durable lifecycle
        lives in the append-only transition store. The latest recorded transition
        is the finding's effective status, so a triage decision made in the
        browser is reflected everywhere the finding is shown — without ever
        rewriting the immutable producer artifact.
        """
        if store is None:
            return finding
        history = store.history(finding.finding_id)
        if not history:
            return finding
        return finding.model_copy(update={"status": history[-1].to_status})

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

    @app.middleware("http")
    async def concurrency_boundary(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Bound in-flight requests before buffering their bodies or dispatching them."""
        started_at = time.monotonic()
        request_id = _trace_id(request.headers.get("x-request-id"), "web")
        lease = concurrency.try_acquire()
        if lease is None:
            telemetry.api_request(
                "themis-web", request.method, "overloaded", 503, time.monotonic() - started_at
            )
            if settings.audit_path is not None:
                append_structured_audit(
                    settings.audit_path,
                    StructuredAuditRecord(
                        timestamp=datetime.now(UTC).isoformat(),
                        execution_id=request_id,
                        action=f"themis.web {request.method} request-overload",
                        outcome="503",
                        metadata={"identity": "anonymous", "status": 503},
                    ),
                )
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Themis Web concurrency limit reached"},
                headers={
                    "Retry-After": "1",
                    "X-Request-ID": request_id,
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Content-Security-Policy": (
                        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                        "connect-src 'self'; form-action 'self'; base-uri 'none'; "
                        "frame-ancestors 'none'"
                    ),
                },
            )
        heartbeat = asyncio.create_task(_renew_request_lease(concurrency, lease))
        try:
            return await call_next(request)
        finally:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
            concurrency.release(lease)

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
        histogram = store.counts_by_state()
        total_jobs = sum(histogram.values())
        recent = [_present_job(job) for job in jobs[:10]]
        # Assessment progress uses database aggregates so older jobs beyond the
        # recent-jobs page are included. TERMINAL_STATES remains the authoritative
        # partition for completed jobs; the widget is absent when there are no jobs.
        assessment_progress: dict[str, object] | None = None
        if total_jobs:
            done = sum(histogram[state.value] for state in TERMINAL_STATES)
            clean = histogram[JobState.SUCCEEDED.value]
            assessment_progress = {
                "total": total_jobs,
                "done": done,
                "active": total_jobs - done,
                "clean": clean,
                "percent": round(done * 100 / total_jobs),
            }
        # Findings-by-severity widget (WEB-G): only for an identity that may read
        # findings, and only when a findings directory is configured and readable —
        # otherwise the card is simply absent (the Findings page surfaces errors).
        findings_summary: dict[str, object] | None = None
        findings_unavailable = False
        if findings_directory is not None and "findings:read" in session.scopes:
            try:
                catalogue = _load_findings_catalogue()
            except _FindingsUnavailable:
                findings_unavailable = True
            else:
                breakdown = severity_breakdown(catalogue)
                sources = source_breakdown(catalogue)
                # Top assets by exposure (WEB-G asset aggregation): worst-exposed
                # first, capped so the card stays compact. The drill-down uses the
                # exact asset filter so it shows only that asset's findings.
                assets = asset_breakdown(catalogue)[:5]
                findings_summary = {
                    "total": len(catalogue),
                    "levels": [
                        {"severity": level, "count": breakdown[level]}
                        for level in ("critical", "high", "medium", "low", "info")
                    ],
                    "sources": [
                        {"source": source, "count": count} for source, count in sources.items()
                    ],
                    "assets": [
                        {
                            "asset_id": exposure.asset_id,
                            "count": exposure.finding_count,
                            "severity": exposure.highest_severity.value,
                        }
                        for exposure in assets
                    ],
                }
        # Scanner-readiness widget (WEB-G): only for an identity that may read
        # capabilities. It is a faithful projection of the capability inventory
        # (the same source the Tools page and ``olympus themis capabilities`` use),
        # answering "which adapted scanners can actually run on this host now?".
        scanner_readiness: dict[str, object] | None = None
        if "capabilities:read" in session.scopes:
            capabilities = list(inventory())
            adapted = [item for item in capabilities if item.adapted]
            scanner_readiness = {
                "catalogued": len(capabilities),
                "adapted": len(adapted),
                "ready": sum(1 for item in adapted if item.ready),
                "available": sum(1 for item in adapted if item.available),
            }
        # Incidents-by-status widget (WEB-G): only for an identity that may read
        # incidents, and only when an incident directory is configured and
        # readable — otherwise the card is simply absent. "open" is the one
        # not-yet-worked status; the rest of the lifecycle is shown for context.
        incident_summary: dict[str, object] | None = None
        incidents_unavailable = False
        if incidents_directory is not None and "incidents:read" in session.scopes:
            incidents = _load_incidents_catalogue()
            if incidents is None:
                incidents_unavailable = True
            else:
                status_counts = incident_status_breakdown(incidents)
                incident_summary = {
                    "total": len(incidents),
                    "open": status_counts["open"],
                    "statuses": [
                        {"status": status, "count": status_counts[status]}
                        for status in (
                            "open",
                            "triaged",
                            "contained",
                            "eradicated",
                            "recovered",
                            "closed",
                        )
                    ],
                }
        return _page(
            request,
            "dashboard.html",
            {
                "identity_id": session.identity_id,
                "scopes": session.scopes,
                "total": total_jobs,
                "histogram": histogram,
                "recent": recent,
                "assessment_progress": assessment_progress,
                "findings_summary": findings_summary,
                "findings_unavailable": findings_unavailable,
                "scanner_readiness": scanner_readiness,
                "incident_summary": incident_summary,
                "incidents_unavailable": incidents_unavailable,
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

    def _engagement_options() -> tuple[list[dict[str, str]], bool]:
        """Offer the operator the engagements they can scope a scan to.

        Best-effort: a missing or unreadable store simply offers no engagements
        (the engagement field stays optional) rather than failing the form.
        """
        if engagements_database is None:
            return [], False
        try:
            engagements = load_engagements(engagements_database)
        except (EngagementStoreError, OSError, sqlite3.Error):
            return [], True
        return (
            [
                {"engagement_id": item.engagement_id, "name": _safe(item.name)}
                for item in engagements
            ],
            False,
        )

    @app.get("/engagements", response_class=HTMLResponse, include_in_schema=False)
    def engagements_page(request: Request, session: WebSession = reads_engagements) -> Response:
        if engagements_database is None:
            return _page(
                request,
                "engagements.html",
                {"configured": False, "unavailable": False, "engagements": []},
            )
        try:
            engagements = [
                _present_engagement(item) for item in load_engagements(engagements_database)
            ]
        except (EngagementStoreError, OSError, sqlite3.Error):
            return _page(
                request,
                "engagements.html",
                {"configured": True, "unavailable": True, "engagements": []},
            )
        return _page(
            request,
            "engagements.html",
            {"configured": True, "unavailable": False, "engagements": engagements},
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
        tool list, so it reflects exactly what Themis has adapted, what is
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

    def _assessment_context(
        session: WebSession, form: dict[str, str] | None = None, error: str | None = None
    ) -> dict[str, object]:
        """Shared context for the guided New Assessment form (step 1)."""
        ready = _ready_scanner_names()
        engagements, engagements_unavailable = _engagement_options()
        return {
            "error": error,
            "form": form or {},
            "engagements": engagements,
            "engagement_store_unavailable": engagements_unavailable,
            "activities": _native_activities(),
            "other_activities": _other_activities(),
            "scanners": _scanner_choices(ready),
            "ready_count": len(ready),
            "manifest_required": settings.trusted_manifest_public_key_pem is not None,
            "csrf_token": _csrf_token(session.nonce),
        }

    @app.get("/assessments/new", response_class=HTMLResponse, include_in_schema=False)
    def new_assessment(request: Request, session: WebSession = writes_jobs) -> Response:
        return _page(request, "new_assessment.html", _assessment_context(session))

    @app.post("/assessments/preview", response_class=HTMLResponse, include_in_schema=False)
    def preview_assessment(
        request: Request,
        activity: Annotated[str, Form()],
        target: Annotated[str, Form()],
        scope_id: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
        target_kind: Annotated[str, Form()] = "host",
        scanner: Annotated[str, Form()] = "",
        engagement_id: Annotated[str | None, Form()] = None,
        idempotency_key: Annotated[str | None, Form()] = None,
        signed_manifest: Annotated[str | None, Form()] = None,
        max_attempts: Annotated[int, Form()] = 1,
        session: WebSession = writes_jobs,
    ) -> Response:
        """Render the "Olympus is about to run" preview before any launch.

        Nothing is queued here: the step re-validates the scope and engagement,
        resolves the scanner (honouring automatic mode), and shows the risk
        class. Only the explicit launch form on this page submits to ``/jobs``.
        """
        _check_csrf(session, csrf_token)
        form = {
            "scanner": scanner,
            "target": target,
            "target_kind": target_kind,
            "scope_id": scope_id,
            "activity": activity,
            "engagement_id": engagement_id or "",
            "signed_manifest": signed_manifest or "",
        }

        def _back(message: str, code: int = 400) -> Response:
            return _page(
                request, "new_assessment.html", _assessment_context(session, form, message), code
            )

        try:
            chosen_activity = ActivityType(activity)
        except ValueError:
            return _back("Choose a valid activity type.", code=422)
        if not activity_info(chosen_activity).themis_native:
            hint = activity_info(chosen_activity).cli_hint or "the relevant Olympus module"
            return _back(f"That activity is not run from the web yet; use {hint}.", code=422)

        ready = _ready_scanner_names()
        resolved = scanner.strip() or recommended_scanner(chosen_activity, ready)
        if resolved is None:
            return _back(
                "No scanner for this activity is ready on this host. "
                "Check the Tools page for what is missing.",
                code=422,
            )
        scanner_profile = profile(resolved)
        if scanner_profile is None:
            return _back("Unknown scanner.", code=422)
        if scanner_profile.activity is not chosen_activity:
            return _back("That scanner does not belong to the chosen activity.", code=422)
        if resolved not in ready:
            return _back(
                f"'{resolved}' is not ready on this host; pick a ready tool or automatic mode.",
                code=422,
            )

        chosen_engagement = (engagement_id or "").strip() or None
        parsed_manifest = None
        if signed_manifest:
            try:
                parsed_manifest = SignedEngagementManifest.model_validate_json(signed_manifest)
            except ValueError:
                return _back("The signed engagement manifest is not valid JSON.", code=422)
        try:
            submission = JobSubmission(
                scanner=resolved,
                target=target,
                target_kind=target_kind,  # type: ignore[arg-type]
                scope_id=scope_id,
                authorized=True,
                engagement_id=chosen_engagement,
                signed_manifest=parsed_manifest,
                idempotency_key=(idempotency_key or None),
                max_attempts=max_attempts,
            )
        except ValidationError:
            return _back("The request is not valid; check target, scope and options.", code=422)

        engagement_name: str | None = None
        if submission.engagement_id is not None:
            if engagements_database is None:
                return _back("No engagement store is configured on this server.", code=400)
            try:
                engagement = require_engagement(engagements_database, submission.engagement_id)
            except EngagementStoreError:
                return _back("The selected engagement does not exist.", code=404)
            if not engagement_covers(engagement, submission.target, submission.target_kind):
                return _back("That target is outside the selected engagement's scope.", code=422)
            engagement_name = _safe(engagement.name)

        try:
            scope_path = _registered_scope(scope_root, submission.scope_id)
        except HTTPException as exc:
            return _back(f"Scope rejected: {exc.detail}", code=exc.status_code)

        try:
            manifest_sha256 = authorize_submission_manifest(settings, submission)
        except HTTPException as exc:
            return _back(f"Authorization rejected: {exc.detail}", code=exc.status_code)

        # Redacted dry-run command (SEC-G): the exact argv the scan would run,
        # built offline from the same shared preview helper the CLI uses. Shown
        # before confirmation; ``None`` degrades to an honest "not shown" note.
        planned_command_tokens: list[str] | None = None
        try:
            from olympus.themis.application import load_scope
            from olympus.themis.preview import planned_command

            tokens = planned_command(
                resolved, submission.target, submission.target_kind, load_scope(scope_path)
            )
            planned_command_tokens = list(tokens) if tokens is not None else None
        except (OSError, ValueError):
            planned_command_tokens = None

        needs_confirmation = scanner_profile.risk is not RiskClass.PASSIVE
        return _page(
            request,
            "assessment_preview.html",
            {
                "scanner": resolved,
                "automatic": not scanner.strip(),
                "summary": scanner_profile.summary,
                "activity_title": activity_info(chosen_activity).title,
                "risk": scanner_profile.risk.value,
                "risk_label": _RISK_LABELS[scanner_profile.risk],
                "risk_explanation": RISK_EXPLANATION[scanner_profile.risk],
                "planned_command": planned_command_tokens,
                "needs_confirmation": needs_confirmation,
                # The raw target is what the launch form must resubmit (and what
                # /jobs re-validates); the safe copy is only ever displayed.
                "target": submission.target,
                "target_display": _safe(submission.target),
                "target_kind": submission.target_kind,
                "scope_id": submission.scope_id,
                "engagement_id": submission.engagement_id or "",
                "engagement_name": engagement_name,
                "idempotency_key": submission.idempotency_key or "",
                "max_attempts": submission.max_attempts,
                "signed_manifest": signed_manifest or "",
                "manifest_sha256": manifest_sha256,
                "csrf_token": _csrf_token(session.nonce),
            },
        )

    def _smart_scan_context(
        session: WebSession, form: dict[str, str] | None = None, error: str | None = None
    ) -> dict[str, object]:
        """Shared context for the Smart Scan form (step 1, before any plan)."""
        engagements, engagements_unavailable = _engagement_options()
        return {
            "error": error,
            "form": form or {},
            "engagements": engagements,
            "engagement_store_unavailable": engagements_unavailable,
            "objectives": [
                {"value": item.value, "summary": OBJECTIVE_SUMMARY[item]} for item in objectives()
            ],
            "risk_levels": [
                {"value": level.value, "label": _RISK_LABELS[level]}
                for level in (RiskClass.PASSIVE, RiskClass.ACTIVE, RiskClass.INTRUSIVE)
            ],
            "manifest_required": settings.trusted_manifest_public_key_pem is not None,
            "plan": None,
            "csrf_token": _csrf_token(session.nonce),
        }

    def _present_smart_scan_plan(
        plan: SmartScanPlan, *, scope_id: str, engagement_name: str | None
    ) -> dict[str, object]:
        """Project a plan into a redacted, handoff-ready view for the template.

        Each stage carries the fields the existing ``/assessments/preview`` form
        needs, so launching a step still goes through the real scope,
        authorization and preview gate — the Smart Scan page only proposes.
        Target- and scanner-derived text is escaped with :func:`_safe` so a
        hostile hostname or rationale cannot inject markup (ROADMAP ``SEC-H``).
        """
        return {
            "objective": plan.objective.value,
            "objective_summary": OBJECTIVE_SUMMARY[plan.objective],
            "target": plan.target,
            "target_display": _safe(plan.target),
            "target_kind": plan.target_kind,
            "scope_id": scope_id,
            "engagement_id": plan.engagement_id or "",
            "engagement_name": engagement_name,
            "in_scope": plan.in_scope,
            "max_risk": plan.max_risk.value,
            "max_risk_label": _RISK_LABELS[plan.max_risk],
            "requires_authorization": plan.requires_authorization,
            "digest": plan.digest,
            "stages": [
                {
                    "order": stage.order,
                    "activity": stage.activity.value,
                    "activity_title": activity_info(stage.activity).title,
                    "scanner": stage.scanner,
                    "risk": stage.risk.value,
                    "risk_label": _RISK_LABELS[stage.risk],
                    "risk_explanation": RISK_EXPLANATION[stage.risk],
                    "needs_authorization": stage.needs_authorization,
                    "rationale": _safe(stage.rationale),
                }
                for stage in plan.stages
            ],
            "excluded": [
                {"activity": dropped.activity.value, "reason": _safe(dropped.reason)}
                for dropped in plan.excluded
            ],
        }

    @app.get("/assessments/smart", response_class=HTMLResponse, include_in_schema=False)
    def smart_scan(request: Request, session: WebSession = writes_jobs) -> Response:
        return _page(request, "smart_scan.html", _smart_scan_context(session))

    @app.post("/assessments/smart/plan", response_class=HTMLResponse, include_in_schema=False)
    def smart_scan_plan(
        request: Request,
        objective: Annotated[str, Form()],
        target: Annotated[str, Form()],
        scope_id: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
        target_kind: Annotated[str, Form()] = "host",
        max_risk: Annotated[str, Form()] = "active",
        engagement_id: Annotated[str | None, Form()] = None,
        session: WebSession = writes_jobs,
    ) -> Response:
        """Propose a deterministic Smart Scan pipeline. Queues and runs nothing.

        The plan is built from the same interface-agnostic engine the CLI uses,
        so it is reproducible. When an engagement is chosen the target is
        scope-checked here: a target outside its perimeter yields a plan with no
        stages, so no branch is ever proposed out of scope.
        """
        _check_csrf(session, csrf_token)
        form = {
            "objective": objective,
            "target": target,
            "target_kind": target_kind,
            "scope_id": scope_id,
            "max_risk": max_risk,
            "engagement_id": engagement_id or "",
        }

        def _back(message: str, code: int = 400) -> Response:
            return _page(
                request, "smart_scan.html", _smart_scan_context(session, form, message), code
            )

        try:
            chosen_objective = ScanObjective(objective)
        except ValueError:
            return _back("Choose a valid objective.", code=422)
        try:
            ceiling = RiskClass(max_risk)
        except ValueError:
            return _back("Choose a valid risk ceiling.", code=422)
        if target_kind not in {"host", "domain", "url"}:
            return _back("Target kind must be host, domain or url.", code=422)
        if not target.strip():
            return _back("Enter a target.", code=422)

        chosen_engagement = (engagement_id or "").strip() or None
        resolved_engagement = None
        engagement_name: str | None = None
        if chosen_engagement is not None:
            if engagements_database is None:
                return _back("No engagement store is configured on this server.", code=400)
            try:
                resolved_engagement = require_engagement(engagements_database, chosen_engagement)
            except EngagementStoreError:
                return _back("The selected engagement does not exist.", code=404)
            engagement_name = _safe(resolved_engagement.name)

        plan = propose_pipeline(
            objective=chosen_objective,
            target=target,
            target_kind=target_kind,
            ready=_ready_scanner_names(),
            engagement=resolved_engagement,
            max_risk=ceiling,
        )

        context = _smart_scan_context(session, form)
        context["plan"] = _present_smart_scan_plan(
            plan, scope_id=scope_id, engagement_name=engagement_name
        )
        return _page(request, "smart_scan.html", context)

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
        signed_manifest: Annotated[str | None, Form()] = None,
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
            "signed_manifest": signed_manifest or "",
        }

        def _error(message: str, code: int = 400) -> Response:
            return _page(
                request,
                "new_assessment.html",
                _assessment_context(session, form, message),
                code=code,
            )

        is_authorized = (authorized or "").strip().lower() in {"on", "true", "1", "yes"}
        if not is_authorized:
            return _error("Documented authorization must be confirmed before an active scan.")
        chosen_engagement = (engagement_id or "").strip() or None
        parsed_manifest = None
        if signed_manifest:
            try:
                parsed_manifest = SignedEngagementManifest.model_validate_json(signed_manifest)
            except ValueError:
                return _error("The signed engagement manifest is not valid JSON.", code=422)
        try:
            submission = JobSubmission(
                scanner=scanner,
                target=target,
                target_kind=target_kind,  # type: ignore[arg-type]
                scope_id=scope_id,
                authorized=True,
                engagement_id=chosen_engagement,
                signed_manifest=parsed_manifest,
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
            manifest_sha256 = authorize_submission_manifest(settings, submission)
        except HTTPException as exc:
            return _error(f"Authorization rejected: {exc.detail}", code=exc.status_code)
        try:
            job = store.submit(
                scanner=submission.scanner,
                target=submission.target,
                target_kind=submission.target_kind,
                scope_path=scope_path,
                authorized=True,
                manifest_sha256=manifest_sha256,
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

    @app.get("/findings", response_class=HTMLResponse, include_in_schema=False)
    def findings_page(
        request: Request,
        status_filter: str = "",
        severity: str = "",
        source: str = "",
        text: str = "",
        kev_only: str = "",
        has_cve: str = "",
        min_risk: str = "",
        engagement: str = "",
        tag: str = "",
        asset: str = "",
        session: WebSession = reads_findings,
    ) -> Response:
        """List findings, filtered and ranked exactly as the CLI does.

        Narrowing reuses :class:`FindingFilter`/:func:`search_findings` and the
        ordering reuses :func:`rank_by_risk`, so the browser produces the same
        result set the operator would get from ``olympus vulcan findings list``.
        Unrecognised filter values simply do not constrain the result.
        """
        query, filters = _finding_filter_from_params(
            status_filter=status_filter,
            severity=severity,
            source=source,
            text=text,
            kev_only=kev_only,
            has_cve=has_cve,
            min_risk=min_risk,
            engagement=engagement,
            tag=tag,
            asset=asset,
        )
        base_context: dict[str, object] = {
            "configured": findings_directory is not None,
            "filters": filters,
            "options": _finding_filter_options(),
            "findings": [],
            "total": 0,
            "matched": 0,
            "error": None,
            "lifecycle_enabled": findings_database is not None,
            "report_query": urlencode({k: v for k, v in filters.items() if v}),
        }
        if findings_directory is None:
            return _page(request, "findings.html", base_context)
        try:
            catalogue = _load_findings_catalogue()
        except _FindingsUnavailable as exc:
            return _page(request, "findings.html", {**base_context, "error": exc.detail})

        store = _open_transition_store()
        try:
            effective = [_effective_finding(finding, store) for finding in catalogue]
        finally:
            if store is not None:
                store.close()
        matched = rank_by_risk(search_findings(effective, query))
        rows = [_present_finding_row(FindingView(finding)) for finding in matched]
        return _page(
            request,
            "findings.html",
            {
                **base_context,
                "findings": rows,
                "total": len(catalogue),
                "matched": len(rows),
            },
        )

    @app.get("/findings/report", include_in_schema=False)
    def findings_report(
        request: Request,
        format: str = "md",
        engagement: str = "",
        status_filter: str = "",
        severity: str = "",
        source: str = "",
        text: str = "",
        kev_only: str = "",
        has_cve: str = "",
        min_risk: str = "",
        tag: str = "",
        asset: str = "",
        report_section: str = "full",
        session: WebSession = reads_findings,
    ) -> Response:
        """Export a Vulcan report of the *currently filtered* findings (ROADMAP ``WEB-I``).

        The report builder composes over Vulcan without duplicating any rendering
        logic: it narrows the catalogue with the **same** filter the table uses
        (:func:`_finding_filter_from_params`), builds the canonical
        :class:`~olympus.core.models.SecurityReport` with
        :func:`build_report_model`, and renders it with the existing
        :func:`render_report_markdown` / :func:`render_report_html` / the model's
        own JSON dump. The result is served as a download so what reaches the
        browser is a report, not a page.
        """
        chosen = format.strip().lower()
        renderers = {"json", "md", "markdown", "html", "sarif", "csv", "pdf"}
        if chosen not in renderers:
            raise HTTPException(
                status_code=422, detail="format must be one of json, md, html, sarif, csv, pdf"
            )
        if findings_directory is None:
            raise HTTPException(status_code=400, detail="no findings directory is configured")
        try:
            catalogue = _load_findings_catalogue()
        except _FindingsUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.detail) from exc

        query, _ = _finding_filter_from_params(
            status_filter=status_filter,
            severity=severity,
            source=source,
            text=text,
            kev_only=kev_only,
            has_cve=has_cve,
            min_risk=min_risk,
            engagement=engagement,
            tag=tag,
            asset=asset,
        )
        store = _open_transition_store()
        try:
            effective = [_effective_finding(finding, store) for finding in catalogue]
        finally:
            if store is not None:
                store.close()
        matched = rank_by_risk(search_findings(effective, query))

        # The engagement is a human label for the report header; sanitise it and
        # derive a filesystem-safe slug so it cannot inject into the download name
        # or the Content-Disposition header.
        label = _safe(engagement.strip()) or "olympus-findings"
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-")[:64] or "olympus-findings"
        report = build_report_model(label, [], matched, [])
        # Markdown/HTML may be scoped to an executive summary; machine formats
        # (json/csv/sarif) are always the full set. An unknown value is full.
        section: ReportSection = "executive" if report_section.strip() == "executive" else "full"

        body: str | bytes
        if chosen == "json":
            body = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            media_type, extension = "application/json", "json"
        elif chosen == "sarif":
            # SARIF of the filtered findings, for any SARIF consumer (CI code-scanning).
            body = json.dumps(findings_to_sarif(matched), indent=2, sort_keys=True) + "\n"
            media_type, extension = "application/sarif+json", "sarif.json"
        elif chosen in {"md", "markdown"}:
            body = render_report_markdown(report, section=section)
            media_type, extension = "text/markdown; charset=utf-8", "md"
        elif chosen == "csv":
            # Spreadsheet-safe CSV of the filtered findings (cells neutralised
            # against formula injection by the renderer).
            body = render_report_csv(report)
            media_type, extension = "text/csv; charset=utf-8", "csv"
        elif chosen == "pdf":
            # Formatted PDF of the filtered findings; needs the optional 'report'
            # extra (reportlab). The section parameter does not apply to the PDF.
            from olympus.vulcan.pdf import PdfUnavailableError, render_report_pdf

            try:
                body = render_report_pdf(report)
            except PdfUnavailableError as exc:
                raise HTTPException(status_code=503, detail=_safe(str(exc))) from exc
            media_type, extension = "application/pdf", "pdf"
        else:
            body = render_report_html(report, section=section)
            media_type, extension = "text/html; charset=utf-8", "html"
        return Response(
            content=body,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="olympus-report-{slug}.{extension}"',
                "Cache-Control": "no-store",
            },
        )

    @app.get("/findings/diff", response_class=HTMLResponse, include_in_schema=False)
    def findings_diff(
        request: Request, format: str = "", session: WebSession = reads_findings
    ) -> Response:
        """Compare the baseline run against the current findings (ROADMAP ``WEB-I``).

        Shows what is **new** (a regression), **resolved** (the evidence a fix
        landed) and **persistent** between a configured baseline directory and the
        current findings directory, reusing :func:`diff_findings` — the same
        engine the CLI (``olympus vulcan diff``) uses — so both agree. It never
        rewrites either producer artifact. ``?format=json`` returns the machine
        -readable ``ScanDiff`` (the same projection as ``vulcan diff --format
        json``) for automation; the default renders the HTML page.
        """
        as_json = format.strip().lower()
        if as_json not in {"", "json"}:
            raise HTTPException(status_code=422, detail="format must be json")
        wants_json = as_json == "json"
        context: dict[str, object] = {
            "has_current": findings_directory is not None,
            "has_baseline": baseline_findings_directory is not None,
            "configured": findings_directory is not None
            and baseline_findings_directory is not None,
            "error": None,
            "summary": None,
            "new": [],
            "resolved": [],
            "persistent": [],
        }
        if findings_directory is None or baseline_findings_directory is None:
            if wants_json:
                raise HTTPException(
                    status_code=400,
                    detail="scan diff needs both --findings-directory and --baseline-directory",
                )
            return _page(request, "findings_diff.html", context)
        try:
            current = _load_findings_catalogue()
            baseline = _load_findings_from(baseline_findings_directory)
        except _FindingsUnavailable as exc:
            if wants_json:
                raise HTTPException(status_code=503, detail=exc.detail) from exc
            return _page(request, "findings_diff.html", {**context, "error": exc.detail})
        result = diff_findings(baseline, current)
        if wants_json:
            return Response(
                content=json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
                media_type="application/json",
                headers={
                    "Content-Disposition": 'attachment; filename="olympus-scan-diff.json"',
                    "Cache-Control": "no-store",
                },
            )
        return _page(
            request,
            "findings_diff.html",
            {
                **context,
                "summary": result.summary(),
                "new": [_present_finding_row(FindingView(f)) for f in result.new],
                "resolved": [_present_finding_row(FindingView(f)) for f in result.resolved],
                "persistent": [
                    {
                        **_present_finding_row(FindingView(item.current)),
                        "baseline_severity": item.baseline.severity.value,
                        "severity_changed": item.severity_changed,
                        "severity_worsened": item.severity_worsened,
                        "risk_delta": f"{item.risk_delta:+g}",
                    }
                    for item in result.persistent
                ],
            },
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse, include_in_schema=False)
    def finding_detail(
        request: Request, finding_id: str, session: WebSession = reads_findings
    ) -> Response:
        """Show one finding's detail, evidence chain and lifecycle history.

        The detail cells come from :meth:`FindingView.display_items` and the
        evidence browser from :func:`build_finding_evidence_view` (custody is
        rendered honestly as "no custody record" when no ledger is wired in).
        The transition choices are exactly :func:`allowed_transitions` of the
        finding's effective status — the GUI never invents a workflow edge.
        """
        if findings_directory is None:
            return _page(request, "finding_detail.html", {"configured": False})
        try:
            catalogue = _load_findings_catalogue()
        except _FindingsUnavailable as exc:
            return _page(
                request, "finding_detail.html", {"configured": True, "error": exc.detail}, code=200
            )
        base = next((item for item in catalogue if item.finding_id == finding_id), None)
        if base is None:
            return _page(request, "not_found.html", {"job_id": _safe(finding_id)}, code=404)

        store = _open_transition_store()
        try:
            finding = _effective_finding(base, store)
            history = store.history(finding.finding_id) if store is not None else []
        finally:
            if store is not None:
                store.close()

        view = FindingView(finding)
        evidence = build_finding_evidence_view(finding)
        transitions = [
            {"value": target.value, "label": _FINDING_STATUS_LABELS[target]}
            for target in sorted(allowed_transitions(finding.status), key=lambda item: item.value)
        ]
        history_rows = [
            {
                "from": _FINDING_STATUS_LABELS.get(record.from_status, record.from_status.value),
                "to": _FINDING_STATUS_LABELS.get(record.to_status, record.to_status.value),
                "actor": _safe(record.actor),
                "reason": _safe(record.reason) if record.reason else None,
                "occurred_at": record.occurred_at.isoformat(),
            }
            for record in history
        ]
        return _page(
            request,
            "finding_detail.html",
            {
                "configured": True,
                "error": None,
                "finding_id": finding.finding_id,
                "title": _safe(finding.title),
                "description": _safe(finding.description) if finding.description else None,
                "status": finding.status.value,
                "status_label": _FINDING_STATUS_LABELS.get(finding.status, finding.status.value),
                "severity": finding.severity.value,
                "items": view.display_items(),
                "evidence_rows": evidence.rows(),
                "custody_signature": evidence.custody_signature(),
                "transitions": transitions,
                "suppression_values": sorted(item.value for item in SUPPRESSED_STATUSES),
                "lifecycle_enabled": findings_database is not None,
                "can_transition": "findings:write" in session.scopes,
                "history": history_rows,
                "csrf_token": _csrf_token(session.nonce),
            },
        )

    @app.post("/findings/{finding_id}/transition", include_in_schema=False)
    def transition_finding(
        request: Request,
        finding_id: str,
        target: Annotated[str, Form()],
        csrf_token: Annotated[str, Form()],
        reason: Annotated[str, Form()] = "",
        session: WebSession = writes_findings,
    ) -> Response:
        """Record a lifecycle transition for one finding, with audit.

        The move is validated by the shared state machine
        (:func:`record_transition`) against the finding's *effective* status and
        appended to the append-only store — the immutable bundle is never
        rewritten. Suppressing a finding (accepted-risk / false-positive) requires
        a non-empty reason, mirroring :func:`olympus.core.finding_lifecycle.suppress`.
        """
        _check_csrf(session, csrf_token)
        _rate_limit(session)
        if findings_directory is None:
            raise HTTPException(status_code=400, detail="no findings directory is configured")
        if findings_database is None:
            raise HTTPException(
                status_code=400, detail="no finding lifecycle store is configured on this server"
            )
        try:
            catalogue = _load_findings_catalogue()
        except _FindingsUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.detail) from exc
        base = next((item for item in catalogue if item.finding_id == finding_id), None)
        if base is None:
            return _page(request, "not_found.html", {"job_id": _safe(finding_id)}, code=404)

        target_status = _as_finding_status(target)
        if target_status is None:
            raise HTTPException(status_code=422, detail="unknown target status")
        if target_status in SUPPRESSED_STATUSES and not reason.strip():
            raise HTTPException(
                status_code=422,
                detail="a reason is required to accept or dismiss a finding",
            )

        store = _open_transition_store()
        assert store is not None  # noqa: S101 - guarded by the findings_database check above
        try:
            finding = _effective_finding(base, store)
            try:
                _, built = record_transition(
                    finding,
                    target_status,
                    actor=session.identity_id,
                    reason=reason.strip(),
                )
            except (FindingTransitionError, ValidationError) as exc:
                raise HTTPException(status_code=422, detail=_safe(str(exc))) from exc
            # ``new_id`` restarts its counter per process, so a restarted worker
            # would regenerate ids already in this append-only ledger. append_next
            # allocates a store-unique id and inserts it in one transaction (with a
            # bounded retry on the primary key), so concurrent requests stay
            # collision-free without a surfaced duplicate error.
            try:
                store.append_next(built)
            except FindingTransitionStoreError as exc:
                raise HTTPException(status_code=409, detail=_safe(str(exc))) from exc
        finally:
            store.close()
        return RedirectResponse(
            f"/findings/{finding.finding_id}", status_code=status.HTTP_303_SEE_OTHER
        )

    @app.get("/jobs/{job_id}/events", include_in_schema=False)
    def job_events(request: Request, job_id: str, session: WebSession = reads_jobs) -> Response:
        del session
        # WEB-A-01 resume: on an automatic reconnect the browser re-sends the id
        # of the last event it delivered as ``Last-Event-ID``. Seeding the last
        # seen state from it means a dropped stream resumes without replaying the
        # state the client already has, while any transition it missed is emitted
        # on the next tick. The event id is the state name (states are distinct).
        resume_from = request.headers.get("last-event-id") or None

        async def stream() -> AsyncIterator[str]:
            last_state: str | None = resume_from
            # Reconnect hint so a dropped stream comes back promptly.
            yield "retry: 1000\n\n"
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
                    yield f"id: {last_state}\nevent: state\ndata: {payload}\n\n"
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

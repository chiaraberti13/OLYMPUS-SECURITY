"""Typed ports (Protocol interfaces) the Athena application depends on.

The application layer talks only to these interfaces, never to concrete
infrastructure. Adapters (SQLite, audit sink, tool runners, reporting) and the
CLI wire real implementations in; tests wire in-memory doubles. Adapters
receive typed requests, not CLI argument arrays.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from olympus.athena.domain.assessment import Assessment, AssessmentState, Job, JobState
from olympus.athena.domain.audit import AuditEvent
from olympus.athena.domain.contracts import AssessmentPlan
from olympus.core.models import Asset, Finding
from olympus.vulcan.enrichment import FindingEnrichment


@dataclass(frozen=True)
class ToolRequest:
    """A single, typed adapter invocation request."""

    target_kind: str
    target_value: str
    allowed_domains: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class ToolResult:
    """The bounded, normalized outcome of one adapter invocation."""

    ok: bool
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error_code: str | None = None


class Cancellation(Protocol):
    """A cooperative cancellation token checked before and during work."""

    def is_cancelled(self) -> bool:
        """Return ``True`` once cancellation has been requested."""
        ...


class ToolRunner(Protocol):
    """An in-process adapter that runs one bounded assessment step."""

    @property
    def name(self) -> str:
        """Stable adapter name used in plans and the registry."""
        ...

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Human-readable capabilities this adapter provides."""
        ...

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        """Run the adapter, returning a normalized, bounded result."""
        ...


class Clock(Protocol):
    """An injected monotonic clock and wall-clock timestamp source."""

    def monotonic(self) -> float:
        """Return a monotonically increasing seconds value."""
        ...

    def now_iso(self) -> str:
        """Return the current UTC time as an ISO-8601 string."""
        ...


class IdProvider(Protocol):
    """An injected identifier source for deterministic tests."""

    def new_id(self, prefix: str) -> str:
        """Return a fresh identifier for ``prefix``."""
        ...


class AuditSink(Protocol):
    """An append-only audit event sink with per-assessment ordering."""

    def append(self, event: AuditEvent) -> None:
        """Persist ``event`` durably."""
        ...


class AssessmentRepository(Protocol):
    """Atomic persistence for plans, assessments, jobs, and result documents."""

    def save_plan(self, plan: AssessmentPlan) -> str:
        """Persist ``plan`` and return its stored plan id."""
        ...

    def save_assessment(self, assessment: Assessment) -> None:
        """Persist a new assessment and its queued jobs atomically."""
        ...

    def load_assessment(self, assessment_id: str) -> Assessment | None:
        """Return the stored assessment, or ``None`` if it does not exist."""
        ...

    def load_plan(self, plan_id: str) -> AssessmentPlan | None:
        """Return the stored plan, or ``None`` if it does not exist."""
        ...

    def transition_assessment(self, assessment_id: str, target: AssessmentState) -> None:
        """Persist an assessment state transition."""
        ...

    def transition_job(
        self,
        job: Job,
        target: JobState,
        *,
        error_code: str | None = None,
        result_id: str | None = None,
    ) -> Job:
        """Persist a job transition and return the updated job."""
        ...

    def save_result(self, assessment_id: str, job_id: str, document: str) -> str:
        """Persist a bounded result document and return its result id."""
        ...

    def load_result(self, result_id: str) -> str | None:
        """Return a stored result document, or ``None`` if it does not exist."""
        ...

    def running_jobs(self) -> list[tuple[str, Job]]:
        """Return ``(assessment_id, job)`` pairs still marked running (for recovery)."""
        ...


class ReportRenderer(Protocol):
    """Renders normalized findings into an operator-facing report."""

    def render(self, findings: list[Finding], fmt: str) -> str:
        """Render ``findings`` in a text ``fmt`` (``json``, ``markdown`` or ``html``)."""
        ...

    def render_pdf(
        self, findings: list[Finding], enrichments: Sequence[FindingEnrichment] | None = None
    ) -> bytes:
        """Render ``findings`` as a formatted PDF report, with an optional overlay."""
        ...

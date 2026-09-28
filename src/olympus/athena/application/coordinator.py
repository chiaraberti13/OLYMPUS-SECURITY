"""Synchronous, bounded assessment coordinator for Athena.

The coordinator is the single place that turns a validated
:class:`~olympus.athena.domain.contracts.AssessmentPlan` into a persisted,
audited assessment. It resolves adapters from a closed registry, enqueues one
job per (adapter, target), executes them under a bounded worker pool with a
per-job timeout and an overall deadline, persists every terminal transition,
and derives the terminal assessment state. It spawns no daemon and claims no
distributed execution.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

from olympus.athena.domain.assessment import (
    Assessment,
    AssessmentState,
    Job,
    JobState,
    derive_terminal_state,
)
from olympus.athena.domain.audit import AuditEvent
from olympus.athena.domain.contracts import AssessmentPlan, AssessmentResult
from olympus.athena.ports import (
    AssessmentRepository,
    AuditSink,
    Clock,
    IdProvider,
    ToolRequest,
    ToolResult,
    ToolRunner,
)
from olympus.core.execution import (
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
)
from olympus.core.models import Finding
from olympus.core.observability import Correlation, Observability

AdapterResolver = Callable[[tuple[str, ...]], dict[str, ToolRunner]]


_RETRYABLE_TOOL_ERRORS = frozenset({"lookup_failed", "timeout", "unreachable"})


@dataclass(frozen=True)
class RunOutcome:
    """The result of running one assessment to completion."""

    assessment_id: str
    state: AssessmentState
    findings: list[Finding]


class Coordinator:
    """Drives assessment execution against the injected ports."""

    def __init__(
        self,
        repository: AssessmentRepository,
        audit: AuditSink,
        clock: Clock,
        ids: IdProvider,
        resolver: AdapterResolver,
        observability: Observability | None = None,
    ) -> None:
        self._repo = repository
        self._audit = audit
        self._clock = clock
        self._ids = ids
        self._resolver = resolver
        self._observability = observability or Observability()
        self._sequence: dict[str, int] = {}

    # -- auditing ---------------------------------------------------------- #
    def _emit(
        self,
        assessment_id: str,
        action: str,
        outcome: str,
        *,
        job_id: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> None:
        sequence = self._sequence.get(assessment_id, 0)
        self._sequence[assessment_id] = sequence + 1
        self._audit.append(
            AuditEvent(
                assessment_id=assessment_id,
                sequence=sequence,
                timestamp=self._clock.now_iso(),
                action=action,
                outcome=outcome,
                job_id=job_id,
                metadata=metadata or {},
            )
        )

    # -- planning ---------------------------------------------------------- #
    def _build_jobs(self, plan: AssessmentPlan) -> tuple[Job, ...]:
        jobs: list[Job] = []
        for target in plan.targets:
            for adapter in plan.adapters:
                jobs.append(
                    Job(
                        job_id=self._ids.new_id("job"),
                        adapter=adapter,
                        target_kind=target.kind,
                        target_value=target.value,
                    )
                )
        return tuple(jobs)

    # -- execution --------------------------------------------------------- #
    def run(self, plan: AssessmentPlan) -> RunOutcome:
        """Persist and execute ``plan``, returning the terminal outcome."""
        policy = ExecutionPolicy(
            authorized=plan.authorization.confirmed,
            approval_reference=plan.authorization.approval_reference,
            timeout_seconds=float(plan.limits.per_job_timeout_seconds),
            deadline_seconds=float(plan.limits.overall_deadline_seconds),
            max_concurrency=plan.limits.concurrency,
            retries=plan.limits.max_retries,
        )
        policy.require_authorization("Athena assessment")
        runners = self._resolver(plan.adapters)  # UnknownAdapterError bubbles to the caller
        plan_id = self._repo.save_plan(plan)
        assessment_id = self._ids.new_id("assessment")
        jobs = self._build_jobs(plan)
        assessment = Assessment(assessment_id=assessment_id, plan_id=plan_id, jobs=jobs)
        self._repo.save_assessment(assessment)
        self._emit(
            assessment_id, "assessment_created", "planned", metadata={"count": str(len(jobs))}
        )

        started_at = self._clock.monotonic()
        correlation = Correlation(assessment_id=assessment_id)
        with self._observability.span("athena.assessment", correlation):
            self._repo.transition_assessment(assessment_id, AssessmentState.RUNNING)
            self._emit(assessment_id, "assessment_started", "running")

            findings: list[Finding] = []
            terminal_jobs: list[Job] = []
            deadline = started_at + policy.deadline_seconds
            concurrency = policy.max_concurrency
            allowed = plan.scope.allowed_domains

            pool = ThreadPoolExecutor(max_workers=concurrency)
            try:
                for batch_start in range(0, len(jobs), concurrency):
                    batch = jobs[batch_start : batch_start + concurrency]
                    deadline_hit = self._clock.monotonic() >= deadline
                    if deadline_hit:
                        terminal_jobs.extend(self._cancel_batch(assessment_id, batch, "deadline"))
                        continue
                    terminal_jobs.extend(
                        self._run_batch(
                            assessment_id,
                            batch,
                            runners,
                            allowed,
                            policy,
                            findings,
                            pool,
                            deadline,
                        )
                    )
            finally:
                # Timed-out adapters receive cooperative cancellation. Do not make
                # the coordinator wait again for a non-cooperative worker here.
                pool.shutdown(wait=False, cancel_futures=True)

            state = derive_terminal_state(tuple(terminal_jobs))
            self._repo.transition_assessment(assessment_id, state)
            self._emit(assessment_id, "assessment_finished", state.value)
            self._observability.assessment_finished(
                "athena", state.value, self._clock.monotonic() - started_at
            )
            return RunOutcome(assessment_id=assessment_id, state=state, findings=findings)

    def _cancel_batch(self, assessment_id: str, batch: tuple[Job, ...], reason: str) -> list[Job]:
        cancelled: list[Job] = []
        for job in batch:
            updated = self._repo.transition_job(job, JobState.CANCELLED, error_code=reason)
            self._emit(
                assessment_id,
                "job_cancelled",
                reason,
                job_id=job.job_id,
                metadata={"adapter": job.adapter, "reason": reason},
            )
            self._observability.job_finished("athena", job.adapter, "cancelled", 0.0)
            cancelled.append(updated)
        return cancelled

    def _run_batch(
        self,
        assessment_id: str,
        batch: tuple[Job, ...],
        runners: dict[str, ToolRunner],
        allowed: tuple[str, ...],
        policy: ExecutionPolicy,
        findings: list[Finding],
        pool: ThreadPoolExecutor,
        deadline: float,
    ) -> list[Job]:
        running: list[Job] = [self._repo.transition_job(job, JobState.RUNNING) for job in batch]
        started_at = {job.job_id: self._clock.monotonic() for job in running}
        tokens = {job.job_id: CancellationToken() for job in running}
        futures = {
            pool.submit(
                self._invoke,
                assessment_id,
                runners[job.adapter],
                job,
                allowed,
                policy,
                tokens[job.job_id],
            ): job
            for job in running
        }
        deadline_remaining = max(0.0, deadline - self._clock.monotonic())
        timeout_budget = min(policy.timeout_seconds, deadline_remaining)
        done, pending = wait(futures, timeout=timeout_budget)
        deadline_limited = deadline_remaining <= policy.timeout_seconds

        results: list[Job] = []
        for future, job in futures.items():
            if future in done:
                duration = self._clock.monotonic() - started_at[job.job_id]
                results.append(
                    self._finish(assessment_id, job, future.result(), findings, duration)
                )
                continue
            if future in pending:
                tokens[job.job_id].cancel()
                duration = self._clock.monotonic() - started_at[job.job_id]
                if deadline_limited:
                    results.append(self._finish_deadline(assessment_id, job, duration))
                else:
                    results.append(self._finish_timed_out(assessment_id, job, duration))
        return results

    def _invoke(
        self,
        assessment_id: str,
        runner: ToolRunner,
        job: Job,
        allowed: tuple[str, ...],
        policy: ExecutionPolicy,
        cancellation: CancellationToken,
    ) -> ToolResult:
        correlation = Correlation(assessment_id=assessment_id, job_id=job.job_id)
        with self._observability.span("athena.job", correlation):
            request = ToolRequest(
                target_kind=job.target_kind,
                target_value=job.target_value,
                allowed_domains=allowed,
                timeout_seconds=int(policy.timeout_seconds),
            )
            for attempt in range(policy.retries + 1):
                try:
                    policy.check_cancellation(cancellation)
                except CancellationRequested:
                    return ToolResult(ok=False, error_code="cancelled")
                result = runner.run(request, cancellation)
                if (
                    result.ok
                    or result.error_code not in _RETRYABLE_TOOL_ERRORS
                    or attempt == policy.retries
                ):
                    return result
            return ToolResult(ok=False, error_code="retry_exhausted")

    def _finish(
        self,
        assessment_id: str,
        job: Job,
        result: ToolResult,
        findings: list[Finding],
        duration_seconds: float,
    ) -> Job:
        if not result.ok:
            updated = self._repo.transition_job(
                job, JobState.FAILED, error_code=result.error_code or "failed"
            )
            self._emit(
                assessment_id,
                "job_failed",
                result.error_code or "failed",
                job_id=job.job_id,
                metadata={"adapter": job.adapter},
            )
            outcome = "cancelled" if result.error_code == "cancelled" else "failed"
            self._observability.job_finished("athena", job.adapter, outcome, duration_seconds)
            return updated
        document = AssessmentResult(
            assessment_id=assessment_id,
            job=job.to_contract(assessment_id).model_copy(update={"state": "succeeded"}),
            assets=tuple(result.assets),
            findings=tuple(result.findings),
        )
        result_id = self._repo.save_result(assessment_id, job.job_id, document.canonical_json())
        with self._observability.span(
            "athena.evidence",
            Correlation(
                assessment_id=assessment_id,
                job_id=job.job_id,
                evidence_id=result_id,
            ),
        ):
            self._observability.artifact_created("athena", "evidence", "json")
        findings.extend(result.findings)
        updated = self._repo.transition_job(job, JobState.SUCCEEDED, result_id=result_id)
        self._emit(
            assessment_id,
            "job_succeeded",
            "succeeded",
            job_id=job.job_id,
            metadata={"adapter": job.adapter, "count": str(len(result.findings))},
        )
        self._observability.job_finished("athena", job.adapter, "succeeded", duration_seconds)
        return updated

    def _finish_timed_out(self, assessment_id: str, job: Job, duration_seconds: float) -> Job:
        updated = self._repo.transition_job(job, JobState.TIMED_OUT, error_code="timeout")
        self._emit(
            assessment_id,
            "job_timed_out",
            "timeout",
            job_id=job.job_id,
            metadata={"adapter": job.adapter},
        )
        self._observability.job_finished("athena", job.adapter, "timed_out", duration_seconds)
        return updated

    def _finish_deadline(self, assessment_id: str, job: Job, duration_seconds: float) -> Job:
        updated = self._repo.transition_job(job, JobState.CANCELLED, error_code="deadline")
        self._emit(
            assessment_id,
            "job_cancelled",
            "deadline",
            job_id=job.job_id,
            metadata={"adapter": job.adapter, "reason": "deadline"},
        )
        self._observability.job_finished("athena", job.adapter, "cancelled", duration_seconds)
        return updated

    # -- lifecycle use cases ---------------------------------------------- #
    def cancel(self, assessment_id: str) -> AssessmentState:
        """Cancel a persisted, non-terminal assessment and its open jobs."""
        assessment = self._repo.load_assessment(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment not found: {assessment_id}")
        if assessment.state in {
            AssessmentState.SUCCEEDED,
            AssessmentState.PARTIAL,
            AssessmentState.FAILED,
            AssessmentState.CANCELLED,
        }:
            return assessment.state
        for job in assessment.jobs:
            if not job.is_terminal():
                self._repo.transition_job(job, JobState.CANCELLED, error_code="operator_cancel")
        self._repo.transition_assessment(assessment_id, AssessmentState.CANCELLED)
        self._emit(assessment_id, "assessment_cancelled", "cancelled")
        return AssessmentState.CANCELLED

    def recover(self) -> list[str]:
        """Fail interrupted running jobs and settle their assessments after a crash."""
        affected: dict[str, Assessment] = {}
        for assessment_id, job in self._repo.running_jobs():
            self._repo.transition_job(job, JobState.FAILED, error_code="interrupted")
            self._emit(assessment_id, "job_recovered", "interrupted", job_id=job.job_id)
            loaded = self._repo.load_assessment(assessment_id)
            if loaded is not None:
                affected[assessment_id] = loaded
        settled: list[str] = []
        for assessment_id in affected:
            reloaded = self._repo.load_assessment(assessment_id)
            if reloaded is None or reloaded.state is not AssessmentState.RUNNING:
                continue
            state = derive_terminal_state(reloaded.jobs)
            self._repo.transition_assessment(assessment_id, state)
            self._emit(assessment_id, "assessment_recovered", state.value)
            settled.append(assessment_id)
        return settled

"""Assessment and job state machines for Athena.

These are pure, immutable domain objects with explicit, audited transitions.
No I/O, framework, or infrastructure is imported here: the coordinator drives
state through :func:`advance_assessment` / :func:`advance_job` and persists the
returned values, so the rules for *what may follow what* live in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum

from olympus.core.models import ScanJob


class AssessmentState(StrEnum):
    """Lifecycle of a whole assessment."""

    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobState(StrEnum):
    """Lifecycle of a single adapter-against-target job."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


_ASSESSMENT_TERMINAL = frozenset(
    {
        AssessmentState.SUCCEEDED,
        AssessmentState.PARTIAL,
        AssessmentState.FAILED,
        AssessmentState.CANCELLED,
    }
)
_JOB_TERMINAL = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.TIMED_OUT, JobState.CANCELLED}
)
_JOB_FAILURE = frozenset({JobState.FAILED, JobState.TIMED_OUT})

_ASSESSMENT_TRANSITIONS: dict[AssessmentState, frozenset[AssessmentState]] = {
    AssessmentState.PLANNED: frozenset({AssessmentState.RUNNING, AssessmentState.CANCELLED}),
    AssessmentState.RUNNING: frozenset(
        {
            AssessmentState.SUCCEEDED,
            AssessmentState.PARTIAL,
            AssessmentState.FAILED,
            AssessmentState.CANCELLED,
        }
    ),
}
_JOB_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.QUEUED: frozenset({JobState.RUNNING, JobState.CANCELLED}),
    JobState.RUNNING: frozenset(
        {JobState.SUCCEEDED, JobState.FAILED, JobState.TIMED_OUT, JobState.CANCELLED}
    ),
}


class TransitionError(RuntimeError):
    """Raised when a requested state transition is not permitted."""


@dataclass(frozen=True)
class Job:
    """One adapter invocation against one target, with its terminal outcome."""

    job_id: str
    adapter: str
    target_kind: str
    target_value: str
    state: JobState = JobState.QUEUED
    error_code: str | None = None
    result_id: str | None = None

    def is_terminal(self) -> bool:
        """Return ``True`` if the job can no longer transition."""
        return self.state in _JOB_TERMINAL

    def to_contract(self, assessment_id: str) -> ScanJob:
        """Return the versioned shared representation persisted with job results."""
        return ScanJob(
            job_id=self.job_id,
            assessment_id=assessment_id,
            adapter=self.adapter,
            target_kind=self.target_kind,
            target_value=self.target_value,
            state=self.state.value,
            error_code=self.error_code,
            result_id=self.result_id,
        )


@dataclass(frozen=True)
class Assessment:
    """An assessment references its plan and owns an ordered list of jobs."""

    assessment_id: str
    plan_id: str
    state: AssessmentState = AssessmentState.PLANNED
    jobs: tuple[Job, ...] = field(default_factory=tuple)


def advance_job(
    job: Job, target: JobState, *, error_code: str | None = None, result_id: str | None = None
) -> Job:
    """Return ``job`` moved to ``target`` state, or raise :class:`TransitionError`."""
    if job.state in _JOB_TERMINAL:
        raise TransitionError(f"job {job.job_id} is terminal ({job.state})")
    allowed = _JOB_TRANSITIONS.get(job.state, frozenset())
    if target not in allowed:
        raise TransitionError(f"illegal job transition {job.state} -> {target}")
    return replace(job, state=target, error_code=error_code, result_id=result_id)


def advance_assessment(assessment: Assessment, target: AssessmentState) -> Assessment:
    """Return ``assessment`` moved to ``target`` state, or raise on an illegal move."""
    if assessment.state in _ASSESSMENT_TERMINAL:
        raise TransitionError(f"assessment {assessment.assessment_id} is terminal")
    allowed = _ASSESSMENT_TRANSITIONS.get(assessment.state, frozenset())
    if target not in allowed:
        raise TransitionError(f"illegal assessment transition {assessment.state} -> {target}")
    return replace(assessment, state=target)


def derive_terminal_state(jobs: tuple[Job, ...]) -> AssessmentState:
    """Derive the terminal assessment state from its jobs' terminal states.

    * every job succeeded -> ``succeeded``;
    * any cancellation with no failure -> ``cancelled``;
    * at least one success and at least one failure -> ``partial``;
    * zero successes with any failure -> ``failed``.
    """
    if not jobs:
        return AssessmentState.FAILED
    states = [job.state for job in jobs]
    succeeded = sum(state is JobState.SUCCEEDED for state in states)
    failed = sum(state in _JOB_FAILURE for state in states)
    cancelled = sum(state is JobState.CANCELLED for state in states)

    if succeeded == len(states):
        return AssessmentState.SUCCEEDED
    if failed == 0 and cancelled > 0 and succeeded == 0:
        return AssessmentState.CANCELLED
    if succeeded > 0 and (failed > 0 or cancelled > 0):
        return AssessmentState.PARTIAL
    return AssessmentState.FAILED

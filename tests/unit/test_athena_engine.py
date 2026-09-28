"""Coordinator and lifecycle tests for Athena (offline, deterministic)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from olympus.athena.adapters.audit import InMemoryAuditSink
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.application.coordinator import Coordinator
from olympus.athena.application.registry import UnknownAdapterError
from olympus.athena.domain.assessment import Assessment, AssessmentState, Job, JobState
from olympus.athena.domain.contracts import AssessmentPlan, load_plan
from olympus.athena.ports import Cancellation, Clock, ToolRequest, ToolResult, ToolRunner
from olympus.core.enums import Severity, Source
from olympus.core.http import HttpResponse
from olympus.core.models import Finding
from olympus.core.observability import InMemoryExporter, Observability


class _Clock:
    def __init__(self, values: list[float] | None = None) -> None:
        self._values = list(values or [])
        self._last = 0.0

    def monotonic(self) -> float:
        if self._values:
            self._last = self._values.pop(0)
        return self._last

    def now_iso(self) -> str:
        return "2026-08-24T00:00:00+00:00"


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now_iso(self) -> str:
        return "2026-08-24T00:00:00+00:00"


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def new_id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix.upper()}-{self._n:04d}"


class _Runner:
    def __init__(self, name: str, result: ToolResult | None = None, block: bool = False) -> None:
        self._name = name
        self._result = result or ToolResult(ok=True)
        self._block = block
        self._event = threading.Event()
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("test",)

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        self.calls += 1
        if self._block:
            self._event.wait(timeout=1.2)
        return self._result


def _plan(**overrides: object) -> AssessmentPlan:
    base: dict[str, object] = {
        "engagement_id": "ENG-1",
        "name": "demo",
        "targets": [{"kind": "domain", "value": "example.com"}],
        "adapters": ["a"],
        "scope": {"allowed_domains": ["example.com"]},
        "authorization": {"engagement_id": "ENG-1", "approval_reference": "T", "confirmed": True},
    }
    base.update(overrides)
    return load_plan(base)


def _coordinator(
    tmp_path: Path,
    runners: dict[str, ToolRunner],
    clock: Clock | None = None,
    observability: Observability | None = None,
) -> tuple[Coordinator, SqliteAssessmentRepository, InMemoryAuditSink]:
    repo = SqliteAssessmentRepository(tmp_path / "athena.db")
    audit = InMemoryAuditSink()
    coordinator = Coordinator(
        repository=repo,
        audit=audit,
        clock=clock or _Clock(),
        ids=_Ids(),
        resolver=lambda names: {name: runners[name] for name in names},
        observability=observability,
    )
    return coordinator, repo, audit


def _finding() -> Finding:
    return Finding(asset_id="AST-1", source=Source.ARGUS, title="x", severity=Severity.LOW)


def test_run_success(tmp_path: Path) -> None:
    runner = _Runner("a", ToolResult(ok=True, findings=[_finding()]))
    coordinator, repo, audit = _coordinator(tmp_path, {"a": runner})
    outcome = coordinator.run(_plan())
    assert outcome.state is AssessmentState.SUCCEEDED
    assert len(outcome.findings) == 1
    stored = repo.load_assessment(outcome.assessment_id)
    assert stored is not None and stored.jobs[0].state is JobState.SUCCEEDED
    assert any(e.action == "assessment_finished" for e in audit.events)
    repo.close()


def test_run_correlates_assessment_job_and_evidence_without_metric_ids(tmp_path: Path) -> None:
    exporter = InMemoryExporter()
    telemetry = Observability(exporter)
    runner = _Runner("a", ToolResult(ok=True, findings=[_finding()]))
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner}, observability=telemetry)

    outcome = coordinator.run(_plan())

    metric_names = {record.name for record in exporter.records}
    assert {
        "olympus_assessments_total",
        "olympus_jobs_total",
        "olympus_artifacts_total",
    } <= metric_names
    assert outcome.assessment_id not in repr(exporter.records)
    span_attributes = [dict(attributes) for _name, attributes in exporter.spans]
    assert any(
        item.get("olympus.assessment.id") == outcome.assessment_id for item in span_attributes
    )
    assert any("olympus.job.id" in item for item in span_attributes)
    assert any("olympus.evidence.id" in item for item in span_attributes)
    repo.close()


def test_run_partial(tmp_path: Path) -> None:
    runners: dict[str, ToolRunner] = {
        "a": _Runner("a", ToolResult(ok=True)),
        "b": _Runner("b", ToolResult(ok=False, error_code="unreachable")),
    }
    coordinator, repo, _ = _coordinator(tmp_path, runners)
    outcome = coordinator.run(_plan(adapters=["a", "b"], limits={"concurrency": 2}))
    assert outcome.state is AssessmentState.PARTIAL
    repo.close()


def test_run_failed(tmp_path: Path) -> None:
    runner = _Runner("a", ToolResult(ok=False, error_code="lookup_failed"))
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner})
    outcome = coordinator.run(_plan())
    assert outcome.state is AssessmentState.FAILED
    repo.close()


def test_run_uses_declared_retry_budget_for_transient_failures(tmp_path: Path) -> None:
    runner = _Runner("a", ToolResult(ok=False, error_code="unreachable"))
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner})

    outcome = coordinator.run(_plan(limits={"max_retries": 2}))

    assert outcome.state is AssessmentState.FAILED
    assert runner.calls == 3
    repo.close()


def test_run_timeout(tmp_path: Path) -> None:
    runner = _Runner("a", ToolResult(ok=True), block=True)
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner})
    outcome = coordinator.run(_plan(limits={"per_job_timeout_seconds": 1, "concurrency": 1}))
    assert outcome.state is AssessmentState.FAILED
    stored = repo.load_assessment(outcome.assessment_id)
    assert stored is not None and stored.jobs[0].state is JobState.TIMED_OUT
    repo.close()


def test_concurrent_timeouts_share_one_timeout_window(tmp_path: Path) -> None:
    runners: dict[str, ToolRunner] = {
        "a": _Runner("a", ToolResult(ok=True), block=True),
        "b": _Runner("b", ToolResult(ok=True), block=True),
    }
    coordinator, repo, _ = _coordinator(tmp_path, runners, clock=_SystemClock())

    started = time.monotonic()
    outcome = coordinator.run(
        _plan(
            adapters=["a", "b"],
            limits={"per_job_timeout_seconds": 1, "concurrency": 2},
        )
    )
    elapsed = time.monotonic() - started

    assert outcome.state is AssessmentState.FAILED
    assert elapsed < 1.6
    stored = repo.load_assessment(outcome.assessment_id)
    assert stored is not None
    assert {job.state for job in stored.jobs} == {JobState.TIMED_OUT}
    repo.close()


def test_deadline_limits_running_batch(tmp_path: Path) -> None:
    runner = _Runner("a", ToolResult(ok=True), block=True)
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner}, clock=_SystemClock())

    outcome = coordinator.run(
        _plan(
            limits={
                "per_job_timeout_seconds": 5,
                "overall_deadline_seconds": 1,
                "concurrency": 1,
            }
        )
    )

    assert outcome.state is AssessmentState.CANCELLED
    stored = repo.load_assessment(outcome.assessment_id)
    assert stored is not None
    assert stored.jobs[0].state is JobState.CANCELLED
    assert stored.jobs[0].error_code == "deadline"
    repo.close()


def test_run_deadline_cancels(tmp_path: Path) -> None:
    # First monotonic() sets the deadline base (0 + deadline); the batch check
    # then returns a value already past the deadline.
    clock = _Clock([0.0, 10_000.0])
    runner = _Runner("a", ToolResult(ok=True))
    coordinator, repo, _ = _coordinator(tmp_path, {"a": runner}, clock=clock)
    outcome = coordinator.run(_plan(limits={"overall_deadline_seconds": 1}))
    assert outcome.state is AssessmentState.CANCELLED
    stored = repo.load_assessment(outcome.assessment_id)
    assert stored is not None and stored.jobs[0].state is JobState.CANCELLED
    repo.close()


def test_run_unknown_adapter(tmp_path: Path) -> None:
    from olympus.athena.application.registry import resolve_adapters

    repo = SqliteAssessmentRepository(tmp_path / "athena.db")

    class _Http:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            raise AssertionError("should not be called")

    coordinator = Coordinator(
        repository=repo,
        audit=InMemoryAuditSink(),
        clock=_Clock(),
        ids=_Ids(),
        resolver=lambda names: resolve_adapters(names, _Http()),
    )
    with pytest.raises(UnknownAdapterError):
        coordinator.run(_plan(adapters=["does-not-exist"]))
    repo.close()


def test_cancel_lifecycle(tmp_path: Path) -> None:
    coordinator, repo, _ = _coordinator(tmp_path, {})
    plan_id = repo.save_plan(_plan())
    job = Job(job_id="J1", adapter="a", target_kind="domain", target_value="example.com")
    repo.save_assessment(Assessment(assessment_id="A1", plan_id=plan_id, jobs=(job,)))
    state = coordinator.cancel("A1")
    assert state is AssessmentState.CANCELLED
    stored = repo.load_assessment("A1")
    assert stored is not None and stored.jobs[0].state is JobState.CANCELLED
    # Cancelling an already-terminal assessment is a no-op that returns its state.
    assert coordinator.cancel("A1") is AssessmentState.CANCELLED
    with pytest.raises(LookupError):
        coordinator.cancel("ghost")
    repo.close()


def test_recover(tmp_path: Path) -> None:
    coordinator, repo, _ = _coordinator(tmp_path, {})
    plan_id = repo.save_plan(_plan())
    job = Job(job_id="J1", adapter="a", target_kind="domain", target_value="example.com")
    repo.save_assessment(Assessment(assessment_id="A1", plan_id=plan_id, jobs=(job,)))
    repo.transition_assessment("A1", AssessmentState.RUNNING)
    repo.transition_job(job, JobState.RUNNING)
    settled = coordinator.recover()
    assert settled == ["A1"]
    stored = repo.load_assessment("A1")
    assert stored is not None
    assert stored.state is AssessmentState.FAILED
    assert stored.jobs[0].state is JobState.FAILED
    assert stored.jobs[0].error_code == "interrupted"
    repo.close()

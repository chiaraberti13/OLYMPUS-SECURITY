"""Tests for Athena domain contracts, state machines, audit, and scope."""

from __future__ import annotations

import pytest

from olympus.athena.domain.assessment import (
    Assessment,
    AssessmentState,
    Job,
    JobState,
    TransitionError,
    advance_assessment,
    advance_job,
    derive_terminal_state,
)
from olympus.athena.domain.audit import AuditEvent, AuditRedactionError
from olympus.athena.domain.contracts import (
    AssessmentResult,
    PlanValidationError,
    ResultValidationError,
    load_plan,
    load_result,
)
from olympus.athena.scope import (
    SsrfBlockedError,
    TargetOutOfScopeError,
    TargetResolutionError,
    TargetValidationError,
    ensure_target_allowed,
    ensure_web_target_allowed,
    host_of,
)


def _plan_dict(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "engagement_id": "ENG-1",
        "name": "demo",
        "targets": [{"kind": "domain", "value": "example.com"}],
        "adapters": ["web-headers", "dns"],
        "scope": {"allowed_domains": ["example.com"]},
        "authorization": {
            "engagement_id": "ENG-1",
            "approval_reference": "TICKET-1",
            "confirmed": True,
        },
    }
    base.update(overrides)
    return base


def test_load_plan_valid() -> None:
    plan = load_plan(_plan_dict())
    assert plan.engagement_id == "ENG-1"
    assert plan.scope.covers("api.example.com")
    assert not plan.scope.covers("evil.test")
    assert len(plan.digest()) == 64
    assert len(plan.scope_digest()) == 64
    # Digest is stable for identical content.
    assert plan.digest() == load_plan(_plan_dict()).digest()
    assert plan.schema_version == "1.0.0"


def test_load_plan_migrates_explicit_legacy_integer_version() -> None:
    plan = load_plan(_plan_dict(schema_name="olympus.athena.plan", schema_version=1))
    assert plan.schema_version == "1.0.0"


def test_load_plan_rejects_incompatible_contract_header() -> None:
    with pytest.raises(PlanValidationError, match="unsupported"):
        load_plan(_plan_dict(schema_name="olympus.athena.plan", schema_version="2.0.0"))


def test_load_plan_rejects_non_dict() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(["not", "a", "dict"])


def test_load_plan_rejects_unknown_field() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(_plan_dict(surprise="x"))


def test_load_plan_requires_confirmed_authorization() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(
            _plan_dict(
                authorization={
                    "engagement_id": "ENG-1",
                    "approval_reference": "T",
                    "confirmed": False,
                }
            )
        )


def test_load_plan_engagement_must_match_authorization() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(_plan_dict(engagement_id="OTHER"))


def test_load_plan_rejects_duplicate_adapters() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(_plan_dict(adapters=["dns", "dns"]))


def test_load_plan_clamps_limits() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(_plan_dict(limits={"concurrency": 999}))


def test_load_plan_rejects_target_with_space() -> None:
    with pytest.raises(PlanValidationError):
        load_plan(_plan_dict(targets=[{"kind": "domain", "value": "bad target"}]))


def test_job_transitions() -> None:
    job = Job(job_id="J1", adapter="dns", target_kind="domain", target_value="example.com")
    running = advance_job(job, JobState.RUNNING)
    done = advance_job(running, JobState.SUCCEEDED, result_id="R1")
    assert done.state is JobState.SUCCEEDED
    assert done.result_id == "R1"
    assert done.is_terminal()
    with pytest.raises(TransitionError):
        advance_job(done, JobState.RUNNING)
    with pytest.raises(TransitionError):
        advance_job(job, JobState.SUCCEEDED)  # cannot skip running

    contract = done.to_contract("ASM-1")
    assert contract.schema_name == "olympus.scan-job"
    assert contract.state == "succeeded"


def test_assessment_result_round_trip_and_identity_validation() -> None:
    job = Job(
        job_id="J1",
        adapter="dns",
        target_kind="domain",
        target_value="example.com",
        state=JobState.SUCCEEDED,
    )
    result = AssessmentResult(assessment_id="ASM-1", job=job.to_contract("ASM-1"))

    assert load_result(result.model_dump(mode="json")) == result
    with pytest.raises(ResultValidationError):
        load_result({**result.model_dump(mode="json"), "schema_version": "2.0.0"})


def test_assessment_transitions() -> None:
    assessment = Assessment(assessment_id="A1", plan_id="P1")
    running = advance_assessment(assessment, AssessmentState.RUNNING)
    done = advance_assessment(running, AssessmentState.SUCCEEDED)
    with pytest.raises(TransitionError):
        advance_assessment(done, AssessmentState.RUNNING)
    with pytest.raises(TransitionError):
        advance_assessment(assessment, AssessmentState.SUCCEEDED)


def _job(state: JobState) -> Job:
    return Job(job_id="J", adapter="dns", target_kind="domain", target_value="x", state=state)


def test_derive_terminal_state() -> None:
    assert derive_terminal_state(()) is AssessmentState.FAILED
    assert derive_terminal_state((_job(JobState.SUCCEEDED),)) is AssessmentState.SUCCEEDED
    assert derive_terminal_state((_job(JobState.FAILED),)) is AssessmentState.FAILED
    assert derive_terminal_state((_job(JobState.CANCELLED),)) is AssessmentState.CANCELLED
    assert (
        derive_terminal_state((_job(JobState.SUCCEEDED), _job(JobState.FAILED)))
        is AssessmentState.PARTIAL
    )
    assert (
        derive_terminal_state((_job(JobState.SUCCEEDED), _job(JobState.CANCELLED)))
        is AssessmentState.PARTIAL
    )
    assert (
        derive_terminal_state((_job(JobState.FAILED), _job(JobState.TIMED_OUT)))
        is AssessmentState.FAILED
    )


def test_audit_event_redaction() -> None:
    event = AuditEvent(
        assessment_id="A1",
        sequence=0,
        timestamp="2026-01-01T00:00:00Z",
        action="job_succeeded",
        outcome="succeeded",
        metadata={"adapter": "dns"},
    )
    assert event.to_dict()["metadata"] == {"adapter": "dns"}


def test_audit_event_redacts_sensitive_query_values_in_allowed_target() -> None:
    event = AuditEvent(
        assessment_id="A1",
        sequence=0,
        timestamp="2026-01-01T00:00:00Z",
        action="job_failed",
        outcome="failed",
        metadata={"target": "https://api.example/?token=secret&item=1"},
    )
    target = event.metadata["target"]
    assert "secret" not in target
    assert "item=1" in target
    with pytest.raises(AuditRedactionError):
        AuditEvent(
            assessment_id="A1",
            sequence=1,
            timestamp="t",
            action="x",
            outcome="y",
            metadata={"password": "secret"},
        )


def test_scope_host_of() -> None:
    assert host_of("domain", "Example.com") == "example.com"
    assert host_of("url", "https://example.com/a") == "example.com"
    assert host_of("url", "example.com") == "example.com"
    with pytest.raises(TargetValidationError):
        host_of("domain", "no-dot")
    with pytest.raises(TargetValidationError):
        host_of("url", "https://")
    with pytest.raises(TargetValidationError):
        host_of("mac", "x")


def test_ensure_target_allowed() -> None:
    assert ensure_target_allowed("domain", "api.example.com", ("example.com",)) == "api.example.com"
    with pytest.raises(TargetOutOfScopeError):
        ensure_target_allowed("domain", "evil.test", ("example.com",))


def test_ensure_target_blocks_ssrf() -> None:
    with pytest.raises(SsrfBlockedError):
        ensure_target_allowed("url", "http://127.0.0.1/admin", ("example.com",))
    with pytest.raises(SsrfBlockedError):
        ensure_target_allowed("url", "http://10.0.0.5", ("example.com",))


def test_web_target_checks_all_resolved_addresses() -> None:
    def mixed_answers(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("10.0.0.5", 0)),
        ]

    with pytest.raises(SsrfBlockedError, match=r"10\.0\.0\.5"):
        ensure_web_target_allowed(
            "url", "https://example.com", ("example.com",), resolver=mixed_answers
        )


def test_web_target_fails_closed_when_dns_returns_nothing() -> None:
    with pytest.raises(TargetResolutionError, match="no addresses"):
        ensure_web_target_allowed(
            "url", "https://example.com", ("example.com",), resolver=lambda *args, **kwargs: []
        )

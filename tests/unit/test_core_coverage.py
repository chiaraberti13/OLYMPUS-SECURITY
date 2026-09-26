"""Tests for the shared run-status and coverage vocabulary."""

import pytest

from olympus.core.coverage import (
    MAX_ERROR_SAMPLES,
    Coverage,
    CoverageTracker,
    FailureKind,
    RunStatus,
    classify_run_status,
    exit_code_for,
    summarize,
)
from olympus.core.exit_codes import ExitCode, normalize_exit_code


def test_full_coverage_without_findings_is_clean() -> None:
    coverage = Coverage(planned=3, completed=3)
    assert coverage.complete is True
    assert coverage.status(0) is RunStatus.CLEAN
    assert coverage.status(2) is RunStatus.FINDINGS


def test_nothing_completed_is_failed_even_with_planned_work() -> None:
    coverage = Coverage(planned=2, failed=2, reasons={FailureKind.TIMEOUT: 2})
    assert coverage.status(0) is RunStatus.FAILED
    assert coverage.status(5) is RunStatus.FAILED


def test_partial_outranks_findings_so_a_gap_is_never_hidden() -> None:
    """A run that found something but lost coverage must not read as complete."""
    coverage = Coverage(planned=3, completed=2, failed=1, reasons={FailureKind.DNS_FAILURE: 1})
    assert coverage.status(1) is RunStatus.PARTIAL
    assert coverage.status(0) is RunStatus.PARTIAL


def test_units_a_run_never_reached_are_visible() -> None:
    coverage = Coverage(planned=10, completed=4)
    assert coverage.unattempted == 6
    assert coverage.complete is False
    assert coverage.ratio == pytest.approx(0.4)


def test_planning_nothing_is_not_a_failure() -> None:
    assert Coverage().status(0) is RunStatus.CLEAN
    assert Coverage().status(1) is RunStatus.FINDINGS
    assert Coverage().ratio == 1.0


def test_coverage_rejects_impossible_accounting() -> None:
    with pytest.raises(ValueError):
        Coverage(planned=1, completed=2)
    with pytest.raises(ValueError):
        Coverage(planned=-1)


def test_tracker_accumulates_reasons_and_bounded_error_samples() -> None:
    tracker = CoverageTracker(30)
    tracker.complete()
    for index in range(20):
        tracker.fail(FailureKind.TRANSPORT_ERROR, f"host-{index} reset the connection")
    coverage = tracker.build()

    assert coverage.completed == 1
    assert coverage.failed == 20
    assert coverage.reasons == {FailureKind.TRANSPORT_ERROR: 20}
    assert len(coverage.errors) == MAX_ERROR_SAMPLES
    assert coverage.errors[0].startswith("transport_error: ")


def test_tracker_redacts_secrets_out_of_error_samples() -> None:
    tracker = CoverageTracker(1)
    tracker.fail(
        FailureKind.TRANSPORT_ERROR,
        "GET https://target.example/cb?api_key=s3cret&page=2 failed",
    )
    sample = tracker.build().errors[0]

    assert "s3cret" not in sample
    assert "[REDACTED]" in sample
    assert "page=2" in sample  # routing context survives redaction


def test_tracker_can_plan_more_work_as_a_run_discovers_it() -> None:
    tracker = CoverageTracker(1)
    tracker.complete()
    tracker.plan(1)
    tracker.fail(FailureKind.TIMEOUT, "second stage timed out")
    coverage = tracker.build()

    assert coverage.planned == 2
    assert coverage.status(0) is RunStatus.PARTIAL


def test_exit_codes_map_one_to_one_onto_the_canonical_set() -> None:
    assert exit_code_for(RunStatus.CLEAN) is ExitCode.OK
    assert exit_code_for(RunStatus.FINDINGS) is ExitCode.FINDINGS
    assert exit_code_for(RunStatus.PARTIAL) is ExitCode.PARTIAL
    assert exit_code_for(RunStatus.FAILED) is ExitCode.FAILED
    assert exit_code_for(RunStatus.CANCELLED) is ExitCode.CANCELLED
    assert {exit_code_for(status) for status in RunStatus} == {
        ExitCode.OK,
        ExitCode.FINDINGS,
        ExitCode.PARTIAL,
        ExitCode.FAILED,
        ExitCode.CANCELLED,
    }


def test_terminal_status_classification_has_one_shared_precedence() -> None:
    assert classify_run_status() is RunStatus.CLEAN
    assert classify_run_status(2) is RunStatus.FINDINGS
    assert classify_run_status(2, partial=True) is RunStatus.PARTIAL
    assert classify_run_status(2, failed=True) is RunStatus.FAILED
    assert classify_run_status(2, cancelled=True) is RunStatus.CANCELLED
    with pytest.raises(ValueError, match="mutually exclusive"):
        classify_run_status(partial=True, cancelled=True)


def test_external_exit_codes_cannot_escape_the_public_contract() -> None:
    assert normalize_exit_code(None) is ExitCode.OK
    assert normalize_exit_code(ExitCode.PARTIAL) is ExitCode.PARTIAL
    assert normalize_exit_code(127) is ExitCode.FAILED
    assert normalize_exit_code(-9) is ExitCode.FAILED


def test_summary_names_the_status_the_gap_and_the_reasons() -> None:
    coverage = Coverage(
        planned=4,
        completed=2,
        failed=2,
        reasons={FailureKind.TIMEOUT: 1, FailureKind.DNS_FAILURE: 1},
    )
    line = summarize(coverage.status(1), coverage, 1)

    assert "status=partial" in line
    assert "coverage=2/4" in line
    assert "dns_failure=1" in line
    assert "timeout=1" in line


def test_serialized_coverage_is_deterministic_and_json_ready() -> None:
    coverage = Coverage(
        planned=2, completed=1, failed=1, reasons={FailureKind.TIMEOUT: 1}, errors=("timeout: x",)
    )
    assert coverage.to_dict() == {
        "planned": 2,
        "completed": 1,
        "failed": 1,
        "skipped": 0,
        "unattempted": 0,
        "complete": False,
        "reasons": {"timeout": 1},
        "errors": ["timeout: x"],
    }

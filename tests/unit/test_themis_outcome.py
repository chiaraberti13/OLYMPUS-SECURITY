"""Tests for the honest, interface-agnostic scan outcome summary (UX-B).

The summary exists so distinct outcomes that all carry zero findings —
simulation, unavailable, disabled, failed, cancelled, partial — are never read
as a trustworthy "nothing found". These tests pin that only a live run that
completed with no findings is ``CLEAN`` / ``trustworthy_empty``, and that every
other state is reported as inconclusive.
"""

from __future__ import annotations

import json

import pytest

from olympus.themis.model import ScanResult
from olympus.themis.outcome import (
    OUTCOME_EXPLANATION,
    OUTCOME_HEADLINE,
    OutcomeKind,
    from_mapping,
    from_result,
    summarize,
)
from olympus.themis.runner import TerminationCause, TerminationReport
from olympus.themis.states import ExecutionState


def test_live_completed_empty_is_the_only_trustworthy_empty() -> None:
    summary = summarize(
        state=ExecutionState.LIVE,
        finding_count=0,
        termination_cause=TerminationCause.COMPLETED,
    )
    assert summary.kind is OutcomeKind.CLEAN
    assert summary.conclusive is True
    assert summary.trustworthy_empty is True


def test_live_completed_with_findings_is_conclusive_not_empty() -> None:
    summary = summarize(
        state=ExecutionState.LIVE,
        finding_count=4,
        termination_cause=TerminationCause.COMPLETED,
    )
    assert summary.kind is OutcomeKind.FINDINGS
    assert summary.conclusive is True
    assert summary.trustworthy_empty is False
    assert summary.finding_count == 4


@pytest.mark.parametrize(
    ("state", "cause", "expected"),
    [
        (ExecutionState.SIMULATION, TerminationCause.COMPLETED, OutcomeKind.SIMULATION),
        (ExecutionState.UNAVAILABLE, None, OutcomeKind.UNAVAILABLE),
        (ExecutionState.DISABLED, None, OutcomeKind.DISABLED),
        (ExecutionState.FAILED, None, OutcomeKind.FAILED),
        (ExecutionState.LIVE, TerminationCause.CANCELLED, OutcomeKind.CANCELLED),
        (ExecutionState.LIVE, TerminationCause.TIMEOUT, OutcomeKind.PARTIAL),
        (ExecutionState.LIVE, TerminationCause.OUTPUT_LIMIT, OutcomeKind.PARTIAL),
        (ExecutionState.LIVE, TerminationCause.RESOURCE_LIMIT, OutcomeKind.PARTIAL),
        (ExecutionState.LIVE, TerminationCause.SIGNALLED, OutcomeKind.PARTIAL),
    ],
)
def test_non_clean_states_are_inconclusive(
    state: ExecutionState, cause: TerminationCause, expected: OutcomeKind
) -> None:
    summary = summarize(state=state, finding_count=0, termination_cause=cause)
    assert summary.kind is expected
    assert summary.conclusive is False
    assert summary.trustworthy_empty is False


def test_cancelled_wins_over_failed_state() -> None:
    # A cancelled run may be recorded as FAILED, but the operator's intent wins.
    summary = summarize(
        state=ExecutionState.FAILED,
        finding_count=0,
        termination_cause=TerminationCause.CANCELLED,
    )
    assert summary.kind is OutcomeKind.CANCELLED


def test_simulation_with_findings_is_still_not_conclusive() -> None:
    summary = summarize(
        state=ExecutionState.SIMULATION,
        finding_count=2,
        termination_cause=TerminationCause.COMPLETED,
    )
    assert summary.kind is OutcomeKind.SIMULATION
    assert summary.conclusive is False
    assert summary.trustworthy_empty is False


def test_from_result_reads_state_and_termination() -> None:
    result = ScanResult(
        scanner="nmap",
        state=ExecutionState.LIVE,
        target="scanme.nmap.org",
        termination=TerminationReport(cause=TerminationCause.TIMEOUT, detail="deadline"),
    )
    summary = from_result(result)
    assert summary.kind is OutcomeKind.PARTIAL


def test_from_result_clean_with_no_termination() -> None:
    result = ScanResult(scanner="nmap", state=ExecutionState.LIVE, target="scanme.nmap.org")
    assert from_result(result).kind is OutcomeKind.CLEAN


def test_from_mapping_reads_persisted_result() -> None:
    assert (
        from_mapping(
            {"state": "live", "finding_count": 0, "termination": {"cause": "completed"}}
        ).kind
        is OutcomeKind.CLEAN
    )
    assert (
        from_mapping(
            {"state": "live", "finding_count": 7, "termination": {"cause": "output_limit"}}
        ).kind
        is OutcomeKind.PARTIAL
    )


def test_from_mapping_fails_safe_on_unknown_state() -> None:
    # An unrecognized or missing state is treated as FAILED, never understated.
    assert from_mapping({"state": "nonsense"}).kind is OutcomeKind.FAILED
    assert from_mapping({}).kind is OutcomeKind.FAILED
    assert from_mapping({"state": "live", "finding_count": True}).finding_count == 0


def test_from_mapping_ignores_an_unrecognized_termination_cause() -> None:
    # An unknown termination cause on a live run is dropped, not crashed: a
    # completed live run with no findings stays CLEAN.
    summary = from_mapping(
        {"state": "live", "finding_count": 0, "termination": {"cause": "not-a-real-cause"}}
    )
    assert summary.kind is OutcomeKind.CLEAN
    # A termination mapping with no cause key is likewise ignored.
    assert (
        from_mapping({"state": "live", "finding_count": 2, "termination": {}}).kind
        is OutcomeKind.FINDINGS
    )


def test_to_dict_is_json_safe_and_complete() -> None:
    summary = summarize(state=ExecutionState.UNAVAILABLE, finding_count=0)
    data = summary.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert set(data) == set(vars(summary))


def test_lines_spell_out_the_empty_meaning_without_colour() -> None:
    clean = summarize(
        state=ExecutionState.LIVE, finding_count=0, termination_cause=TerminationCause.COMPLETED
    ).lines()
    unavailable = summarize(state=ExecutionState.UNAVAILABLE, finding_count=0).lines()
    assert any("yes" in line for line in clean)
    assert any("NO" in line for line in unavailable)
    assert all("\x1b[" not in line for line in clean + unavailable)


def test_tables_cover_every_kind() -> None:
    assert set(OUTCOME_HEADLINE) == set(OutcomeKind)
    assert set(OUTCOME_EXPLANATION) == set(OutcomeKind)

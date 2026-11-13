"""Unit tests for the finding lifecycle state machine (WEB-C)."""

from __future__ import annotations

import pytest

from olympus.core.enums import FindingStatus, Source
from olympus.core.finding_lifecycle import (
    FINDING_TRANSITIONS,
    FindingTransitionError,
    allowed_transitions,
    can_transition,
    close_after_retest,
    record_transition,
    transition,
)
from olympus.core.models import Finding


def _finding(status: FindingStatus = FindingStatus.NEW) -> Finding:
    return Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x", status=status)


def test_transition_map_is_exhaustive_over_every_status() -> None:
    assert set(FINDING_TRANSITIONS) == set(FindingStatus)


def test_can_transition_follows_the_workflow() -> None:
    assert can_transition(FindingStatus.NEW, FindingStatus.CONFIRMED)
    assert can_transition(FindingStatus.CONFIRMED, FindingStatus.IN_REMEDIATION)
    assert can_transition(FindingStatus.IN_REMEDIATION, FindingStatus.CLOSED)
    # recurrence / retest-required re-opens a closed finding
    assert can_transition(FindingStatus.CLOSED, FindingStatus.CONFIRMED)
    # a false positive only re-opens to confirmed, never straight to remediation
    assert can_transition(FindingStatus.FALSE_POSITIVE, FindingStatus.CONFIRMED)
    assert not can_transition(FindingStatus.FALSE_POSITIVE, FindingStatus.IN_REMEDIATION)
    # a closed finding never jumps back to new
    assert not can_transition(FindingStatus.CLOSED, FindingStatus.NEW)


def test_same_status_is_not_a_transition() -> None:
    assert not can_transition(FindingStatus.CONFIRMED, FindingStatus.CONFIRMED)


def test_allowed_transitions_lists_outgoing_edges() -> None:
    assert allowed_transitions(FindingStatus.FALSE_POSITIVE) == frozenset({FindingStatus.CONFIRMED})


def test_transition_returns_updated_copy_without_mutating_original() -> None:
    finding = _finding(FindingStatus.NEW)
    before = finding.last_seen
    moved = transition(finding, FindingStatus.TRIAGED)
    assert moved.status is FindingStatus.TRIAGED
    assert finding.status is FindingStatus.NEW  # original untouched
    assert moved.last_seen >= before  # workflow step is timestamped


def test_transition_rejects_an_illegal_move() -> None:
    with pytest.raises(FindingTransitionError):
        transition(_finding(FindingStatus.CLOSED), FindingStatus.NEW)


def test_transition_rejects_a_no_op() -> None:
    with pytest.raises(FindingTransitionError):
        transition(_finding(FindingStatus.CONFIRMED), FindingStatus.CONFIRMED)


def test_suppress_requires_reason_and_records_it() -> None:
    from olympus.core.finding_lifecycle import is_suppressed, suppress

    finding = _finding(FindingStatus.CONFIRMED)
    moved, record = suppress(finding, actor="analyst", reason="accepted until Q3")
    assert moved.status is FindingStatus.ACCEPTED
    assert is_suppressed(moved)
    assert record.reason == "accepted until Q3"
    assert record.actor == "analyst"
    # an empty/whitespace reason is rejected
    with pytest.raises(FindingTransitionError, match="non-empty reason"):
        suppress(finding, actor="analyst", reason="   ")


def test_suppress_as_false_positive() -> None:
    from olympus.core.finding_lifecycle import suppress

    moved, _ = suppress(
        _finding(FindingStatus.CONFIRMED),
        actor="a",
        reason="duplicate of FND-X",
        as_status=FindingStatus.FALSE_POSITIVE,
    )
    assert moved.status is FindingStatus.FALSE_POSITIVE


def test_suppress_rejects_a_non_suppression_status() -> None:
    from olympus.core.finding_lifecycle import suppress

    with pytest.raises(FindingTransitionError, match="not a suppression status"):
        suppress(
            _finding(FindingStatus.CONFIRMED), actor="a", reason="x", as_status=FindingStatus.CLOSED
        )


def test_unsuppress_reopens_to_confirmed() -> None:
    from olympus.core.finding_lifecycle import suppress, unsuppress

    accepted, _ = suppress(_finding(FindingStatus.CONFIRMED), actor="a", reason="risk accepted")
    reopened, record = unsuppress(accepted, actor="a", reason="resurfaced on retest")
    assert reopened.status is FindingStatus.CONFIRMED
    assert record.from_status is FindingStatus.ACCEPTED


def test_unsuppress_rejects_a_finding_that_is_not_suppressed() -> None:
    from olympus.core.finding_lifecycle import unsuppress

    with pytest.raises(FindingTransitionError, match="not suppressed"):
        unsuppress(_finding(FindingStatus.CONFIRMED), actor="a")


def test_full_happy_path_lifecycle() -> None:
    finding = _finding(FindingStatus.NEW)
    # Up to in_remediation is the generic workflow...
    for target in (
        FindingStatus.TRIAGED,
        FindingStatus.CONFIRMED,
        FindingStatus.IN_REMEDIATION,
    ):
        finding = transition(finding, target)
    # ...but closing is retest-gated: it needs the evidence of a passing retest.
    from olympus.core.finding_lifecycle import close_after_retest

    finding, _ = close_after_retest(finding, actor="qa", retest_evidence="EVD-2026-00007")
    assert finding.status is FindingStatus.CLOSED
    # a recurrence re-opens it
    reopened = transition(finding, FindingStatus.CONFIRMED)
    assert reopened.status is FindingStatus.CONFIRMED


# ---------------------------------------------------------------------------
# Retest-gated close (VAL-2)
# ---------------------------------------------------------------------------


def test_generic_transition_refuses_to_close_a_finding() -> None:
    # A fix is never asserted on the mover's word: the generic path cannot close.
    with pytest.raises(FindingTransitionError, match="requires the evidence of a retest"):
        transition(_finding(FindingStatus.IN_REMEDIATION), FindingStatus.CLOSED)


def test_record_transition_also_refuses_to_close() -> None:
    # record_transition is transition + audit; the gate holds there too.
    with pytest.raises(FindingTransitionError, match="requires the evidence of a retest"):
        record_transition(_finding(FindingStatus.CONFIRMED), FindingStatus.CLOSED, actor="a")


def test_close_after_retest_requires_a_real_evidence_reference() -> None:
    for bogus in ("", "   ", "we retested it", "EVD-123", "not-a-digest"):
        with pytest.raises(FindingTransitionError, match="requires retest evidence"):
            close_after_retest(
                _finding(FindingStatus.IN_REMEDIATION), actor="qa", retest_evidence=bogus
            )


def test_close_after_retest_accepts_a_custody_id_and_records_it() -> None:
    moved, record = close_after_retest(
        _finding(FindingStatus.IN_REMEDIATION),
        actor="qa",
        retest_evidence="EVD-2026-00009",
        reason="retest could not reproduce it",
    )
    assert moved.status is FindingStatus.CLOSED
    assert record.to_status is FindingStatus.CLOSED
    assert record.from_status is FindingStatus.IN_REMEDIATION
    assert record.retest_evidence == "EVD-2026-00009"
    assert record.reason == "retest could not reproduce it"


def test_close_after_retest_normalises_a_sha256_digest() -> None:
    digest = "A" * 64
    _, record = close_after_retest(
        _finding(FindingStatus.CONFIRMED), actor="qa", retest_evidence=digest
    )
    assert record.retest_evidence == "a" * 64  # folded to lower-case


def test_close_after_retest_rejects_an_illegal_source_status() -> None:
    # A false_positive cannot jump straight to closed, retest or not.
    with pytest.raises(FindingTransitionError, match="illegal finding transition"):
        close_after_retest(
            _finding(FindingStatus.FALSE_POSITIVE), actor="qa", retest_evidence="EVD-2026-00001"
        )


def test_a_failed_retest_returns_to_confirmed_without_evidence() -> None:
    # A failed retest is not a close: the ordinary workflow handles it, no gate.
    moved, record = record_transition(
        _finding(FindingStatus.IN_REMEDIATION),
        FindingStatus.CONFIRMED,
        actor="qa",
        reason="retest failed",
    )
    assert moved.status is FindingStatus.CONFIRMED
    assert record.retest_evidence is None


def test_structural_legality_still_lists_closed_as_reachable() -> None:
    # The gate lives in the application functions, not the legality map, so the
    # re-open semantics and "closed is reachable" stay honest.
    assert can_transition(FindingStatus.IN_REMEDIATION, FindingStatus.CLOSED)
    assert can_transition(FindingStatus.CLOSED, FindingStatus.CONFIRMED)

"""Unit tests for the finding lifecycle state machine (WEB-C)."""

from __future__ import annotations

import pytest

from olympus.core.enums import FindingStatus, Source
from olympus.core.finding_lifecycle import (
    FINDING_TRANSITIONS,
    FindingTransitionError,
    allowed_transitions,
    can_transition,
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
    for target in (
        FindingStatus.TRIAGED,
        FindingStatus.CONFIRMED,
        FindingStatus.IN_REMEDIATION,
        FindingStatus.CLOSED,
    ):
        finding = transition(finding, target)
    assert finding.status is FindingStatus.CLOSED
    # a recurrence re-opens it
    reopened = transition(finding, FindingStatus.CONFIRMED)
    assert reopened.status is FindingStatus.CONFIRMED

"""The finding lifecycle state machine (ROADMAP ``WEB-C``).

A finding is not a static record: it is triaged, confirmed or dismissed as a
false positive, remediated, re-opened on recurrence, or accepted as a known
risk. Letting any code set :attr:`~olympus.core.models.Finding.status` to any
value loses that discipline — a ``closed`` finding could silently jump back to
``new``, or a ``false_positive`` could be marked ``in_remediation`` without ever
being confirmed. This module is the single source of truth for which status
changes are legal, so CLI, TUI, API and the Web UI all enforce the **same**
workflow instead of each inventing its own.

The transitions are defined over the existing
:class:`~olympus.core.enums.FindingStatus` contract (no new states, so no schema
change). The workflow the ROADMAP calls for — triage, false-positive handling,
accepted-risk, remediation, retest/recurrence re-opening — maps onto the seven
canonical states as follows:

* ``new`` — just produced; may be triaged, confirmed, dismissed, accepted or
  closed.
* ``triaged`` — reviewed; awaiting a confirm/dismiss decision.
* ``confirmed`` — a real issue; may enter remediation, be accepted, be closed,
  or (rarely) be reclassified as a false positive.
* ``false_positive`` — not a real issue; only re-opens to ``confirmed`` if it
  turns out to be real after all.
* ``accepted`` — a known, accepted risk; may be re-opened to ``confirmed`` or
  closed.
* ``in_remediation`` — a fix is in progress; closes when done, or returns to
  ``confirmed`` if a retest fails.
* ``closed`` — resolved; re-opens to ``confirmed`` on recurrence (retest
  required).

A transition to the *same* status is not a transition and is rejected, so a
no-op never masquerades as a workflow step.
"""

from __future__ import annotations

from datetime import UTC, datetime

from olympus.core.enums import FindingStatus
from olympus.core.models import Finding, FindingTransition

#: Allowed ``from -> {to, ...}`` status transitions. Every key is present so the
#: map is exhaustive over :class:`FindingStatus`; a status with no outgoing edges
#: would map to an empty set (none do today).
FINDING_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.NEW: frozenset(
        {
            FindingStatus.TRIAGED,
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED,
            FindingStatus.CLOSED,
        }
    ),
    FindingStatus.TRIAGED: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED,
            FindingStatus.CLOSED,
        }
    ),
    FindingStatus.CONFIRMED: frozenset(
        {
            FindingStatus.IN_REMEDIATION,
            FindingStatus.ACCEPTED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.CLOSED,
        }
    ),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.CONFIRMED}),
    FindingStatus.ACCEPTED: frozenset({FindingStatus.CONFIRMED, FindingStatus.CLOSED}),
    FindingStatus.IN_REMEDIATION: frozenset(
        {FindingStatus.CLOSED, FindingStatus.CONFIRMED, FindingStatus.ACCEPTED}
    ),
    FindingStatus.CLOSED: frozenset({FindingStatus.CONFIRMED}),
}


class FindingTransitionError(ValueError):
    """Raised when a finding status change is not a legal workflow transition."""


def can_transition(current: FindingStatus, target: FindingStatus) -> bool:
    """Return ``True`` if moving a finding from ``current`` to ``target`` is legal."""
    return target in FINDING_TRANSITIONS.get(current, frozenset())


def allowed_transitions(current: FindingStatus) -> frozenset[FindingStatus]:
    """Return the set of statuses a finding in ``current`` may move to."""
    return FINDING_TRANSITIONS.get(current, frozenset())


def transition(finding: Finding, target: FindingStatus) -> Finding:
    """Return a copy of ``finding`` moved to ``target``, or raise if illegal.

    The original is left unchanged (a new, validated copy is returned) and
    ``last_seen`` is refreshed to record when the workflow step happened. An
    illegal transition — including a no-op to the same status — raises
    :class:`FindingTransitionError` naming both states, so the caller fails
    loudly instead of silently corrupting the workflow.
    """
    if not can_transition(finding.status, target):
        raise FindingTransitionError(
            f"illegal finding transition {finding.status.value!r} -> {target.value!r}"
        )
    return finding.model_copy(update={"status": target, "last_seen": datetime.now(UTC)})


def record_transition(
    finding: Finding,
    target: FindingStatus,
    *,
    actor: str,
    reason: str = "",
) -> tuple[Finding, FindingTransition]:
    """Apply a transition and return the moved finding plus its audit record.

    This is :func:`transition` with an audit trail: on a legal move it returns the
    updated finding together with an immutable :class:`FindingTransition` capturing
    who (`actor`) moved it from which state to which, why (`reason` — e.g. the
    rationale for a suppression or accepted-risk decision) and when. The record
    inherits the finding's ``engagement_id`` so it stays scoped to the same
    engagement. An illegal move raises :class:`FindingTransitionError` and produces
    no record.
    """
    moved = transition(finding, target)
    record = FindingTransition(
        finding_id=finding.finding_id,
        from_status=finding.status,
        to_status=target,
        actor=actor,
        reason=reason,
        occurred_at=moved.last_seen,
        engagement_id=finding.engagement_id,
    )
    return moved, record


#: The statuses that represent a *suppressed* finding: an accepted risk, or one
#: dismissed as a false positive. A suppressed finding is deliberately kept out of
#: the active worklist, which is exactly why suppressing one must be justified.
SUPPRESSED_STATUSES: frozenset[FindingStatus] = frozenset(
    {FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE}
)


def is_suppressed(finding: Finding) -> bool:
    """Return ``True`` if the finding is suppressed (accepted risk or false positive)."""
    return finding.status in SUPPRESSED_STATUSES


def suppress(
    finding: Finding,
    *,
    actor: str,
    reason: str,
    as_status: FindingStatus = FindingStatus.ACCEPTED,
) -> tuple[Finding, FindingTransition]:
    """Suppress a finding (accepted-risk or false-positive), with a required reason.

    Suppression removes a finding from the active worklist, so Olympus refuses to
    do it silently: ``reason`` must be a non-empty justification and ``as_status``
    must be a suppression status (:data:`SUPPRESSED_STATUSES`). The move itself is
    still validated by the lifecycle state machine, and the returned
    :class:`FindingTransition` records who suppressed it and why. A missing reason,
    a non-suppression target, or an illegal move raises
    :class:`FindingTransitionError` and changes nothing.
    """
    if as_status not in SUPPRESSED_STATUSES:
        raise FindingTransitionError(
            f"{as_status.value!r} is not a suppression status; "
            f"use one of {sorted(s.value for s in SUPPRESSED_STATUSES)}"
        )
    if not reason.strip():
        raise FindingTransitionError("a suppression requires a non-empty reason")
    return record_transition(finding, as_status, actor=actor, reason=reason)


def unsuppress(
    finding: Finding,
    *,
    actor: str,
    reason: str = "",
) -> tuple[Finding, FindingTransition]:
    """Re-open a suppressed finding back to ``confirmed``.

    The reverse of :func:`suppress`: an accepted risk that resurfaced, or a false
    positive that turned out real, returns to the active worklist as ``confirmed``.
    Raises :class:`FindingTransitionError` if the finding is not suppressed.
    """
    if not is_suppressed(finding):
        raise FindingTransitionError(
            f"finding is not suppressed (status {finding.status.value!r}); nothing to re-open"
        )
    return record_transition(finding, FindingStatus.CONFIRMED, actor=actor, reason=reason)

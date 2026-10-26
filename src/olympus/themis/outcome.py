"""Interface-agnostic, honest summary of a completed scan outcome (``UX-B``).

A finished scan has several outcomes that look alike at a glance but mean very
different things, and conflating them is dangerous: a run that was *simulated*,
found its scanner *unavailable*, was *disabled*, *failed*, was *cancelled*, or
completed only *partially* all carry zero real findings — exactly like a run
that genuinely ran to completion and found nothing. ``UX-B`` requires those to
be presented as distinct states so a partial or unavailable result is never
read as "no vulnerabilities".

This module is the single, interface-agnostic source of that verdict, like
:mod:`olympus.integrations.activity` for risk and
:mod:`olympus.themis.preview` for the pre-run safety preview: the CLI, the TUI
and the web control plane render the same :class:`OutcomeSummary` instead of
each re-deriving "what does this result mean?".

The safety property it encodes is a single predicate: a result is a
**trustworthy empty** — a "nothing found" the operator can rely on — only when
the scanner really ran live, ran to completion, and produced no findings. Any
other state is reported as *inconclusive* (``conclusive=False``): the absence
of findings carries no information about the target's exposure. It is pure and
offline; it reads a finished result and contacts nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from olympus.themis.model import ScanResult
from olympus.themis.runner import TerminationCause
from olympus.themis.states import ExecutionState


class OutcomeKind(StrEnum):
    """The one state a finished scan is in, from the operator's point of view."""

    #: Illustrative findings produced only because simulation was requested.
    SIMULATION = "simulation"
    #: The scanner's dependency/service was missing; nothing ran.
    UNAVAILABLE = "unavailable"
    #: Live execution was intentionally switched off; nothing ran.
    DISABLED = "disabled"
    #: A real execution was attempted but failed; the result carries no information.
    FAILED = "failed"
    #: The operator stopped the run before it could finish.
    CANCELLED = "cancelled"
    #: The scanner ran but was cut short (timeout, output/resource budget, signal);
    #: coverage is incomplete and any findings may be only a subset.
    PARTIAL = "partial"
    #: The scanner ran to completion and reported one or more findings.
    FINDINGS = "findings"
    #: The scanner ran to completion and found nothing — a trustworthy empty.
    CLEAN = "clean"


OUTCOME_HEADLINE: dict[OutcomeKind, str] = {
    OutcomeKind.SIMULATION: "Simulated run — findings are illustrative, not real",
    OutcomeKind.UNAVAILABLE: "Scanner unavailable — nothing ran",
    OutcomeKind.DISABLED: "Live execution disabled — nothing ran",
    OutcomeKind.FAILED: "Scan failed — no usable result",
    OutcomeKind.CANCELLED: "Scan cancelled — coverage incomplete",
    OutcomeKind.PARTIAL: "Partial scan — coverage incomplete",
    OutcomeKind.FINDINGS: "Findings reported",
    OutcomeKind.CLEAN: "Clean — ran to completion, nothing found",
}

OUTCOME_EXPLANATION: dict[OutcomeKind, str] = {
    OutcomeKind.SIMULATION: (
        "Simulation was requested, so any findings are illustrative examples and NOT "
        "real scanner output. This says nothing about the target."
    ),
    OutcomeKind.UNAVAILABLE: (
        "The scanner's binary, service or API was not available, so no scan ran. The "
        "absence of findings is NOT a clean result."
    ),
    OutcomeKind.DISABLED: (
        "Live execution is switched off and simulation was not requested, so no scan "
        "ran. The absence of findings is NOT a clean result."
    ),
    OutcomeKind.FAILED: (
        "The scanner was launched but did not finish successfully, so the result "
        "carries no information. The absence of findings is NOT a clean result."
    ),
    OutcomeKind.CANCELLED: (
        "The run was stopped before it could finish, so coverage is incomplete and any "
        "findings are only a partial subset. The absence of findings is NOT a clean result."
    ),
    OutcomeKind.PARTIAL: (
        "The scanner started but was cut short (timeout, output/resource budget or a "
        "signal), so coverage is incomplete. The absence of findings is NOT a clean result."
    ),
    OutcomeKind.FINDINGS: (
        "The scanner ran to completion and reported one or more findings to review."
    ),
    OutcomeKind.CLEAN: (
        "The scanner ran live to completion and reported no findings. This is a "
        "trustworthy empty result for this scanner against this target."
    ),
}

#: Terminations that mean a live run did not cleanly finish, so coverage is
#: incomplete. Cancellation is handled separately (it is the operator's intent).
_PARTIAL_CAUSES = frozenset(
    {
        TerminationCause.TIMEOUT,
        TerminationCause.OUTPUT_LIMIT,
        TerminationCause.RESOURCE_LIMIT,
        TerminationCause.SIGNALLED,
        TerminationCause.START_FAILED,
        TerminationCause.SANDBOX_DENIED,
    }
)


@dataclass(frozen=True)
class OutcomeSummary:
    """The honest, operator-facing verdict for one finished scan."""

    kind: OutcomeKind
    headline: str
    explanation: str
    finding_count: int
    #: True only when the result conclusively characterizes the target for this
    #: scanner — i.e. it ran live to completion (``FINDINGS`` or ``CLEAN``).
    conclusive: bool
    #: True only for ``CLEAN``: a "nothing found" the operator can rely on.
    trustworthy_empty: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "headline": self.headline,
            "explanation": self.explanation,
            "finding_count": self.finding_count,
            "conclusive": self.conclusive,
            "trustworthy_empty": self.trustworthy_empty,
        }

    def lines(self) -> list[str]:
        """Render the verdict as plain, colour-free labelled lines (``UX-E``)."""
        return [
            f"Outcome:   {self.kind.value.upper()} — {self.headline}",
            f"Findings:  {self.finding_count}",
            f"Meaning:   {self.explanation}",
            f"Empty = no vulnerabilities? {'yes' if self.trustworthy_empty else 'NO'}",
        ]


def _kind(
    state: ExecutionState, finding_count: int, termination_cause: TerminationCause | None
) -> OutcomeKind:
    if state is ExecutionState.SIMULATION:
        return OutcomeKind.SIMULATION
    if state is ExecutionState.UNAVAILABLE:
        return OutcomeKind.UNAVAILABLE
    if state is ExecutionState.DISABLED:
        return OutcomeKind.DISABLED
    if termination_cause is TerminationCause.CANCELLED:
        return OutcomeKind.CANCELLED
    if state is ExecutionState.FAILED:
        return OutcomeKind.FAILED
    # From here the run is LIVE. Any non-clean termination means coverage is
    # incomplete, so it can never be reported as a trustworthy empty.
    if termination_cause is not None and termination_cause is not TerminationCause.COMPLETED:
        return OutcomeKind.PARTIAL
    return OutcomeKind.FINDINGS if finding_count else OutcomeKind.CLEAN


def summarize(
    *,
    state: ExecutionState,
    finding_count: int,
    termination_cause: TerminationCause | None = None,
) -> OutcomeSummary:
    """Classify a finished scan into one distinct, honest operator verdict."""
    kind = _kind(state, finding_count, termination_cause)
    conclusive = kind in (OutcomeKind.FINDINGS, OutcomeKind.CLEAN)
    return OutcomeSummary(
        kind=kind,
        headline=OUTCOME_HEADLINE[kind],
        explanation=OUTCOME_EXPLANATION[kind],
        finding_count=finding_count,
        conclusive=conclusive,
        trustworthy_empty=kind is OutcomeKind.CLEAN,
    )


def from_result(result: ScanResult) -> OutcomeSummary:
    """Summarize an in-memory :class:`~olympus.themis.model.ScanResult`."""
    cause = result.termination.cause if result.termination is not None else None
    return summarize(
        state=result.state,
        finding_count=len(result.findings),
        termination_cause=cause,
    )


def from_mapping(result: Mapping[str, object]) -> OutcomeSummary:
    """Summarize a persisted result document (e.g. a durable job's ``result``).

    Reads only the fields it needs and fails safe: an unrecognized or missing
    execution state is treated as :data:`ExecutionState.FAILED` (never clean),
    because understating an outcome is not a safe default.
    """
    raw_state = result.get("state")
    try:
        state = ExecutionState(raw_state) if isinstance(raw_state, str) else ExecutionState.FAILED
    except ValueError:
        state = ExecutionState.FAILED

    raw_count = result.get("finding_count", 0)
    finding_count = (
        raw_count if isinstance(raw_count, int) and not isinstance(raw_count, bool) else 0
    )

    cause: TerminationCause | None = None
    termination = result.get("termination")
    if isinstance(termination, Mapping):
        raw_cause = termination.get("cause")
        if isinstance(raw_cause, str):
            try:
                cause = TerminationCause(raw_cause)
            except ValueError:
                cause = None

    return summarize(state=state, finding_count=finding_count, termination_cause=cause)


__all__ = [
    "OUTCOME_EXPLANATION",
    "OUTCOME_HEADLINE",
    "OutcomeKind",
    "OutcomeSummary",
    "from_mapping",
    "from_result",
    "summarize",
]

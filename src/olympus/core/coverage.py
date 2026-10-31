"""Shared run status and coverage accounting for scanning modules.

A scanner that quietly drops the requests it could not make reports a clean
result for a target it never actually looked at. That is the most dangerous
failure mode a security tool has, so every module that probes a target in a
loop accounts for what it *planned* to do, what it *completed*, and what it
could not complete and why.

The vocabulary is deliberately small and shared:

``RunStatus``
    ``CLEAN`` — full coverage, nothing found.
    ``FINDINGS`` — full coverage, something found.
    ``PARTIAL`` — some units completed, some did not. Findings (if any) are
    still reported, but the absence of a finding proves nothing.
    ``FAILED`` — nothing completed; the result carries no information.
    ``CANCELLED`` — the operator stopped the run before it could finish.

``FailureKind``
    Why a unit did not complete, in terms an operator can act on: a scope or
    policy denial is a configuration answer, a DNS failure is a resolution
    answer, a timeout is a network answer.

``PARTIAL`` outranks ``FINDINGS`` on purpose. A run that both found something
and lost coverage is incomplete first: the findings are printed either way,
but the exit code has to say the run cannot be trusted as exhaustive.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from olympus.core.execution import redact_text
from olympus.core.exit_codes import ExitCode

#: How many redacted error samples a coverage report keeps. Enough to diagnose,
#: bounded so a fully-failing run cannot produce an unbounded report.
MAX_ERROR_SAMPLES = 10

#: Longest single error sample retained, before redaction is applied.
MAX_ERROR_SAMPLE_CHARS = 300


class RunStatus(StrEnum):
    """The trustworthiness of one completed module run (see module docstring)."""

    CLEAN = "clean"
    FINDINGS = "findings"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FailureKind(StrEnum):
    """Why one planned unit of work did not produce a usable result."""

    #: The target was outside the authorized scope and was blocked and audited.
    SCOPE_DENIED = "scope_denied"
    #: An execution policy (authorization, limits, allowlist) refused the work.
    POLICY_DENIED = "policy_denied"
    #: The name could not be resolved.
    DNS_FAILURE = "dns_failure"
    #: The connection attempt or the response timed out.
    TIMEOUT = "timeout"
    #: The network or host is unreachable (routing failure, ICMP unreachable).
    UNREACHABLE = "unreachable"
    #: The connection failed or was reset below the protocol layer.
    TRANSPORT_ERROR = "transport_error"
    #: A response was received but could not be parsed or was malformed.
    PROTOCOL_ERROR = "protocol_error"
    #: A configured bound (body size, redirects, expansion ratio) was hit.
    LIMIT_EXCEEDED = "limit_exceeded"
    #: The overall deadline ran out before this unit was attempted or finished.
    DEADLINE_EXCEEDED = "deadline_exceeded"
    #: Cooperative cancellation was requested before this unit finished.
    CANCELLED = "cancelled"
    #: Anything else; kept last so an unclassified error is still visible.
    ERROR = "error"


@dataclass(frozen=True)
class Coverage:
    """What a run planned to do, what it completed, and why the rest did not.

    ``planned`` is fixed before the first request. ``completed + failed +
    skipped`` never exceeds it; a shortfall means the run stopped early and is
    reported through :attr:`unattempted`.
    """

    planned: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    reasons: Mapping[FailureKind, int] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        negative = min(self.planned, self.completed, self.failed, self.skipped) < 0
        if negative:
            raise ValueError("coverage counters must not be negative")
        if self.completed + self.failed + self.skipped > self.planned:
            raise ValueError("coverage accounted for more units than were planned")

    @property
    def attempted(self) -> int:
        """Units that were actually dispatched (completed or failed)."""
        return self.completed + self.failed

    @property
    def unattempted(self) -> int:
        """Planned units the run never reached, e.g. after a deadline."""
        return self.planned - self.completed - self.failed - self.skipped

    @property
    def complete(self) -> bool:
        """Whether every planned unit produced a usable result."""
        return self.planned == self.completed

    @property
    def ratio(self) -> float:
        """Fraction of planned units that completed; ``1.0`` when nothing was planned."""
        if self.planned == 0:
            return 1.0
        return self.completed / self.planned

    def status(self, finding_count: int) -> RunStatus:
        """Derive the run status from coverage and the number of findings."""
        if self.planned == 0:
            return classify_run_status(finding_count)
        if self.completed == 0:
            return RunStatus.FAILED
        if not self.complete:
            return RunStatus.PARTIAL
        return classify_run_status(finding_count)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable, deterministic view for exports and CLI output."""
        return {
            "planned": self.planned,
            "completed": self.completed,
            "failed": self.failed,
            "skipped": self.skipped,
            "unattempted": self.unattempted,
            "complete": self.complete,
            "reasons": {kind.value: count for kind, count in sorted(self.reasons.items())},
            "errors": list(self.errors),
        }


class CoverageTracker:
    """Accumulate coverage for one run, then freeze it into a :class:`Coverage`.

    Not thread-safe by itself: a concurrent module records results on the
    thread that joins its workers, which is where the counters belong anyway.
    """

    def __init__(self, planned: int = 0) -> None:
        if planned < 0:
            raise ValueError("planned must not be negative")
        self._planned = planned
        self._completed = 0
        self._failed = 0
        self._skipped = 0
        self._reasons: dict[FailureKind, int] = {}
        self._errors: list[str] = []

    @property
    def planned(self) -> int:
        """Units this run committed to attempting."""
        return self._planned

    def plan(self, units: int) -> None:
        """Add ``units`` to the planned total before work starts."""
        if units < 0:
            raise ValueError("units must not be negative")
        self._planned += units

    def complete(self, units: int = 1) -> None:
        """Record ``units`` that produced a usable result."""
        self._completed += units

    def fail(self, kind: FailureKind, detail: str | None = None, units: int = 1) -> None:
        """Record ``units`` that were attempted and did not produce a result."""
        self._failed += units
        self._record(kind, detail, units)

    def skip(self, kind: FailureKind, detail: str | None = None, units: int = 1) -> None:
        """Record ``units`` deliberately not attempted (denied, out of budget)."""
        self._skipped += units
        self._record(kind, detail, units)

    def _record(self, kind: FailureKind, detail: str | None, units: int) -> None:
        if units < 0:
            raise ValueError("units must not be negative")
        self._reasons[kind] = self._reasons.get(kind, 0) + units
        if detail and len(self._errors) < MAX_ERROR_SAMPLES:
            trimmed = detail.strip()[:MAX_ERROR_SAMPLE_CHARS]
            self._errors.append(f"{kind.value}: {redact_text(trimmed)}")

    def build(self) -> Coverage:
        """Freeze the accumulated counters into an immutable report."""
        return Coverage(
            planned=self._planned,
            completed=self._completed,
            failed=self._failed,
            skipped=self._skipped,
            reasons=dict(self._reasons),
            errors=tuple(self._errors),
        )


_EXIT_CODES: dict[RunStatus, ExitCode] = {
    RunStatus.CLEAN: ExitCode.OK,
    RunStatus.FINDINGS: ExitCode.FINDINGS,
    RunStatus.PARTIAL: ExitCode.PARTIAL,
    RunStatus.FAILED: ExitCode.FAILED,
    RunStatus.CANCELLED: ExitCode.CANCELLED,
}


def classify_run_status(
    finding_count: int = 0,
    *,
    partial: bool = False,
    failed: bool = False,
    cancelled: bool = False,
) -> RunStatus:
    """Classify a terminal run using the canonical precedence rules.

    Domain modules keep their richer internal state machines, then reduce the
    terminal result through this function before returning control to a shell.
    Exactly one exceptional terminal flag may be set. ``partial`` deliberately
    outranks findings because incomplete coverage must never read as exhaustive.
    """
    if finding_count < 0:
        raise ValueError("finding_count must not be negative")
    if sum((partial, failed, cancelled)) > 1:
        raise ValueError("partial, failed and cancelled are mutually exclusive")
    if cancelled:
        return RunStatus.CANCELLED
    if failed:
        return RunStatus.FAILED
    if partial:
        return RunStatus.PARTIAL
    return RunStatus.FINDINGS if finding_count else RunStatus.CLEAN


def exit_code_for(status: RunStatus) -> ExitCode:
    """Map a run status onto its canonical process exit code."""
    return _EXIT_CODES[status]


def summarize(status: RunStatus, coverage: Coverage, finding_count: int) -> str:
    """Render a one-line operator summary of a run's status and coverage."""
    line = (
        f"status={status.value} findings={finding_count} "
        f"coverage={coverage.completed}/{coverage.planned}"
    )
    if coverage.reasons:
        detail = " ".join(
            f"{kind.value}={count}" for kind, count in sorted(coverage.reasons.items())
        )
        line = f"{line} ({detail})"
    return line

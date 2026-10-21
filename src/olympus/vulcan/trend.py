"""Finding severity trend across an ordered series of runs (ROADMAP ``WEB-I``).

A single scan is a snapshot; a security programme is a *trajectory*. This module
turns an ordered sequence of finding snapshots (oldest first) into a trend: how
many findings sit at each severity at every point, and — between consecutive
snapshots — how many were **new**, **resolved** or **persistent**. It is the
single, tested place that derives that trajectory, reusing the shared
:func:`olympus.vulcan.compare.diff_findings` for the step deltas and
:func:`olympus.vulcan.aggregate.severity_breakdown` for the per-point counts, so
the CLI and any report agree on what "the trend" means.

Each snapshot is first folded with
:func:`~olympus.vulcan.aggregate.merge_duplicate_findings` so a logical issue
counts once, exactly as the diff and dedup do. The computation is pure and
offline: it reads already-loaded findings and talks to no network, so it is fully
deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from olympus.core.models import Finding
from olympus.vulcan.aggregate import merge_duplicate_findings, severity_breakdown
from olympus.vulcan.compare import diff_findings


@dataclass(frozen=True)
class TrendPoint:
    """One point in the trend: a snapshot's counts and its change from the previous."""

    label: str
    total: int
    severity_breakdown: dict[str, int]
    #: Change versus the previous snapshot; all zero for the first point, which
    #: has nothing to compare against (``is_baseline``).
    new: int
    resolved: int
    persistent: int
    is_baseline: bool

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable projection of this point."""
        return {
            "label": self.label,
            "total": self.total,
            "severity_breakdown": dict(self.severity_breakdown),
            "new": self.new,
            "resolved": self.resolved,
            "persistent": self.persistent,
            "is_baseline": self.is_baseline,
        }


@dataclass(frozen=True)
class FindingTrend:
    """The severity trajectory across an ordered series of finding snapshots."""

    points: tuple[TrendPoint, ...]

    @property
    def regressed(self) -> bool:
        """Whether the most recent step introduced any new finding."""
        return bool(self.points) and self.points[-1].new > 0

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable projection of the whole trend."""
        return {"points": [point.to_dict() for point in self.points]}


def build_finding_trend(
    snapshots: Sequence[tuple[str, Sequence[Finding]]],
) -> FindingTrend:
    """Build the severity trend from ordered ``(label, findings)`` snapshots.

    ``snapshots`` are oldest first. Each is folded to its logical findings; the
    per-point ``total`` and ``severity_breakdown`` describe that folded set, and
    the ``new``/``resolved``/``persistent`` counts describe the transition **from
    the previous snapshot**, computed with :func:`diff_findings`. The first point
    is a baseline (zero deltas). The result is deterministic.
    """
    points: list[TrendPoint] = []
    previous: list[Finding] | None = None
    for label, findings in snapshots:
        folded = merge_duplicate_findings(list(findings))
        if previous is None:
            new = resolved = persistent = 0
            is_baseline = True
        else:
            delta = diff_findings(previous, folded)
            new, resolved, persistent = (
                len(delta.new),
                len(delta.resolved),
                len(delta.persistent),
            )
            is_baseline = False
        points.append(
            TrendPoint(
                label=label,
                total=len(folded),
                severity_breakdown=severity_breakdown(folded),
                new=new,
                resolved=resolved,
                persistent=persistent,
                is_baseline=is_baseline,
            )
        )
        previous = folded
    return FindingTrend(tuple(points))

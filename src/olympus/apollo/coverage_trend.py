"""Detection-coverage metrics over an ordered history (ROADMAP ``VAL-3``).

A single coverage matrix (:mod:`olympus.apollo.coverage`) answers *how detectable
is each ATT&CK technique right now, given the telemetry present*. A security
programme also needs the **evolution**: is defensive coverage improving, and did a
lost log source silently reopen a detection gap? This module builds that time
series by **reusing** :func:`~olympus.apollo.coverage.assess_coverage` over an
ordered list of snapshots — it never derives a parallel coverage engine — and
computes documented, deterministic metrics for each point plus the change since
the previous one.

Every metric carries its **definition** and, above all, its **limit**: these are
measures of *structural* coverage — a rule targets the technique **and** the
telemetry it needs is present — **not** proven detection. A technique counted as
``covered`` is detectable *on paper*; demonstrating that its rule actually fires
on a real attack needs an authorized simulation (``PURPLE-1``), whose outcome is
out of scope here. The series is honest about gaps the same way
:mod:`~olympus.apollo.coverage` is: a technique with a rule but no telemetry is a
**blind spot**, never silently counted as coverage, and a technique that
regresses into one is surfaced explicitly.

The computation is pure, offline and deterministic: given the same ordered
coverage reports it always produces the same trend.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from olympus.apollo.coverage import CoverageReport, CoverageStatus

#: Self-describing definitions + limit, emitted with every trend document so a
#: consumer reads what each metric means and what it does *not* prove.
METRIC_DEFINITIONS: dict[str, str] = {
    "structural_detection_coverage": (
        "covered / total techniques — the fraction of targeted ATT&CK techniques "
        "every rule of which can fire on telemetry that is present."
    ),
    "partial_ratio": (
        "partial / total techniques — targeted techniques detectable by some but "
        "not all of their rules (blind spots remain)."
    ),
    "blind_spot_ratio": (
        "no-telemetry / total techniques — targeted techniques with a rule but no "
        "telemetry present, undetectable however many rules exist on paper."
    ),
}
#: The epistemic ceiling of every metric here, stated so coverage is never read
#: as demonstrated detection.
METRIC_LIMIT: str = (
    "Structural coverage only: a rule exists and its telemetry is present. This "
    "does not prove the rule fires on a real attack — that needs an authorized "
    "simulation (PURPLE-1). Measured against the detection set's own techniques, "
    "not a reference ATT&CK catalogue (honest absence)."
)


def _round(value: float) -> float:
    """Round a ratio to 4 dp so the series is stable and readable."""
    return round(value, 4)


@dataclass(frozen=True)
class CoverageMetrics:
    """Documented structural-coverage ratios for one snapshot (see module limit)."""

    total_techniques: int
    covered: int
    partial: int
    no_telemetry: int

    @property
    def structural_detection_coverage(self) -> float:
        """covered / total; ``0.0`` when the rule set targets no technique."""
        if self.total_techniques == 0:
            return 0.0
        return _round(self.covered / self.total_techniques)

    @property
    def partial_ratio(self) -> float:
        """partial / total; ``0.0`` when there are no techniques."""
        if self.total_techniques == 0:
            return 0.0
        return _round(self.partial / self.total_techniques)

    @property
    def blind_spot_ratio(self) -> float:
        """no-telemetry / total; ``0.0`` when there are no techniques."""
        if self.total_techniques == 0:
            return 0.0
        return _round(self.no_telemetry / self.total_techniques)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_techniques": self.total_techniques,
            "covered": self.covered,
            "partial": self.partial,
            "no_telemetry": self.no_telemetry,
            "structural_detection_coverage": self.structural_detection_coverage,
            "partial_ratio": self.partial_ratio,
            "blind_spot_ratio": self.blind_spot_ratio,
        }


def _metrics_of(report: CoverageReport) -> CoverageMetrics:
    counts = report.counts
    return CoverageMetrics(
        total_techniques=len(report.techniques),
        covered=counts[CoverageStatus.COVERED.value],
        partial=counts[CoverageStatus.PARTIAL.value],
        no_telemetry=counts[CoverageStatus.NO_TELEMETRY.value],
    )


@dataclass(frozen=True)
class CoverageTrendPoint:
    """One snapshot's coverage metrics and how it changed from the previous one."""

    label: str
    metrics: CoverageMetrics
    telemetry_complete: bool
    is_baseline: bool
    #: Techniques that became ``covered`` since the previous snapshot.
    newly_covered: tuple[str, ...]
    #: Techniques that regressed to ``no-telemetry`` (a reopened blind spot).
    newly_blind: tuple[str, ...]
    #: structural_detection_coverage minus the previous snapshot's (``0.0`` at baseline).
    coverage_delta: float

    @property
    def regressed(self) -> bool:
        """Whether this point lost ground: a new blind spot or a coverage drop."""
        return bool(self.newly_blind) or self.coverage_delta < 0

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "metrics": self.metrics.to_dict(),
            "telemetry_complete": self.telemetry_complete,
            "is_baseline": self.is_baseline,
            "newly_covered": list(self.newly_covered),
            "newly_blind": list(self.newly_blind),
            "coverage_delta": self.coverage_delta,
            "regressed": self.regressed,
        }


@dataclass(frozen=True)
class CoverageTrend:
    """The ordered series of coverage metrics across an assessment history."""

    points: tuple[CoverageTrendPoint, ...]

    @property
    def regressed(self) -> bool:
        """Whether any snapshot after the baseline lost coverage ground."""
        return any(point.regressed for point in self.points)

    def summary(self) -> dict[str, object]:
        """The headline a defender reads first: endpoints and the net change."""
        first = self.points[0].metrics.structural_detection_coverage
        last = self.points[-1].metrics.structural_detection_coverage
        return {
            "snapshots": len(self.points),
            "baseline_coverage": first,
            "latest_coverage": last,
            "net_coverage_delta": _round(last - first),
            "regressed": self.regressed,
            "latest_blind_spots": self.points[-1].metrics.no_telemetry,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary(),
            "metric_definitions": METRIC_DEFINITIONS,
            "limit": METRIC_LIMIT,
            "points": [point.to_dict() for point in self.points],
        }


def _covered_set(report: CoverageReport) -> set[str]:
    return {t.technique for t in report.techniques if t.status is CoverageStatus.COVERED}


def _blind_set(report: CoverageReport) -> set[str]:
    return {t.technique for t in report.techniques if t.status is CoverageStatus.NO_TELEMETRY}


def build_coverage_trend(
    snapshots: Sequence[tuple[str, CoverageReport]],
) -> CoverageTrend:
    """Build the coverage trend from an ordered series of coverage reports.

    ``snapshots`` are ``(label, CoverageReport)`` pairs, **oldest first**; at least
    one is required. Each point reuses the report's own honest counts; the
    ``newly_covered`` / ``newly_blind`` deltas compare a snapshot's technique
    statuses with the immediately previous snapshot (by technique id), so a
    reopened detection gap is surfaced rather than averaged away. The intended
    model is a **fixed rule set measured against evolving telemetry**: coverage
    regresses when a log source stops being ingested. Deterministic and offline.
    """
    if not snapshots:
        raise ValueError("a coverage trend needs at least one snapshot")

    points: list[CoverageTrendPoint] = []
    previous: CoverageReport | None = None
    previous_coverage = 0.0
    for index, (label, report) in enumerate(snapshots):
        metrics = _metrics_of(report)
        if previous is None:
            newly_covered: tuple[str, ...] = ()
            newly_blind: tuple[str, ...] = ()
            delta = 0.0
        else:
            prev_covered = _covered_set(previous)
            prev_blind = _blind_set(previous)
            newly_covered = tuple(sorted(_covered_set(report) - prev_covered))
            newly_blind = tuple(sorted(_blind_set(report) - prev_blind))
            delta = _round(metrics.structural_detection_coverage - previous_coverage)
        points.append(
            CoverageTrendPoint(
                label=label,
                metrics=metrics,
                telemetry_complete=report.telemetry_input.complete,
                is_baseline=index == 0,
                newly_covered=newly_covered,
                newly_blind=newly_blind,
                coverage_delta=delta,
            )
        )
        previous = report
        previous_coverage = metrics.structural_detection_coverage

    return CoverageTrend(tuple(points))


__all__ = [
    "METRIC_DEFINITIONS",
    "METRIC_LIMIT",
    "CoverageMetrics",
    "CoverageTrend",
    "CoverageTrendPoint",
    "build_coverage_trend",
]

"""Compare two finding sets to classify what changed between runs (ROADMAP ``WEB-I``).

A security programme is judged by what changes between assessments: which issues
are **new** (a regression, or newly discovered), which were **resolved** (gone
since the baseline — the evidence a remediation worked), and which **persist**
(still open, perhaps with a changed severity). This module is the single, tested
place that decides that classification, so the CLI, the Web UI and any report
share one definition of *new / resolved / persistent* instead of each re-deriving
it (the same single-source principle :mod:`olympus.vulcan.view` applies to
columns and :mod:`olympus.vulcan.search` to filters).

Findings are matched by their **logical identity** —
:func:`olympus.vulcan.aggregate.finding_fingerprint` (same asset + same
vulnerability) — never by the per-run ``finding_id``, which is minted fresh each
scan. Each side is first folded with
:func:`~olympus.vulcan.aggregate.merge_duplicate_findings` so a logical issue seen
by several scanners counts once. The comparison is pure and offline: it reads
already-loaded findings and talks to no network, so it is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from olympus.core.enums import Severity
from olympus.core.models import Finding
from olympus.vulcan.aggregate import finding_fingerprint, merge_duplicate_findings
from olympus.vulcan.view import FindingView

#: Severity ordering (critical first) to tell a worsened issue from an eased one.
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class PersistentFinding:
    """One logical issue present in both the baseline and the current run."""

    current: Finding
    baseline: Finding

    @property
    def severity_changed(self) -> bool:
        """Whether the severity differs between the two runs."""
        return self.current.severity is not self.baseline.severity

    @property
    def severity_worsened(self) -> bool:
        """Whether the current severity is more urgent than the baseline's."""
        return _SEVERITY_ORDER[self.current.severity] < _SEVERITY_ORDER[self.baseline.severity]

    @property
    def risk_delta(self) -> float:
        """Current minus baseline contextual risk score (positive = worse now)."""
        return round(self.current.risk_score() - self.baseline.risk_score(), 2)


@dataclass(frozen=True)
class ScanDiff:
    """The classified difference between a baseline and a current finding set."""

    new: tuple[Finding, ...]
    resolved: tuple[Finding, ...]
    persistent: tuple[PersistentFinding, ...]

    @property
    def has_regressions(self) -> bool:
        """Whether the current run introduced any finding absent from the baseline."""
        return bool(self.new)

    def summary(self) -> dict[str, int]:
        """Counts an operator reads first: new, resolved, persistent, worsened."""
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "persistent": len(self.persistent),
            "worsened": sum(1 for item in self.persistent if item.severity_worsened),
        }

    def to_dict(self) -> dict[str, object]:
        """Full, JSON-serialisable projection reusing the shared finding view."""
        return {
            "summary": self.summary(),
            "new": [FindingView(finding).detail() for finding in self.new],
            "resolved": [FindingView(finding).detail() for finding in self.resolved],
            "persistent": [
                {
                    "current": FindingView(item.current).detail(),
                    "baseline": FindingView(item.baseline).detail(),
                    "severity_changed": item.severity_changed,
                    "severity_worsened": item.severity_worsened,
                    "risk_delta": item.risk_delta,
                }
                for item in self.persistent
            ],
        }


def _fold(findings: Sequence[Finding]) -> dict[tuple[str, str], Finding]:
    """Collapse a finding set to one representative per logical identity."""
    return {finding_fingerprint(finding): finding for finding in merge_duplicate_findings(findings)}


def _rank_key(finding: Finding) -> tuple[float, str]:
    """Order by descending risk, then stable id, so the diff is deterministic."""
    return (-finding.risk_score(), finding.finding_id)


def diff_findings(baseline: Sequence[Finding], current: Sequence[Finding]) -> ScanDiff:
    """Classify every logical finding as new, resolved or persistent across two runs.

    ``baseline`` is the earlier run and ``current`` the later one. A logical issue
    in ``current`` but not ``baseline`` is **new**; one in ``baseline`` but not
    ``current`` is **resolved**; one in both is **persistent** (carrying both
    representatives so a consumer can show a severity or risk change). Each list is
    ordered by descending risk then id; the operation is pure and deterministic.
    """
    base_map = _fold(baseline)
    current_map = _fold(current)
    new = sorted(
        (finding for key, finding in current_map.items() if key not in base_map),
        key=_rank_key,
    )
    resolved = sorted(
        (finding for key, finding in base_map.items() if key not in current_map),
        key=_rank_key,
    )
    persistent = sorted(
        (
            PersistentFinding(current=finding, baseline=base_map[key])
            for key, finding in current_map.items()
            if key in base_map
        ),
        key=lambda item: _rank_key(item.current),
    )
    return ScanDiff(tuple(new), tuple(resolved), tuple(persistent))

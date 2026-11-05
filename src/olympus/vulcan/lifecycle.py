"""Finding lifecycle across an ordered history of assessments (ROADMAP ``VAL-1``).

A two-run diff (:mod:`olympus.vulcan.compare`) answers *what changed since the
previous run*. A recurring programme needs more: against the **whole history** of
an asset, a finding that is open again today is not simply "new" if it was seen,
fixed, and has now come back. This module classifies every logical finding in the
**latest** snapshot of an ordered series as:

- **new** — first ever seen in the latest snapshot (never present before);
- **persistent** — also present in the immediately previous snapshot (still open);
- **reappeared** — present now, absent in the immediately previous snapshot, but
  seen in some earlier snapshot — i.e. it was resolved and has returned;

and lists, separately, the findings that are **resolved** (present in the
previous snapshot, absent now). "Reappeared" is derived purely from the history
and the shared logical identity — it is **not** a new canonical lifecycle state
on :class:`~olympus.core.models.Finding`, exactly as ``VAL-1`` requires.

Findings are matched by :func:`olympus.vulcan.aggregate.finding_fingerprint`
(same asset + same vulnerability), never by the per-run ``finding_id``; each
snapshot is folded with :func:`~olympus.vulcan.aggregate.merge_duplicate_findings`
so a logical issue seen by several scanners counts once — the same single-source
identity the diff and trend use. The computation is pure and offline: it reads
already-loaded findings and talks to no network, so it is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from olympus.core.models import Finding
from olympus.vulcan.aggregate import finding_fingerprint, merge_duplicate_findings
from olympus.vulcan.compare import PersistentFinding, rank_key
from olympus.vulcan.view import FindingView


@dataclass(frozen=True)
class ReappearedFinding:
    """A logical issue open again now after being absent in the previous run.

    ``previous`` is its representative from the most recent earlier snapshot in
    which it was seen (the state it returned *from*), so a consumer can show
    whether it came back worse. ``absent_for`` is how many consecutive snapshots
    it was missing immediately before returning (always ``>= 1``).
    """

    current: Finding
    previous: Finding
    absent_for: int

    @property
    def _pair(self) -> PersistentFinding:
        # Reuse the single severity/risk-delta definition instead of re-deriving it.
        return PersistentFinding(current=self.current, baseline=self.previous)

    @property
    def severity_changed(self) -> bool:
        """Whether the severity differs from when it was last seen."""
        return self._pair.severity_changed

    @property
    def severity_worsened(self) -> bool:
        """Whether it returned more urgent than when it was last seen."""
        return self._pair.severity_worsened

    @property
    def risk_delta(self) -> float:
        """Current minus last-seen contextual risk score (positive = worse now)."""
        return self._pair.risk_delta


@dataclass(frozen=True)
class FindingLifecycle:
    """The latest snapshot's findings classified against the whole history."""

    new: tuple[Finding, ...]
    persistent: tuple[PersistentFinding, ...]
    reappeared: tuple[ReappearedFinding, ...]
    resolved: tuple[Finding, ...]

    @property
    def has_reappearances(self) -> bool:
        """Whether any resolved finding has returned in the latest snapshot."""
        return bool(self.reappeared)

    def summary(self) -> dict[str, int]:
        """Counts an operator reads first, including worsened returns."""
        worsened = sum(1 for item in self.persistent if item.severity_worsened)
        worsened += sum(1 for item in self.reappeared if item.severity_worsened)
        return {
            "new": len(self.new),
            "persistent": len(self.persistent),
            "reappeared": len(self.reappeared),
            "resolved": len(self.resolved),
            "worsened": worsened,
        }

    def to_dict(self) -> dict[str, object]:
        """Full, JSON-serialisable projection reusing the shared finding view."""
        return {
            "summary": self.summary(),
            "new": [FindingView(finding).detail() for finding in self.new],
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
            "reappeared": [
                {
                    "current": FindingView(item.current).detail(),
                    "previous": FindingView(item.previous).detail(),
                    "absent_for": item.absent_for,
                    "severity_changed": item.severity_changed,
                    "severity_worsened": item.severity_worsened,
                    "risk_delta": item.risk_delta,
                }
                for item in self.reappeared
            ],
            "resolved": [FindingView(finding).detail() for finding in self.resolved],
        }


def classify_lifecycle(
    snapshots: Sequence[tuple[str, Sequence[Finding]]],
) -> FindingLifecycle:
    """Classify the latest snapshot's findings against the full ordered history.

    ``snapshots`` are ``(label, findings)`` pairs, **oldest first**; at least one
    is required. Each snapshot is folded to its logical findings. For the latest
    snapshot, every logical finding is classified as **new** (never seen before),
    **persistent** (also in the immediately previous snapshot) or **reappeared**
    (absent in the previous snapshot but seen earlier); findings in the previous
    snapshot but not the latest are **resolved**. With a single snapshot every
    finding is new and nothing is persistent, reappeared or resolved. Each list is
    ordered by descending risk then id; the operation is pure and deterministic.
    """
    if not snapshots:
        raise ValueError("classify_lifecycle needs at least one snapshot")

    folded: list[dict[tuple[str, str], Finding]] = [
        {finding_fingerprint(f): f for f in merge_duplicate_findings(list(findings))}
        for _label, findings in snapshots
    ]
    latest = folded[-1]
    previous = folded[-2] if len(folded) >= 2 else {}
    # Index, per fingerprint, of the most recent snapshot *before* the latest in
    # which it appeared — the state a reappearance returns from.
    last_seen_before: dict[tuple[str, str], int] = {}
    for index in range(len(folded) - 1):
        for key in folded[index]:
            last_seen_before[key] = index

    new: list[Finding] = []
    persistent: list[PersistentFinding] = []
    reappeared: list[ReappearedFinding] = []
    last_index = len(folded) - 1
    for key, finding in latest.items():
        if key in previous:
            persistent.append(PersistentFinding(current=finding, baseline=previous[key]))
        elif key in last_seen_before:
            earlier_index = last_seen_before[key]
            reappeared.append(
                ReappearedFinding(
                    current=finding,
                    previous=folded[earlier_index][key],
                    absent_for=last_index - 1 - earlier_index,
                )
            )
        else:
            new.append(finding)

    resolved = [finding for key, finding in previous.items() if key not in latest]

    return FindingLifecycle(
        new=tuple(sorted(new, key=rank_key)),
        persistent=tuple(sorted(persistent, key=lambda item: rank_key(item.current))),
        reappeared=tuple(sorted(reappeared, key=lambda item: rank_key(item.current))),
        resolved=tuple(sorted(resolved, key=rank_key)),
    )

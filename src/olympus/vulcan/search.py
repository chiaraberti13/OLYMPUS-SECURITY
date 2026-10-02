"""Composable search and filtering over findings (ROADMAP ``WEB-C``).

A findings view — in the CLI, the TUI or the Web UI — needs to narrow a large
set down to what matters now: open criticals, everything KEV-listed, one
engagement, a tag, a free-text match. This module is the single, tested place
that decides what a filter *means*, so every interface narrows findings the same
way instead of each re-implementing the predicates.

:class:`FindingFilter` is an immutable value object: every criterion is optional
and an unset criterion simply does not constrain the result. ``matches`` tests
one finding; :func:`search_findings` applies the filter to a sequence, preserving
input order (callers rank separately, e.g. with ``vulcan.aggregate.rank_findings``
or ``Finding.risk_score``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.models import Finding

#: Severity ordering (critical first) reused for the ``min_severity`` threshold.
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class FindingFilter:
    """An immutable set of optional criteria; unset criteria do not constrain."""

    statuses: frozenset[FindingStatus] = field(default_factory=frozenset)
    sources: frozenset[Source] = field(default_factory=frozenset)
    min_severity: Severity | None = None
    engagement_id: str | None = None
    kev_only: bool = False
    has_cve: bool | None = None
    #: A finding must carry **all** of these tags (case-insensitive).
    tags: frozenset[str] = field(default_factory=frozenset)
    #: Case-insensitive substring matched across title, description, references,
    #: CVE/CWE ids, tags and the asset/finding ids.
    text: str = ""
    min_risk_score: float | None = None

    def matches(self, finding: Finding) -> bool:
        """Return ``True`` if ``finding`` satisfies every set criterion."""
        if self.statuses and finding.status not in self.statuses:
            return False
        if self.sources and finding.source not in self.sources:
            return False
        if (
            self.min_severity is not None
            and _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[self.min_severity]
        ):
            return False
        if self.engagement_id is not None and finding.engagement_id != self.engagement_id:
            return False
        if self.kev_only and not finding.kev:
            return False
        if self.has_cve is not None and bool(finding.cves()) is not self.has_cve:
            return False
        if self.tags and not self._tags_match(finding):
            return False
        if self.min_risk_score is not None and finding.risk_score() < self.min_risk_score:
            return False
        return not self.text or self._text_match(finding)

    def _tags_match(self, finding: Finding) -> bool:
        have = {tag.casefold() for tag in finding.tags}
        return {tag.casefold() for tag in self.tags} <= have

    def _text_match(self, finding: Finding) -> bool:
        needle = self.text.casefold()
        haystack = " ".join(
            [
                finding.title,
                finding.description,
                finding.asset_id,
                finding.finding_id,
                *finding.references,
                *finding.cves(),
                *finding.cwes(),
                *finding.tags,
            ]
        ).casefold()
        return needle in haystack


def search_findings(findings: Sequence[Finding], query: FindingFilter) -> list[Finding]:
    """Return the findings matching ``query``, preserving input order."""
    return [finding for finding in findings if query.matches(finding)]

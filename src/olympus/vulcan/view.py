"""Interface-agnostic projection of a finding into an operator view (ROADMAP ``WEB-C``).

A findings view — in the CLI, the TUI or the Web UI — must show the same columns,
derive them the same way, and above all be **honest about absence**: a datum the
finding does not carry (no CVSS yet, no EPSS overlay, no remediation written) is
not the same as a present-but-empty one, and must never be shown as a fabricated
``0`` or a blank cell that reads like "none found". This module is the single,
tested place that projects a :class:`~olympus.core.models.Finding` into
presentation-ready values, so every interface renders findings identically
instead of each re-deriving the columns (the same principle
:mod:`olympus.vulcan.search` applies to filtering).

The columns follow the ``WEB-C`` finding view: title, severity, status, asset,
source, CVE, CWE, CVSS, EPSS, CISA KEV, confidence, evidence, first/last seen,
remediation and references, plus the contextual :meth:`Finding.risk_score`. There
is no separate *scanner* field on the contract: ``source`` is a finding's
provenance (the producing engine, e.g. ``themis``), so it carries that column.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from olympus.core.models import Finding

#: Rendered in a cell for a datum the finding does not carry, so an operator can
#: tell "absent" apart from a real empty value or a zero.
ABSENT = "—"

#: Columns of the compact one-line list view, in display order.
LIST_COLUMNS: tuple[str, ...] = (
    "risk",
    "severity",
    "status",
    "title",
    "asset",
    "source",
    "cve",
    "kev",
)


def _scalar(value: object) -> str:
    """Render one optional scalar: absent values become :data:`ABSENT`."""
    return ABSENT if value is None else str(value)


def _sequence(values: Sequence[str]) -> str:
    """Render a list field: joined when present, :data:`ABSENT` when empty."""
    return ", ".join(values) if values else ABSENT


@dataclass(frozen=True)
class FindingView:
    """A presentation-ready projection of one finding.

    Scalar optionals stay ``None`` in :meth:`detail` (never coerced to ``0`` or
    ``""``) so a consumer can distinguish absent from empty; list fields are
    returned as lists that may be empty. :meth:`row` renders the compact list
    cells and :meth:`display_items` the detail cells, both using :data:`ABSENT`
    for missing data.
    """

    finding: Finding

    @property
    def risk_score(self) -> float:
        """The finding's contextual risk score in ``[0, 100]`` (computed)."""
        return self.finding.risk_score()

    @property
    def cves(self) -> tuple[str, ...]:
        """Resolved CVE ids (structured field, else text-derived)."""
        return tuple(self.finding.cves())

    @property
    def cwes(self) -> tuple[str, ...]:
        """Resolved CWE ids (structured field, else text-derived)."""
        return tuple(self.finding.cwes())

    def row(self) -> dict[str, str]:
        """Compact, table-ready cells keyed by :data:`LIST_COLUMNS`."""
        finding = self.finding
        return {
            "risk": f"{self.risk_score:g}",
            "severity": finding.severity.value,
            "status": finding.status.value,
            "title": finding.title,
            "asset": finding.asset_id,
            "source": finding.source.value,
            "cve": _sequence(self.cves),
            "kev": "yes" if finding.kev else ABSENT,
        }

    def display_items(self) -> list[tuple[str, str]]:
        """Ordered ``(label, rendered value)`` pairs for a detail view.

        Every ``WEB-C`` finding-view column appears; a datum the finding does not
        carry renders as :data:`ABSENT` rather than a blank or a fabricated zero.
        """
        finding = self.finding
        confidence = finding.confidence.value if finding.confidence is not None else None
        return [
            ("Finding", finding.finding_id),
            ("Title", finding.title),
            ("Severity", finding.severity.value),
            ("Status", finding.status.value),
            ("Risk", f"{self.risk_score:g}/100"),
            ("Asset", finding.asset_id),
            ("Source", finding.source.value),
            ("Engagement", _scalar(finding.engagement_id)),
            ("CVSS", _scalar(finding.cvss)),
            ("CVE", _sequence(self.cves)),
            ("CWE", _sequence(self.cwes)),
            ("EPSS", _scalar(finding.epss)),
            ("EPSS percentile", _scalar(finding.epss_percentile)),
            ("CISA KEV", "yes" if finding.kev else ABSENT),
            ("Confidence", _scalar(confidence)),
            ("First seen", finding.first_seen.isoformat()),
            ("Last seen", finding.last_seen.isoformat()),
            ("Tags", _sequence(finding.tags)),
            ("References", _sequence(finding.references)),
            ("Evidence", _sequence(finding.evidence)),
            ("Remediation", finding.remediation or ABSENT),
        ]

    def detail(self) -> dict[str, object]:
        """Full, JSON-serialisable projection; absent scalars stay ``None``.

        Unlike :meth:`display_items` (human cells with :data:`ABSENT`), this keeps
        machine-readable types so a UI or an export can decide its own rendering.
        """
        finding = self.finding
        confidence = finding.confidence.value if finding.confidence is not None else None
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "asset_id": finding.asset_id,
            "source": finding.source.value,
            "engagement_id": finding.engagement_id,
            "risk_score": self.risk_score,
            "cvss": finding.cvss,
            "cve": list(self.cves),
            "cwe": list(self.cwes),
            "epss": finding.epss,
            "epss_percentile": finding.epss_percentile,
            "kev": finding.kev,
            "confidence": confidence,
            "evidence": list(finding.evidence),
            "remediation": finding.remediation or None,
            "references": list(finding.references),
            "tags": list(finding.tags),
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
        }


def finding_views(findings: Sequence[Finding]) -> list[FindingView]:
    """Wrap each finding in a :class:`FindingView`, preserving input order."""
    return [FindingView(finding) for finding in findings]


def rank_by_risk(findings: Sequence[Finding]) -> list[Finding]:
    """Return the findings ordered by descending risk score (stable for ties).

    A findings view leads with what matters now, so the default ordering is by
    :meth:`Finding.risk_score`. The sort is stable, so findings sharing a score
    keep their input order (rank them further upstream if a tie-break matters).
    """
    return sorted(findings, key=lambda finding: finding.risk_score(), reverse=True)

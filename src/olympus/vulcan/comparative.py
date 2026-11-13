"""Comparative Vulcan report across an ordered assessment history (ROADMAP ``VAL-1``).

A single-run report (:mod:`olympus.vulcan.report`) answers *what does this
assessment show*. A recurring security programme needs the complementary view:
*how has the picture changed since the previous assessments* — which findings are
new regressions, which persist, which were fixed and have come back, which are
gone; and whether the reachable attack surface grew. This module is the single
place that assembles that comparative view into one human-readable, offline,
deterministic document, **reusing** the existing engines rather than deriving a
parallel one:

- the **finding lifecycle** over the whole ordered history
  (:func:`olympus.vulcan.lifecycle.classify_lifecycle`): new / persistent /
  reappeared / resolved, with "reappeared" derived from history and never a new
  canonical finding state;
- the **attack-surface diff** between a baseline and a current asset snapshot
  (:func:`olympus.vulcan.compare.diff_assets`): new / removed / persistent assets,
  with criticality and reachable-surface changes.

Both inputs are already-loaded shared contracts; the computation talks to no
network and is fully deterministic, so the same inputs always render the same
report. Target-controlled text (titles, hostnames) is escaped through the same
tested Markdown neutraliser the single-run report uses
(:func:`olympus.vulcan.report.markdown_text`), so a finding title can never forge
report structure or a clickable link.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from olympus.core.models import Asset, Finding
from olympus.vulcan.compare import AssetSurfaceDiff, PersistentAsset, diff_assets
from olympus.vulcan.lifecycle import FindingLifecycle, ReappearedFinding, classify_lifecycle
from olympus.vulcan.report import markdown_text

#: Name and version of the comparative document shape, so a consumer can pin the
#: projection it reads. The report aggregates already-contracted findings and
#: assets; it is a derived view (like ``trend`` and ``lifecycle``), not a new
#: shared data contract, so it is not published to the schema catalogue.
SCHEMA_NAME = "olympus.comparative-report"
SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class ComparativeReport:
    """The finding lifecycle and attack-surface change across a history, combined.

    ``lifecycle`` classifies the latest snapshot's findings against the whole
    ordered history. ``asset_diff`` is the optional attack-surface change between a
    baseline and a current asset snapshot, present only when both were supplied.
    ``baseline_label`` and ``latest_label`` name the oldest and newest finding
    snapshots the history spans. The object is pure data: rendering is offline and
    deterministic.
    """

    engagement: str | None
    generated_at: datetime
    baseline_label: str
    latest_label: str
    lifecycle: FindingLifecycle
    asset_diff: AssetSurfaceDiff | None

    @property
    def has_regression(self) -> bool:
        """Whether the latest state is worse: a new/reappeared finding or a grown surface."""
        finding_regression = bool(self.lifecycle.new) or self.lifecycle.has_reappearances
        surface_regression = self.asset_diff is not None and self.asset_diff.surface_expanded
        return finding_regression or surface_regression

    def summary(self) -> dict[str, object]:
        """Counts an operator reads first, plus the single regression verdict."""
        data: dict[str, object] = {
            "findings": self.lifecycle.summary(),
            "regression": self.has_regression,
        }
        if self.asset_diff is not None:
            data["attack_surface"] = self.asset_diff.summary()
        return data

    def to_dict(self) -> dict[str, object]:
        """Full, JSON-serialisable projection of the comparative report.

        Carries ``schema_name``/``schema_version`` so a consumer can pin the
        document shape, and reuses the lifecycle and asset-diff projections
        verbatim so the JSON agrees field-for-field with ``vulcan lifecycle`` and
        ``vulcan asset-diff``.
        """
        document: dict[str, object] = {
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "report_type": "comparative",
            "engagement": self.engagement,
            "generated_at": self.generated_at.isoformat(),
            "baseline_label": self.baseline_label,
            "latest_label": self.latest_label,
            "summary": self.summary(),
            "findings": self.lifecycle.to_dict(),
        }
        if self.asset_diff is not None:
            document["attack_surface"] = self.asset_diff.to_dict()
        return document

    def render_markdown(self) -> str:
        """Render the comparative report as deterministic, injection-safe Markdown."""
        return "\n".join(self._markdown_lines()) + "\n"

    # -- Markdown rendering ------------------------------------------------- #

    def _markdown_lines(self) -> list[str]:
        lines: list[str] = [
            "# Comparative security report",
            "",
            f"- Engagement: {markdown_text(self.engagement) if self.engagement else '_n/a_'}",
            f"- Generated at: {self.generated_at.isoformat()}",
            f"- History span: {markdown_text(self.baseline_label)} "
            f"→ {markdown_text(self.latest_label)}",
            f"- Regression since previous assessment: {'**yes**' if self.has_regression else 'no'}",
            "",
        ]
        lines += self._findings_section()
        if self.asset_diff is not None:
            lines += self._attack_surface_section(self.asset_diff)
        return lines

    def _findings_section(self) -> list[str]:
        summary = self.lifecycle.summary()
        lines: list[str] = [
            "## Findings lifecycle",
            "",
            "Latest snapshot classified against the whole assessment history.",
            "",
            f"- New: {summary['new']}",
            f"- Reappeared: {summary['reappeared']}",
            f"- Persistent: {summary['persistent']}",
            f"- Resolved: {summary['resolved']}",
            f"- Worsened: {summary['worsened']}",
            "",
        ]
        lines += _finding_list("New (never seen before)", self.lifecycle.new)
        lines += _reappeared_list(self.lifecycle.reappeared)
        lines += _finding_list(
            "Persistent (still open)",
            tuple(item.current for item in self.lifecycle.persistent),
            worsened={
                item.current.finding_id
                for item in self.lifecycle.persistent
                if item.severity_worsened
            },
        )
        lines += _finding_list("Resolved (gone since the previous run)", self.lifecycle.resolved)
        return lines

    def _attack_surface_section(self, diff: AssetSurfaceDiff) -> list[str]:
        summary = diff.summary()
        lines: list[str] = [
            "## Attack surface",
            "",
            "Change in reachable assets between the baseline and current snapshot.",
            "",
            f"- New: {summary['new']}",
            f"- Removed: {summary['removed']}",
            f"- Persistent: {summary['persistent']}",
            f"- Surface-changed: {summary['surface_changed']}",
            "",
        ]
        lines += _asset_list("New assets (surface grew)", diff.new)
        lines += _asset_list("Removed assets", diff.removed)
        lines += _persistent_asset_list(diff.persistent)
        return lines


def _finding_line(finding: Finding, *, suffix: str = "") -> str:
    severity = finding.severity.value.upper()
    base = (
        f"- [{severity}] {markdown_text(finding.title)} "
        f"— {markdown_text(finding.asset_id)} (risk {finding.risk_score():.0f})"
    )
    return f"{base}{suffix}" if suffix else base


def _finding_list(
    title: str,
    findings: Sequence[Finding],
    *,
    worsened: set[str] | None = None,
) -> list[str]:
    lines = [f"### {title}", ""]
    if not findings:
        return [*lines, "_None._", ""]
    marked = worsened or set()
    for finding in findings:
        suffix = " **(worsened)**" if finding.finding_id in marked else ""
        lines.append(_finding_line(finding, suffix=suffix))
    lines.append("")
    return lines


def _reappeared_list(items: Sequence[ReappearedFinding]) -> list[str]:
    lines = ["### Reappeared (fixed earlier, open again)", ""]
    if not items:
        return [*lines, "_None._", ""]
    for item in items:
        detail = f" — absent for {item.absent_for} run(s)"
        if item.severity_worsened:
            detail += ", **worsened**"
        lines.append(_finding_line(item.current, suffix=detail))
    lines.append("")
    return lines


def _asset_line(asset: Asset, *, suffix: str = "") -> str:
    hostname = markdown_text(asset.hostname) if asset.hostname else "—"
    ips = markdown_text(", ".join(sorted(asset.ip_addresses))) if asset.ip_addresses else "—"
    base = (
        f"- {markdown_text(asset.asset_id)} "
        f"({markdown_text(asset.asset_type.value)}, {markdown_text(asset.criticality.value)}) "
        f"— host {hostname}, ips {ips}"
    )
    return f"{base}{suffix}" if suffix else base


def _asset_list(title: str, assets: Sequence[Asset]) -> list[str]:
    lines = [f"### {title}", ""]
    if not assets:
        return [*lines, "_None._", ""]
    for asset in assets:
        lines.append(_asset_line(asset))
    lines.append("")
    return lines


def _persistent_asset_list(items: Sequence[PersistentAsset]) -> list[str]:
    lines = ["### Persistent assets", ""]
    if not items:
        return [*lines, "_None._", ""]
    for item in items:
        changes = ", ".join(
            name
            for name, active in (
                ("criticality", item.criticality_changed),
                ("surface", item.attack_surface_changed),
            )
            if active
        )
        suffix = f" — changed: {changes}" if changes else ""
        lines.append(_asset_line(item.current, suffix=suffix))
    lines.append("")
    return lines


def build_comparative_report(
    *,
    snapshots: Sequence[tuple[str, Sequence[Finding]]],
    asset_baseline: Sequence[Asset] | None = None,
    asset_current: Sequence[Asset] | None = None,
    engagement: str | None = None,
    generated_at: datetime | None = None,
) -> ComparativeReport:
    """Assemble a comparative report from an ordered finding history and optional assets.

    ``snapshots`` are ``(label, findings)`` pairs **oldest first**; at least two
    are required for a comparison to be meaningful. The finding lifecycle reuses
    :func:`~olympus.vulcan.lifecycle.classify_lifecycle` over the whole history.

    ``asset_baseline`` and ``asset_current`` are the two asset snapshots for the
    attack-surface diff; pass **both or neither** — passing only one is a usage
    error, since diffing a snapshot against nothing would misreport every asset as
    new or removed. When both are given the diff reuses
    :func:`~olympus.vulcan.compare.diff_assets`.

    The result is pure data; it performs no I/O and is deterministic for a fixed
    ``generated_at`` (defaulting to the current UTC time when omitted).
    """
    if len(snapshots) < 2:
        raise ValueError("a comparative report needs at least two finding snapshots")
    if (asset_baseline is None) != (asset_current is None):
        raise ValueError(
            "the attack-surface diff needs both a baseline and a current asset snapshot"
        )

    lifecycle = classify_lifecycle(snapshots)
    asset_diff: AssetSurfaceDiff | None = None
    if asset_baseline is not None and asset_current is not None:
        asset_diff = diff_assets(asset_baseline, asset_current)

    return ComparativeReport(
        engagement=engagement,
        generated_at=generated_at or datetime.now(UTC),
        baseline_label=snapshots[0][0],
        latest_label=snapshots[-1][0],
        lifecycle=lifecycle,
        asset_diff=asset_diff,
    )

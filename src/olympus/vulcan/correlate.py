"""Correlation over the shared Olympus contracts (ROADMAP ``CORR-1``, first slice).

A single finding is one tool's view; a security picture emerges from the
*relationships* between findings — the same asset reported by several tools, the
same vulnerability spread across assets. This module is the single, tested place
that derives those relationships from the shared :class:`~olympus.core.models.Finding`
contract, as a **versioned data contract** (not a rendering function).

Every correlation is, per ``CORR-1``:

- **traceable** — it names the ``members`` (finding ids) and ``sources`` it was
  built from;
- **motivated** — it carries a plain-language ``reason``;
- **graded** — it carries a ``confidence`` and an
  :class:`~olympus.core.enums.EpistemicClass` (the same taxonomy as ``EXPL-1``).

The correlations here are **deterministic joins on identity** (a shared asset id,
a shared CVE id, a shared Minerva evidence artifact), so they are
``deterministic_result`` facts, never a hypothesis and **never a claim of
compromise** — a correlation is a relationship, not proof that an attacker used
it. Weaker, inferred relationships (suggested exposure paths) will carry
``suggested_correlation``/``unverified_hypothesis`` when later slices add them.
The computation is pure and offline: it reads already-loaded findings and talks
to no network, so it is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from olympus.core.enums import Confidence, EpistemicClass
from olympus.core.models import Finding
from olympus.vulcan.aggregate import merge_duplicate_findings

#: Versioned identity of one correlation record.
SCHEMA_NAME = "olympus.correlation"
SCHEMA_VERSION = "1.0.0"
#: Versioned identity of a *set* of correlations (the CLI/report document).
CORRELATIONS_SCHEMA_NAME = "olympus.correlations"
CORRELATIONS_SCHEMA_VERSION = "1.0.0"

#: The relationship kinds this first slice derives. All are deterministic joins.
CorrelationKind = Literal["asset-overlap", "shared-cve", "shared-evidence"]


@dataclass(frozen=True)
class Correlation:
    """One relationship between findings, with provenance and epistemic class."""

    kind: CorrelationKind
    key: str
    members: tuple[str, ...]
    sources: tuple[str, ...]
    reason: str
    confidence: Confidence
    epistemic_class: EpistemicClass

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable projection of this correlation (the published shape)."""
        return {
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "kind": self.kind,
            "key": self.key,
            "members": list(self.members),
            "sources": list(self.sources),
            "reason": self.reason,
            "confidence": self.confidence.value,
            "epistemic_class": self.epistemic_class.value,
        }


class CorrelationModel(BaseModel):
    """The versioned, published shape of one correlation (``CORR-1``)."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.correlation"] = "olympus.correlation"
    schema_version: Literal["1.0.0"] = "1.0.0"
    kind: CorrelationKind
    key: str
    members: list[str]
    sources: list[str]
    reason: str
    confidence: Confidence
    epistemic_class: EpistemicClass


class CorrelationsDocument(BaseModel):
    """The versioned, published shape of a set of correlations (``CORR-1``)."""

    model_config = ConfigDict(extra="forbid")

    schema_name: Literal["olympus.correlations"] = "olympus.correlations"
    schema_version: Literal["1.0.0"] = "1.0.0"
    count: int
    correlations: list[CorrelationModel]  # each carries its own olympus.correlation header


def _sort_key(correlation: Correlation) -> tuple[str, str]:
    return (correlation.kind, correlation.key)


def correlate_findings(findings: Sequence[Finding]) -> tuple[Correlation, ...]:
    """Derive deterministic correlations from a set of findings.

    Three relationship kinds are produced, each a pure join on logical identity:

    * **asset-overlap** — one asset carries findings from **two or more distinct
      tool sources** (e.g. the same host reported by Argus and Themis); evidence
      that several tools converge on the same asset.
    * **shared-cve** — one CVE appears on findings against **two or more distinct
      assets**; the same vulnerability spread across the estate.
    * **shared-evidence** — one Minerva evidence artifact (a reference carried in
      ``Finding.evidence``, pointing at an ``olympus.evidence`` custody id or
      digest) is cited by **two or more distinct findings**; the findings are
      corroborated by a common artifact.

    Each correlation is a ``deterministic_result`` with ``high`` confidence — it is
    a provable join, not a hypothesis and not a claim of compromise. Findings are
    folded by logical identity first (so one issue seen twice counts once), and the
    result is ordered deterministically by ``(kind, key)``.
    """
    folded = merge_duplicate_findings(list(findings))

    sources_by_asset: dict[str, dict[str, None]] = {}
    members_by_asset: dict[str, dict[str, None]] = {}
    assets_by_cve: dict[str, dict[str, None]] = {}
    members_by_cve: dict[str, dict[str, None]] = {}
    members_by_evidence: dict[str, dict[str, None]] = {}
    sources_by_evidence: dict[str, dict[str, None]] = {}

    for finding in folded:
        asset = finding.asset_id
        sources_by_asset.setdefault(asset, {})[finding.source.value] = None
        members_by_asset.setdefault(asset, {})[finding.finding_id] = None
        for cve in finding.cves():
            assets_by_cve.setdefault(cve, {})[asset] = None
            members_by_cve.setdefault(cve, {})[finding.finding_id] = None
        for reference in finding.evidence:
            evidence_ref = reference.strip()
            if not evidence_ref:
                continue  # a blank citation links nothing
            members_by_evidence.setdefault(evidence_ref, {})[finding.finding_id] = None
            sources_by_evidence.setdefault(evidence_ref, {})[finding.source.value] = None

    correlations: list[Correlation] = []

    for asset, sources in sources_by_asset.items():
        if len(sources) < 2:
            continue
        source_list = tuple(sorted(sources))
        correlations.append(
            Correlation(
                kind="asset-overlap",
                key=asset,
                members=tuple(sorted(members_by_asset[asset])),
                sources=source_list,
                reason=(
                    f"Asset {asset} is reported by {len(source_list)} distinct tool "
                    f"sources ({', '.join(source_list)})."
                ),
                confidence=Confidence.HIGH,
                epistemic_class=EpistemicClass.DETERMINISTIC_RESULT,
            )
        )

    for cve, assets in assets_by_cve.items():
        if len(assets) < 2:
            continue
        asset_list = tuple(sorted(assets))
        correlations.append(
            Correlation(
                kind="shared-cve",
                key=cve,
                members=tuple(sorted(members_by_cve[cve])),
                sources=asset_list,
                reason=(
                    f"{cve} affects {len(asset_list)} distinct assets ({', '.join(asset_list)})."
                ),
                confidence=Confidence.HIGH,
                epistemic_class=EpistemicClass.DETERMINISTIC_RESULT,
            )
        )

    for evidence_ref, members in members_by_evidence.items():
        if len(members) < 2:
            continue
        member_list = tuple(sorted(members))
        source_list = tuple(sorted(sources_by_evidence[evidence_ref]))
        correlations.append(
            Correlation(
                kind="shared-evidence",
                key=evidence_ref,
                members=member_list,
                sources=source_list,
                reason=(
                    f"Evidence {evidence_ref} corroborates {len(member_list)} distinct "
                    f"findings from {len(source_list)} source(s) ({', '.join(source_list)})."
                ),
                confidence=Confidence.HIGH,
                epistemic_class=EpistemicClass.DETERMINISTIC_RESULT,
            )
        )

    return tuple(sorted(correlations, key=_sort_key))


def correlations_document(findings: Sequence[Finding]) -> dict[str, object]:
    """Build the versioned ``olympus.correlations`` document for a finding set."""
    correlations = correlate_findings(findings)
    return {
        "schema_name": CORRELATIONS_SCHEMA_NAME,
        "schema_version": CORRELATIONS_SCHEMA_VERSION,
        "count": len(correlations),
        "correlations": [correlation.to_dict() for correlation in correlations],
    }


__all__ = [
    "CORRELATIONS_SCHEMA_NAME",
    "CORRELATIONS_SCHEMA_VERSION",
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "Correlation",
    "CorrelationKind",
    "CorrelationModel",
    "CorrelationsDocument",
    "correlate_findings",
    "correlations_document",
]

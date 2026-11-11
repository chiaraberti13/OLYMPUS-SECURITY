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

Most correlations here are **deterministic joins on identity** (a shared asset id,
a shared CVE id, a shared Minerva evidence artifact), so they are
``deterministic_result`` facts, never a hypothesis and **never a claim of
compromise** — a correlation is a relationship, not proof that an attacker used
it. One kind is deliberately weaker: an **IOC↔event** match (a Metis indicator
value observed in an Apollo event) is a CTI *lead*, not proof the event is the
entity the intel meant, so it carries ``suggested_correlation`` — honouring the
rule that a hypothesis is never presented as a fact. ``unverified_hypothesis``
remains reserved for still weaker, inferred relationships added by later slices.
The computation is pure and offline: it reads already-loaded findings, indicators
and events and talks to no network, so it is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from olympus.core.enums import Confidence, EpistemicClass
from olympus.core.models import Event, Finding
from olympus.metis.models import Indicator
from olympus.vulcan.aggregate import merge_duplicate_findings

#: Versioned identity of one correlation record.
SCHEMA_NAME = "olympus.correlation"
SCHEMA_VERSION = "1.0.0"
#: Versioned identity of a *set* of correlations (the CLI/report document).
CORRELATIONS_SCHEMA_NAME = "olympus.correlations"
CORRELATIONS_SCHEMA_VERSION = "1.0.0"

#: The relationship kinds this slice derives. The first three are deterministic
#: joins on identity; ``ioc-event`` is a weaker, ``suggested_correlation`` lead.
CorrelationKind = Literal["asset-overlap", "shared-cve", "shared-evidence", "ioc-event"]


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


def _normalize_observable(value: object) -> str:
    """Normalise an indicator value or event observable for exact matching.

    A single, symmetric rule applied to both sides: strip surrounding whitespace
    and lower-case. This makes the match case-insensitive for domains, URLs,
    e-mail addresses, hashes and CVE ids (where case is not significant) without
    affecting IPv4/IPv6 literals. Matching is exact, never substring, so a value
    only correlates when an event genuinely observed that same value.
    """
    return str(value).strip().lower()


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


def correlate_indicators_with_events(
    indicators: Sequence[Indicator],
    events: Sequence[Event],
) -> tuple[Correlation, ...]:
    """Correlate Metis threat-intel indicators with Apollo events (``ioc-event``).

    A cross-module relationship: a Metis :class:`~olympus.metis.models.Indicator`
    value that is **observed** in an Apollo :class:`~olympus.core.models.Event`
    (in any attribute value or the event's ``asset_id``) links the intel to the
    telemetry. This is a CTI *lead*, not proof — an indicator value matching an
    observable does not establish that the event is the entity the intel meant
    (addresses and domains are reused, shared, and reassigned), so every match is
    graded ``suggested_correlation`` with ``medium`` confidence and **never**
    asserts compromise. Matching is exact on a normalised value (see
    :func:`_normalize_observable`), so the computation is pure and deterministic.

    Indicators sharing the same ``indicator_type``/value are folded into one
    correlation; the output is ordered deterministically by ``(kind, key)``.
    """
    # Inverted index: normalised observable -> ordered event ids / sources.
    events_by_observable: dict[str, dict[str, None]] = {}
    sources_by_observable: dict[str, dict[str, None]] = {}
    for event in events:
        observables: dict[str, None] = {}
        for raw in (event.asset_id, *event.attributes.values()):
            normalized = _normalize_observable(raw)
            if normalized:
                observables[normalized] = None
        for normalized in observables:
            events_by_observable.setdefault(normalized, {})[event.event_id] = None
            sources_by_observable.setdefault(normalized, {})[event.source.value] = None

    # Fold indicators that share a logical identity (type + normalised value).
    folded: dict[tuple[str, str], dict[str, object]] = {}
    for indicator in indicators:
        normalized = _normalize_observable(indicator.value)
        if not normalized:
            continue
        identity = (indicator.indicator_type.value, normalized)
        entry = folded.setdefault(
            identity,
            {"value": indicator.value, "cti_sources": {}},
        )
        cti_sources = entry["cti_sources"]
        assert isinstance(cti_sources, dict)  # noqa: S101 - local accumulator shape
        cti_sources[indicator.source] = None

    correlations: list[Correlation] = []
    for (indicator_type, normalized), entry in folded.items():
        matched_events = events_by_observable.get(normalized)
        if not matched_events:
            continue
        member_list = tuple(sorted(matched_events))
        source_list = tuple(sorted(sources_by_observable[normalized]))
        cti_sources = entry["cti_sources"]
        assert isinstance(cti_sources, dict)  # noqa: S101 - local accumulator shape
        cti_source_list = ", ".join(sorted(cti_sources))
        value = entry["value"]
        correlations.append(
            Correlation(
                kind="ioc-event",
                key=f"{indicator_type}:{value}",
                members=member_list,
                sources=source_list,
                reason=(
                    f"Indicator {value} ({indicator_type}) from CTI source(s) "
                    f"[{cti_source_list}] was observed in {len(member_list)} Apollo "
                    f"event(s) from source(s) ({', '.join(source_list)}); a lead to "
                    f"verify, not a proven compromise."
                ),
                confidence=Confidence.MEDIUM,
                epistemic_class=EpistemicClass.SUGGESTED_CORRELATION,
            )
        )

    return tuple(sorted(correlations, key=_sort_key))


def correlations_document(
    findings: Sequence[Finding],
    *,
    indicators: Sequence[Indicator] = (),
    events: Sequence[Event] = (),
) -> dict[str, object]:
    """Build the versioned ``olympus.correlations`` document.

    Correlates the finding set (``asset-overlap`` / ``shared-cve`` /
    ``shared-evidence``) and, when both ``indicators`` and ``events`` are given,
    the cross-module ``ioc-event`` leads. All kinds share one deterministically
    ordered document.
    """
    correlations = sorted(
        (
            *correlate_findings(findings),
            *correlate_indicators_with_events(indicators, events),
        ),
        key=_sort_key,
    )
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
    "correlate_indicators_with_events",
    "correlations_document",
]

"""Map offensive findings to MITRE ATT&CK techniques (ROADMAP ``OPS-RED``).

Apollo already carries ATT&CK technique ids on *detections* and alerts (the Blue
side). This module adds the Red side the roadmap asks for: associating a
**technique, tactic, confidence and rationale** to a Vulcan :class:`Finding`,
keeping the association's provenance explicit — **automatic** (derived here from a
versioned, reviewed CWE→ATT&CK table) versus **reviewed** (confirmed or added by a
human analyst).

Like :mod:`olympus.vulcan.enrichment`, this is a pure, offline **overlay**: it
never mutates the shared :class:`~olympus.core.models.Finding` contract and never
contacts the network. The derivation is deterministic, so the same findings and
reviews always produce the same associations (diffable, reproducible). The
technique counts it produces feed the existing ATT&CK Navigator layer builder in
:mod:`olympus.apollo.attack`, so offensive findings and defensive detections
colour the *same* matrix rather than two divergent ones.

The mapping is a starting, deliberately conservative set keyed by CWE; it is
versioned (:data:`ATTACK_MAP_VERSION`) so growing or correcting it is a reviewed,
traceable change, exactly as a published contract would be. An unmapped CWE
produces no invented association (honest absence), never a guessed technique.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from olympus.core.enums import Confidence
from olympus.core.models import Finding

#: Version of the CWE→ATT&CK mapping table. Bump on any reviewed change so a
#: downstream consumer can tell which mapping produced an association.
ATTACK_MAP_VERSION = "1.0.0"

#: A MITRE ATT&CK (sub-)technique id, e.g. ``T1190`` or ``T1059.001``.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

#: A CWE identifier in its canonical ``CWE-<n>`` form.
_CWE_RE = re.compile(r"^CWE-\d+$")


class AttackSource(StrEnum):
    """Where an ATT&CK association came from.

    The distinction is the point of the feature: an operator must be able to tell
    a machine-derived guess from an association a human analyst confirmed.
    """

    AUTOMATIC = "automatic"
    REVIEWED = "reviewed"


@dataclass(frozen=True)
class AttackTechnique:
    """One reviewed CWE→ATT&CK mapping entry."""

    technique: str
    name: str
    tactic: str
    confidence: Confidence


#: Reviewed CWE → ATT&CK technique mapping. Conservative on purpose: each entry
#: is a defensible, well-understood correspondence between a weakness class and
#: the technique an attacker uses to exploit it. Confidence reflects how direct
#: that correspondence is, not how severe the finding is.
_CWE_ATTACK_MAP: dict[str, tuple[AttackTechnique, ...]] = {
    # Injection into a public-facing application.
    "CWE-89": (  # SQL injection
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.HIGH
        ),
    ),
    "CWE-78": (  # OS command injection
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.HIGH
        ),
        AttackTechnique("T1059", "Command and Scripting Interpreter", "execution", Confidence.HIGH),
    ),
    "CWE-94": (  # code injection
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.MEDIUM
        ),
        AttackTechnique("T1059", "Command and Scripting Interpreter", "execution", Confidence.HIGH),
    ),
    "CWE-502": (  # deserialization of untrusted data
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.MEDIUM
        ),
    ),
    "CWE-79": (  # cross-site scripting
        AttackTechnique("T1059.007", "JavaScript", "execution", Confidence.MEDIUM),
    ),
    # Server-side request forgery / proxying.
    "CWE-918": (  # SSRF
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.MEDIUM
        ),
    ),
    # Path traversal / file disclosure.
    "CWE-22": (  # path traversal
        AttackTechnique("T1083", "File and Directory Discovery", "discovery", Confidence.MEDIUM),
    ),
    # Authentication / access control.
    "CWE-287": (  # improper authentication
        AttackTechnique("T1078", "Valid Accounts", "initial-access", Confidence.MEDIUM),
    ),
    "CWE-306": (  # missing authentication for critical function
        AttackTechnique(
            "T1190", "Exploit Public-Facing Application", "initial-access", Confidence.MEDIUM
        ),
    ),
    "CWE-798": (  # hard-coded credentials
        AttackTechnique("T1078", "Valid Accounts", "initial-access", Confidence.HIGH),
    ),
    # Information exposure → reconnaissance.
    "CWE-200": (  # exposure of sensitive information
        AttackTechnique(
            "T1592", "Gather Victim Host Information", "reconnaissance", Confidence.LOW
        ),
    ),
}


class AttackMappingError(ValueError):
    """Raised when a human-review association is malformed."""


@dataclass(frozen=True)
class AttackAssociation:
    """One ATT&CK association attached to a finding, with explicit provenance."""

    technique: str
    name: str
    tactic: str
    confidence: Confidence
    rationale: str
    source: AttackSource

    def to_dict(self) -> dict[str, str]:
        return {
            "technique": self.technique,
            "name": self.name,
            "tactic": self.tactic,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "source": self.source.value,
        }


@dataclass(frozen=True)
class FindingAttack:
    """The ATT&CK overlay for one finding: its ordered, deduplicated associations."""

    finding_id: str
    associations: tuple[AttackAssociation, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "map_version": ATTACK_MAP_VERSION,
            "associations": [item.to_dict() for item in self.associations],
        }


@dataclass(frozen=True)
class ReviewedAssociation:
    """A human analyst's ATT&CK association for a finding (overrides automatic)."""

    technique: str
    name: str
    tactic: str
    confidence: Confidence
    rationale: str


def _normalize_cwe(value: str) -> str | None:
    """Return the canonical ``CWE-<n>`` form, or ``None`` if not a CWE id."""
    candidate = value.strip().upper()
    if candidate.isdigit():
        candidate = f"CWE-{candidate}"
    return candidate if _CWE_RE.match(candidate) else None


def _sort_key(item: AttackAssociation) -> tuple[int, str, str]:
    # Reviewed associations first (they are the authoritative ones), then by id.
    return (0 if item.source is AttackSource.REVIEWED else 1, item.technique, item.tactic)


def associate_attack(
    finding: Finding,
    *,
    reviews: Sequence[ReviewedAssociation] | None = None,
) -> FindingAttack:
    """Return the ATT&CK overlay for ``finding``.

    Automatic associations are derived from the finding's CWEs via the reviewed
    mapping table. ``reviews`` are a human analyst's associations for *this*
    finding; each is tagged :data:`AttackSource.REVIEWED` and takes precedence —
    when a reviewed association names the same technique+tactic as an automatic
    one, only the reviewed entry is kept, so a human decision is never shadowed by
    or duplicated against the machine guess.
    """
    reviewed: dict[tuple[str, str], AttackAssociation] = {}
    for review in reviews or ():
        if not _TECHNIQUE_RE.match(review.technique):
            raise AttackMappingError(f"invalid ATT&CK technique id {review.technique!r}")
        if not review.tactic.strip() or not review.rationale.strip():
            raise AttackMappingError("a reviewed association needs a tactic and a rationale")
        reviewed[(review.technique, review.tactic)] = AttackAssociation(
            technique=review.technique,
            name=review.name,
            tactic=review.tactic,
            confidence=review.confidence,
            rationale=review.rationale,
            source=AttackSource.REVIEWED,
        )

    automatic: dict[tuple[str, str], AttackAssociation] = {}
    for raw_cwe in finding.cwes():
        cwe = _normalize_cwe(raw_cwe)
        if cwe is None:
            continue
        for entry in _CWE_ATTACK_MAP.get(cwe, ()):
            key = (entry.technique, entry.tactic)
            if key in reviewed or key in automatic:
                continue  # reviewed wins; the first CWE to map a technique wins
            automatic[key] = AttackAssociation(
                technique=entry.technique,
                name=entry.name,
                tactic=entry.tactic,
                confidence=entry.confidence,
                rationale=f"derived from {cwe} (map {ATTACK_MAP_VERSION})",
                source=AttackSource.AUTOMATIC,
            )

    merged = sorted([*reviewed.values(), *automatic.values()], key=_sort_key)
    return FindingAttack(finding_id=finding.finding_id, associations=tuple(merged))


def associate_all(
    findings: Iterable[Finding],
    *,
    reviews: Mapping[str, Sequence[ReviewedAssociation]] | None = None,
) -> list[FindingAttack]:
    """Return the ATT&CK overlay for every finding, ordered by finding id.

    ``reviews`` maps a ``finding_id`` to that finding's human-reviewed
    associations. Deterministic and offline.
    """
    review_map = reviews or {}
    overlays = [
        associate_attack(finding, reviews=review_map.get(finding.finding_id))
        for finding in findings
    ]
    return sorted(overlays, key=lambda overlay: overlay.finding_id)


def technique_counts(overlays: Iterable[FindingAttack]) -> Counter[str]:
    """Count ATT&CK technique ids across finding overlays (for a Navigator layer).

    Mirrors :func:`olympus.apollo.attack.techniques_from_alerts` so offensive
    findings can be rendered on the same ATT&CK Navigator as detections.
    """
    counter: Counter[str] = Counter()
    for overlay in overlays:
        counter.update(
            association.technique
            for association in overlay.associations
            if _TECHNIQUE_RE.match(association.technique)
        )
    return counter


__all__ = [
    "ATTACK_MAP_VERSION",
    "AttackAssociation",
    "AttackMappingError",
    "AttackSource",
    "AttackTechnique",
    "FindingAttack",
    "ReviewedAssociation",
    "associate_all",
    "associate_attack",
    "technique_counts",
]

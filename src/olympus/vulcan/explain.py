"""Unified finding explainability contract (ROADMAP ``EXPL-1``).

Every surface — CLI, API, Web and the Vulcan reports — must answer the same
question the same way: *why is this a finding, why this severity, and how sure
are we?* This module is the single, tested place that derives that answer, as a
**shared, versioned data contract** (not a rendering function): a
:class:`FindingExplanation` built by :func:`explain_finding`. `EXPL-2` then wires
every surface to this one core so they agree by construction (a parity test),
with no explanation logic duplicated in a frontend.

The explanation is **derived purely from the finding's own fields** — it performs
no scanning, opens no network, and invents nothing. Every claim carries an
:class:`~olympus.core.enums.EpistemicClass` saying *how it is known*, so a weaker
claim is never presented as a stronger one: an identifier parsed from free text is
an ``inference``, not ``observed_evidence``; the risk score is a
``deterministic_result`` computed from the finding's fields, never an observation.
The risk rationale is reproduced from the same constants the score itself uses
(:data:`~olympus.core.models.SEVERITY_RISK_BASE`,
:data:`~olympus.core.models.KEV_RISK_FLOOR`,
:data:`~olympus.core.models.CONFIDENCE_RISK_MODIFIER`) so the score and its
explanation can never diverge, and the explanation states its own **limits**
explicitly. It is pure and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from olympus.core.enums import Confidence, EpistemicClass
from olympus.core.models import (
    CONFIDENCE_RISK_MODIFIER,
    KEV_RISK_FLOOR,
    SEVERITY_RISK_BASE,
    Finding,
)
from olympus.vulcan.view import FindingView

#: Versioned contract identity, so a consumer can pin and evolve the shape.
SCHEMA_NAME = "olympus.finding-explanation"
SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class Statement:
    """One claim in an explanation, tagged with how it is known.

    The ``epistemic_class`` is the guard against presenting a weaker claim as a
    stronger one — the single rule both `EXPL-1` and `CORR-1` enforce.
    """

    text: str
    epistemic_class: EpistemicClass

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable projection of this claim."""
        return {"text": self.text, "epistemic_class": self.epistemic_class.value}


@dataclass(frozen=True)
class RiskFactor:
    """One contribution to the contextual risk score, in plain language.

    ``decisive`` marks the factor that set the score's floor (CVSS/severity base,
    a KEV escalation or an EPSS floor); the confidence modifier is never decisive,
    it only nudges.
    """

    factor: str
    detail: str
    decisive: bool = False

    def to_dict(self) -> dict[str, object]:
        """A JSON-serialisable projection of this factor."""
        return {"factor": self.factor, "detail": self.detail, "decisive": self.decisive}


@dataclass(frozen=True)
class FindingExplanation:
    """A shared, surface-agnostic, versioned explanation of one finding.

    ``statements`` carries every claim with its :class:`EpistemicClass`; ``limits``
    states caveats a reader must keep in mind. Nothing here is fetched or invented
    — it is a projection of the finding alone.
    """

    finding_id: str
    title: str
    asset_id: str
    source: str
    severity: str
    status: str
    risk_score: float
    summary: str
    risk_factors: tuple[RiskFactor, ...]
    statements: tuple[Statement, ...]
    limits: tuple[str, ...]
    cve: tuple[str, ...] = field(default_factory=tuple)
    cwe: tuple[str, ...] = field(default_factory=tuple)
    remediation: str | None = None

    def statements_of(self, *classes: EpistemicClass) -> tuple[Statement, ...]:
        """Return the statements whose epistemic class is one of ``classes``."""
        wanted = set(classes)
        return tuple(s for s in self.statements if s.epistemic_class in wanted)

    @property
    def observed(self) -> tuple[Statement, ...]:
        """Only the directly-observed evidence (the strongest class)."""
        return self.statements_of(EpistemicClass.OBSERVED_EVIDENCE)

    @property
    def derived(self) -> tuple[Statement, ...]:
        """Everything Olympus derived rather than observed."""
        return self.statements_of(
            EpistemicClass.DETERMINISTIC_RESULT,
            EpistemicClass.INFERENCE,
            EpistemicClass.SUGGESTED_CORRELATION,
            EpistemicClass.UNVERIFIED_HYPOTHESIS,
        )

    def summary_line(self) -> str:
        """One compact line an operator reads first."""
        return f"[{self.severity}] {self.title} — risk {self.risk_score:g}/100: {self.summary}"

    def to_dict(self) -> dict[str, object]:
        """Full, JSON-serialisable projection; the contract every surface renders."""
        return {
            "schema_name": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "finding_id": self.finding_id,
            "title": self.title,
            "asset_id": self.asset_id,
            "source": self.source,
            "severity": self.severity,
            "status": self.status,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "risk_factors": [item.to_dict() for item in self.risk_factors],
            "statements": [item.to_dict() for item in self.statements],
            "limits": list(self.limits),
            "cve": list(self.cve),
            "cwe": list(self.cwe),
            "remediation": self.remediation,
        }


def _risk_factors(finding: Finding) -> tuple[RiskFactor, ...]:
    """Reproduce, from the shared constants, why the finding scored as it did.

    ``decisive`` marks the single factor that set the pre-confidence score — the
    base, or a KEV/EPSS floor only when it actually rose above the base — so the
    explanation never claims an escalation that did not change the number.
    """
    if finding.cvss is not None:
        base_value = finding.cvss * 10.0
        base = RiskFactor(
            "cvss-base", f"CVSS {finding.cvss:g} sets the base at {base_value:g}/100."
        )
    else:
        base_value = SEVERITY_RISK_BASE[finding.severity]
        base = RiskFactor(
            "severity-base",
            f"No CVSS recorded; the {finding.severity.value} severity band "
            f"sets the base at {base_value:g}/100.",
        )

    escalation: RiskFactor | None = None
    escalation_value = base_value
    if finding.kev:
        escalation_value = max(base_value, KEV_RISK_FLOOR)
        note = (
            "raises"
            if base_value < KEV_RISK_FLOOR
            else "already below the base, so it does not raise"
        )
        escalation = RiskFactor(
            "kev",
            "Listed in the CISA KEV catalogue (confirmed in-the-wild exploitation); "
            f"its {KEV_RISK_FLOOR:g}/100 floor {note} the score.",
        )
    elif finding.epss is not None:
        epss_floor = finding.epss * 100.0
        escalation_value = max(base_value, epss_floor)
        percentile = (
            f" (≈{finding.epss_percentile * 100:g}th percentile)"
            if finding.epss_percentile is not None
            else ""
        )
        note = "lifts" if epss_floor > base_value else "stays below the base, so it does not lift"
        escalation = RiskFactor(
            "epss",
            f"EPSS predicts a {finding.epss * 100:g}% chance of exploitation{percentile}; "
            f"its {epss_floor:g}/100 floor {note} the score.",
        )

    # The decisive factor is the one equal to the pre-confidence maximum.
    decisive_is_escalation = escalation is not None and escalation_value > base_value
    base = RiskFactor(base.factor, base.detail, decisive=not decisive_is_escalation)
    factors: list[RiskFactor] = [base]
    if escalation is not None:
        factors.append(
            RiskFactor(escalation.factor, escalation.detail, decisive=decisive_is_escalation)
        )

    if finding.confidence in CONFIDENCE_RISK_MODIFIER:
        modifier = CONFIDENCE_RISK_MODIFIER[finding.confidence]
        factors.append(
            RiskFactor(
                "confidence",
                f"{finding.confidence.value.capitalize()} confidence adjusts the "
                f"score by {modifier:+g} (a nudge, never decisive).",
            )
        )
    return tuple(factors)


def _summary(finding: Finding, cwes: tuple[str, ...]) -> str:
    """A one-sentence, invention-free précis of what the finding is."""
    what = finding.title
    if cwes:
        what += f" ({', '.join(cwes)})"
    if finding.kev:
        return f"{what}, a vulnerability under confirmed active exploitation."
    if finding.epss is not None and finding.epss >= 0.5:
        return f"{what}, with a high predicted likelihood of exploitation."
    return f"{what}."


def _statements(
    finding: Finding, cves: tuple[str, ...], cwes: tuple[str, ...]
) -> tuple[Statement, ...]:
    """Build the classified claims, each tagged with how it is known.

    Observed facts (attached evidence, KEV, CVSS, EPSS, structured identifiers) are
    ``observed_evidence``; an identifier parsed from free text is only an
    ``inference``; the risk score is a ``deterministic_result`` of the fields.
    """
    items: list[Statement] = []
    if finding.evidence:
        items.append(
            Statement(
                f"{len(finding.evidence)} evidence reference(s) attached to the finding.",
                EpistemicClass.OBSERVED_EVIDENCE,
            )
        )
    if finding.kev:
        items.append(
            Statement(
                "CISA KEV: confirmed in-the-wild exploitation.",
                EpistemicClass.OBSERVED_EVIDENCE,
            )
        )
    if finding.cvss is not None:
        items.append(
            Statement(
                f"Vendor/scanner CVSS score of {finding.cvss:g}.",
                EpistemicClass.OBSERVED_EVIDENCE,
            )
        )
    if finding.epss is not None:
        items.append(
            Statement(
                f"EPSS exploitation probability: {finding.epss * 100:g}%.",
                EpistemicClass.OBSERVED_EVIDENCE,
            )
        )
    if cves:
        # A structured field is observed; a text-derived id is only an inference.
        structured = bool(finding.cve)
        items.append(
            Statement(
                f"Linked CVE(s): {', '.join(cves)}"
                + ("." if structured else " (parsed from free text)."),
                EpistemicClass.OBSERVED_EVIDENCE if structured else EpistemicClass.INFERENCE,
            )
        )
    if cwes:
        structured = bool(finding.cwe)
        items.append(
            Statement(
                f"Weakness class(es): {', '.join(cwes)}"
                + ("." if structured else " (parsed from free text)."),
                EpistemicClass.OBSERVED_EVIDENCE if structured else EpistemicClass.INFERENCE,
            )
        )
    items.append(
        Statement(
            f"Contextual risk score {finding.risk_score():g}/100, computed from the "
            "factors above (KEV > EPSS > CVSS > severity, with a confidence nudge).",
            EpistemicClass.DETERMINISTIC_RESULT,
        )
    )
    return tuple(items)


def explain_finding(finding: Finding) -> FindingExplanation:
    """Derive the shared :class:`FindingExplanation` from a finding's own fields.

    Pure and deterministic: no network, no scanning, nothing invented. The
    ``risk_score`` is the finding's authoritative :meth:`~Finding.risk_score`, and
    ``risk_factors`` reproduce how that number was reached from the same shared
    constants. Each claim in ``statements`` carries its epistemic class; ``limits``
    names the caveats.
    """
    view = FindingView(finding)
    cves = tuple(view.cves)
    cwes = tuple(view.cwes)

    limits: list[str] = [
        "Derived only from the finding's stored fields — no new scanning or "
        "network lookup was performed.",
    ]
    if finding.cvss is None:
        limits.append("No CVSS recorded; the base comes from the severity band alone.")
    if not finding.cve and cves:
        limits.append("CVE id(s) were parsed from free text, not a structured field.")
    if not finding.cwe and cwes:
        limits.append("CWE id(s) were parsed from free text, not a structured field.")
    if not finding.evidence:
        limits.append("No evidence is attached; the finding rests on its source's report alone.")
    if finding.confidence is None:
        limits.append("No confidence was recorded for this finding.")
    elif finding.confidence is Confidence.LOW:
        limits.append("Confidence is low: treat as a lead to verify, not a confirmed issue.")

    return FindingExplanation(
        finding_id=finding.finding_id,
        title=finding.title,
        asset_id=finding.asset_id,
        source=finding.source.value,
        severity=finding.severity.value,
        status=finding.status.value,
        risk_score=finding.risk_score(),
        summary=_summary(finding, cwes),
        risk_factors=_risk_factors(finding),
        statements=_statements(finding, cves, cwes),
        limits=tuple(limits),
        cve=cves,
        cwe=cwes,
        remediation=finding.remediation or None,
    )


__all__ = [
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "FindingExplanation",
    "RiskFactor",
    "Statement",
    "explain_finding",
]

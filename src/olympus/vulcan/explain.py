"""Unified finding explainability contract (ROADMAP ``EXPL-1``).

Every surface — CLI, API, Web and the Vulcan reports — must answer the same
question the same way: *why is this a finding, why this severity, and how sure
are we?* This module is the single, tested place that derives that answer, as a
**shared data contract** (not a rendering function): a :class:`FindingExplanation`
built by :func:`explain_finding`. `EXPL-2` then wires every surface to this one
core so they agree by construction (a parity test), with no explanation logic
duplicated in a frontend.

The explanation is **derived purely from the finding's own fields** — it performs
no scanning, opens no network, and invents nothing. It distinguishes what was
**observed** (the finding's stored evidence and structured intelligence) from what
is **inferred** (the contextual risk score), reproduces the risk rationale from the
same constants the score itself uses (:data:`~olympus.core.models.SEVERITY_RISK_BASE`,
:data:`~olympus.core.models.KEV_RISK_FLOOR`,
:data:`~olympus.core.models.CONFIDENCE_RISK_MODIFIER`) so the score and its
explanation can never diverge, and states its own **limits** explicitly. It is
pure and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from olympus.core.enums import Confidence
from olympus.core.models import (
    CONFIDENCE_RISK_MODIFIER,
    KEV_RISK_FLOOR,
    SEVERITY_RISK_BASE,
    Finding,
)
from olympus.vulcan.view import FindingView


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
    """A shared, surface-agnostic explanation of one finding.

    ``observed`` lists what the finding actually carries (evidence, confirmed
    exploitation, structured identifiers); ``inferred`` names what Olympus derived
    (the risk score); ``limits`` states caveats a reader must keep in mind. Nothing
    here is fetched or invented — it is a projection of the finding alone.
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
    observed: tuple[str, ...]
    inferred: tuple[str, ...]
    limits: tuple[str, ...]
    cve: tuple[str, ...] = field(default_factory=tuple)
    cwe: tuple[str, ...] = field(default_factory=tuple)
    remediation: str | None = None

    def summary_line(self) -> str:
        """One compact line an operator reads first."""
        return f"[{self.severity}] {self.title} — risk {self.risk_score:g}/100: {self.summary}"

    def to_dict(self) -> dict[str, object]:
        """Full, JSON-serialisable projection; the contract every surface renders."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "asset_id": self.asset_id,
            "source": self.source,
            "severity": self.severity,
            "status": self.status,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "risk_factors": [item.to_dict() for item in self.risk_factors],
            "observed": list(self.observed),
            "inferred": list(self.inferred),
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


def explain_finding(finding: Finding) -> FindingExplanation:
    """Derive the shared :class:`FindingExplanation` from a finding's own fields.

    Pure and deterministic: no network, no scanning, nothing invented. The
    ``risk_score`` is the finding's authoritative :meth:`~Finding.risk_score`, and
    ``risk_factors`` reproduce how that number was reached from the same shared
    constants. ``observed`` / ``inferred`` / ``limits`` separate fact from
    derivation and name the caveats.
    """
    view = FindingView(finding)
    cves = tuple(view.cves)
    cwes = tuple(view.cwes)

    observed: list[str] = []
    if finding.evidence:
        observed.append(f"{len(finding.evidence)} evidence reference(s) attached to the finding.")
    if finding.kev:
        observed.append("CISA KEV: confirmed in-the-wild exploitation.")
    if finding.cvss is not None:
        observed.append(f"Vendor/scanner CVSS score of {finding.cvss:g}.")
    if cves:
        observed.append(f"Linked CVE(s): {', '.join(cves)}.")
    if cwes:
        observed.append(f"Weakness class(es): {', '.join(cwes)}.")
    if finding.epss is not None:
        observed.append(f"EPSS exploitation probability: {finding.epss * 100:g}%.")

    inferred = [
        f"Contextual risk score {finding.risk_score():g}/100, blended from the "
        "factors above (KEV > EPSS > CVSS > severity, with a confidence nudge).",
    ]

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
        observed=tuple(observed),
        inferred=tuple(inferred),
        limits=tuple(limits),
        cve=cves,
        cwe=cwes,
        remediation=finding.remediation or None,
    )


__all__ = ["FindingExplanation", "RiskFactor", "explain_finding"]

"""Deterministic, explainable Smart Scan pipeline proposals (ROADMAP ``WEB-F``).

A Smart Scan turns a *goal* — an objective, a target and (optionally) an
engagement — into an **ordered pipeline the operator can read before anything
runs**. The engine only ever *proposes*: it never executes a scanner, contacts a
target, reads the environment or queues a job. Execution stays on the existing
audited path (the guided ``/assessments/preview`` → ``/jobs`` flow, or the CLI),
so every stage still passes the real scope, authorization and preview gates.

The proposal is built to satisfy the ``WEB-F`` Definition of Done:

* **deterministic** — given the same objective, target, ``ready`` set, risk
  ceiling and engagement, :func:`propose_pipeline` always returns the identical
  plan, down to a stable :attr:`SmartScanPlan.digest`;
* **explainable** — every included stage carries a plain-language rationale and
  every dropped stage an honest reason, so an operator understands the shape of
  the plan without reading code;
* **scope-aware** — when an engagement is supplied, a target outside its
  authorized perimeter yields *zero* proposed stages (no branch is ever planned
  out of scope);
* **policy-aware** — a risk ceiling (default :data:`RiskClass.ACTIVE`) keeps
  intrusive techniques out of a plan unless the operator opts in explicitly, and
  no stage is ever marked as needing less authorization than its risk demands;
* **bounded and configurable** — the number of stages is capped and the
  objective and ceiling are the operator's to choose.

This module is interface-agnostic on purpose: the web control plane, the CLI and
any future TUI wizard all read the same answers here, exactly as they share
:mod:`olympus.integrations.activity` for the single-scanner guided flow.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from olympus.core.models import Engagement
from olympus.engagements.resolve import engagement_covers
from olympus.integrations.activity import (
    RISK_EXPLANATION,
    ActivityType,
    RiskClass,
    activity_info,
    profile,
    recommended_scanner,
)

#: Hard safety cap on how many stages a single plan may contain. A proposal is a
#: convenience, not a licence to chain an unbounded number of scanners; the cap
#: guards against a future objective accidentally planning a huge pipeline.
MAX_PIPELINE_STAGES = 8

#: Risk classes in increasing intrusiveness, used to compare against a ceiling.
_RISK_ORDER: dict[RiskClass, int] = {
    RiskClass.PASSIVE: 0,
    RiskClass.ACTIVE: 1,
    RiskClass.INTRUSIVE: 2,
}


class ScanObjective(StrEnum):
    """What the operator wants to achieve, independent of individual scanners.

    Each objective expands to a reviewed, ordered list of *native* activities
    (those the web control plane can run as a scanner job). Recon always comes
    first so later, louder stages act on a mapped surface rather than blindly.
    """

    RECON = "recon"
    WEB_APP = "web-app"
    NETWORK = "network"
    FULL = "full"


#: Objective → ordered activities. Only Themis-native activities appear here;
#: secret scanning, detection engineering and the full Athena playbook live in
#: other modules and are never silently folded into a web Smart Scan.
_OBJECTIVE_ACTIVITIES: dict[ScanObjective, tuple[ActivityType, ...]] = {
    ScanObjective.RECON: (ActivityType.RECON,),
    ScanObjective.WEB_APP: (
        ActivityType.RECON,
        ActivityType.WEB,
        ActivityType.VULNERABILITY,
    ),
    ScanObjective.NETWORK: (
        ActivityType.RECON,
        ActivityType.NETWORK,
        ActivityType.VULNERABILITY,
    ),
    ScanObjective.FULL: (
        ActivityType.RECON,
        ActivityType.NETWORK,
        ActivityType.WEB,
        ActivityType.VULNERABILITY,
    ),
}

#: Plain-language explanation of each objective, shown before the plan so the
#: operator understands what they asked for.
OBJECTIVE_SUMMARY: dict[ScanObjective, str] = {
    ScanObjective.RECON: (
        "Map the target's public surface only — no direct probing of the target."
    ),
    ScanObjective.WEB_APP: (
        "Map the surface, then assess a web application and check it for known vulnerabilities."
    ),
    ScanObjective.NETWORK: (
        "Map the surface, then enumerate network and transport services and check for "
        "known vulnerabilities."
    ),
    ScanObjective.FULL: (
        "Map the surface, then enumerate network and web services and check for known "
        "vulnerabilities — the broadest proposal."
    ),
}


def objectives() -> tuple[ScanObjective, ...]:
    """Return every objective in presentation order."""
    return (
        ScanObjective.RECON,
        ScanObjective.WEB_APP,
        ScanObjective.NETWORK,
        ScanObjective.FULL,
    )


@dataclass(frozen=True)
class PipelineStage:
    """One proposed step: an activity, the scanner chosen for it and its risk."""

    order: int
    activity: ActivityType
    scanner: str
    risk: RiskClass
    rationale: str

    @property
    def needs_authorization(self) -> bool:
        """True when this stage is anything louder than passive observation."""
        return self.risk is not RiskClass.PASSIVE

    def to_dict(self) -> dict[str, object]:
        return {
            "order": self.order,
            "activity": self.activity.value,
            "scanner": self.scanner,
            "risk": self.risk.value,
            "risk_explanation": RISK_EXPLANATION[self.risk],
            "needs_authorization": self.needs_authorization,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ExcludedStage:
    """An activity that was *not* planned, with an honest reason why."""

    activity: ActivityType
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"activity": self.activity.value, "reason": self.reason}


@dataclass(frozen=True)
class SmartScanPlan:
    """A reproducible, explainable Smart Scan proposal — never an execution."""

    objective: ScanObjective
    target: str
    target_kind: str
    engagement_id: str | None
    in_scope: bool
    max_risk: RiskClass
    stages: tuple[PipelineStage, ...]
    excluded: tuple[ExcludedStage, ...]

    @property
    def requires_authorization(self) -> bool:
        """True when any proposed stage is louder than passive observation."""
        return any(stage.needs_authorization for stage in self.stages)

    @property
    def digest(self) -> str:
        """Stable SHA-256 over the plan's defining inputs and ordered stages.

        Two proposals built from the same inputs produce the same digest, so an
        operator (or a test) can prove the plan is reproducible rather than a
        snapshot of a non-deterministic choice.
        """
        payload = {
            "objective": self.objective.value,
            "target": self.target,
            "target_kind": self.target_kind,
            "engagement_id": self.engagement_id,
            "in_scope": self.in_scope,
            "max_risk": self.max_risk.value,
            "stages": [
                [stage.order, stage.activity.value, stage.scanner, stage.risk.value]
                for stage in self.stages
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "objective": self.objective.value,
            "objective_summary": OBJECTIVE_SUMMARY[self.objective],
            "target": self.target,
            "target_kind": self.target_kind,
            "engagement_id": self.engagement_id,
            "in_scope": self.in_scope,
            "max_risk": self.max_risk.value,
            "requires_authorization": self.requires_authorization,
            "digest": self.digest,
            "stages": [stage.to_dict() for stage in self.stages],
            "excluded": [stage.to_dict() for stage in self.excluded],
        }


def _rationale(activity: ActivityType, scanner: str, risk: RiskClass) -> str:
    """Build a one-line, plain-language reason for proposing this stage."""
    spec = profile(scanner)
    what = spec.summary if spec is not None else activity_info(activity).summary
    return f"{activity_info(activity).title}: {what}"


def propose_pipeline(
    *,
    objective: ScanObjective,
    target: str,
    target_kind: str = "host",
    ready: set[str],
    engagement: Engagement | None = None,
    max_risk: RiskClass = RiskClass.ACTIVE,
    max_stages: int = MAX_PIPELINE_STAGES,
) -> SmartScanPlan:
    """Propose a deterministic Smart Scan pipeline. Executes nothing.

    ``ready`` is the set of scanner names adapted *and* available on this host
    (the caller computes it from the capability inventory); only ready scanners
    are ever proposed, so the plan never pretends something unavailable will run.

    When ``engagement`` is supplied and ``target`` falls outside its authorized
    perimeter the plan is returned ``in_scope=False`` with **no stages** — a
    Smart Scan never plans a branch out of scope. ``max_risk`` is the ceiling:
    an activity whose ready scanner is riskier than the ceiling is dropped with
    an explicit reason rather than quietly escalating the operator's intent.
    """
    if max_stages < 1:
        raise ValueError("max_stages must be at least 1")
    ceiling = min(max_stages, MAX_PIPELINE_STAGES)

    in_scope = True
    if engagement is not None and not engagement_covers(engagement, target, target_kind):
        in_scope = False

    stages: list[PipelineStage] = []
    excluded: list[ExcludedStage] = []

    if in_scope:
        for activity in _OBJECTIVE_ACTIVITIES[objective]:
            if len(stages) >= ceiling:
                excluded.append(
                    ExcludedStage(activity, f"pipeline is capped at {ceiling} stage(s)")
                )
                continue
            scanner = recommended_scanner(activity, ready)
            if scanner is None:
                excluded.append(
                    ExcludedStage(
                        activity,
                        "no scanner for this activity is ready on this host",
                    )
                )
                continue
            scanner_profile = profile(scanner)
            if scanner_profile is None:  # pragma: no cover - ready names come from the registry
                excluded.append(ExcludedStage(activity, f"unknown scanner {scanner!r}"))
                continue
            if _RISK_ORDER[scanner_profile.risk] > _RISK_ORDER[max_risk]:
                excluded.append(
                    ExcludedStage(
                        activity,
                        f"the ready scanner '{scanner}' is {scanner_profile.risk.value}, "
                        f"above the {max_risk.value} risk ceiling",
                    )
                )
                continue
            stages.append(
                PipelineStage(
                    order=len(stages) + 1,
                    activity=activity,
                    scanner=scanner,
                    risk=scanner_profile.risk,
                    rationale=_rationale(activity, scanner, scanner_profile.risk),
                )
            )

    return SmartScanPlan(
        objective=objective,
        target=target,
        target_kind=target_kind,
        engagement_id=engagement.engagement_id if engagement is not None else None,
        in_scope=in_scope,
        max_risk=max_risk,
        stages=tuple(stages),
        excluded=tuple(excluded),
    )


__all__ = [
    "MAX_PIPELINE_STAGES",
    "OBJECTIVE_SUMMARY",
    "ExcludedStage",
    "PipelineStage",
    "ScanObjective",
    "SmartScanPlan",
    "objectives",
    "propose_pipeline",
]

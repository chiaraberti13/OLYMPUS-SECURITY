"""Deterministic, non-executing engagement planning for Metis."""

from __future__ import annotations

from olympus.metis.catalog import recommend
from olympus.metis.models import EngagementPlan, OperatingMode, PlanStep


def build_plan(
    objective: str,
    *,
    scope: tuple[str, ...] = (),
    authorization_confirmed: bool = False,
    include_active: bool = False,
    limit: int = 6,
) -> EngagementPlan:
    """Build an ordered plan and mark every unsatisfied authorization gate."""
    recommendations = recommend(objective, limit=limit, include_active=include_active)
    steps = []
    for order, item in enumerate(recommendations, start=1):
        capability = item.capability
        needs_authorization = capability.requires_authorization and (
            not authorization_confirmed or not scope
        )
        steps.append(
            PlanStep(
                order=order,
                capability_id=capability.capability_id,
                title=capability.title,
                commands=capability.commands,
                mode=capability.mode,
                noise=capability.noise,
                authorization_required=capability.requires_authorization,
                status="authorization-required" if needs_authorization else "ready",
            )
        )
    if any(step.mode is OperatingMode.ACTIVE for step in steps) and not include_active:
        raise AssertionError("active capability escaped the include_active gate")
    return EngagementPlan(
        objective=objective,
        scope=scope,
        authorization_confirmed=authorization_confirmed,
        steps=tuple(steps),
    )

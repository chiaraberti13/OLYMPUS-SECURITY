"""Tests for the Smart Scan pipeline proposal engine (ROADMAP ``WEB-F``).

These pin the ``WEB-F`` Definition of Done at the engine level: the proposal is
deterministic and reproducible, explainable, scope-aware (no branch out of
scope), policy-aware (a risk ceiling, intrusive only on explicit opt-in),
bounded and configurable — and it never executes anything.
"""

from __future__ import annotations

import pytest

from olympus.core.models import Engagement, EngagementScope
from olympus.integrations.activity import ActivityType, RiskClass
from olympus.integrations.smartscan import (
    MAX_PIPELINE_STAGES,
    ScanObjective,
    objectives,
    propose_pipeline,
)

# A generous "ready" set: at least one scanner per native activity and one
# intrusive tool, so ceiling behaviour is observable.
READY = {"subfinder", "nmap", "testssl", "nuclei", "openvas", "sqlmap"}


def test_every_objective_expands_to_at_least_one_activity() -> None:
    for objective in objectives():
        plan = propose_pipeline(
            objective=objective, target="example.com", target_kind="domain", ready=READY
        )
        # Each objective yields either a proposed stage or an honest exclusion;
        # it never silently produces nothing at all.
        assert plan.stages or plan.excluded


def test_recon_objective_is_passive_and_needs_no_authorization() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.RECON, target="example.com", target_kind="domain", ready=READY
    )
    assert [stage.activity for stage in plan.stages] == [ActivityType.RECON]
    assert plan.stages[0].scanner == "subfinder"
    assert plan.stages[0].risk is RiskClass.PASSIVE
    assert plan.requires_authorization is False


def test_full_objective_orders_recon_first_then_louder_stages() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    activities = [stage.activity for stage in plan.stages]
    # Recon always precedes anything that probes the target directly.
    assert activities[0] is ActivityType.RECON
    assert ActivityType.NETWORK in activities
    assert plan.requires_authorization is True
    # Orders are a dense 1..n sequence.
    assert [stage.order for stage in plan.stages] == list(range(1, len(plan.stages) + 1))


def test_proposal_is_deterministic_and_reproducible() -> None:
    first = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    second = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    assert first.digest == second.digest
    assert first.to_dict() == second.to_dict()


def test_digest_changes_when_the_plan_changes() -> None:
    full = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    recon = propose_pipeline(
        objective=ScanObjective.RECON, target="example.com", target_kind="domain", ready=READY
    )
    assert full.digest != recon.digest


def test_only_ready_scanners_are_proposed() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.NETWORK,
        target="example.com",
        target_kind="domain",
        ready={"subfinder"},  # nothing for network/vulnerability is ready
    )
    assert all(stage.scanner == "subfinder" for stage in plan.stages)
    dropped = {item.activity for item in plan.excluded}
    assert ActivityType.NETWORK in dropped
    reasons = {item.reason for item in plan.excluded}
    assert any("ready" in reason for reason in reasons)


def test_active_ceiling_drops_intrusive_tools_with_a_reason() -> None:
    # Only an intrusive web tool is ready; at the default ACTIVE ceiling the web
    # stage must be dropped rather than silently escalating to intrusive.
    plan = propose_pipeline(
        objective=ScanObjective.WEB_APP,
        target="example.com",
        target_kind="domain",
        ready={"subfinder", "sqlmap"},
        max_risk=RiskClass.ACTIVE,
    )
    assert all(stage.risk is not RiskClass.INTRUSIVE for stage in plan.stages)
    web_excluded = [item for item in plan.excluded if item.activity is ActivityType.WEB]
    assert web_excluded
    assert "risk ceiling" in web_excluded[0].reason


def test_intrusive_ceiling_allows_intrusive_tools() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.WEB_APP,
        target="example.com",
        target_kind="domain",
        ready={"subfinder", "sqlmap"},
        max_risk=RiskClass.INTRUSIVE,
    )
    web = [stage for stage in plan.stages if stage.activity is ActivityType.WEB]
    assert web and web[0].scanner == "sqlmap"
    assert web[0].risk is RiskClass.INTRUSIVE
    assert web[0].needs_authorization is True


def test_out_of_scope_target_proposes_nothing() -> None:
    engagement = Engagement(
        name="Acme",
        client="Acme",
        scope=EngagementScope(included=("acme.test",), excluded=()),
    )
    plan = propose_pipeline(
        objective=ScanObjective.FULL,
        target="evil.example",  # outside the engagement perimeter
        target_kind="domain",
        ready=READY,
        engagement=engagement,
    )
    assert plan.in_scope is False
    assert plan.stages == ()
    assert plan.excluded == ()
    assert plan.engagement_id == engagement.engagement_id


def test_in_scope_target_with_engagement_proposes_stages() -> None:
    engagement = Engagement(
        name="Acme",
        client="Acme",
        scope=EngagementScope(included=("acme.test",), excluded=()),
    )
    plan = propose_pipeline(
        objective=ScanObjective.RECON,
        target="acme.test",
        target_kind="domain",
        ready=READY,
        engagement=engagement,
    )
    assert plan.in_scope is True
    assert plan.stages
    assert plan.engagement_id == engagement.engagement_id


def test_pipeline_is_bounded_by_max_stages() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.FULL,
        target="example.com",
        target_kind="domain",
        ready=READY,
        max_stages=1,
    )
    assert len(plan.stages) <= 1
    # Activities beyond the cap are reported as excluded, not dropped silently.
    assert any("capped" in item.reason for item in plan.excluded)


def test_max_stages_is_clamped_to_the_safety_cap() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.FULL,
        target="example.com",
        target_kind="domain",
        ready=READY,
        max_stages=10_000,
    )
    assert len(plan.stages) <= MAX_PIPELINE_STAGES


def test_max_stages_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_stages"):
        propose_pipeline(
            objective=ScanObjective.RECON,
            target="example.com",
            target_kind="domain",
            ready=READY,
            max_stages=0,
        )


def test_no_scanner_is_proposed_for_more_than_one_stage() -> None:
    plan = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    scanners = [stage.scanner for stage in plan.stages]
    assert len(scanners) == len(set(scanners))


def test_to_dict_is_json_serialisable_and_self_describing() -> None:
    import json

    plan = propose_pipeline(
        objective=ScanObjective.FULL, target="example.com", target_kind="domain", ready=READY
    )
    document = plan.to_dict()
    # Round-trips through JSON without raising (no raw bytes or non-serialisable).
    assert json.loads(json.dumps(document)) == document
    assert document["objective"] == "full"
    assert document["digest"] == plan.digest
    assert isinstance(document["stages"], list)

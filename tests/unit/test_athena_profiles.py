"""Unit tests for Athena named scan profiles."""

from __future__ import annotations

import pytest

from olympus.athena.application.profiles import (
    ScanProfile,
    UnknownProfileError,
    get_profile,
    profiles,
)
from olympus.athena.application.registry import active_adapters, available_adapters
from olympus.athena.domain.contracts import AssessmentPlan, ExecutionLimits, Target


def test_profiles_reference_only_registered_adapters() -> None:
    registered = set(available_adapters())
    for profile in profiles():
        assert set(profile.adapters) <= registered, profile.profile_id


def test_light_is_passive_and_deep_is_an_active_superset() -> None:
    light = get_profile("light")
    deep = get_profile("deep")
    assert light.active is False
    assert deep.active is True
    assert set(light.adapters) <= set(deep.adapters)
    # The only thing that makes deep active is an adapter the registry calls active.
    assert set(deep.adapters) & set(active_adapters())
    assert not set(light.adapters) & set(active_adapters())


def test_get_profile_rejects_an_unknown_id() -> None:
    with pytest.raises(UnknownProfileError, match="unknown profile"):
        get_profile("ghost")


def test_describe_is_json_safe_and_target_free() -> None:
    described = get_profile("light").describe()
    assert described["profile_id"] == "light"
    assert described["active"] is False
    assert described["adapters"] == ["dns", "web-headers", "whois"]
    assert described["active_adapters"] == []
    # A profile description never carries a target: it says how, not what.
    assert "targets" not in described
    assert "target" not in described


def test_build_plan_produces_a_valid_confirmed_plan() -> None:
    plan = get_profile("deep").build_plan(
        engagement_id="ENG-9",
        approval_reference="APPROVAL-9",
        targets=(Target(kind="domain", value="example.com"),),
        allowed_domains=("example.com",),
        confirmed=True,
    )
    assert isinstance(plan, AssessmentPlan)
    assert plan.engagement_id == "ENG-9"
    assert plan.name == "Deep scan"  # defaults to the profile title
    assert plan.adapters == ("dns", "themis", "web-headers", "whois")
    assert plan.authorization.confirmed is True
    assert plan.limits == ExecutionLimits(
        concurrency=4, per_job_timeout_seconds=300, overall_deadline_seconds=1800, max_retries=1
    )


def test_build_plan_refuses_an_unconfirmed_authorization() -> None:
    # A profile never self-authorizes: an unconfirmed build fails the contract.
    with pytest.raises(ValueError, match="confirmed"):
        get_profile("light").build_plan(
            engagement_id="ENG-1",
            approval_reference="REF",
            targets=(Target(kind="domain", value="example.com"),),
            allowed_domains=("example.com",),
            confirmed=False,
        )


def test_build_plan_rejects_an_empty_scope() -> None:
    with pytest.raises(ValueError):
        get_profile("light").build_plan(
            engagement_id="ENG-1",
            approval_reference="REF",
            targets=(Target(kind="domain", value="example.com"),),
            allowed_domains=(),
            confirmed=True,
        )


def test_build_plan_honours_a_custom_name_and_report_formats() -> None:
    plan = get_profile("light").build_plan(
        engagement_id="ENG-2",
        approval_reference="REF",
        targets=(Target(kind="url", value="https://app.example.com/login"),),
        allowed_domains=("example.com",),
        name="Quarterly recon",
        confirmed=True,
        report_formats=("json", "markdown"),
    )
    assert plan.name == "Quarterly recon"
    assert plan.output.report_formats == ("json", "markdown")
    # The embedded scope covers the subdomain the URL target lives on.
    assert plan.scope.covers("app.example.com")


def test_profile_dataclass_is_immutable() -> None:
    profile = get_profile("light")
    with pytest.raises((AttributeError, TypeError)):
        profile.adapters = ()  # type: ignore[misc]
    assert isinstance(profile, ScanProfile)

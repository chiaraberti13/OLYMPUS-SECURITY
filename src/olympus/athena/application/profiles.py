"""Named assessment profiles that generate validated Athena plans.

A *profile* is a reusable, inspectable preset — a fixed set of adapters plus
default execution limits — that turns engagement-specific inputs (targets,
scope, authorization) into a validated :class:`AssessmentPlan`. It mirrors the
"Light scan / Deep scan" presets of an integrated toolkit, yet adds nothing new
to the orchestrator: a profile only *chooses* which already-registered adapters
run, and with which safe limits.

A profile deliberately carries **no targets of its own**. It describes *how* to
assess, never *what*: building a plan from a profile always requires an
explicit, in-scope target, an embedded scope and a confirmed authorization
reference, so a preset can never be run against an unintended host.

``light`` is passive and fast — DNS/WHOIS lookups against fixed third-party
services plus a single unauthenticated header fetch, with no active probing and
no credentials. ``deep`` adds the active AEGIS scan step (Themis), so it is
appropriate only once active scanning is authorized for the engagement.
"""

from __future__ import annotations

from dataclasses import dataclass

from olympus.athena.application.registry import active_adapters, available_adapters
from olympus.athena.domain.contracts import (
    AssessmentPlan,
    AuthorizationContext,
    ExecutionLimits,
    OutputPolicy,
    ScopeReference,
    Target,
)


class UnknownProfileError(ValueError):
    """Raised when a profile id is requested that no profile defines."""


@dataclass(frozen=True)
class ScanProfile:
    """An inspectable, target-free preset that builds an :class:`AssessmentPlan`."""

    profile_id: str
    title: str
    summary: str
    adapters: tuple[str, ...]
    limits: ExecutionLimits

    @property
    def active(self) -> bool:
        """Whether the profile runs any adapter that actively probes a target."""
        active = set(active_adapters())
        return any(name in active for name in self.adapters)

    def describe(self) -> dict[str, object]:
        """Return a JSON-serializable, target-free description for inspection."""
        active = set(active_adapters())
        return {
            "profile_id": self.profile_id,
            "title": self.title,
            "summary": self.summary,
            "adapters": list(self.adapters),
            "active_adapters": sorted(name for name in self.adapters if name in active),
            "active": self.active,
            "limits": self.limits.model_dump(mode="json"),
        }

    def build_plan(
        self,
        *,
        engagement_id: str,
        approval_reference: str,
        targets: tuple[Target, ...],
        allowed_domains: tuple[str, ...],
        name: str | None = None,
        confirmed: bool = False,
        report_formats: tuple[str, ...] | None = None,
    ) -> AssessmentPlan:
        """Turn engagement inputs into a validated plan for this profile.

        The profile supplies the adapters and limits; the caller supplies the
        authorized target(s), the scope and the authorization reference.
        ``confirmed`` must be set explicitly by the caller — a profile never
        self-authorizes a run, so a plan generated without confirmation fails
        validation rather than becoming silently runnable.

        Raises :class:`ValueError` (the Pydantic ``ValidationError`` is a
        subclass) on any contract violation: an unconfirmed authorization, an
        out-of-shape target, an empty scope or an unknown report format.
        """
        output = (
            OutputPolicy(report_formats=report_formats)  # type: ignore[arg-type]
            if report_formats is not None
            else OutputPolicy()
        )
        return AssessmentPlan(
            engagement_id=engagement_id,
            name=name or self.title,
            targets=targets,
            adapters=self.adapters,
            scope=ScopeReference(allowed_domains=allowed_domains),
            authorization=AuthorizationContext(
                engagement_id=engagement_id,
                approval_reference=approval_reference,
                confirmed=confirmed,
            ),
            limits=self.limits,
            output=output,
        )


# Passive and fast: third-party DNS/WHOIS lookups and one unauthenticated header
# fetch. No active probing and no credentials, so it is safe to run first.
_LIGHT = ScanProfile(
    profile_id="light",
    title="Light scan",
    summary=(
        "Passive and fast: DNS/WHOIS lookups against fixed third-party services "
        "and a single unauthenticated header fetch. No active probing, no "
        "credentials."
    ),
    adapters=("dns", "web-headers", "whois"),
    limits=ExecutionLimits(
        concurrency=2,
        per_job_timeout_seconds=60,
        overall_deadline_seconds=600,
        max_retries=1,
    ),
)

# Everything in light plus the active AEGIS scan step (Themis). Higher limits
# because active scanning is slower; only appropriate with active-scan
# authorization for the engagement.
_DEEP = ScanProfile(
    profile_id="deep",
    title="Deep scan",
    summary=(
        "Everything in the light profile plus the active AEGIS scan step "
        "(Themis). Active scanning must be authorized for the engagement."
    ),
    adapters=("dns", "themis", "web-headers", "whois"),
    limits=ExecutionLimits(
        concurrency=4,
        per_job_timeout_seconds=300,
        overall_deadline_seconds=1800,
        max_retries=1,
    ),
)

_PROFILES: dict[str, ScanProfile] = {_LIGHT.profile_id: _LIGHT, _DEEP.profile_id: _DEEP}


def _validate_registry() -> None:
    """Fail fast if a profile ever drifts from the adapter registry.

    Every profile may reference only registered adapters, the light profile must
    stay passive, and deep must be a strict superset of light. These are module
    invariants, not runtime input, so a violation is a programming error.
    """
    registered = set(available_adapters())
    for profile in _PROFILES.values():
        unknown = [name for name in profile.adapters if name not in registered]
        if unknown:
            raise RuntimeError(
                f"profile {profile.profile_id!r} references unregistered adapter(s): {unknown}"
            )
    if _LIGHT.active:
        raise RuntimeError("the light profile must not run active adapters")
    if not _DEEP.active:
        raise RuntimeError("the deep profile must run the active AEGIS scan step")
    if not set(_LIGHT.adapters) <= set(_DEEP.adapters):
        raise RuntimeError("the deep profile must be a superset of the light profile")


_validate_registry()


def profiles() -> tuple[ScanProfile, ...]:
    """Return every scan profile, ordered by id."""
    return tuple(_PROFILES[key] for key in sorted(_PROFILES))


def get_profile(profile_id: str) -> ScanProfile:
    """Return the profile with ``profile_id`` or raise :class:`UnknownProfileError`."""
    try:
        return _PROFILES[profile_id]
    except KeyError as exc:
        available = [profile.profile_id for profile in profiles()]
        raise UnknownProfileError(
            f"unknown profile: {profile_id!r}; available: {available}"
        ) from exc


__all__ = ["ScanProfile", "UnknownProfileError", "get_profile", "profiles"]

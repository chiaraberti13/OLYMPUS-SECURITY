"""Shared, fail-closed engine runtime budget resolution (TOOLS-4.3).

All execution surfaces converge on :class:`ThemisApplicationService`.  This
module resolves the effective timeout there, and checks a reviewed engine's
minimum address-space request against the sandbox ceiling before the adapter
can resolve or contact a target.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass

from olympus.engines.loader import ManifestError, manifest_for
from olympus.themis.sandbox import SandboxPolicy

DEFAULT_ENGINE_TIMEOUT_SECONDS = 300.0
DEFAULT_ENGINE_DEADLINE_SECONDS = 600.0
DEADLINE_HEADROOM_SECONDS = 300.0


class EngineResourceError(ValueError):
    """The selected engine cannot run inside the configured safety ceilings."""


@dataclass(frozen=True)
class EngineRuntimeBudget:
    """Effective, redaction-safe limits for one engine run."""

    timeout_seconds: float
    deadline_seconds: float
    resource_profile: str | None
    resource_confidence: str
    sandbox_memory_bytes: int
    required_memory_bytes: int | None


def resolve_engine_runtime_budget(
    scanner: str,
    *,
    timeout_seconds: float | None,
    deadline_seconds: float | None,
    sandbox: SandboxPolicy | None = None,
    enforce_memory: bool = True,
) -> EngineRuntimeBudget:
    """Resolve one runtime budget and reject requests above sandbox ceilings.

    Explicit timeouts remain explicit.  When a caller omits them, a reviewed
    manifest supplies the engine default, so CLI, API, Web and workers use the
    same value.  Estimated manifest values remain documentation until reviewed.
    A reviewed minimum-memory request is compared with the configured sandbox
    address-space ceiling and is never used to raise that ceiling automatically.
    """

    if sandbox is not None:
        policy = sandbox
    elif enforce_memory:
        policy = SandboxPolicy.from_environment()
    else:
        # Simulation/preview launches no child, so a host sandbox setting is
        # irrelevant and must not make an offline operation fail.
        policy = SandboxPolicy()
    adapter = None
    with suppress(ManifestError, OSError):
        adapter = manifest_for(scanner).adapter

    reviewed = adapter is not None and adapter.reviewed
    declared_timeout = (
        float(adapter.timeout_seconds)
        if reviewed and adapter is not None
        else DEFAULT_ENGINE_TIMEOUT_SECONDS
    )
    effective_timeout = declared_timeout if timeout_seconds is None else timeout_seconds
    effective_deadline = (
        max(DEFAULT_ENGINE_DEADLINE_SECONDS, effective_timeout + DEADLINE_HEADROOM_SECONDS)
        if deadline_seconds is None
        else deadline_seconds
    )

    required_memory = adapter.min_memory_bytes if reviewed and adapter is not None else None
    if enforce_memory and required_memory is not None and required_memory > policy.memory_bytes:
        raise EngineResourceError(
            f"{scanner} requires at least {required_memory} bytes of address space for its "
            f"reviewed profile, but the sandbox ceiling is {policy.memory_bytes} bytes; "
            "raise THEMIS_SANDBOX_MEMORY_BYTES within the deployment security policy or "
            "choose a smaller reviewed engine profile"
        )

    return EngineRuntimeBudget(
        timeout_seconds=effective_timeout,
        deadline_seconds=effective_deadline,
        resource_profile=adapter.resource_profile if adapter is not None else None,
        resource_confidence="measured" if reviewed else "estimated",
        sandbox_memory_bytes=policy.memory_bytes,
        required_memory_bytes=required_memory,
    )


__all__ = [
    "DEFAULT_ENGINE_DEADLINE_SECONDS",
    "DEFAULT_ENGINE_TIMEOUT_SECONDS",
    "EngineResourceError",
    "EngineRuntimeBudget",
    "resolve_engine_runtime_budget",
]

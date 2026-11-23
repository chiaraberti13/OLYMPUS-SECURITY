"""Model Router security contract (AI-2 / ADR-012 DEC-13).

Verified entirely offline (providers are an injectable port): the layer is off by
default, local by default, never egresses to an external provider without the
registered opt-in, redacts before any egress, tracks and bounds a budget, and
fails closed.
"""

from __future__ import annotations

import pytest

from olympus.ai.router import (
    Budget,
    BudgetExceededError,
    DeterministicLocalProvider,
    EgressNotAuthorizedError,
    ModelResponse,
    ModelRouter,
    RouterDisabledError,
    default_router,
    redact,
)

pytestmark = pytest.mark.unit

ON = {"OLYMPUS_AI_ENABLED": "true"}


class _RecordingExternal:
    """A fake external provider that records what prompt it received."""

    name = "fake-external"
    local = False

    def __init__(self) -> None:
        self.seen: list[str] = []

    def available(self) -> bool:
        return True

    def generate(self, prompt: str, *, max_tokens: int) -> ModelResponse:
        self.seen.append(prompt)
        return ModelResponse(text="ext", tokens_used=1, provider=self.name)


def test_disabled_by_default_is_deterministic_refusal() -> None:
    router = default_router(env={})  # flag unset
    with pytest.raises(RouterDisabledError):
        router.generate("hello")


def test_local_by_default_when_enabled() -> None:
    router = default_router(env=ON)
    out = router.generate("scan the host", max_tokens=8)
    assert out.provider == "deterministic-local"
    assert out.tokens_used > 0
    assert router.budget.calls_made == 1


def test_external_without_optin_never_touches_the_provider() -> None:
    ext = _RecordingExternal()
    router = default_router(env=ON, extra_providers=[ext], allow_external=False)
    with pytest.raises(EgressNotAuthorizedError):
        router.generate("secret 10.0.0.1", external=True)
    assert ext.seen == []  # no data left the perimeter


def test_external_with_optin_redacts_before_egress() -> None:
    ext = _RecordingExternal()
    router = default_router(
        env=ON, extra_providers=[ext], allow_external=True, redact_terms=["acme-dc01"]
    )
    router.generate("host acme-dc01 at 10.0.0.1 admin@acme.test", external=True, max_tokens=16)
    assert ext.seen, "external provider should have been called"
    sent = ext.seen[0]
    assert "10.0.0.1" not in sent and "admin@acme.test" not in sent and "acme-dc01" not in sent
    assert "[REDACTED]" in sent


def test_budget_is_enforced_fail_closed() -> None:
    router = ModelRouter(
        providers=[DeterministicLocalProvider()], env=ON, budget=Budget(max_calls=1)
    )
    router.generate("one", max_tokens=1)
    with pytest.raises(BudgetExceededError):
        router.generate("two", max_tokens=1)


def test_no_usable_provider_fails_closed() -> None:
    router = ModelRouter(providers=[], env=ON)
    with pytest.raises(RouterDisabledError):
        router.generate("x")


def test_redact_masks_ip_email_and_terms() -> None:
    out = redact("10.1.2.3 user@x.io target-host", extra_terms=["target-host"])
    assert "10.1.2.3" not in out and "user@x.io" not in out and "target-host" not in out
    assert out.count("[REDACTED]") == 3

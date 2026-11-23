"""Multi-provider Model Router (AI-2, decided in ADR-012 / DEC-13).

The router is the one place the AI layer talks to a language model. Its contract is
security-first and deterministic, exactly as decided:

* **Local by default.** A local provider is used first; the bundled
  :class:`DeterministicLocalProvider` always works offline and needs no model
  weights, so there is always a deterministic local path. Real local runtimes
  (llama.cpp / Ollama-class) plug in through the :class:`ModelProvider` port.
* **No egress without opt-in, and redacted when it happens.** An external provider
  is used only when the caller passes ``external=True`` *and* the router was built
  with ``allow_external=True`` (the registered per-engagement opt-in). Even then the
  prompt is **redacted** first (:func:`redact`). Without the opt-in the external
  provider is never called — no data leaves the perimeter.
* **Bounded.** Every call is counted against a :class:`Budget` (tokens and calls);
  exceeding it fails closed.
* **Off by default.** With the AI feature flag unset the router refuses
  deterministically (:class:`RouterDisabledError`) and touches no provider.

The router performs no network I/O itself: providers are an injectable port, so the
whole module is unit-tested offline. A real external provider adapter lives behind
the same port and is the only place egress happens.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from olympus.ai import ai_enabled


class AIRouterError(RuntimeError):
    """Base class for router refusals."""


class RouterDisabledError(AIRouterError):
    """The AI layer is disabled, or no provider can serve the request."""


class EgressNotAuthorizedError(AIRouterError):
    """An external provider was requested without the registered opt-in."""


class BudgetExceededError(AIRouterError):
    """The token/call budget for this router would be exceeded."""


@dataclass(frozen=True)
class ModelResponse:
    text: str
    tokens_used: int
    provider: str


@runtime_checkable
class ModelProvider(Protocol):
    """Port for a language-model backend. Implementations may be local or external."""

    name: str
    local: bool

    def available(self) -> bool:
        """Whether this provider can serve a request right now."""

    def generate(self, prompt: str, *, max_tokens: int) -> ModelResponse:
        """Produce a completion for ``prompt`` bounded by ``max_tokens``."""


def _count_tokens(text: str) -> int:
    # A deterministic, model-agnostic token estimate (whitespace words). Good enough
    # to enforce a budget without importing a tokenizer.
    return len(text.split())


class DeterministicLocalProvider:
    """A bundled, offline, deterministic local provider (no model weights, no I/O).

    It is not a language model: it returns a reproducible, bounded acknowledgement of
    the prompt. Its purpose is to guarantee a working local path and a deterministic
    fallback; a real local runtime replaces it through the same port.
    """

    name = "deterministic-local"
    local = True

    def available(self) -> bool:
        return True

    def generate(self, prompt: str, *, max_tokens: int) -> ModelResponse:
        words = prompt.split()[: max(0, max_tokens)]
        text = "deterministic-local: " + " ".join(words)
        return ModelResponse(text=text, tokens_used=_count_tokens(text), provider=self.name)


@dataclass
class Budget:
    """A token/call budget. Both bounds are enforced fail-closed."""

    max_tokens: int = 100_000
    max_calls: int = 1_000
    _tokens: int = field(default=0, init=False)
    _calls: int = field(default=0, init=False)

    @property
    def tokens_used(self) -> int:
        return self._tokens

    @property
    def calls_made(self) -> int:
        return self._calls

    def check(self, additional_tokens: int) -> None:
        if self._calls + 1 > self.max_calls:
            raise BudgetExceededError(f"call budget {self.max_calls} exhausted")
        if self._tokens + additional_tokens > self.max_tokens:
            raise BudgetExceededError(f"token budget {self.max_tokens} would be exceeded")

    def record(self, tokens: int) -> None:
        self._calls += 1
        self._tokens += tokens


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_REDACTED = "[REDACTED]"


def redact(text: str, *, extra_terms: Sequence[str] = ()) -> str:
    """Mask sensitive tokens before any external egress (DEC-13 / DATA-3).

    Masks IPv4 addresses, email addresses, and any explicit ``extra_terms`` (for
    example the engagement's target hostnames). It is intentionally conservative:
    the external path is opt-in, and this is the last line before data leaves.
    """
    for term in sorted((t for t in extra_terms if t), key=len, reverse=True):
        text = text.replace(term, _REDACTED)
    text = _EMAIL.sub(_REDACTED, text)
    text = _IPV4.sub(_REDACTED, text)
    return text


@dataclass
class ModelRouter:
    """Route a prompt to a provider under the ADR-012 security contract."""

    providers: Sequence[ModelProvider]
    env: Mapping[str, str] | None = None
    budget: Budget = field(default_factory=Budget)
    #: The registered per-engagement opt-in that allows using an external provider.
    allow_external: bool = False
    #: Terms always masked before external egress (e.g. engagement target hosts).
    redact_terms: Sequence[str] = ()

    def _local_providers(self) -> list[ModelProvider]:
        return [p for p in self.providers if p.local and p.available()]

    def _external_providers(self) -> list[ModelProvider]:
        return [p for p in self.providers if not p.local and p.available()]

    def generate(
        self, prompt: str, *, max_tokens: int = 512, external: bool = False
    ) -> ModelResponse:
        """Generate a completion. Local by default; external only with the opt-in.

        Fails closed: disabled layer or no usable provider raises
        :class:`RouterDisabledError`; an un-opted-in external request raises
        :class:`EgressNotAuthorizedError` before any provider is touched; a request
        that would break the budget raises :class:`BudgetExceededError`.
        """
        if not ai_enabled(self.env):
            raise RouterDisabledError("the AI layer is disabled (set OLYMPUS_AI_ENABLED)")

        if external:
            if not self.allow_external:
                # No data leaves the perimeter without the registered opt-in.
                raise EgressNotAuthorizedError(
                    "external model egress requires an explicit per-engagement opt-in"
                )
            candidates = self._external_providers()
            payload = redact(prompt, extra_terms=self.redact_terms)
        else:
            candidates = self._local_providers()
            payload = prompt

        if not candidates:
            raise RouterDisabledError("no usable provider for this request")

        provider = candidates[0]
        estimate = _count_tokens(payload) + max_tokens
        self.budget.check(estimate)
        response = provider.generate(payload, max_tokens=max_tokens)
        self.budget.record(response.tokens_used)
        return response


def default_router(
    *,
    env: Mapping[str, str] | None = None,
    extra_providers: Sequence[ModelProvider] = (),
    allow_external: bool = False,
    redact_terms: Sequence[str] = (),
) -> ModelRouter:
    """A router with the deterministic local provider plus any injected providers."""
    providers: list[ModelProvider] = [DeterministicLocalProvider(), *extra_providers]
    return ModelRouter(
        providers=providers,
        env=env,
        allow_external=allow_external,
        redact_terms=redact_terms,
    )

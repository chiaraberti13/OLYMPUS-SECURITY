# Optional AI layer

Olympus has an **optional** AI layer (ADR-011, ADR-012). It is **off by default**:
with the feature flag unset the platform behaves exactly as without it. Nothing in
the AI layer runs a scanner, and every action that would touch a target or run an
engine still goes through Themis authorization, scope and isolation — the AI layer
schedules and reasons, Themis remains the only execution authority.

Enable it with:

```bash
export OLYMPUS_AI_ENABLED=true
```

## Model Router (`olympus.ai.router`, AI-2)

The router is the one place the AI layer talks to a language model, under the
contract decided in ADR-012 (`DEC-13`):

- **Local by default.** A local provider is used first. The bundled
  `DeterministicLocalProvider` always works offline with no model weights, so there
  is always a deterministic local path. A real local runtime (llama.cpp /
  Ollama-class) plugs in through the `ModelProvider` port.
- **No egress without opt-in, redacted when it happens.** An external provider is
  used only when the caller asks for it **and** the router was built with
  `allow_external=True` (the registered per-engagement opt-in). Even then the prompt
  is redacted first (`redact`: IPv4, emails and the engagement's target terms are
  masked, per the DATA-3 privacy policy). Without the opt-in the external provider
  is never called — no data leaves the perimeter.
- **Bounded.** Every call is counted against a `Budget` (tokens and calls);
  exceeding it fails closed (`BudgetExceededError`).
- **Deterministic when off/unavailable.** A disabled layer or no usable provider
  raises `RouterDisabledError`; the router never falls back to an external model
  silently.

The router performs no network I/O itself: providers are an injectable port, so the
whole module is unit-tested offline (`tests/unit/test_ai_router.py`). Egress happens
only inside an external provider adapter behind that port.

```python
from olympus.ai.router import default_router

router = default_router()  # OLYMPUS_AI_ENABLED must be set, else it refuses
answer = router.generate("summarise these findings", max_tokens=256)
```

## Status

`AI-0` (audit + license matrix) and the foundational decisions `DEC-13`/`DEC-14`/
`DEC-16` are recorded (ADR-011, ADR-012). The Model Router contract above is
implemented and tested. Still to come, each behind the flag with its own
fail-closed tests: a real local-LLM runtime adapter, the multi-agent orchestration
(`AI-1`), the verifiable Fact Graph (`AI-3`, gated on `CORR-1`/`DEC-15`), the
specialized agents (`AI-4`) and the evaluation harness (`AI-7`).

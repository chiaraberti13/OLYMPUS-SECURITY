# ADR-012: AI foundations — model router, autonomy gating and evaluation

- **Status:** Accepted — non-binding except the security invariants below
- **Date:** 2026-11-23
- **Decision owners:** Olympus maintainers
- **Roadmap:** resolves `DEC-13` (`AI-2`), `DEC-14` (`AI-4`), `DEC-16` (`AI-7`); depends on ADR-011
- **Supersedes / depends on:** depends on ADR-011 (AI layer audit); extends ADR-005 (signed engagement manifest) and the DATA-3 privacy policy

> **Non-binding** unless stated: only the invariants under *Security consequences*
> are requirements. This ADR records the explicit decisions ADR-011 said each AI
> task must carry before code; it authorizes no implementation by itself.

## Context

ADR-011 decided *what* the AI layer is (optional, off by default, no execution
outside Themis, no hypothesis promoted to fact, egress gated). Three foundational
decisions were left explicit for the team: the model router's providers and
egress/privacy policy (`DEC-13`), the agent autonomy levels and approval-gating
matrix (`DEC-14`), and the evaluation harness and its reproducible notion of
"improvement" (`DEC-16`). This ADR settles them inside ADR-011's frame and the
DATA-3 privacy classification.

## Decision

### DEC-13 — Model Router: local-default, egress gated and redacted

- **Local models are the default.** The router exposes a provider **port**; the
  default provider is a local runtime (llama.cpp / Ollama-class) reachable without
  leaving the perimeter. With no provider available the router returns a
  **deterministic** refusal, never a silent external call.
- **External providers are opt-in and per-engagement.** An external provider is
  used only when the engagement explicitly enables it (a registered opt-in, as the
  signed engagement manifest already scopes live actions), and only through the
  egress path that **redacts** per the DATA-3 privacy policy
  (`contains_targets`/`contains_identities`/`redaction_required`).
- **Budget and provenance.** Every call records token/cost against a budget and is
  written to the audit trail with provenance; exceeding the budget fails closed.

### DEC-14 — Autonomy tiers and approval-gating matrix

Actions are classified and gated by class, tied to `OperatingMode` and the signed
engagement manifest (ADR-005):

| Action class | Examples | Autonomy |
| --- | --- | --- |
| Observe / read | read findings, inspect graph, plan | autonomous |
| Analyze / simulate | correlate, replay telemetry, `--simulate` | autonomous |
| Active / live | any Themis live scan or engine run against a target | **requires** `--i-am-authorized` + in-scope signed manifest (unchanged) |
| Destructive / state-changing | exploitation, writes to external systems, remediation apply | **mandatory human approval** per action, never auto |

An agent may never widen its own tier; the Themis authority (scope, isolation,
fail-closed) is the single enforcement point. Autonomy is advisory scheduling on
top of that gate, never a replacement for it.

### DEC-16 — Evaluation harness and "improvement"

- The eval harness is **deterministic, reproducible and offline**: it reuses the
  existing evaluation path (`athena.purple` + Apollo + Vulcan correlation) on the
  reproducible lab (`PURPLE-2`/`labs/mars`), not a new scoring engine.
- "Improvement" is a **measured delta** against a committed baseline (detection
  coverage, gap count, false-positive rate, reproducibility), with signed evidence
  (`TOOLS-4.5`) — never an opaque learned score. A run that cannot be reproduced to
  the same result does not count as improvement.

### DEC-15 — deferred

The Fact Graph / shared-memory storage decision (`DEC-15`, `AI-3`) extends `DEC-6`,
which the roadmap gates on `CORR-1`. It is **not decided here** — recording it now
would pre-empt the correlation work it depends on. It stays open until `CORR-1`.

## Security consequences (requirements)

- No external model call without a registered per-engagement opt-in **and**
  redaction per the DATA-3 policy; with no provider the router fails closed
  deterministically.
- No autonomy tier bypasses Themis authorization/scope/isolation; destructive and
  live actions keep their existing mandatory gates (manifest + `--i-am-authorized`
  / human approval).
- Evaluation is reproducible and evidence-backed; no opaque learning may gate a
  "pass".

## Alternatives rejected

- **External model by default / best-effort fallback to a remote provider:**
  rejected — it would leak perimeter data by default and make runs non-deterministic.
- **Blanket agent autonomy with post-hoc audit:** rejected — audit is not a
  substitute for a pre-action gate on destructive/live classes.
- **A learned/opaque evaluation score:** rejected — unreproducible and
  unexplainable, against the project's epistemic model (`EXPL-1`).

## Migration and rollback

Nothing is implemented by this ADR. Each AI task (`AI-2`/`AI-4`/`AI-7`) implements
its decision behind the AI feature flag with its own fail-closed tests; rollback is
the flag off (ADR-011).

## Verification criteria

- `DEC-13`/`DEC-14`/`DEC-16` are recorded here and in the decision log.
- When `AI-2`/`AI-4`/`AI-7` are built, each carries the tests these invariants imply
  (deterministic refusal with no provider; redaction-on-egress; per-class approval
  gating; reproducible eval delta) before being marked done.

# ADR-011: AI layer — architectural audit, gap analysis and license matrix

- **Status:** Accepted — non-binding except the security invariants below
- **Date:** 2026-11-23
- **Decision owners:** Olympus maintainers
- **Roadmap:** `AI-0` (precedes all AI code; relates to `DEC-12`, `AI-1`…`AI-7`)
- **Supersedes / depends on:** depends on ADR-009 (Execution Engine); none superseded

> **Non-binding** unless stated: only the invariants under *Security consequences*
> are requirements. This ADR authorizes **no** code by itself; it is the audit
> `AI-0` requires before any AI code is written.

## Context

The roadmap proposes an optional AI layer (`AI-1`…`AI-7`): multi-agent
orchestration, a multi-provider model router, a verifiable shared knowledge graph,
specialized Red/Blue/Purple/CTI/QA agents, and evaluation. Two external references
are named for evaluation, **not adopted**: **Sapper-v2** (autonomous offensive-agent
orchestration, **MIT**) and its general-purpose base **Nüwa**. `AI-0` requires, as a
document, three things before any AI code: a per-mechanism *reuse / reimplement /
discard* decision, a license-compatibility matrix, and a gap analysis mapping each
proposed capability onto an existing Olympus module or justifying it as new.

Olympus is licensed **GPL-3.0** (`LICENSE`). The execution authority, job engine,
contracts and epistemic model already exist and are the baseline every AI mechanism
is measured against.

## Decision

**Do not fork Sapper-v2/Nüwa as the orchestration engine.** Reuse *selected
mechanisms* by clean native (re)implementation on Olympus' existing contracts and
engines; the orchestrator is an optional, separable, feature-flagged service that
**never** becomes a parallel assessment engine. Per mechanism:

| Mechanism | Decision | Rationale / Olympus home |
| --- | --- | --- |
| Coordinator / agents | **Reimplement** natively | Planning/lifecycle on Athena, execution authority on Themis (`AI-1`); no new authority path |
| Parallel task scheduling | **Reuse** existing | Themis Execution Engine job store/worker (lease, retry/backoff, cancellation) — ADR-009 / `API-3`; the orchestrator schedules *through* it |
| Self-healing / recovery | **Reuse** existing | `ThemisJobStore` expired-lease recovery and retry already provide checkpoint/recovery |
| Shared memory / knowledge | **Reimplement** natively | Fact Graph on `argus.graph` + `vulcan.correlate`, provenance + epistemic class (`CORR-1`/`EXPL-1`), evidence refs to Minerva custody (`AI-3`) |
| Multi-model router | **New** subsystem | No Olympus equivalent; local models by default, egress gated/redacted (`AI-2`, `DEC-13`) |
| Result-based evaluation | **Reuse** existing | `athena.purple` + Apollo evaluation + Vulcan correlation (`PURPLE-1`, `VAL-2/3`) |

So the only genuinely new subsystem is the **Model Router**; everything else is
either native reimplementation on existing contracts or direct reuse of the
Execution Engine. No complete fork is started without an explicit, separate team
decision (`DEC-12`).

### License-compatibility matrix

| Component | License | Combined with Olympus (GPL-3.0) | Obligation |
| --- | --- | --- | --- |
| Olympus (this repo) | GPL-3.0 | — | — |
| Sapper-v2 | MIT | **Compatible** — MIT is one-way compatible into GPL-3.0; the combined work is GPL-3.0 | Keep the MIT notice/attribution for any incorporated file |
| Nüwa (Sapper base) | per its own license (verify at use) | Only if GPL-3.0-compatible | Verify + attribute before incorporating any file |
| Any reused dependency | must be GPL-3.0-compatible (permissive, or GPL-compatible copyleft) | required | A GPL-incompatible (e.g. proprietary, or incompatible-copyleft) dependency is **discarded**, not vendored |

Because mechanisms/ideas are not themselves copyrightable, the reimplement
decisions carry no license obligation; where actual MIT code is incorporated, the
MIT notice is preserved and the combined work remains GPL-3.0. Each dependency's
license is checked per component before use; anything GPL-incompatible is discarded.

### Gap analysis (proposed capability → Olympus home)

- `AI-1` orchestration → Athena (plan/lifecycle) + Themis (authority/execution) —
  existing; new glue only.
- `AI-2` model router → **new** (no equivalent).
- `AI-3` fact graph → `argus.graph` / `vulcan.correlate` + Minerva custody +
  epistemic enum (`EXPL-1`/`CORR-1`) — existing.
- `AI-4` specialized agents → existing engines (Argus/Artemis/Helios,
  Apollo/Minerva/Metis, Athena/Vulcan); the Purple loop is the vehicle of
  `PURPLE-1`/`VAL-2/3`, not a parallel engine.
- `AI-5`…`AI-7` (autonomy gating, UX, evaluation) → gating on existing
  authorization, UX on the existing control plane, eval on Apollo/Vulcan.

## Security consequences (requirements)

- The AI layer is **optional and off by default**: with the AI feature flag off,
  Olympus behaves exactly as today (a required test for `AI-1`).
- **No execution outside Themis.** Every agent action that touches a target or runs
  an engine goes through Themis authorization, scope and isolation, fail-closed. An
  agent attempting an out-of-scope or unauthorized action is refused.
- **No hypothesis promoted to fact.** Every knowledge-graph assertion carries
  provenance, confidence and epistemic class; a hypothesis is never recorded as a
  fact.
- **Egress is gated and redacted.** No sensitive data leaves the perimeter to an
  external model without a registered opt-in and redaction (`AI-2`, `DEC-13`).
- **No GPL-incompatible dependency** is vendored; incorporated MIT code keeps its
  attribution.

## Alternatives rejected

- **Fork Sapper-v2 as the engine:** rejected — it would create a second
  orchestration/execution authority beside Themis, duplicating (and risking
  divergence from) the audited execution path.
- **Adopt the framework wholesale as a dependency:** rejected for the orchestration
  core — the value is in a handful of mechanisms, which are cheaper and safer to
  reimplement on existing contracts than to inherit with an external runtime.

## Migration and rollback

Nothing changes until `AI-1`+ are implemented behind the feature flag. Rollback is
turning the flag off (Olympus unchanged) or removing the optional service; the
Execution Engine and contracts it builds on are untouched.

## Verification criteria

- This ADR is committed with a per-mechanism decision, the license matrix, and the
  gap analysis (the `AI-0` acceptance).
- Each later AI task carries its own fail-closed tests (flag-off parity, out-of-scope
  refusal, no hypothesis→fact promotion, egress redaction) before it is marked done.

# ADR-009: Themis Execution Engine as an explicit, separable service

- **Status:** Accepted
- **Date:** 2026-11-17
- **Decision owners:** Olympus maintainers
- **Roadmap:** `ARCH-3` / `API-3`
- **Supersedes / depends on:** depends on `ADR-007` (web control plane), `DATA-2`
  (persistence port), `TOOLS-4.1` (shared preflight)

> **Non-binding** unless stated: only the security invariants listed under
> *Security consequences* are requirements.

## Context

Themis must run real scanners durably and identically from the CLI, the API and
the web control plane, with equivalent audit, states and safety. The pieces of an
execution engine already exist in the codebase, but they were described only
implicitly:

- **Durable queue & store** — `ThemisJobStore` (SQLite): `submit`, atomic
  `claim_next` under a renewed **lease**, `heartbeat`, `complete`, `cancel`,
  `counts_by_state`, `recover_expired_leases`, `prune`, backup/restore. The
  backend is selected through the `DATA-2` factory (`resolve_job_store`).
- **Worker** — `ThemisWorker.run_next`: claims one job, re-validates the signed
  engagement manifest at execution time, runs the shared **engine preflight**
  (`TOOLS-4.1`) so a missing/unusable engine fails the job closed *before* any
  target I/O, executes through the one `ThemisApplicationService`, and settles
  the job to a canonical state.
- **States** — `JobState` with explicit terminal/active/retryable partitions and
  `classify_result`/`classify_exception`; the vocabulary is shared with
  `RunStatus`/`ExecutionState`/exit codes (`docs/run-status.md`).
- **Reliability** — lease expiry + `recover_expired_leases` (requeue or fail),
  bounded retries with backoff (`RETRYABLE_STATES`, `backoff_for`), cooperative
  cancellation (`cancellation_requested` / `_JobCancellation`).

What was missing is naming this an **explicit service** with a documented
contract and an observable health surface, so that higher layers (`WEB-5`,
`WEB-7`) and operators can reason about it without reading the worker code.

## Decision

Treat the above as **one execution engine**, a separable service, and make its
contract explicit:

1. The engine's data contract is the `JobStore` **port** (`DATA-2`); the SQLite
   store is today's only adapter, a Postgres adapter is planned.
2. **Safety lives in the engine, not in the interfaces.** The engine preflight
   (`TOOLS-4.1`) already runs inside the worker; CLI `themis run` keeps its own
   pre-check only as an operator convenience. Signed-evidence emission
   (`TOOLS-4.5`) now runs in the engine too: the worker writes and signs run
   evidence per attempt on an immutable path, exactly like `themis run
   --evidence` (see *Verification criteria*).
3. The engine is **observable**: `ThemisJobStore.health()` returns a read-only
   `EngineHealth` snapshot (counts by canonical state, active count, and the
   number of running jobs holding an **expired lease** — orphaned work), surfaced
   by `olympus themis jobs health` (exit `0` healthy, `5`/partial when degraded).
   `expired_lease_count()` is the read-only complement of
   `recover_expired_leases()` and never mutates state.
4. Interfaces (CLI/API/Web) only **submit and observe**; they never embed queue,
   lease or state logic of their own.

## Security consequences

- **Fail-closed preflight is an engine property** (requirement): a live job whose
  required engine is missing/unusable is refused in the worker, before target
  resolution, and settled `failed` — never `clean`/`partial`.
- **No interface may weaken engine state or safety** (requirement): states come
  from `classify_result`/`classify_exception`; an interface rendering an outcome
  (e.g. `WEB-5`) must not upgrade a partial/failed run to clean.
- **Health is read-only** (requirement): `health()`/`expired_lease_count()` must
  not requeue or fail jobs; only `recover_expired_leases()` mutates, deliberately.

## Alternatives rejected

- **An external broker (Celery/Redis) now** — rejected: adds infrastructure and
  attack surface without a demonstrated need; SQLite + leased workers cover the
  single-host and small-cluster cases (`TECH-4`). Revisit under the documented
  criteria in the Themis runbook.
- **Per-interface execution logic** — rejected: it is exactly what produces
  divergent audit/states between CLI, API and Web.

## Migration and rollback

No schema or contract change: `health()`/`expired_lease_count()` are additive,
read-only methods; the `jobs health` command is new. Rollback is removing them.

## Verification criteria

- `tests/unit/test_themis_jobs.py`: engine health reports states and is healthy
  by default; an expired lease flags `degraded` without recovering the job; the
  `jobs health` CLI exits `5` (partial) when degraded.
- Already enforced elsewhere: the worker preflight (`tests/unit/test_themis_jobs.py`,
  `TOOLS-4.1`) and the shared canonical states (`docs/run-status.md`).
- Signed run evidence (`TOOLS-4.5`) **emitted by the engine**: the worker writes
  and signs evidence per attempt on an immutable `<job>.attempt-N.json` path,
  with all-or-nothing evidence-dir/signer configuration
  (`tests/unit/test_themis_jobs.py::test_worker_passes_signed_evidence_path_per_job`,
  `…::test_worker_uses_a_distinct_immutable_evidence_path_for_each_retry`,
  `…::test_worker_evidence_configuration_is_all_or_nothing`). This closed the last
  `ARCH-3`-specific item; `ARCH-3` is now `[x]` at the "verified in CI" level.
- **Remaining** (`API-3` / `TOOLS-4.3`, **not** `ARCH-3`): explicit
  backpressure/checkpoint and resource caps (`TOOLS-4.3`) enforced in the engine —
  engine enhancements tracked under those items, not the "explicit, documented,
  separable service" deliverable of `ARCH-3`.

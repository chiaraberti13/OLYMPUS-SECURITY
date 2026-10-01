# THEMIS durable job plane

`olympus.themis.jobs` is the control plane for queued scans: SQLite owns the
lifecycle, and the canonical application service remains the only path that may
execute an adapter, so queued work cannot bypass authorization, scope, SSRF
validation, deadlines, output limits or redacted audit.

Implemented in `src/olympus/themis/jobs.py`; exposed by `olympus themis jobs …`
and the native API (`src/olympus/themis/api.py`); tested in
`tests/unit/test_themis_jobs.py` e nella suite di fault injection
`tests/integration/test_themis_resilience.py`; la cancellazione di un processo
reale è verificata dalla suite POSIX.

## Job states

A terminal state answers "what happened", not just "did it work".

| State | Meaning |
| --- | --- |
| `queued` | Waiting for a worker — including a job serving its retry backoff |
| `running` | Leased by a worker that is renewing its heartbeat |
| `succeeded` | The scanner ran and produced a result |
| `partial` | Nothing ran, and that is not a failure: the scanner binary is missing, or live scanning is switched off |
| `failed` | The scanner ran and failed, or the worker raised |
| `timed_out` | A timeout or deadline stopped the work |
| `cancelled` | Cancellation was requested and honoured |
| `policy_denied` | Authorization, scope or SSRF policy refused the work before any traffic |

`olympus themis jobs work` exits `4` for `failed`, `timed_out` and
`policy_denied`; `partial` and `succeeded` exit `0`.

## Leases, heartbeats and orphan recovery

A claim is a **lease**, not a permanent assignment:

1. `claim_next(worker_id)` marks the job `running`, records the owner,
   increments `attempts` and sets `lease_expires_at`.
2. While the scan runs, the worker renews the lease in the background
   (`THEMIS_… heartbeat`, default every 60s against a 300s lease).
3. Every state transition — heartbeat, finish, fail, cancel — is conditional on
   `worker_id` still matching. A worker that lost its lease gets
   `LeaseLostError` and reports the job as its **new** owner left it, instead of
   overwriting the recovery.
4. `recover_expired_leases()` (run automatically before every claim, and
   available as `olympus themis jobs recover`) requeues jobs whose lease expired
   while attempts remain, and fails them when the budget is spent. A job can no
   longer sit in `running` forever because a worker was killed.

When a lease is lost mid-scan, the heartbeat marks the run cancelled through the
same cooperative token used for operator cancellation, so the abandoned worker
stops scanning rather than racing its replacement.

## Retries, backoff and idempotency

- `max_attempts` (1–10, default **1**) bounds executions of one job. The default
  means "run once": retries are opt-in.
- Only transient outcomes are retried — currently `timed_out` and an expired
  lease. A policy refusal, a cancellation, or a scanner that ran and failed will
  behave identically on a second run; retrying it only re-sends traffic.
- A retried job returns to `queued` with `available_at` set to now plus an
  exponential backoff (`5s × 2^(attempts-1)`, capped at 300s) with up to 25%
  jitter, so a fleet of workers does not retry in lockstep. A claim never takes
  a job before its `available_at`.
- `idempotency_key` (1–128 characters) makes resubmission safe: the same key
  returns the job that already exists rather than queueing a second scan of the
  same target. Reusing a key for a *different* request is refused —
  `IdempotencyConflict`, surfaced as HTTP **409**.

```bash
olympus themis jobs submit nmap --target 10.0.0.1 --scope ./scope.json \
  --idempotency-key ticket-4711 --max-attempts 3 --i-am-authorized
olympus themis jobs work --worker-id scanner-pod-3
olympus themis jobs recover
```

## Schema versioning, migration and durability

- The SQLite layout carries `PRAGMA user_version`; the current version is **2**.
- `initialize()` migrates forward: a fresh file gets the current schema, and a
  pre-versioning database is altered in place (leases, attempt budget,
  availability and idempotency columns are added, `available_at` is backfilled
  from `created_at`) without losing queued jobs.
- Schema inspection remains read-only on a current database. When migration is
  necessary, all DDL and the `user_version` bump run in one `BEGIN IMMEDIATE`
  transaction; an interruption rolls back columns, indexes and version together,
  and a later startup can retry safely. DDL is executed statement by statement
  because Python's `executescript()` would commit a pending transaction first.
- A database written by a **newer** release is refused with `SchemaVersionError`
  rather than being silently misread.
- Connections use WAL journalling with `synchronous = FULL` and a 10s busy
  timeout, so a status query is not locked out by a worker's write transaction
  and a committed transition is on disk before the caller is told it happened.
- Concurrent writers wait for the SQLite lock instead of losing a claim;
  concurrent resubmissions with the same idempotency key converge on exactly one
  persisted job. Restart recovery preserves a completed terminal state and never
  manufactures a second job.

## What the store publishes

Persisted and published text is treated as attacker-influenced and
operator-visible at the same time:

- **Errors** are redacted before they are stored: URL query secrets via the
  shared `redact_text`, and absolute filesystem paths reduced to
  `[path]/<name>` — an error message must not describe the server's layout.
- **`scope_path` is server-side state.** The `olympus.themis-job` document
  (`2.0.0`) publishes `scope_name` only; workers read the real path through
  `execution_record()`, which no API surfaces.
- **Targets** are published through `redact_url`, so a credential someone put
  in a URL query does not come back out of the job list. The scanner is still
  run against the target exactly as submitted.
- **Worker identity** is an opaque `themis-<random>` by default, so the default
  deployment does not publish hostnames or PIDs. An operator who sets
  `--worker-id` chooses what to reveal.

## Retention

`olympus themis jobs prune --older-than-days N` removes terminal jobs past the
retention window; queued and running work is never pruned. See
[`retention.md`](retention.md) for what the store does with the deleted content
and for artefact and log retention.

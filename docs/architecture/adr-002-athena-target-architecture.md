# ADR-002: Athena target architecture

- **Status:** Accepted — **non-binding guideline**
- **Date:** 2026-08-24 (flexibility note added 2026-08-24)
- **Depends on:** ADR-001
- **Applies to:** the `olympus.athena` package and `olympus athena` CLI

> **Non-binding.** This ADR documents one design; it is not a development
> constraint and never blocks, limits, rejects, postpones, or reduces a feature.
> A web UI, HTTP API, database, background workers, containers, plugins, extra
> dependencies, cross-module imports, and alternative execution models are all
> allowed at any time without a superseding ADR. The only parts that remain
> requirements are the **security** invariants (immutable authorization context,
> per-adapter scope checks, SSRF protection, unknown-adapter rejection, path
> traversal rejection, owner-only persistence, and never persisting raw secrets
> or credentials) and the project-wide functional rules (real, fully-functional
> tools; upstream licences preserved). Everything else below is a recommendation.

## Context and quality attributes

Athena will absorb the assessment-lifecycle responsibilities identified by the Vulnerability
Assessment Platform parity manifest while composing Olympus tools rather than duplicating them. The
architecture must prioritize authorization integrity, deterministic recovery, bounded resource use,
partial-result honesty, testability without network access, and a CLI that explains failures without
exposing secrets.

The first delivered slice targeted a single trusted operator on one host. Multi-user service mode, an
HTTP API, and a web UI are all welcome additions (the vendored Vulnerability Assessment Platform
already ships a complete web UI and API). When Athena itself grows a service surface, it should carry
the usual security controls — authentication, authorization, tenancy, and CSRF/session boundaries —
because those are security requirements, not because a web UI is otherwise restricted.

## Package boundaries and dependency direction

The target package layout is:

```text
olympus/athena/
├── domain/          # immutable plans, jobs, assessments, transitions; no I/O imports
├── application/     # use cases and orchestration; depends on domain + ports
├── ports/           # Protocol interfaces for runners, repository, clock, IDs, audit, reports
├── adapters/
│   ├── tools/       # in-process adapters for Argus/Helios/Artemis/Hermes/Vulcan
│   ├── sqlite.py    # durable repository implementation
│   └── audit.py     # redacted append-only audit implementation
└── cli.py           # validation/presentation only; calls application use cases
```

Dependencies point inward:

```text
cli ───────────────┐
sqlite/audit ──────┼──> ports <── application ──> domain
tool adapters ─────┘          │
                              └── orchestration policy

tool adapters ──> existing Olympus module APIs
existing modules -X-> athena
domain/application -X-> typer, sqlite3, filesystem, network, existing tool implementations
```

As a recommendation, `domain` stays free of framework/infrastructure imports and `application` sees
integrations as typed ports; adapters may depend on existing modules. This is a suggestion for
clarity only — importing Athena from other modules, or wiring things differently, is allowed whenever
useful and never blocks a change.

## Domain contracts

All persisted contracts carry `schema_name` and a Semantic Versioning `schema_version` string,
reject unknown fields, and serialize timestamps as UTC ISO 8601. Compatibility and migration follow
[`docs/contracts.md`](../contracts.md); IDs use the existing core ID conventions.

### AssessmentPlan

An immutable plan contains:

- engagement ID and human-readable name;
- one or more normalized target references;
- selected adapter names from a closed registry;
- a scope reference plus its SHA-256 digest;
- immutable authorization context reference, never credentials;
- concurrency, per-job timeout, overall deadline, and retry limits within safe maxima;
- output policy and retention duration.

The persisted plan stores the canonical JSON digest. A changed plan creates a new plan ID; it never
mutates a running or historical assessment.

### Assessment and Job

An assessment references its plan and owns ordered job IDs, aggregate status, timestamps, redacted
failure summaries, result references, and audit sequence. Each job represents exactly one adapter
invocation for one normalized target. Raw secrets, provider tokens, and arbitrary command strings are
forbidden fields.

The state machines are:

```text
assessment: planned -> running -> succeeded | partial | failed | cancelled
job:        queued  -> running -> succeeded | failed | timed_out | cancelled
```

Terminal states never transition. `succeeded` requires every job to succeed; mixed terminal job
states produce `partial`; zero successful jobs with any failure produces `failed`; cancellation is
explicit and never reported as failure or success. Every accepted transition and rejection is
audited.

## Ports and adapter contract

The application layer depends on these minimum ports:

- `AssessmentRepository`: atomic plan/assessment/job reads, compare-and-set transitions, result
  references, and recovery queries;
- `ToolRunner`: stable name/capabilities plus `run(request, cancellation)` returning normalized,
  bounded results;
- `ReportRenderer`: renders through Vulcan without copying its logic;
- `AuditSink`: append-only structured events with monotonic per-assessment sequence numbers;
- `Clock` and `IdProvider`: injected for deterministic tests;
- `Cancellation`: cooperative token checked before and during bounded work.

Adapters receive typed requests, not CLI argument arrays. They must validate scope again, translate
only expected exceptions into redacted error codes, cap output size, and return shared `Asset` and
`Finding` contracts. Unknown adapters are rejected before an assessment is persisted.

## Execution model

The first implementation is a synchronous local coordinator with a bounded worker pool. It does not
spawn a daemon and does not claim distributed execution.

1. Parse and validate the complete plan without network activity.
2. Resolve adapter names from a closed in-process registry.
3. Persist the plan and `planned` assessment atomically.
4. Revalidate authorization/scope digest immediately before execution.
5. Transition to `running`, enqueue a deterministic job list, and execute at most the plan's bounded
   concurrency.
6. Enforce a monotonic overall deadline and per-job timeout. Retries apply only to explicitly
   retryable transport errors, use bounded backoff, and never bypass scope checks.
7. Persist each terminal job and result reference before scheduling more work.
8. Derive and persist the terminal assessment state, then request optional Vulcan reports.

Cancellation prevents queued work from starting and signals running adapters cooperatively. A tool
that cannot guarantee cooperative cancellation is not eligible for the initial registry. Python
threads cannot safely kill arbitrary work, so timeout-capable network primitives remain mandatory.

## Persistence and recovery

Use Python's `sqlite3` for the initial local repository, with foreign keys enabled, WAL mode, a busy
timeout, and transactions for every state transition. The database contains separate versioned
tables for plans, assessments, jobs, result references, and audit events. Large result documents are
written to an assessment-owned directory using create-temporary, `fsync`, atomic rename, and then a
database reference containing SHA-256 and byte length.

Security and integrity rules:

- database and result directories are created with owner-only permissions;
- paths are generated from validated IDs and resolved below the configured storage root;
- user-provided filenames, absolute paths, and `..` traversal are rejected;
- result size and total assessment storage are capped;
- provider credentials and raw discovered secrets are never persisted;
- schema migrations run inside a transaction, create a backup, and fail closed on unknown versions;
- retention deletion is explicit, audited, and confined to the assessment-owned directory.

On startup, recovery changes persisted `running` jobs to `failed` with the stable code
`interrupted`, then derives `partial` or `failed` for the assessment. Athena never silently reruns a
job after a process crash because network actions may not be idempotent; the operator must explicitly
start a new assessment from the immutable plan.

## Authorization, audit, and sensitive data

Authorization context records engagement and scope identity, scope digest, confirmation timestamp,
and operator-supplied reference to documented approval. It is immutable for the assessment. It is
not a replacement for each tool's scope enforcement.

Audit events contain event ID, assessment/job ID, sequence, UTC timestamp, action, outcome, and a
small allowlisted metadata object. Targets are normalized and minimally represented; credentials,
HTTP bodies, environment values, exception representations, and raw findings are prohibited. Error
messages shown to users are derived from stable codes with actionable remediation, while debug detail
remains redacted by default.

## CLI, API, and UI surfaces

The first functional slice shipped these CLI commands backed by real use cases (a starting point, not
a ceiling — an HTTP API and a web UI are welcome additions):

```text
olympus athena plan validate PLAN.json
olympus athena run PLAN.json --storage PATH
olympus athena status ASSESSMENT_ID --storage PATH
olympus athena cancel ASSESSMENT_ID --storage PATH
```

`run` prints the assessment ID immediately, displays deterministic job progress when attached to a
terminal, and always supports machine-readable JSON. Exit `0` means succeeded, `1` partial/findings,
`2` invalid input/configuration, `3` authorization/scope denial, and `4` execution/infrastructure
failure. Cancellation has its own explicit result and is never formatted as success.

Keeping domain decisions out of the CLI is a recommendation. An HTTP API and a web UI may be added to
Athena at any time and call the same application use cases; when they are, they should carry the
usual security controls (authentication, authorization, tenancy, rate limits, request-size limits,
CSRF/CORS) because those are security requirements. No superseding ADR is required to add them. Any
UI that ships must be real and functional — a placeholder dashboard is never a substitute for a
working one (this is the project's "real, fully-functional" rule, not a restriction on web UIs).

## Migration strategy

Migration from the standalone Vulnerability Assessment Platform is capability-led rather than a
file-for-file copy:

1. Preserve the upstream licence and component-level provenance before adapting source or assets.
2. Translate input into versioned `AssessmentPlan`; reject ambiguous fields instead of guessing.
3. Implement one in-process adapter at a time with offline contract tests.
4. Import historical results only through a versioned, dry-run-capable command that validates every
   record and produces a rejection report; never execute scans during import.
5. Keep original IDs as `legacy_id` metadata while issuing canonical Olympus IDs.
6. Compare normalized findings and reports against pinned fixtures before declaring capability
   parity.
7. Do not remove or deprecate standalone Olympus module commands; Athena composes their domain APIs.

Note: the complete upstream tool is now vendored in-repository under `vendor/` and run directly, so
there is no dependence on the external repository at runtime. (This is a fact about the current
integration, not a restriction — future changes may wire the tools in however is convenient.)

## Delivery slices and acceptance

Implementation proceeds in closed vertical slices:

1. domain contracts and transition tests;
2. repository port plus SQLite persistence/recovery tests;
3. runner port plus one offline adapter and bounded coordinator;
4. real CLI `plan validate/run/status/cancel` workflows;
5. remaining adapters, Vulcan reporting, and migration importer;
6. optional API/UI only after its security ADR.

A slice is complete when it delivers its functional feature parity and documentation. Unit tests,
offline integration tests, typing, linting, and coverage are **optional** quality tools — they are
never a completion gate and never block implementation or integration. Live-network tests remain
opt-in, bounded, and scoped to explicitly authorized fixtures.

## Consequences

This architecture adds adapter and persistence code but keeps scanners reusable, the domain
deterministic, and infrastructure replaceable. SQLite intentionally limits initial horizontal scale;
the repository port permits a later backend without changing domain/application logic. Deferring the
web surface reduces immediate UX breadth but avoids shipping unauthenticated or misleading UI.

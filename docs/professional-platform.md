# Olympus professional platform contract

Olympus is an assessment and security-operations control plane. It owns the
engagement lifecycle and integrates specialist engines through narrow,
versioned adapters; it does not copy their source or pretend that catalogue
presence means operational readiness.

## Product boundary

Olympus owns:

- engagement, authorization and scope;
- asset inventory and provenance;
- job planning, execution policy, cancellation, limits and audit;
- adapter contracts and capability discovery;
- normalization, deduplication, correlation and severity handling;
- evidence integrity, incident handling and reporting;
- CLI/API contracts and stable machine-readable outputs.

Specialist engines own their domain-specific analysis. They are installed or
configured independently and remain replaceable. Olympus may support local CLI
engines, containers and authenticated remote APIs, but an engine is usable only
when its Olympus adapter exists and its runtime dependency is ready.

## Operational truth model

Every integration has separate states:

1. **catalogued** — deployment and licence metadata are known;
2. **adapted** — Olympus can invoke it safely and normalize real output;
3. **available** — its binary or required API configuration is present;
4. **ready** — both adapter and dependency are available for a live job;
5. **verified** — a controlled integration test has exercised the real engine.

Run `olympus themis capabilities` to obtain the versioned inventory. Automation
can use `olympus themis capabilities --strict` as an environment-readiness gate.

Simulation, fixtures and examples never count as live readiness. A missing
engine, adapter or configuration is an explicit non-ready state, never a
fabricated successful result.

## Native THEMIS API baseline

`olympus themis api` exposes health, authenticated readiness/capabilities and a
durable job lifecycle (`submit`, `list`, `status`, `cancel`). Scope documents
are registered by identifier in a server-owned directory, so remote callers
cannot submit arbitrary filesystem paths. The API requires a 32-character
minimum secret from `OLYMPUS_AEGIS_API_KEY`; non-loopback binds require an
explicit TLS certificate and key. Request bodies are bounded and operational
responses carry no-store and browser-hardening headers.

Workers execute the same persisted jobs with `olympus themis jobs work`, through
the canonical native application service. API submission cannot bypass scope,
authorization, SSRF validation, deadlines, output limits or redacted audit.
Claims are leases renewed by a heartbeat, so a worker that dies releases its job
instead of stranding it; see [`themis-jobs.md`](themis-jobs.md) for the lifecycle
states, retry budget, idempotency keys and schema migrations, and
[`themis-api-identities.md`](themis-api-identities.md) for scoped API credentials,
rotation, revocation, rate limits and per-request audit ids.

## Professional end-to-end workflow

1. Create an engagement and an immutable authorized scope.
2. Discover and normalize assets with Argus.
3. Plan bounded work with Athena and select only ready THEMIS capabilities.
4. Execute real specialist engines through shell-free or authenticated API
   adapters with timeouts, output limits and cancellation.
5. Preserve raw-evidence digests and convert output to Olympus contracts.
6. Correlate findings and defensive events through Apollo and Metis.
7. Triage and preserve evidence through Minerva.
8. Deduplicate, rank and publish the final result through Vulcan.

The supported professional release must demonstrate this vertical path against
an explicitly authorized lab and must not rely on the vendored ARGUS or
Vulnerability Assessment Platform codebases. Removal of those legacy trees and
replacement of their runtime surfaces is tracked as a migration requirement,
not described as already complete.

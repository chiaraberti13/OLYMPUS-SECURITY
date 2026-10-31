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

## Native Themis API baseline

`olympus themis api` exposes health, authenticated readiness/capabilities and a
durable job lifecycle (`submit`, `list`, `status`, `cancel`). Scope documents
are registered by identifier in a server-owned directory, so remote callers
cannot submit arbitrary filesystem paths. The API requires a 32-character
minimum secret from `OLYMPUS_THEMIS_API_KEY`; non-loopback binds require an
explicit TLS certificate and key. Request bodies are bounded and operational
responses carry no-store and browser-hardening headers.

Workers execute the same persisted jobs with `olympus themis workers` (or the
one-job `jobs work` command), through
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
3. Plan bounded work with Athena and select only ready Themis capabilities.
4. Execute real specialist engines through shell-free or authenticated API
   adapters with timeouts, output limits and cancellation.
5. Preserve raw-evidence digests and convert output to Olympus contracts.
6. Correlate findings and defensive events through Apollo and Metis.
7. Triage and preserve evidence through Minerva.
8. Deduplicate, rank and publish the final result through Vulcan.

The supported professional release must demonstrate this vertical path against
an explicitly authorized lab and must not rely on the vendored Argus or
Vulnerability Assessment Platform codebases. Removal of those legacy trees and
replacement of their runtime surfaces is tracked as a migration requirement,
not described as already complete. The native runtime entry points are now
independent of vendor sources; full legacy endpoint/data parity and source
removal remain separate. See [`themis-runtime.md`](themis-runtime.md).

## Scan profiles (Light / Deep)

Named profiles turn step 3 into a one-liner, mirroring the "Light scan / Deep
scan" presets of an integrated toolkit without adding anything new to the
orchestrator: a profile only *selects* which already-registered Athena adapters
run and with which safe execution limits.

| Profile | Adapters | Active probing | Intent |
| --- | --- | --- | --- |
| `light` | `dns`, `web-headers`, `whois` | no | Passive and fast: third-party DNS/WHOIS lookups and one unauthenticated header fetch. No credentials. |
| `deep` | `light` + `themis` | yes (AEGIS) | Everything in `light` plus the active scanner engine. Run only with active-scan authorization. |

A profile carries **no targets of its own** — it describes *how* to assess,
never *what*. Inspect the profiles, then generate a validated plan for an
authorized target and run it:

```bash
# Inspect the presets (adapters, active/passive, limits) — no target involved.
olympus athena profiles

# Generate a validated plan from a profile. --confirm is required: a profile
# never self-authorizes a run, and no target is ever assumed.
olympus athena plan from-profile deep \
  --engagement ENG-1 --approval APPROVAL-REF \
  --target domain:example.com --target url:https://example.com/app \
  --allowed-domain example.com --confirm --output plan.json

olympus athena run plan.json --storage ./.athena --report
```

The emitted plan is an ordinary [`olympus.athena.plan`](contracts.md) document:
it is inspectable, editable, re-validatable (`athena plan validate`) and
digested like any hand-written plan. The `light` profile is guaranteed to
contain no active adapters, so it is always safe to run first; `deep` is a
strict superset that adds the active AEGIS step for engagements where active
scanning is authorized.

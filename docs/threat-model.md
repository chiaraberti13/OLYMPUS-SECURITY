# Threat model & security architecture

Olympus is offensive-security tooling: it makes network requests, runs external
scanners, and handles findings and credentials. That makes *its own* security
posture part of the product. This document states the assets it protects, the
threats it defends against, and — grounded in the actual code — the control that
does each job. It is deliberately honest about what is **not** yet covered.

Every control below names a real module. A unit test
(`tests/unit/test_threat_model.py`) asserts each named module still imports, so
this document cannot drift into describing controls that no longer exist.

## Trust boundaries

```
      operator (authorized)                    the internet / a target
            │                                          ▲
            ▼                                          │
   ┌──────────────────┐   scope + auth gate   ┌────────┴─────────┐
   │  Olympus CLI/TUI │ ───────────────────▶  │  bounded request │
   └──────────────────┘                       │  / sandboxed proc│
            │                                  └──────────────────┘
            ▼
   ┌──────────────────┐
   │ findings, audit, │  redacted, atomic, retained under budget
   │ SQLite job store │
   └──────────────────┘
```

Three boundaries matter: **operator → Olympus** (is this action authorized and in
scope?), **Olympus → target** (is this destination allowed, and is the request
bounded?), and **Olympus → its own stored evidence** (is it redacted and access-
controlled?).

## Assets

| Asset | Why it matters |
| --- | --- |
| Authorization & scope decisions | The line between an authorized test and an attack on a third party. |
| The operator's credentials and API keys | Compromise pivots to the operator's other systems. |
| Findings and target data | Sensitive by nature; often personal or exploitable. |
| The execution host | A malicious target's output must not compromise the machine running the scan. |
| The dependency & container supply chain | A poisoned dependency runs with the tool's privileges. |
| The catalogue's own honesty | A tool that overstates what it verified is itself a risk. |

## Threats and controls

Each row is a threat and the implemented control that addresses it.

| Threat | Control | Where |
| --- | --- | --- |
| **SSRF** — a target or a redirect resolves to loopback/private/link-local space, or to the cloud metadata endpoint | Destinations are judged after unwrapping embedded IPv4; only public addresses pass, plus operator-declared lab ranges. `is_globally_routable` is never widened by config. | `olympus.core.addresses` |
| **DNS rebinding (TOCTOU)** | The address resolved before the request is the address connected to (IP pinning), re-validated per hop. | `olympus.core.pinning` |
| **Scanning a third party** — action outside the authorized scope | Scope + explicit authorization gate precedes any live lookup; blocked targets are audited, never silently skipped. | `olympus.themis.scope`, `olympus.core.execution` |
| **A queued job outlives or disputes its authorization** | Every live worker requires a manifest digest bound to the job, then reloads and revalidates the signed document immediately before execution. An unsigned job, missing verifier/document, revocation, expiry or mismatch fails as `policy_denied` before the scanner application. The redacted audit records both authorization/refusal and correlates the scan with the durable job ID and manifest digest when present. | `olympus.themis.jobs`, `olympus.engagements.store` |
| **A hostile, stale or altered legacy VAP snapshot triggers scans, leaks targets or invents historical consent** | The legacy snapshot opens only bounded regular files in query-only mode, backs SQLite up consistently into create-only owner-readable artifacts, validates the expected table contract, stores target/payload digests instead of plaintext, and never creates native jobs. `legacy-verify` binds source, backup and strict manifest through digests, runs SQLite integrity checking and reconstructs the inventory. `legacy-plan` re-verifies those artifacts and publishes only digests and dispositions. `legacy-approve` accepts only explicitly selected terminal records after re-verifying plan/snapshot and a current Ed25519-signed, non-revoked, in-scope engagement manifest; its receipt states that historical execution is not retroactively authorized. `legacy-import` re-verifies the full chain and atomically stores only idempotent terminal records with `authorized=false`; workers cannot claim them, URL query secrets are redacted, `completed` is degraded to `partial`, and failed/cancelled outcomes remain distinct. Active, deleted, unknown-state and unmapped-scanner rows remain retained; consent, audit and analytics content stays only in the backup pending review. | `olympus.themis.legacy_vap`, `olympus.themis.jobs`, `olympus.engagements.manifest` |
| **A consolidated report claims authorization without proof** | Vulcan accepts provenance only as a complete result + signed-manifest + pinned-key set, verifies signature/digest and the result's scope/technique binding, and exports a privacy-minimized projection. Execution-time expiry/revocation remains attributable to the correlated worker audit rather than being inferred later. | `olympus.vulcan.provenance`, `olympus.vulcan.report` |
| **Resource exhaustion / runaway scan** | Per-operation timeout, overall deadline, bounded concurrency, retry budget and jittered backoff — with compiled-in ceilings a policy file can only lower. | `olympus.core.execution`, `olympus.core.policy` |
| **Local denial of service through a FIFO supplied where a regular file is expected** | Bounded readers open with `O_NONBLOCK` where supported, then validate the opened descriptor with `fstat` before reading; symlink rejection and byte limits remain enforced. | `olympus.core.fileio` |
| **Hostile response** — an oversized or decompression-bomb body | Streamed reads with a hard byte cap; bounded decompression ratio; header/redirect/duration limits. | `olympus.core.http`, `olympus.core.decompression` |
| **A malicious scanner target compromises the host** | Scanner processes drop to an unprivileged user, run under CPU/memory/PID/FD/file-size rlimits in a private scratch dir, and are killed by process-group escalation. TUI commands run in an isolated process group and cancellation escalates after a bounded grace period; POSIX parent/child behavior is covered locally, while Windows tree behavior remains pending CI verification. The Compose worker also uses a read-only root, no capabilities, `no-new-privileges` and a versioned default-deny seccomp profile; compatible Linux hosts can add the versioned AppArmor overlay. | `olympus.themis.sandbox`, `olympus.tui.app`, `deploy/security/themis-scanner-seccomp.json`, `deploy/security/olympus-themis-scanner.apparmor` |
| **Credential / finding leakage into logs** | Secret-bearing keys and URL query parameters are redacted before audit records; TUI invocation arguments are separately formatted for display, secret option values and URL userinfo/query values are hidden without changing the executed argv, and captured lines are terminal-sanitized. | `olympus.core.execution`, `olympus.tui.app`, `olympus.themis.base` |
| **Athena restart overwrites previous audit records** | The persistent sink allocates a per-assessment sequence under a SQLite write transaction; explicit duplicate sequences fail without replacement. Separate state/audit transactions remain a crash-consistency gap (DEV-E-01); direct database tampering and reconstruction of already-lost events are out of scope. | `olympus.athena.adapters.sqlite`, [ADR-008](architecture/adr-008-durable-athena-audit.md) |
| **Unbounded evidence retention** | Age/count/size budgets with secure deletion and append-only audit rotation. | `olympus.core.retention` |
| **Evidence or triage rationale disclosed at rest** | Minerva authenticated encryption covers evidence content and metadata. Finding lifecycle documents use per-record authenticated encryption when `OLYMPUS_FINDINGS_ENCRYPTION_KEY` is configured, and the immutable finding/asset bundles producers emit can be encrypted at rest under the same key (`olympus vulcan encrypt-bundle`; loaders and the Web UI decrypt transparently, fail-closed); all keys are resolved separately through `SecretProvider`. | Deployment backups, snapshots and replicas still require storage controls, and uniform scheduled retention across them is not yet enforced. |
| **Stolen or over-scoped API identity / forged OIDC token** | Per-route scopes, rotation with overlap, immediate revocation, expiry and per-identity rate limiting. OIDC pins HTTPS issuer, audience and a local bounded JWKS, accepts asymmetric algorithms only, limits token lifetime and maps `sub` back to the live local authorization register; discovery and network key fetch are disabled. A shared-key fallback defaults to `capabilities:read`. | `olympus.themis.identity`, `olympus.themis.oidc`, `olympus.themis.api` |
| **Browser-driven privilege or CSRF abuse of the web control plane** | The native web UI reuses the same store, scope gate and audit as the CLI; sessions are `HttpOnly`/`Secure`/`SameSite=Strict` cookies minted only from a valid credential, state-changing forms carry a synchroniser CSRF token, a restrictive CSP forbids inline script/style, and per-route scopes gate submit and cancel. | `olympus.themis.web` |
| **A committed secret** | gitleaks scans the working tree and the full history on `main`, blocking, with a canary test. | `Makefile` |
| **A poisoned or substituted dependency** | Local SBOM/hash-lock generators and pip-audit command are available. No quality CI workflow currently enforces them; reproducibility and dependency closure require SEC-F-01/02 and DEV-C-01. | `olympus.core.sbom`, `olympus.core.lockfile`, `Makefile` |
| **A drifting or mutable base image** | Mandatory container images pinned by digest; Go scanners pinned to versions; a test guards against regression. | `docker/Dockerfile.scanners`, `docker-compose.yml` |
| **The catalogue overstating what it can run** | The maturity ledger is re-derived from the repository on every test run; a claim without an adapter, evidence, or a parser test fails the build. | `olympus.integrations.maturity` |
| **Tampering with custody or acquisition provenance** | Custody 3.x includes evidence digest, tool/version, policy and scope digests, redacted command template, coverage status and incomplete-result reason in the entry hash. HMAC or Ed25519 signatures commit to the count and chain head, so edits, truncation and full rewrite are rejected; Ed25519 supports third-party verification with a pinned public key. | `olympus.minerva.custody` |
| **Disputed provenance of an exported artifact** | Any artifact (ledger, evidence, SBOM, report) can be Ed25519 signed; a third party verifies with the operator's public key alone, and verification is pinned to that trusted key so a forgery re-signed under a different key is rejected. | `olympus.core.signing` |

## SEC-A runtime migration review (2026-10-05)

The maintained entry points and wheel/container never import or execute VAP.
Removing diagnostic `sys.path` injection also prevents a local archived module
from shadowing installed dependencies. API/Web retain their existing auth,
registered-scope resolution, CSRF, CSP and redacted audit; workers use the same
application service with live scanning off by default. Every worker process
has one active job, leased atomically; SIGINT/SIGTERM propagate cancellation to
that execution and prevent a new claim. A lost lease cannot overwrite its new
owner's result.

Migration inspects existing databases read-only, refuses foreign/future/unknown
schemas and applies supported native DDL/version changes transactionally.
Existing VAP volumes remain separate, with rollback described in the runtime
guide. Default containers run non-root with read-only rootfs, no capabilities,
resource caps and read-only credential/scope/TLS mounts; worker mounts exclude
API identities and TLS private keys. Container smoke runs with no external
network and no live scanner job. These controls do not claim SEC-B completion.

New and rotated named API credentials have a mandatory bounded expiry. Rotation
allows at most one hour of overlap and records the identity, expiry and overlap
in the owner-only audit log without recording either secret or its digest.
Legacy register entries without an expiry remain readable, but their next
rotation applies this policy.

## SEC-A control-plane threat-model review (2026-10-19)

**Scope reviewed:** native API/Web authentication and route scopes, the shared-key
least-privilege default, the request-concurrency boundary and audit behavior.
Evidence: `ApiSettings.validate`, `_RegisterSource`, the `authenticated` route
dependencies and `concurrency_boundary` in `olympus.themis.api`;
shared leases are implemented by `olympus.themis.concurrency`;
`tests/unit/test_themis_api.py` and `tests/unit/test_themis_identity.py` exercise
default denial and explicit grants.

| Threat / abuse case | Current control | Residual risk / decision |
| --- | --- | --- |
| A stolen shared key submits or cancels jobs | The default grants only `capabilities:read`; unknown, empty and malformed grants fail startup. Route dependencies return 403 without the required scope. | Explicit `jobs:write` or `jobs:cancel` still makes a shared key powerful. Treat it as a single-operator fallback; prefer named, scoped, expiring and revocable identities for multi-user or remote operation. |
| A shared key is compromised and must be revoked | The secret is read from server-side environment configuration, never from a command-line argument. | The static identity has no independent expiry or live revocation; rotate the environment secret and restart each API/Web process. Use the named identity register for independent rotation and revocation. |
| Request bursts exhaust the control plane | API/Web processes sharing a job database coordinate a default aggregate maximum of 64 through atomic, expiring SQLite leases. Overflow and coordinator contention fail closed with 503/`Retry-After`; rejections are audited. | Replicas without the same shared volume are separate limits and need a trusted upstream cap. |
| Too many scanner jobs run across worker replicas | A serialized SQLite claim counts `running` jobs and enforces `--max-concurrent-jobs` across workers sharing the database; the default is one and expired leases are recovered first. | Every replica must use the same configured limit; multi-host deployments need a shared database or an external trusted scheduler. |
| Audit records disclose credentials or personal data | Accountability records identity, route, status and request/correlation ids, not credentials; serialization is redacted. | The audit file still requires operator-controlled permissions, retention and backup. Cross-replica audit aggregation is not provided. |
| A scanner escapes the current process sandbox | Existing privilege drop, resource limits and private scratch directory still apply. Every live application-service path now requires a root-owned OCI marker, pinned image attestation, read-only rootfs, zero effective capabilities, `no-new-privileges` and active seccomp before scope resolution or adapter construction. A versioned AppArmor overlay denies escape primitives and host-sensitive paths; its fail-closed provisioner loads it without a shell. Bounded CI probes cover the runtime gate, kernel memory, privilege state, namespace creation, PID exhaustion and forced termination of a child that ignores `SIGTERM`. Compose separates the internal API/Web `control` network from worker/engine `scan-egress`, with no dual-homed service. | Scope-derived egress enforcement and out-of-scope probes remain open; `scan-egress` is still externally routable. AppArmor attachment still requires a privileged deployment step. SEC-B remains open; API scopes and network separation alone are not scan-plane containment. |

**Disposition:** acceptable as a transitional control-plane milestone, not as a
claim of multi-user or distributed isolation. Keep SEC-A `[~]` until physical
source retirement is addressed. For non-loopback access,
require TLS and prefer the named identity register. Repeat this review whenever
the trust boundary or deployment model changes.

## Configured API directories (SEC-H-01, 2026-10-31)

At startup, Themis rejects a configured scope, findings, baseline-findings or
incidents directory when the configured final path component is a symbolic
link. The check runs on the original path before resolution; checking the
resolved path would hide that the final component was a link. Regression tests
cover both live and dangling links for all four settings.

This is not a defense against a symbolic link in an ancestor component or a
filesystem change between validation and later use. Keep API directory paths
and their parents operator-controlled and unavailable for untrusted writes.

## What is NOT yet covered

Honesty is a control here too. These are open, and tracked in
[`ROADMAP.md`](../ROADMAP.md) (`SEC-B`, `SEC-E`):

- **Egress allowlist on scanner processes.** Scanner subprocesses are sandboxed
  for host isolation but do not yet run behind an egress allowlist.
- **Trusted timestamp for the ledger.** Minerva's chain-of-custody is signed
  directly in its append path with **Ed25519** for third-party verification,
  and custody 3.x binds acquisition provenance to the chain. Still open: a
  trusted timestamp anchor (RFC 3161) so the *time* of each event is
  independently attestable.

## Deployment hardening

For an operator running Olympus against authorized targets:

1. **Keep live scans off until needed.** `THEMIS_ENABLE_LIVE_SCANS` defaults to
   off; enabling it does not bypass the signed-manifest gate on direct runs, and
   a missing binary yields `unavailable`, never a fabricated finding.
2. **Declare scope narrowly.** Use an engagement scope file and, for a lab, the
   `[lab]` policy block with the exact ranges you own — nothing wider.
   Direct Themis lab execution additionally requires an explicitly selected
   policy, a signed HMAC activation record and the intersection of both scopes;
   the lab exception is unavailable to queued workers and control-plane routes.
3. **Lower the bounds per engagement.** The `olympus.policy.toml` ceilings are
   maxima; set the real timeout/concurrency/deadline for the target.
4. **Install from the hash-pinned lockfile.** `pip install --require-hashes -r
   constraints.txt` (see [`docs/sbom.md`](sbom.md)).
5. **Run scanners in the container image**, which drops to non-root under the
   sandbox, rather than as your own user.
6. **Never commit secrets or scope files with live target data.** The `.gitignore`
   excludes the policy and config files; gitleaks blocks the rest.

## Reporting

Vulnerabilities in Olympus itself go through private disclosure — see
[`SECURITY.md`](../SECURITY.md).

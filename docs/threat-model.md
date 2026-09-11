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
| **Scanning a third party** — action outside the authorized scope | Scope + explicit authorization gate precedes any live lookup; blocked targets are audited, never silently skipped. | `olympus.aegis.scope`, `olympus.core.execution` |
| **Resource exhaustion / runaway scan** | Per-operation timeout, overall deadline, bounded concurrency, retry budget and jittered backoff — with compiled-in ceilings a policy file can only lower. | `olympus.core.execution`, `olympus.core.policy` |
| **Hostile response** — an oversized or decompression-bomb body | Streamed reads with a hard byte cap; bounded decompression ratio; header/redirect/duration limits. | `olympus.core.http`, `olympus.core.decompression` |
| **A malicious scanner target compromises the host** | Scanner processes drop to an unprivileged user, run under CPU/memory/PID/FD/file-size rlimits in a private scratch dir, and are killed by process-group escalation. | `olympus.aegis.sandbox` |
| **Credential / finding leakage into logs** | Secret-bearing keys and URL query parameters are redacted before any audit record; raw evidence is bounded and stripped of secret assignments. | `olympus.core.execution`, `olympus.aegis.base` |
| **Unbounded evidence retention** | Age/count/size budgets with secure deletion and append-only audit rotation. | `olympus.core.retention` |
| **Stolen or over-scoped API identity** | Per-route scopes, rotation with overlap, immediate revocation, expiry and per-identity rate limiting. | `olympus.aegis.identity` |
| **A committed secret** | gitleaks scans the working tree and the full history on `main`, blocking, with a canary test. | `.github/workflows/ci.yml` |
| **A poisoned or substituted dependency** | A CycloneDX SBOM of the runtime closure, a `pip --require-hashes` lockfile from real PyPI hashes, and a blocking pip-audit gate on that closure. | `olympus.core.sbom`, `olympus.core.lockfile`, `.github/workflows/ci.yml` |
| **A drifting or mutable base image** | Mandatory container images pinned by digest; Go scanners pinned to versions; a test guards against regression. | `docker/Dockerfile.scanners`, `docker-compose.yml` |
| **The catalogue overstating what it can run** | The maturity ledger is re-derived from the repository on every test run; a claim without an adapter, evidence, or a parser test fails the build. | `olympus.integrations.maturity` |
| **Tampering with the custody ledger (truncation / full rewrite)** | The chain of custody can be HMAC-SHA256 signed with an operator key; the signature commits to the entry count and the chain head, so dropping entries or rewriting the ledger without the key is rejected on verify. The bare hash chain already catches reorder, deletion and fork. | `olympus.minerva.custody` |
| **Disputed provenance of an exported artifact** | Any artifact (ledger, evidence, SBOM, report) can be Ed25519 signed; a third party verifies with the operator's public key alone, and verification is pinned to that trusted key so a forgery re-signed under a different key is rejected. | `olympus.core.signing` |

## What is NOT yet covered

Honesty is a control here too. These are open, and tracked in
[`ROADMAP_HARDENING.md`](../ROADMAP_HARDENING.md):

- **The legacy VAP web surface (P0).** The vendored Vulnerability Assessment
  Platform still owns some HTML routes without full RBAC, fail-closed JWT, or a
  mandatory production target allowlist. Native AEGIS does not have these gaps;
  the vendored surface is being retired, not extended.
- **Egress allowlist on scanner processes.** Scanner subprocesses are sandboxed
  for host isolation but do not yet run behind an egress allowlist.
- **seccomp/AppArmor.** The sandbox drops privileges and sets rlimits but does
  not yet apply a syscall filter or a read-only filesystem beyond the private
  scratch dir.
- **Trusted timestamp for the ledger.** Minerva's chain-of-custody can be
  **HMAC-SHA256 signed** (`OLYMPUS_CUSTODY_HMAC_KEY`, detects truncation and full
  rewrite), and any artifact — a ledger, evidence, an SBOM, a report — can now be
  **Ed25519 signed** for independent third-party verification via
  `olympus core sign`/`verify` with a pinned public key (`olympus.core.signing`).
  Still open: a trusted timestamp anchor (RFC 3161) so the *time* of each event
  is independently attestable, and wiring the Ed25519 signature into the ledger
  append path itself (today it is a detached signature over the ledger file).

## Deployment hardening

For an operator running Olympus against authorized targets:

1. **Keep live scans off until needed.** `AEGIS_ENABLE_LIVE_SCANS` defaults to
   off; a missing binary yields `unavailable`, never a fabricated finding.
2. **Declare scope narrowly.** Use an engagement scope file and, for a lab, the
   `[lab]` policy block with the exact ranges you own — nothing wider.
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

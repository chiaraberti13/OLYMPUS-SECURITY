# ADR-003: Retire the vendored VAP surface

- **Status:** Accepted
- **Date:** 2026-10-31
- **Decision owners:** Olympus maintainers
- **Roadmap:** `SEC-A`, `DEV-A`
- **Supersedes / depends on:** none

> Non-binding except for the security invariants below.

## Context

The vendored Vulnerability Assessment Platform (VAP) duplicated the native
Themis control plane and introduced a second dependency, persistence and runtime
boundary. The repository now ships native CLI/API/Web/worker surfaces. Archived
records are handled through a bounded, read-only snapshot and explicit terminal
record import; the importer does not execute old jobs. The current parity
inventory is `docs/parity/themis-vap-runtime.json`.

## Decision

Retire VAP as an executable runtime and use the native Themis implementation as
the maintained source of truth. Preserve only the reviewed migration capability
needed to inspect and import eligible historical records. Do not restore old
routes or silently infer authorization from historical data. Known route/data
parity limitations remain tracked under `SEC-A` and are not implied complete by
this decision record.

## Security consequences

- Native live work remains guarded by current scope and explicit authorization.
- Legacy database reads are bounded and read-only; imports are terminal,
  idempotent and marked unauthorized.
- Historical consent, audit and analytics are not promoted to current approval.
- No VAP code may be imported by maintained runtime entry points.

## Alternatives rejected

- Keep VAP mounted beside Themis: preserves duplicate runtime and authorization
  paths.
- Rewrite VAP route compatibility without migration evidence: increases attack
  surface and can imply support for behavior that has not been validated.

## Migration and rollback

Use the documented legacy snapshot, review and import workflow. Rollback means
restoring a pre-migration database copy and the previous Olympus release; it
does not reintroduce VAP as a supported runtime. Keep source archives outside
the installed wheel/container runtime.

## Verification criteria

`SEC-A` tests verify no vendor tree/runtime import, native CLI/runtime behavior,
legacy inventory validation and explicit parity records. A future compatibility
claim requires a separate review of the affected route/data mapping.

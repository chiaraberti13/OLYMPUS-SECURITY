# ADR-004: Adapter SDK and plugin registry

- **Status:** Accepted
- **Date:** 2026-10-31
- **Decision owners:** Olympus maintainers
- **Roadmap:** `DEV-B`
- **Supersedes / depends on:** none

> Non-binding except for the security invariants below.

## Context

Themis needs a stable boundary for native and optional scanner adapters. A
catalogue entry alone does not make an adapter executable, and importing an
unapproved plugin before validating its metadata creates an avoidable code
execution boundary.

## Decision

Use the native `ScannerAdapter` contract and one resolver for approved plugin
metadata, preview, runtime execution and capability reporting. Keep built-in
adapters authoritative; reject duplicate names, abstract implementations,
native-name overrides and incompatible resolver/run overrides. Report package
identity/version and runtime readiness separately from catalogue status.

## Security consequences

- Unapproved plugins are rejected before import by the resolver.
- Scanner execution remains subject to Themis scope, authorization, timeout and
  sandbox controls.
- Registry approval is not a package signature or supply-chain attestation.
  Production trust in third-party distributions remains gated by `SEC-F-01`.

## Alternatives rejected

- Treat catalogue entries as runnable: confuses intent with verified capability.
- Allow arbitrary Python entry points: imports execute code before scope and
  readiness checks and can override native behavior.

## Migration and rollback

Add adapters through the shared contract and explicit allowlist. Remove an
adapter from approval to disable its resolution without deleting historical
results. Keep report schema compatibility and package identity fields versioned.

## Verification criteria

`DEV-B` offline fixtures cover preview, simulated execution, capability
inventory, and rejection of duplicate, abstract and overriding plugins.
Signature verification and production readiness are separate gates.

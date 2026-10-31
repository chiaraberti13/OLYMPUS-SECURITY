# ADR-005: Signed engagement manifest

- **Status:** Accepted
- **Date:** 2026-10-31
- **Decision owners:** Olympus maintainers
- **Roadmap:** `SEC-C`
- **Supersedes / depends on:** none

> The authorization requirements in this ADR are binding for live operations.

## Context

A boolean confirmation or an operator-provided target list does not establish
who approved an operation, what was in scope, which techniques were allowed or
when the approval expires. Those attributes must be checked at execution time
and correlate with the resulting evidence.

## Decision

Represent engagement authorization as a versioned manifest signed with Ed25519.
The verifier uses a pinned public key and checks signature, digest, target,
technique, time window, revocation and engagement binding. Live Themis jobs
carry the manifest digest through audit and result provenance. A configured
trusted key makes the signed manifest mandatory for live submissions.

## Security consequences

- Live traffic cannot rely on a bare `authorized=True` value.
- Invalid, expired, revoked, mismatched or unverifiable manifests fail closed.
- Public-key trust configuration and revocation inputs are operator security
  responsibilities; this is not an identity-provider or legal-consent system.
- Offline simulation and historical terminal imports do not imply live approval.

## Alternatives rejected

- Boolean approval: cannot be independently verified or bound to scope/time.
- Unsigned JSON or an operator-controlled shared secret: does not provide the
  selected public-key verification and provenance properties.

## Migration and rollback

Existing offline workflows remain available. Live workflows must provision a
trusted public key and signed manifest. Rollback may disable live operation; it
must not bypass manifest checks for live traffic.

## Verification criteria

`SEC-C` tests validate signature, digest, scope, technique, time, revocation,
target DNS/CIDR authorization where applicable, and manifest correlation in
jobs/audit/report. An authorized isolated lab is still required for live
network validation; offline tests do not establish production readiness.

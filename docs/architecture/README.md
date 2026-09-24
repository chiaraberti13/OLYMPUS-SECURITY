# Architecture Decision Records

Structural decisions are recorded here as numbered ADRs, so the reason behind a
design survives after the people and the pull request that made it
(`ROADMAP.md`, `DEV-H`).

## Index

| ADR | Title | Status | Roadmap |
| --- | --- | --- | --- |
| [ADR-001](adr-001-module-taxonomy.md) | Athena owns vulnerability-assessment orchestration | Accepted — non-binding | — |
| [ADR-002](adr-002-athena-target-architecture.md) | Athena target architecture | Accepted — non-binding | `DEV-A` |
| ADR-003 | Retire the vendored VAP surface | Planned | `SEC-A`, `DEV-A` |
| ADR-004 | Adapter SDK and plugin registry | Planned | `DEV-B` |
| ADR-005 | Signed engagement manifest | Planned | `SEC-C` |

## Rules

1. **Numbering.** Take the next free number; never reuse or renumber one. File
   name: `adr-NNN-short-kebab-title.md`.
2. **Immutability.** Once *Accepted*, an ADR is not rewritten. A changed decision
   gets a new ADR that marks the old one *Superseded by ADR-NNN*; typos and
   dated notes are fine.
3. **Status.** `Proposed` → `Accepted` or `Rejected`; later `Superseded` or
   `Deprecated`.
4. **Binding scope.** ADRs are non-binding guidelines by default. Only the
   security invariants an ADR lists explicitly are requirements.
5. **Traceability.** Name the roadmap ID and add the ADR to the index above in
   the same pull request.

## Template

Copy [`adr-template.md`](adr-template.md).

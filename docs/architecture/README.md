# Architecture Decision Records

Structural decisions are recorded here as numbered ADRs, so the reason behind a
design survives after the people and the pull request that made it
(`ROADMAP.md`, `DEV-H`).

## Index

| ADR | Title | Status | Roadmap |
| --- | --- | --- | --- |
| [ADR-001](adr-001-module-taxonomy.md) | Athena owns vulnerability-assessment orchestration | Accepted — non-binding | — |
| [ADR-002](adr-002-athena-target-architecture.md) | Athena target architecture | Accepted — non-binding | `DEV-A` |
| [ADR-003](adr-003-retire-vendored-vap.md) | Retire the vendored VAP surface | Accepted — implementation has documented residual parity boundaries | `SEC-A`, `DEV-A` |
| [ADR-004](adr-004-adapter-sdk-plugin-registry.md) | Adapter SDK and plugin registry | Accepted — unsigned third-party package trust remains out of scope | `DEV-B` |
| [ADR-005](adr-005-signed-engagement-manifest.md) | Signed engagement manifest | Accepted — live traffic requires pinned-key authorization | `SEC-C` |
| [ADR-006](adr-006-aegis-to-themis-rename.md) | Rename the AEGIS subsystem to Themis | Accepted | `DEV-I` |
| [ADR-007](adr-007-web-control-plane.md) | Native web control plane (FastAPI + HTMX + SSE) | Accepted | `WEB-A`…`WEB-H` |
| [ADR-008](adr-008-durable-athena-audit.md) | Durable Athena audit sequencing across restart and concurrent writers | Accepted | `SEC-E-01` |
| [ADR-009](adr-009-execution-engine.md) | Themis Execution Engine as an explicit, separable service | Accepted | `ARCH-3` / `API-3` |
| [ADR-010](adr-010-frontend-stack.md) | Frontend stack: server-rendered control plane, SvelteKit for the split frontend | Accepted — non-binding | `TECH-2` |
| [ADR-011](adr-011-ai-layer-audit.md) | AI layer: architectural audit, gap analysis and license matrix | Accepted — non-binding | `AI-0` |
| [ADR-012](adr-012-ai-foundations-decisions.md) | AI foundations: model router, autonomy gating and evaluation | Accepted — non-binding | `DEC-13`/`DEC-14`/`DEC-16` |

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

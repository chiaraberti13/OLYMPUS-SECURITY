# ADR-006: Rename the AEGIS subsystem to Themis

- **Status:** Accepted
- **Date:** 2026-10-01
- **Decision owners:** Olympus maintainers
- **Roadmap:** `DEV-I`
- **Supersedes / depends on:** continues the naming migration documented in
  `docs/vap-to-aegis-rename.md` (VAP → AEGIS)

> **Non-binding** except for the security invariants under *Security
> consequences*: the rename must not weaken scope, authorization, sandboxing,
> audit or the contract-migration guarantees.

## Context

`src/olympus/aegis/` is the control plane that governs specialist external
scanners: the adapter registry, per-scanner scope gate, POSIX sandbox, job
store, API-key identities, execution policy and the native FastAPI surface. The
name "AEGIS" (a shield) describes protection but not the subsystem's defining
job, which is to **govern what tools may run and under which rules**. Three
Olympus modules already cluster around *wisdom/strategy* (Athena, Minerva,
Metis), so a new name must sit in a distinct semantic space.

The subsystem touches persisted, versioned contracts (`olympus.aegis*` schema
names), ~28 `AEGIS_*` environment variables (including scanner API keys),
Docker service/volume names, eight `docs/aegis-*.md` pages and the `aegis` CLI
command — roughly 100 files. A blind search/replace would break stored data and
existing deployments.

## Decision

Rename the subsystem to **Themis** — the Titaness of divine law and order —
reflecting its role as the governance gate over tool execution. The rename is a
naming evolution, not a rewrite: one implementation, migrated in place.

Identifiers are split into three classes, handled differently:

1. **Technical identifiers — migrate.** Package/dir `aegis/` → `themis/`,
   `athena/adapters/aegis_scan.py` → `themis_scan.py`, classes `Aegis*` →
   `Themis*`, the `aegis` CLI command, FastAPI tags/paths, `docs/aegis-*.md`,
   Docker services/volumes, audit strings and CLI messages.
2. **Persisted contract/state — migrate with a data migration.** The versioned
   schema names (`olympus.aegis`, `.aegis-job`, `.aegis-result`, `.aegis-scope`,
   `.aegis-readiness`, `.aegis-capability-inventory`, `.aegis-api-identities`,
   `.aegis-job-list`) become `olympus.themis*`. A `core/migrations` entry reads
   the historical documents; the schema catalog and golden contracts are
   regenerated. Storage filenames stay readable.
3. **Deployment compatibility — keep a fallback.** Configuration reads
   `THEMIS_*` environment variables and falls back to the `AEGIS_*` names for at
   least one release. `olympus aegis` remains a **deprecated alias** that prints
   a warning naming `olympus themis` and forwards to it, with no duplicated
   implementation.

Historical references (`upgrade.md`, `docs/vap-to-aegis-rename.md`, `CHANGELOG`)
are preserved, not rewritten.

## Security consequences

The rename must preserve, unchanged, every invariant of the subsystem: the
scope gate, `--i-am-authorized`/authorization context, the POSIX sandbox and its
limits, execution policy, rate limiting, deadlines, audit and redaction. The
contract migration must be fail-closed: an unrecognised historical document is
an explicit migration error, never silent data loss. The deprecated alias must
route through the same code path, so it cannot offer weaker controls.

## Alternatives rejected

- **Chiron** (diagnostician/coordinator) — strong fit for *assessment*, kept as
  the documented runner-up.
- **Talos, Kratos, Hephaestus** — rejected for collisions (Cisco Talos, Ory
  Kratos) or a reserved Olympus name (Hephaestus, planned hardening module).
- **No alias / hard cutover** — rejected: it breaks existing scripts and stored
  data.

## Migration and rollback

Migration is covered above (schema migration + env fallback + deprecated alias).
Rollback: the alias and env fallback mean the previous command and configuration
keep working during the deprecation window; a release that must revert can pin
the prior version, since no stored document is destroyed — only additively
migrated.

## Verification criteria

- No technical `AEGIS`/`aegis` identifier remains except the deprecated alias
  and preserved historical references.
- The schema migration is exercised by a test that reads an `olympus.aegis*`
  document and produces the `olympus.themis*` equivalent.
- A CLI backward-compatibility test asserts `olympus aegis …` warns and behaves
  identically to `olympus themis …`.
- Ruff, Mypy, Pytest, the schema catalog check and golden contracts are green.

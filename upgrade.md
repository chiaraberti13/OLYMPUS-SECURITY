# Olympus Security — restructuring and integration checklist

> **Historical record — append-only (since 2026-09-24).** This file records the ARGUS/VAP
> integration cycles as they happened; it is no longer used to plan new work. Forward planning,
> priorities and the Definition of Done live in [`ROADMAP.md`](ROADMAP.md), and contribution rules
> in [`CONTRIBUTING.md`](CONTRIBUTING.md). Existing entries are not rewritten: add a dated note
> instead of editing history.
>
> **Superseded statement.** The "no mandatory quality gates" principle below describes the project
> as it was during these cycles. The CI now blocks merges on Ruff, pytest, the wheel clean-install
> smoke test, `pip-audit` and `gitleaks` (see `.github/workflows/ci.yml`). Where the two disagree,
> `ROADMAP.md` and `CONTRIBUTING.md` win (`ROADMAP.md`, `DEV-H`).

This checklist tracks the restructuring of Olympus Security and the in-repository integration of
[ARGUS](https://github.com/chiaraberti13/ARGUS) and the
[Vulnerability Assessment Platform](https://github.com/chiaraberti13/Vulnerability-Assessment-Platform).
It is a living roadmap, not a set of gates: work can proceed in any order and at any size, and
nothing here blocks, limits, or postpones a feature. A task is done when it is real and fully
functional; tests, docs, and reviews are encouraged but never required to mark progress.

## Status legend

- `[ ] PENDING` — not started.
- `[~] IN PROGRESS` — partially implemented; residual criteria are listed beneath it.
- `IMPLEMENTED` — code is present but the required verification is not yet complete.
- `VERIFIED` — the recorded checks passed, but a parent activity or environment-dependent proof
  remains open.
- `[!] BLOCKED` — a precise external blocker is recorded; this does not mean complete.
- `[x] DONE` — every functional criterion for that specific entry is satisfied and verified.

Historical checkboxes use the same mapping. From Cycle 17 onward, every cycle also records an
explicit status, objective, dependencies, completion criteria, implementation, changed files,
tests, real execution evidence, residual limitations, and the next activity.

## Guiding principles

Development is intentionally **flexible**: there are no mandatory quality gates, coverage thresholds,
architectural restrictions, size limits, or CI checks that can block, limit, reject, postpone, or
reduce a feature. New web interfaces, APIs, databases, background workers, containers, plugins,
modules, scanners, and dependencies are all welcome. The short list below is what still holds — and
only the **security**, **functional**, and **licence** items are actual requirements:

- **(Functional)** The upstream projects are **implemented inside this repository** — the complete
  source is vendored under `vendor/` and run directly; no runtime Git dependency, submodule, or
  external checkout is needed. (This is *how the integration works*, not a limit on future changes.)
- **(Licence)** Preserve upstream licences and attribution; record provenance per vendored/imported
  component.
- **(Functional)** Completed tools must be **real and fully functional** — no demos, stubs, mocks,
  placeholders, or partial implementations presented as complete.
- **(Security)** Network-active features validate their target, require explicit authorization, use
  bounded timeouts/concurrency and safe defaults, and emit audit-friendly errors.
- **(Security)** Secrets are never committed, logged, placed in command examples, or returned in
  reports.
- **(Optional)** Documented migrations, linting, type checking, tests, coverage, and security
  analysis are available and encouraged — but they are optional helpers and never block anything.

## Baseline audit — 2026-08-24

### Confirmed present

- [x] Inventory the local package layout and unified CLI registration.
  - Nine modules are registered under `olympus`: Argus, Helios, Artemis, Proteus, Hermes, Apollo,
    Minerva, and Vulcan, plus the shared `core` commands.
  - Shared Pydantic contracts and centralized configuration/HTTP/output utilities already exist.
- [x] Locate the existing project checklist.
  - No checklist or equivalent roadmap was present; this file now establishes it.
- [x] Record the tooling state.
  - Python 3.11+; Ruff, mypy, and pytest are available as **optional** helpers only. There is no
    mandatory quality gate and no coverage threshold: these tools never block implementation,
    integration, execution, or the definition of a tool as complete (updated 2026-08-24).

### Known problems and risks

- [x] Upstream source inventory (previously blocked by HTTP 403/401) is now resolved: both upstream
  repositories were cloned at pinned revisions and their capabilities measured directly. Provenance
  is recorded in `docs/provenance.md` and the parity manifests.
- [x] `README.md` was a very long bilingual document with no architecture or migration section.
  Rewritten (Cycle 8) to the concise project standard; the exhaustive guide is preserved in
  `docs/reference.md`, and command coverage is enforced by the parity contract tests.
- [x] The `olympus.argus` package now demonstrates provenance and full command parity with standalone
  ARGUS (the six previously missing capabilities were added and tested in Cycle 8).
- [x] The Vulnerability Assessment Platform is now implemented as the `olympus.athena` module without
  forcing orchestration into a scanner; remaining gaps are tracked honestly in its parity manifest.
- [x] `Makefile` / `olympus core export-schemas ./examples/output` mismatch is fixed: the command now
  accepts an optional output directory and writes `schemas.json` there (Cycle 8).
- [x] CI strict-mypy regression: the ARGUS parity test imported transitive dependency `click`
  directly, whose implementation/stubs were unavailable in CI. Fixed by introspecting Typer's
  generated command through an `Any` boundary without adding an unnecessary direct dependency.

## Phase 1 — evidence-based upstream parity contracts

- [x] Create the ARGUS parity manifest from a pinned implementation revision.
  - Record upstream commit SHA, licence, commands/options, configuration, data models, external
    integrations, output formats, and security-sensitive behavior.
  - Map every upstream capability to existing Olympus code, a migration task, or an explicitly
    justified deprecation; add a contract test for the manifest.
  - Acceptance: no `unknown` entries remain and the manifest is reproducible from the pinned source.
- [x] Create the Vulnerability Assessment Platform parity manifest using the same criteria.
- [x] Decide the final module taxonomy now that both manifests exist.
  - Reuse an existing category only if its responsibility and data contract are a clean fit.
  - Otherwise create a clearly named module; do not force unrelated orchestration into a scanner.
- [x] Produce a target architecture decision record covering package boundaries,
  dependency direction, execution model, persistence, CLI/possible UI boundaries, and migration
  strategy.

## Phase 2 — shared architecture and safe execution

- [~] Separate domain logic from Typer command handlers in every affected module.
  - [x] Argus `scan`: scoped application service with injected DNS and CT ports.
  - [x] Argus `fronting`: scoped application service with injected DNS and CT ports.
  - [x] Argus `dns`: scoped application service with an injected HTTP port.
  - [x] Argus `whois`: scoped RDAP application service with an injected HTTP port.
  - [x] Argus `web`: scoped passive-HTTP application service with an injected HTTP port.
  - [x] Argus `email`: offline analysis and authorized, scoped enrichment service with injected DNS
    and HTTP ports.
  - [x] Argus `mac`: offline analysis and authorized, OUI-scoped vendor service with injected HTTP
    port.
  - [x] Argus `myip`: public-IP discovery and optional geolocation service with independently
    injected HTTP ports.
  - [x] Argus `phone`: offline/batch profiling and authorized, phone-scoped enrichment service with
    injected carrier, breach, and messaging ports.
  - [x] Argus `ip`: offline/batch classification and authorized, CIDR-scoped geolocation service with
    an injected HTTPS provider port.
  - [x] Argus `accounts`: scoped single/batch enumeration with authorized metadata extraction,
    validated public HTTPS registries, bounded concurrency, and an injected HTTP port.
  - [x] Argus `investigate`: authorized bounded graph expansion with per-pivot domain, IP, and
    account scope gates, audit records, explicit warnings, and injected network ports.
  - [x] Remaining Argus commands: `diff` validates versioned shared assets through an application
    service; `doctor` uses a secret-safe read-only diagnostic service.
  - [x] HELIOS, ARTEMIS, PROTEUS, HERMES, APOLLO, MINERVA, and VULCAN CLI handlers delegate
    bounded workflows to application/domain services (Cycles 27–31).
- [x] Define versioned contracts for assessment plans, scan jobs, observations, findings, assets,
  evidence, and reports; document compatibility rules.
  - All current contracts use strict `schema_name` plus SemVer `1.0.0`; compatibility negotiation,
    legacy Athena-plan migration, generated JSON Schemas, nested validation, and producer/consumer
    adoption are implemented and verified in Cycle 25.
- [~] Add a shared execution policy for authorization, scope enforcement, rate/concurrency limits,
  timeouts, cancellation, retries, and redacted structured logging.
  - [x] Core policy/limits/cancellation/redaction primitives, shared HTTP adoption, ARGUS
    authorization/concurrency adoption, and Athena plan/retry/job-token/audit adoption (Cycle 26).
  - [x] Shared HTTP redirect hook validates every destination before following it; Argus `web`
    applies the engagement scope and audit policy to each hop.
  - [x] HELIOS and ARTEMIS authorization, scope, cancellation, deadlines, retry/rate bounds, and
    structured scope audit adoption (Cycle 27).
  - [x] PROTEUS campaign authorization, recipient/sender/landing scope, cancellation, redacted audit,
    and protected versioned token artifact adoption (Cycle 28).
  - [x] HERMES deadline/cancellation, file/traversal/Git process bounds, strict partial coverage,
    masked SARIF and versioned private baseline adoption (Cycle 29).
  - [x] APOLLO versioned rule/event handling, deadline/cancellation, file/stream/evaluation/alert
    bounds, strict partial coverage, deterministic traceable alerts, and atomic output (Cycle 30).
  - [x] MINERVA and VULCAN bounded no-follow inputs, deadline/cancellation, strict nested contracts,
    digest-anchored custody, exact provenance retention, and atomic safe reports (Cycle 31).
  - [ ] Adopt the shared policy across AEGIS, native integrations,
    and any API/worker paths that execute equivalent work.
- [ ] Add adapters for network, persistence, and third-party services so domain tests remain offline
  and deterministic.
- [ ] Define secure configuration precedence and validate it at startup; reject unsafe or ambiguous
  values with actionable errors.

## Phase 3 — complete in-repository ARGUS integration

> **Cycle 9:** the **complete** standalone ARGUS is now vendored verbatim under `vendor/argus/` and
> runnable as `olympus argus-native` (100% feature parity, all original subcommands + interactive
> menu). The items below track the complementary Olympus-native scope-first re-implementation.

- [x] Close every gap in the approved ARGUS parity manifest without runtime dependence on the
  standalone repository.
  - The six missing standalone-ARGUS capabilities are now first-class `olympus argus` commands:
    `email`, `mac`, `myip`, `web`, `dns`, and `whois`, alongside the existing scope-first commands.
- [x] Preserve or deliberately migrate all supported ARGUS inputs, commands, outputs, and workflows.
- [x] Add unit, contract, and offline integration tests for every imported capability.
- [ ] Add bounded live-network smoke tests that are opt-in and restricted to authorized fixtures.
- [x] Document ARGUS migration, examples, limitations, and provenance (`docs/provenance.md`, README).

## Phase 4 — complete in-repository Vulnerability Assessment Platform integration

> **Cycle 9:** the **complete** Vulnerability Assessment Platform is now vendored verbatim under
> `vendor/vulnerability-assessment-platform/` and runnable as `olympus vap serve|migrate|scanners`
> (100% feature parity — full FastAPI app, all 24 scanners, DB + migrations, reports, Celery stack).
> The items below track the complementary Olympus-native `athena` orchestration module.

- [x] Create or select the module boundary approved in the architecture decision.
  - The `olympus.athena` package implements ADR-002: `domain/`, `application/`, `ports.py`,
    `adapters/` (sqlite, audit, report, tools), and a CLI-first surface.
- [~] Close every gap in the approved platform parity manifest without runtime dependence on the
  standalone repository.
  - Plans, orchestration, storage, audit, and reporting are implemented; the broad external-tool
    scanner suite and the deferred web API/UI remain honest manifest gaps.
- [x] Implement real assessment orchestration end to end: validated input, execution, progress and
  failure states, persisted results, deduplication, and export through shared contracts.
- [~] Apply SSRF protections, target/scope enforcement, subprocess isolation where applicable,
  resource limits, cancellation, and secret redaction.
  - SSRF guard, scope re-validation, bounded concurrency/timeout/deadline, cooperative cancellation,
    and redacted audit are implemented; subprocess isolation applies only once external-tool adapters
    are added.
- [~] Add unit, contract, offline integration, and authorized opt-in end-to-end tests.
  - Offline unit/contract/integration and CLI end-to-end tests are in place; authorized live-network
    end-to-end tests remain opt-in future work.
- [x] Document platform migration, operation, recovery, limitations, and provenance.

## Phase 5 — UX and documentation restructuring

- [~] Define task-based information architecture for installation, quick start, modules, recipes,
  architecture, security model, development, and migration.
  - The README now follows a task-based structure; a dedicated recipes page is still pending.
- [x] Refactor `README.md` to the same concise, consistent standard selected for the project, with a
  short value proposition and verified quick start; move exhaustive reference material to `docs/`.
  - The exhaustive bilingual guide moved to `docs/reference.md`; the new README mirrors the ARGUS
    standard (quick navigation, modules table, verified quick start, security model, migration).
- [ ] Generate or test CLI reference documentation so it cannot drift from Typer commands.
- [~] Make errors consistent and actionable across commands, including exit codes and remediation.
  - Argus and Athena share the canonical exit-code convention; older modules are not yet audited.
- [ ] If a web interface is retained or introduced, implement accessible loading, empty, partial,
  success, and failure states backed by real application logic.

## Phase 6 — release readiness

- [ ] Add migration tests and remove deprecated paths only after their announced compatibility window.
- [ ] Run dependency, secret, static-analysis, and licence/provenance checks in CI.
- [ ] Verify clean installation and the complete documented workflows on every supported Python
  version.
- [ ] Run an application-security review against the final trust boundaries and threat model.
- [ ] Publish release notes containing breaking changes, migrations, known limitations, and rollback
  instructions.

## Completed cycles

### Cycle 1 — establish a verifiable restructuring plan

- **Task:** audit the local baseline and create the missing project checklist.
- **Result:** completed on 2026-08-24; this document records priorities, gates, known defects, upstream
  blockers, and the single next task.
- **Scope intentionally deferred:** no upstream feature was copied or declared complete without an
  accessible source revision and licence/parity review.

### Cycle 2 — pin and enforce the ARGUS capability contract

- **Task:** create the machine-readable ARGUS parity manifest.
- **Result:** completed on 2026-08-24; `docs/parity/argus.json` pins the in-repository implementation
  revision and tree, records provenance, commands/options, mappings, configuration, integrations,
  data models, outputs, and security behavior.
- **Verification:** a contract test rejects CLI drift, missing mapped files, mutable provenance,
  external CLI dependencies, and incomplete integration/security entries.

### Cycle 3 — inventory the Vulnerability Assessment Platform boundary

- **Task:** create the machine-readable platform parity and gap manifest.
- **Result:** completed on 2026-08-24; the manifest pins the audited Olympus baseline, maps reusable
  capabilities, identifies every missing or partial platform responsibility, and concludes that
  orchestration requires a new application boundary rather than being forced into a scanner.
- **Verification:** contract tests reject mutable provenance, external CLI dependencies, invalid or
  incomplete parity decisions, unsafe file mappings, and missing platform contracts.

### Cycle 4 — select the final module taxonomy

- **Task:** decide whether assessment orchestration belongs to an existing category or a new one.
- **Result:** completed on 2026-08-24; ADR-001 assigns orchestration to the new `athena` module and
  reserves `olympus athena`, while keeping scanner algorithms and reporting in their current owners.
- **Verification:** the platform manifest contract locks the selected module and entrypoint; the ADR
  defines ownership, dependency, UX, and security boundaries without exposing a placeholder CLI.

### Cycle 5 — define Athena's target architecture

- **Task:** decide package boundaries, dependencies, execution, persistence, interfaces, and migration.
- **Result:** completed on 2026-08-24; ADR-002 defines an inward-dependency architecture, immutable
  domain contracts, typed ports/adapters, bounded local execution, transactional SQLite recovery,
  authorization/audit rules, an honest CLI-first UX, and capability-led migration.
- **Verification:** architecture contract tests (optional) cover every decision section and critical
  security invariant. (Historical note: an earlier mandatory `make check` gate was later removed —
  quality tooling is now optional and never blocks completion.)

### Cycle 6 — separate Argus domain scan from Typer

- **Task:** extract the first closed domain/application slice from the Argus `scan` handler.
- **Result:** completed on 2026-08-24; `DomainScanService` now owns scope-first orchestration through
  injected DNS and Certificate Transparency ports, while Typer only constructs dependencies,
  translates errors, exports assets, and renders output.
- **Verification:** direct offline tests prove successful orchestration and prove that out-of-scope
  targets are audited before either network-capable dependency is called.

### Cycle 7 — restore strict mypy portability in CI

- **Task:** fix the `click` import failure reported by the strict-mypy CI job.
- **Result:** completed on 2026-08-24; the parity test no longer imports Click directly and confines
  runtime CLI introspection to an explicit `Any` boundary around Typer's generated command.
- **Verification (historical):** at the time the focused contract test, mypy, and Ruff all ran clean.
  (These are optional tools today; the mandatory quality gate referenced here was later removed.)

### Cycle 8 — implement both integrations and restructure the surface

- **Task:** close ARGUS command parity, implement the Athena (Vulnerability Assessment Platform)
  application boundary end to end, and bring the README to the project's chosen standard.
- **Result:** completed on 2026-08-24.
  - **ARGUS parity:** added six real, tested `olympus argus` commands — `email`, `mac`, `myip`,
    `web`, `dns`, `whois` — as offline-first cores with injected HTTP/DNS ports, scope enforcement,
    authorization gating for privacy-sensitive enrichment, and `core.Asset`/`core.Finding` output.
    `docs/parity/argus.json` and its contract test now cover all thirteen commands.
  - **Athena / VAP:** implemented `olympus.athena` per ADR-002 — immutable `AssessmentPlan`
    contracts with a canonical digest, assessment/job state machines, typed ports, a closed adapter
    registry, three offline tool adapters (`web-headers`, `dns`, `whois`), a bounded synchronous
    coordinator (concurrency, per-job timeout, overall deadline, cooperative cancellation, crash
    recovery), a transactional SQLite repository with owner-only permissions and bounded results, a
    redacting audit sink, and a Vulcan-backed report renderer. The CLI exposes real
    `plan validate` / `run` / `status` / `cancel` / `recover` / `adapters` use cases with the
    canonical exit codes. `docs/parity/vulnerability-assessment-platform.json` flips the implemented
    capabilities and keeps honest `partial`/`missing` gaps (external-tool scanner suite and web UI).
  - **Restructuring/docs:** rewrote `README.md` to the ARGUS standard (moving the exhaustive guide to
    `docs/reference.md`), recorded upstream MIT provenance in `docs/provenance.md`, fixed the
    documented `olympus core export-schemas` directory-output mismatch, and added an example plan.
- **Verification (optional tooling):** at the time, Ruff, mypy, and the test suite all ran clean.
  These checks are optional helpers, not a gate. All network activity in tests is injected and offline.
- **Scope intentionally deferred:** the broad external-tool scanner suite (nmap, nuclei, sqlmap, …)
  as isolated subprocess adapters, the deferred Athena web API/UI (needs its own security ADR),
  opt-in authorized live-network smoke/e2e tests, and generated CLI reference docs.

### Cycle 9 — vendor the complete upstream tools and drop the mandatory gate

- **Task:** integrate ARGUS and the Vulnerability Assessment Platform at 100% feature parity (not
  demos/stubs), make the standalone repositories safe to delete, keep the README bilingual, and
  remove the mandatory strict-mypy/≥90%-coverage gate from the whole project.
- **Result:** completed on 2026-08-24.
  - **Bilingual README:** added `README-IT.md` and a language switcher to `README.md`, matching the
    ARGUS 🇬🇧/🇮🇹 standard.
  - **Complete vendored tools:** copied the full, unmodified upstream source of both tools under
    `vendor/argus/` and `vendor/vulnerability-assessment-platform/` (all modules, the complete VAP
    FastAPI app with ~40 routes, all **24 scanners**, database + Alembic migrations, reports,
    templates, static assets, background/Celery stack, tests, Dockerfiles, docker-compose, and
    licences). Wired them into `olympus` as first-class runnable commands: `olympus argus-native`
    (verbatim ARGUS CLI passthrough — verified: `ip`, `phone`, `mac`, `--help`, `--version`) and
    `olympus vap serve|migrate|scanners|info` (verified: the web app boots, auto-runs its migrations,
    and serves `/`, `/api/v1/scan-catalog`, `/api/v1/scans` with HTTP 200). Missing external binaries
    and services (Redis) fail gracefully with actionable messages. Added `[argus]`/`[vap]` extras,
    `scripts/setup-vendored-tools.sh`, feature-parity tests, and updated `docs/provenance.md`.
  - **Gate removal:** removed the mandatory strict-mypy + ≥90%-coverage gate everywhere — `Makefile`
    (`check` is now non-blocking), `pyproject.toml` (no coverage threshold; mypy annotated optional),
    `.github/workflows/ci.yml` (quality steps are `continue-on-error`), `.pre-commit-config.yaml`
    (mypy hook removed), `README`/`README-IT`, `upgrade.md`, and `docs/architecture/adr-002`. Mypy,
    tests, and coverage remain available as **optional** helpers that never block completion.
- **Verification (optional tooling):** the full offline test suite, Ruff, and mypy run clean; the
  vendored ARGUS CLI and the vendored VAP web app were both exercised end to end in this environment.
- **Definition of complete:** 100% functional feature parity, not a passing gate. Vendored code is
  preserved verbatim and held to its own tooling.

### Cycle 10 — ecosystem audit, AEGIS rename, diagnostics & full scanner coverage

- **Task:** audit every tool; rename the Olympus-facing VAP component to AEGIS;
  add diagnostics; document and cover all 24 scanners; analyse additional tools.
- **Result:** completed on 2026-08-24.
  - **Ecosystem audit:** `docs/ecosystem-audit.md` inventories all 12 tools with
    an honest per-tool matrix and verification status. Key honest finding: the 24
    vendored scanners default to **simulated** output unless `VAP_ENABLE_LIVE_SCANS=true`
    + the binary/API is present + authorization; this is surfaced, never hidden.
  - **AEGIS rename** (collision audit passed — `aegis` was unused): `olympus vap`
    → `olympus aegis` with subcommands serve / migrate / workers / scanners
    (`--check`) / deps / scan / info / doctor. `olympus vap` kept as a deprecated
    forwarding alias; `[vap]` extra aliases `[aegis]`; compose services renamed
    `aegis-*`; `Source.AEGIS` added. Vendored source and `VAP_*` contract left
    intact. Map: `docs/vap-to-aegis-rename.md`.
  - **Diagnostics:** `olympus doctor`, `olympus aegis doctor`, `olympus argus
    doctor`, and a secret-safe diagnostics helper; a 24-entry scanner registry
    (`olympus.integrations.scanners`) drives `aegis scanners --check` / `deps`.
  - **Scanner coverage:** `docker/Dockerfile.scanners` now installs 19/24
    open-source scanners (apt/pip/go/git/gem, best-effort); the 5 API/commercial
    engines are documented for manual install and surfaced by diagnostics.
    Matrix: `docs/scanner-matrix.md`. Unified install/ops: `docs/install.md`.
  - **Additional-tool analysis:** `docs/tooling-analysis.md` proposes an optional
    SCA/SBOM/container/IaC profile (OSV-Scanner, Syft, Grype, Trivy, Checkov) —
    presented for review, not implemented.
- **Verification (optional tooling):** full suite passes; ruff/mypy clean on new
  code; AEGIS web app boots + migrates + serves; compose config validated. No
  live scan / container `up` was run (no scanner binaries, no Docker daemon in
  this environment) — stated explicitly, not simulated.

### Cycle 11 — AEGIS native execution layer (no implicit simulation)

- **Task:** make AEGIS genuinely operational — eliminate implicit simulation,
  add real execution adapters with explicit states, correct the scanner
  classification, add Compose profiles, and prove real execution in a local lab.
- **Result:** completed on 2026-08-25.
  - **Explicit states (no fabrication):** new `olympus.aegis` package —
    `states` (live/unavailable/failed/disabled/simulation), `model`, `runner`
    (shell-free, timeout + process-group kill), `scope` (SSRF-aware; loopback
    lab targets allowed only when explicitly authorized), `base` orchestrator,
    and `olympus aegis run`. Simulation is produced **only** with `--simulate` /
    `AEGIS_SIMULATION_MODE=true`; a missing binary is `unavailable` (with install
    instructions), live-off is `disabled` — never a fake finding. Authorization
    and scope are mandatory (exit 3/4).
  - **Real adapters:** nmap (XML), nikto (text), wafw00f (JSON), sqlmap (text),
    whatweb (text), testssl (JSON) — real command construction + real parsers.
    Verified live end-to-end here against a local authorized lab: nmap, nikto,
    wafw00f, sqlmap (evidence in `docs/aegis-execution-evidence.md`). whatweb's
    apt binary has a broken Ruby env → honest `failed`. 18 native adapters remain
    pending (registry rejects them with a clear error, never a fabricated result).
  - **Classification fix:** added a `kind` taxonomy; ZAP and OpenVAS reclassified
    as `containerised-oss-service` (OSS), not commercial. Recalculated totals:
    **21/24 OSS**, 3 proprietary (nessus/acunetix/burp). Updated
    `docs/scanner-matrix.md`.
  - **Compose profiles:** `zap` (OWASP ZAP daemon), `gvm` (Greenbone GVM),
    `commercial-connectors` (Nessus, operator-provided image), `scanners-cli`;
    default lightweight stack unchanged. Validated with `docker compose config`.
  - **AEGIS_* config:** `olympus.aegis.config` reads `AEGIS_*` with legacy
    `VAP_*` fallback (`docs/aegis-config.md`); vendored `VAP_*` contract untouched.
- **Verification (optional tooling):** full suite passes (ruff + mypy clean over
  183 files); 4 scanners verified live end-to-end; all five states + scope/auth
  refusals demonstrated. Live execution of the other scanners and the container
  stack remains environment-dependent (documented, never simulated).
- **Held:** the optional SCA profile (OSV/Syft/Grype/Trivy/Checkov) is NOT
  implemented — deferred until AEGIS execution coverage is broader.

### Cycle 12 — separate Argus fronting orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `fronting`.
- **Result:** completed on 2026-08-25. `FrontingAssessmentService` now owns input-policy
  validation, scope authorization, and passive fronting orchestration through injected DNS and
  Certificate Transparency ports. The Typer handler is limited to dependency construction, error
  translation, presentation, and export.
- **Verification:** direct offline application tests prove execution without the CLI, rejection of
  an invalid fan-out limit, and that out-of-scope targets are audited before either network-capable
  dependency is invoked. Existing CLI fronting tests continue to cover output and exit semantics.
- **Scope intentionally deferred:** the repository-wide audit and remaining application-service
  extractions stay open; no broader completeness claim is made by this cycle.

### Cycle 13 — separate Argus DNS orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `dns`.
- **Result:** completed on 2026-08-25. `DnsLookupService` now owns record-type policy, scope
  authorization, and DNS-over-HTTPS orchestration through an injected HTTP port. The Typer handler
  is limited to dependency construction, error translation, presentation, and export.
- **Verification:** direct offline application tests prove execution without the CLI, normalization
  of requested record types, rejection of an empty record-type policy, and that out-of-scope
  targets are audited before HTTP is invoked. Existing DNS tests retain protocol and CLI coverage.
- **Scope intentionally deferred:** the remaining Argus application-service extractions stay open;
  no broader completeness claim is made by this cycle.

### Cycle 14 — separate Argus WHOIS/RDAP orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `whois`.
- **Result:** completed on 2026-08-25. `WhoisLookupService` now owns scope authorization and RDAP
  orchestration through an injected HTTP port. The Typer handler only wires dependencies, translates
  errors, and presents or exports the result.
- **Verification:** direct offline application tests prove successful RDAP execution without the CLI
  and prove that an out-of-scope target is audited before the HTTP dependency can be invoked.
- **Scope intentionally deferred:** the remaining Argus application-service extractions stay open;
  no broader completeness claim is made by this cycle.

### Cycle 15 — separate Argus web reconnaissance from Typer

- **Task:** extract the next checklist-sized application slice: Argus `web`.
- **Result:** completed on 2026-08-25. `WebReconService` now owns URL/host validation, scope
  authorization, passive HTTP orchestration, and mapping to shared asset/finding contracts through
  an injected HTTP port. The Typer handler retains error-to-exit-code translation and presentation.
- **Verification:** offline application tests prove successful contract mapping, invalid-target
  rejection, and out-of-scope audit before HTTP. Existing CLI semantics distinguish invalid input
  (exit 2), scope denial (exit 3), network failure (exit 4), and findings (exit 1).
- **Known limitation:** redirect destinations are followed by the shared urllib transport and are
  not re-authorized after each hop because its response contract does not expose redirect history.
  Redirect-aware transport hardening was tracked under the shared execution-policy task and resolved
  in Cycle 16.
- **Scope intentionally deferred:** remaining Argus extractions stay open.

### Cycle 16 — enforce scope before every HTTP redirect

- **Task:** close the redirect authorization gap identified in Cycle 15.
- **Result:** completed on 2026-08-25. The shared urllib adapter accepts an optional redirect
  validator and invokes it before following every hop. Argus `web` supplies its URL validation,
  engagement-scope, and audit policy, so an out-of-scope or loopback redirect is refused before the
  redirected request is sent while preserving initial-target validation in the application service.
- **Verification:** offline transport tests prove validation precedes redirect construction and that
  validator errors stop the hop. A CLI integration test proves a scoped public target redirecting to
  loopback exits with scope denial and writes the blocked destination to the audit log.
- **Scope intentionally deferred:** generalized DNS rebinding protection and remaining shared
  execution-policy elements stay open; no broader policy-completeness claim is made.

### Cycle 17 — separate Argus email analysis and enrichment from Typer

- **Status:** `VERIFIED` (the parent repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move the complete `argus email` use case behind a command-independent application
  service without weakening its privacy and engagement controls.
- **Component:** ARGUS native Olympus integration; CLI and shared asset/finding contracts.
- **Dependencies:** injected `DnsResolver` and `HttpClient` ports, domain scope policy, and the existing
  offline email-analysis primitives.
- **Completion criteria:** offline analysis performs no network access; enrichment requires explicit
  authorization and valid scope; rejected targets never reach either network port; CLI exit and
  export behavior remains compatible.
- **Implementation:** added `EmailAnalysisService`, `EmailAnalysisRequest`, and a typed
  `AuthorizationRequiredError`; the service now owns parsing, authorization, scope enforcement,
  enrichment orchestration, and contract mapping. Typer only creates adapters, translates errors,
  presents results, and exports them.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/cli.py`,
  `tests/unit/test_argus_application.py`, and `upgrade.md`.
- **Tests executed:** focused application and email CLI/unit tests plus the complete offline suite;
  exact commands and outcomes are recorded in the commit/PR verification report.
- **Real execution evidence:** direct service tests execute offline analysis and prove empty port-call
  logs; authorization and out-of-scope tests prove refusal before DNS/HTTP. Existing CLI tests cover
  JSON/export success and exit codes 2, 3, and 4.
- **Residual limitations:** live enrichment still depends on an authorized target and reachable DNS
  and Gravatar services; this environment-independent fact is not represented as verified live
  execution.
- **Next activity:** extract the Argus `mac` analysis/vendor lookup use case, adding an explicit
  authorization and scope policy before its optional third-party network request.

### Cycle 18 — separate and authorize Argus MAC vendor lookup

- **Status:** `VERIFIED` (the parent repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move `argus mac` behind a command-independent application service and prevent its
  optional third-party OUI lookup from running without explicit authorization and engagement scope.
- **Component:** ARGUS Olympus-native integration, CLI, shared HTTP port, scope/audit policy, parity
  contract, and examples.
- **Dependencies:** `HttpClient`, offline MAC normalization/classification, shared asset/finding
  contracts, and a new dedicated OUI scope rather than an incorrect domain/IP scope reuse.
- **Completion criteria:** offline analysis makes no network call; `--vendor` requires explicit
  authorization; only allowed 24-bit OUIs reach the registry; invalid scope is actionable; blocked
  targets are audited; CLI output/export and parity remain consistent.
- **Implementation:** added `MacAnalysisService`/`MacAnalysisRequest`; the service owns parsing,
  authorization, OUI scope enforcement, vendor orchestration, and contract mapping. Added a strict
  `allowed_ouis`/`excluded_ouis` scope with normalized matching and audit records. Typer now only
  constructs the HTTP adapter, translates failures to canonical exit codes, presents, and exports.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/cli.py`,
  `src/olympus/argus/mac_scope.py`, `examples/input/argus-mac-scope.json`,
  `docs/parity/argus.json`, `tests/unit/test_argus_application.py`,
  `tests/unit/test_argus_mac.py`, `tests/unit/test_argus_mac_scope.py`, and `upgrade.md`.
- **Tests executed:** focused MAC/application/parity suite: `40 passed`; complete offline suite:
  `524 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed `olympus` CLI classified the example MAC offline with
  exit 0; an unconfirmed vendor lookup exited 4 before network; an authorized but out-of-scope OUI
  exited 3 and wrote a timestamped `blocked_out_of_scope` audit record. Direct application tests
  prove empty HTTP call logs for offline, unauthorized, and rejected requests; the authorized
  adapter test proves the exact registry URL is reached through the injected port.
- **Residual limitations:** a real macvendors.com response was not claimed in this restricted
  environment; live availability remains dependent on that third-party registry. This does not
  weaken the verified authorization/scope boundary or offline functionality.
- **Next activity:** extract `argus myip` discovery/geolocation from Typer, keeping public-IP
  discovery failures explicit and ensuring optional geolocation is independently testable.

### Cycle 19 — separate Argus self public-IP discovery from Typer

- **Status:** `VERIFIED` (live optional geolocation evidence is `BLOCKED` by an environment approval;
  the parent repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move `argus myip` orchestration behind an application service while keeping public-IP
  provider failure explicit and optional geolocation isolated from discovery.
- **Component:** ARGUS Olympus-native integration, application/CLI boundary, shared HTTP ports,
  parity contract, and tests.
- **Dependencies:** bounded `HttpClient`, the existing multi-provider discovery primitive, IP
  classification/geolocation primitives, and shared asset/finding contracts.
- **Completion criteria:** the CLI contains no discovery/enrichment orchestration; discovery and
  geolocation can use independent adapters; no geolocation call occurs without `--geo`; all provider
  failures return the established network exit code; output/export compatibility is preserved.
- **Implementation:** added `MyIpDiscoveryService`/`MyIpDiscoveryRequest`, split result building from
  provider discovery through `build_result`, and kept `discover` as a backward-compatible wrapper.
  The service injects separate discovery and geolocation ports; Typer only constructs adapters,
  translates `MyIpError`, presents, and exports.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/myip.py`,
  `src/olympus/argus/cli.py`, `docs/parity/argus.json`,
  `tests/unit/test_argus_application.py`, `tests/unit/test_argus_myip.py`, and `upgrade.md`.
- **Tests executed:** focused application/myip/parity suite: `37 passed`; complete offline suite:
  `528 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed `olympus argus myip` command queried the bounded provider
  chain and returned a real public IP with exit 0; the value is intentionally not recorded in this
  register. Direct service tests prove the geolocation port remains untouched by default, uses its
  own adapter only when requested, and is never called when all discovery providers fail.
- **Residual limitations:** live `--geo` verification was not run because the environment correctly
  required separate approval before sending the discovered public IP to ip-api.com. The adapter is
  covered offline and this external-evidence gap is recorded as `BLOCKED`, not as verified.
- **Next activity:** extract the privacy-sensitive `argus phone` analysis/enrichment workflow from
  Typer while retaining authorization, phone-specific scope, audit, and stable exit behavior.

### Cycle 20 — separate and repair Argus phone enrichment

- **Status:** `VERIFIED` (real-person third-party enrichment remains intentionally unexecuted; the
  parent repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move the complete single/batch phone workflow out of Typer, preserve enrichment
  results instead of discarding them, and close a secret-transport defect in Numverify.
- **Component:** ARGUS Olympus-native application/CLI boundary, phone contracts, three optional
  enrichment adapters, scope/audit policy, parity manifest, reference documentation, and tests.
- **Dependencies:** phone-specific E.164 prefix scope, `PhoneEnrichmentClient` and
  `MessagingPresenceClient` ports, shared bounded HTTP configuration, environment-only API keys,
  and shared asset/finding contracts.
- **Completion criteria:** offline mode never calls enrichment ports; real lookups require explicit
  authorization and valid phone scope; batch skips are explicit and audited; carrier, breach, and
  messaging results survive into JSON/assets/findings; secrets never cross plaintext HTTP or appear
  in surfaced failures; non-2xx responses are not treated as successful data.
- **Implementation:** added `PhoneProfileService`, single/batch requests and outcomes, injected
  carrier/breach/messaging ports, safe non-fatal adapter warnings, and batch skip records. Removed
  enrichment/scope/domain orchestration from Typer. Extended `PhoneIntel` and phone asset metadata
  with real enrichment/messaging output. Changed Numverify to HTTPS, stopped reflecting secret-bearing
  transport URLs, and made all three adapters reject non-2xx responses explicitly.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/cli.py`,
  `src/olympus/argus/phone.py`, `src/olympus/argus/enrichment.py`,
  `docs/parity/argus.json`, `docs/reference.md`, `tests/unit/test_argus_application.py`,
  `tests/unit/test_argus_cli_phone.py`, `tests/unit/test_argus_phone.py`,
  `tests/unit/test_argus_enrichment.py`, and `upgrade.md`.
- **Tests executed:** focused application/phone/CLI/enrichment/parity suite: `62 passed`; complete
  offline suite: `535 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed CLI profiled the reserved fictional example number with
  exit 0 and explicit `enrichment: null`; an unconfirmed breach request exited 4 before network; an
  out-of-scope number exited 3 and produced an audit record. Direct tests prove zero adapter calls
  offline/unauthorized/out-of-scope and prove authorized carrier/breach/messaging data reaches the
  exported contract and findings.
- **Residual limitations:** no real-person Numverify, Hudson Rock, or messaging query was sent from
  this environment; Numverify/RapidAPI also require operator credentials. These external proofs are
  not represented as verified, while the adapters and security boundary are tested offline.
- **Next activity:** extract `argus ip` analysis/geolocation from Typer, preserving CIDR scope,
  authorization, offline classification, and explicit geolocation failures.

### Cycle 21 — separate Argus IP profiling and replace plaintext geolocation

- **Status:** `VERIFIED` (live third-party geolocation evidence remains `BLOCKED` by the environment
  approval boundary; the parent repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move single/batch IP profiling out of Typer, preserve geolocation as explicit output,
  and replace the plaintext third-party endpoint with a documented HTTPS provider.
- **Component:** ARGUS Olympus-native application/CLI boundary, IP contracts, geolocation adapter,
  investigation and `myip` consumers, CIDR scope/audit policy, parity/reference docs, and tests.
- **Dependencies:** `IpGeoClient`, shared bounded HTTP configuration, IP CIDR scope, shared
  asset/finding contracts, and the documented ipwho.is free HTTPS response contract.
- **Completion criteria:** offline classification makes no geolocation call; `--geo` requires
  authorization and CIDR scope; batch skips are explicit/audited; normalized geolocation is retained
  in `geo`, assets, and findings; transport is encrypted; HTTP/application failures are explicit;
  existing importers retain a compatibility path.
- **Implementation:** added `IpProfileService` with single/batch request/outcome contracts and an
  injected geo port; removed profiling/scope/geo orchestration from Typer. Added explicit `geo` data
  to `IpIntel`. Replaced `http://ip-api.com` with `https://ipwho.is`, normalized its documented
  `connection`/optional `security` payload, rejected non-2xx and `success:false`, updated `myip` and
  investigation transforms, and retained `IpApiClient` as a no-network compatibility alias.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/cli.py`,
  `src/olympus/argus/ip_osint.py`, `src/olympus/argus/myip.py`,
  `src/olympus/argus/transforms.py`, `docs/parity/argus.json`, `docs/reference.md`,
  `tests/unit/test_argus_application.py`, `tests/unit/test_argus_cli_ip.py`,
  `tests/unit/test_argus_ip.py`, `tests/unit/test_argus_myip.py`,
  `tests/unit/test_argus_transforms.py`, and `upgrade.md`.
- **Tests executed:** focused application/IP/CLI/myip/transforms/parity suite: `74 passed`; complete
  offline suite: `541 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed CLI classified the authorized documentation-range IP
  offline with exit 0 and explicit `geo: null`; an unconfirmed geo request exited 4 before network;
  an out-of-scope public IP exited 3 and wrote an audit record. Direct tests prove zero geo calls
  offline/unauthorized/out-of-scope and prove normalized ASN/geolocation reaches the output contract.
- **Residual limitations:** no live target IP was sent to ipwho.is because the environment requires
  separate approval for that privacy-sensitive disclosure. The provider adapter is verified against
  its real documented schema offline; this external proof remains `BLOCKED`, not verified.
- **Next activity:** extract `argus accounts` single/batch enumeration from Typer, retaining handle
  scope, metadata authorization, bounded concurrency/rate, partial results, and actionable failures.

### Cycle 22 — separate and harden Argus account enumeration

- **Status:** `VERIFIED` (live third-party account queries are intentionally unexecuted; the parent
  repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move `argus accounts` single/batch orchestration out of Typer, prove policy checks
  happen before network traffic, and prevent a custom site registry from becoming an immediate SSRF
  or handle-injection primitive.
- **Component:** ARGUS Olympus-native application/CLI boundary, account contracts, handle scope and
  audit policy, shared bounded HTTP client, site-registry validation, parity/reference docs, and tests.
- **Dependencies:** `HttpClient`, account allowlist/audit primitives, shared asset/finding contracts,
  the declarative site registry, and the shared retry/rate-limit configuration.
- **Completion criteria:** metadata extraction requires explicit authorization; every handle is
  checked against scope before network; batch skips are explicit and audited; partial site failures
  remain indeterminate rather than invented; concurrency is bounded and cannot bypass rate limiting;
  configured and redirected destinations reject plaintext, credentials, local hostnames, private
  literal IPs, and authority injection; output/export remains compatible.
- **Implementation:** added `AccountEnumerationService` with single/batch request and result contracts,
  injected site specs/HTTP port, authorization and scope-first ordering, stable partial results, and
  explicit batch warnings. Typer now only validates command shape, constructs adapters, presents, and
  exports. Registry templates must use HTTPS, contain exactly one path/query `{username}` placeholder,
  and target a public-looking host without embedded credentials; the handle is encoded as one segment
  and every redirect is revalidated. The shared HTTP throttle now serializes dispatch timing across
  account worker threads.
- **Files modified:** `src/olympus/argus/accounts.py`, `src/olympus/argus/application.py`,
  `src/olympus/argus/cli.py`, `src/olympus/core/http.py`, `docs/parity/argus.json`,
  `docs/reference.md`, `tests/unit/test_argus_accounts.py`,
  `tests/unit/test_argus_application.py`, `tests/unit/test_argus_cli_accounts.py`, and `upgrade.md`.
- **Tests executed:** focused accounts/application/scope/CLI/HTTP/parity suite: `99 passed`; complete
  offline suite: `558 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed CLI rejected metadata collection without confirmation
  with exit 4 before any site request; an out-of-scope handle exited 3 and wrote a timestamped
  `blocked_out_of_scope` record. Application/CLI integration tests with an injected deterministic
  transport prove the authorized in-scope success path, metadata propagation, partial-error behavior,
  batch skip semantics, and zero HTTP calls for unauthorized/out-of-scope requests.
- **Residual limitations:** no real handle was sent to GitHub or the other public-site providers because
  no target authorization was supplied. Literal private destinations and unsafe redirects are blocked;
  hostname DNS rebinding cannot be completely excluded by URL validation alone and deployments should
  retain outbound network controls. These limits are not represented as live-provider verification.
- **Next activity:** extract `argus investigate` graph orchestration from Typer, verify each networked
  transform is authorization/scope gated, and remove simulated or silently invented pivot results.

### Cycle 23 — scope and separate Argus investigation graphs

- **Status:** `VERIFIED` (live third-party fan-out is intentionally unexecuted; the parent
  repository-wide separation activity remains `IN PROGRESS`).
- **Objective:** move graph investigation orchestration out of Typer and guarantee that every direct
  or transitively discovered network pivot is authorized, checked with the correct scope dialect,
  audited, and based only on adapter results.
- **Component:** ARGUS investigation application service, transform engine, CLI, domain/IP/account
  scopes, audit log, graph exports, parity/reference docs, and tests.
- **Dependencies:** injected DNS, Certificate Transparency, bounded HTTP and site-registry ports;
  domain-suffix, IP-CIDR, and exact-handle scope policies; the graph/entity contracts; encrypted
  `ipwho.is` geolocation; and the hardened account registry/redirect policy.
- **Completion criteria:** no fan-out without explicit authorization; a direct out-of-scope network
  seed exits before an adapter call; discovered out-of-scope pivots are audited, warned, and skipped
  without discarding valid graph branches; depth remains bounded; adapter failures are explicit
  warnings rather than fabricated nodes; CLI/JSON/Mermaid/DOT/GraphML use one real graph result.
- **Implementation:** added `InvestigationService`, request/outcome contracts, a cached per-entity
  scope gate, application-owned start audit, strict seed/name/depth validation, and explicit warning
  propagation. Domain/host DNS and CT transforms use domain scope, optional IP geolocation uses CIDR
  scope, and username enumeration uses account scope immediately before traffic. Direct network seeds
  fail closed; later rejected pivots preserve independent graph branches. DNS, CT, invalid-IP, and geo
  failures now produce warnings without inventing entities. Typer constructs ports, maps exit codes,
  renders, and exports; its shared HTTP adapter also validates every HTTPS redirect.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/transforms.py`,
  `src/olympus/argus/cli.py`, `docs/parity/argus.json`, `docs/reference.md`,
  `tests/unit/test_argus_application.py`, `tests/unit/test_argus_cli_investigate.py`, and `upgrade.md`.
- **Tests executed:** focused application/investigate/transforms/graph/parity suite: `64 passed`;
  complete offline suite: `563 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed CLI produced and exported a depth-zero authorized graph
  with exactly the real seed and no invented relationships (exit 0); the same command without
  confirmation exited 4; an authorized domain outside the configured perimeter exited 3 before DNS,
  CT, or HTTP and appended a timestamped `blocked_out_of_scope` audit record. Injected application
  tests prove scoped successful pivots and that a discovered unauthorized username is audited/skipped
  while the independently authorized domain branch continues.
- **Residual limitations:** no live DNS, crt.sh, public-account, or IP-geolocation fan-out was sent
  because no authorized live target was provided; provider availability is therefore not represented
  as verified. Network egress controls remain recommended in addition to application scope checks.
- **Next activity:** inspect and separate the remaining Argus `diff` and diagnostic/asset entry points,
  then close the parent Argus application-boundary item only after CLI/API/report parity is proven.

### Cycle 24 — finish Argus snapshot and diagnostic boundaries

- **Status:** `DONE` for the remaining ARGUS `diff`/`doctor` subtask; the repository-wide separation
  parent remains `IN PROGRESS` until the non-ARGUS modules are audited.
- **Objective:** remove the last ARGUS domain/diagnostic orchestration from Typer and ensure snapshot
  comparisons cannot silently accept incompatible or malformed shared contracts.
- **Component:** ARGUS application service, snapshot diff domain logic, diagnostic service, CLI,
  parity manifest, and tests.
- **Dependencies:** versioned `olympus.argus-assets` documents, the strict shared `Asset` model, and
  secret-safe shared diagnostic checks for Python modules and environment-key presence.
- **Completion criteria:** both commands are thin presentation adapters; diff remains offline and
  deterministic; both inputs have the supported collection schema and each asset validates against
  the compatible shared contract; invalid data exits actionably; doctor is read-only and never emits
  secret values; parity and tests cover both entry points.
- **Implementation:** added `SnapshotDiffService` and `ArgusDiagnosticsService`; Typer now only maps
  their results/errors to JSON and exit codes. Snapshot loading validates collection name, supported
  major version, every strict `Asset`, and each asset contract name/major version before comparing
  normalized hostnames. Malformed entries are rejected instead of silently disappearing from a diff.
- **Files modified:** `src/olympus/argus/application.py`, `src/olympus/argus/diff.py`,
  `src/olympus/argus/cli.py`, `docs/parity/argus.json`,
  `tests/unit/test_argus_application.py`, `tests/unit/test_argus_assets_diff.py`,
  `tests/unit/test_argus_cli_diff_doctor.py`, and `upgrade.md`.
- **Tests executed:** focused application/assets/diff/doctor/parity/vendored suite: `66 passed`;
  complete offline suite: `570 passed`; Ruff: clean; strict mypy: clean across 113 source files.
- **Real execution evidence:** the installed CLI compared the checked-in versioned ARGUS asset
  snapshot with itself and returned two real unchanged hostnames with no additions/removals. The
  installed doctor found both required Python modules importable, reported optional keys only as
  `not set`, and returned overall `ok: true`; no network or mutation occurred.
- **Residual limitations:** diff intentionally remains hostname-level and does not yet describe field
  changes within the same asset; optional provider credentials and live availability are outside a
  read-only diagnostic. Neither limitation is presented as a missing existing command behavior.
- **Next activity:** define and enforce the pending versioned assessment-plan, scan-job, observation,
  finding, asset, evidence, and report contracts, then document compatibility rules for every consumer.

### Cycle 25 — enforce shared versioned contracts end to end

- **Status:** `DONE`.
- **Objective:** give assessment plans, scan jobs, observations, assets, findings, evidence, and reports
  strict durable identities; define compatibility/migration behavior; and make real producers,
  persistence adapters, aggregators, CLI schema export, and downstream consumers enforce it.
- **Component:** Core contracts and IDs, Athena domain/coordinator/SQLite, Helios observation export,
  Argus snapshot input, Apollo-to-Minerva alert input, Vulcan aggregation/reporting, CLI schema export,
  examples, architecture/compatibility documentation, and tests.
- **Dependencies:** Pydantic strict models, Semantic Versioning, existing core IDs/enums, Athena
  persistence and job lifecycle, and the versioned collection envelopes already emitted by Argus,
  Helios, and Apollo.
- **Completion criteria:** every named contract has exact schema identity and SemVer; wrong names,
  malformed versions, different major versions, newer unsupported minors, unknown/nested-invalid
  fields, and ambiguous documents fail closed; known legacy inputs have explicit tested adapters;
  Athena persists versioned result/job contracts; real observations and consolidated reports use the
  shared models; consumers validate envelopes; JSON Schemas and compatibility rules are published.
- **Implementation:** added strict `ContractVersion`/`validate_contract_header` negotiation and exact
  literal identity/version fields on all core models. Added canonical `Observation`, `ScanJob`,
  `ReportSummary`, and `SecurityReport` contracts plus traceable `OBS-*` IDs. Standardized
  `AssessmentPlan` on `1.0.0`, retained only the known missing-header/integer-v1 migration, added
  versioned `AssessmentResult`, mapped Athena jobs to the shared job contract, and validate/canonicalize
  every SQLite result write/read. Helios now exports actual TCP observations alongside findings;
  Vulcan validates versioned Argus/Helios/Apollo/report envelopes while retaining its named legacy
  bare-array path; Minerva and Argus use the shared compatibility gate; Vulcan emits a validated
  machine report. `core export-schemas` now includes plan, result, observation, job, and report.
- **Files modified:** `src/olympus/core/contracts.py`, `src/olympus/core/models.py`,
  `src/olympus/core/ids.py`, `src/olympus/core/__init__.py`, `src/olympus/cli.py`,
  `src/olympus/athena/domain/contracts.py`, `src/olympus/athena/domain/assessment.py`,
  `src/olympus/athena/application/coordinator.py`, `src/olympus/athena/adapters/sqlite.py`,
  `src/olympus/helios/export.py`, `src/olympus/helios/cli.py`,
  `src/olympus/argus/diff.py`, `src/olympus/minerva/triage.py`,
  `src/olympus/vulcan/aggregate.py`, `src/olympus/vulcan/report.py`,
  `examples/input/athena-plan.json`, `docs/contracts.md`,
  `docs/architecture/adr-002-athena-target-architecture.md`, `README.md`, `README-IT.md`,
  `tests/unit/test_core_contracts.py`, `tests/unit/test_cli.py`,
  `tests/unit/test_athena_contracts.py`, `tests/unit/test_athena_adapters.py`,
  `tests/unit/test_helios.py`, `tests/unit/test_vulcan.py`, and `tests/unit/test_minerva_triage.py`.
- **Tests executed:** focused contracts/core/CLI/Athena/Helios/Vulcan/Minerva/Argus suite:
  `103 passed`; complete offline suite: `583 passed`; Ruff: clean; strict mypy: clean across 114
  source files.
- **Real execution evidence:** the installed `olympus core export-schemas` wrote the complete schema
  catalog successfully; the installed `olympus athena plan validate` accepted the now explicitly
  versioned example and returned stable plan/scope SHA-256 digests. Coordinator/SQLite tests persist
  and reload canonical `olympus.athena.result` documents with nested `olympus.scan-job`; Helios CLI
  integration proves its real discovered open port becomes a strict `olympus.observation`.
- **Residual limitations:** original pre-contract Vulcan bare arrays remain deliberately accepted and
  documented for compatibility; unversioned Athena results are rejected because their missing job
  identity cannot be reconstructed safely. Future major versions require an explicit migration.
- **Next activity:** implement the pending shared execution policy for authorization, scope,
  rate/concurrency, timeout/deadline, cancellation, retry, and redacted structured audit, then adopt it
  across network-active modules without weakening their dedicated scope dialects.

### Cycle 26 — establish shared execution policy and adopt it in Core, ARGUS, and Athena

- **Status:** `VERIFIED`; the repository-wide policy item remains `IN PROGRESS` pending adoption by
  the remaining modules and vendored/native execution surfaces.
- **Objective:** replace locally interpreted authorization/resource settings with one fail-closed
  policy, make cancellation and audit redaction reusable, and close Athena's declared-but-unused retry
  behavior without weakening any dedicated scope checker.
- **Component:** Core execution and HTTP, ARGUS application services, Athena coordinator/audit,
  shared documentation, and offline tests.
- **Dependencies:** module-specific scope gates, injected HTTP/tool ports, Athena plan limits and
  cancellation protocol, bounded transports, and append-only audit sinks.
- **Completion criteria:** invalid timeouts/deadlines/concurrency/retries/backoff/rate fail rather than
  clamp; authorization precedes scope/adapter calls; cancellation is thread-safe and checked before
  dispatch/retry; HTTP uses shared timeout/retry/rate values; Athena consumes every declared plan
  limit and retries only explicit transient errors; audit records recursively redact secret-bearing
  keys and URL query parameters before persistence; adoption gaps remain explicit.
- **Implementation:** added `ExecutionPolicy`, strict global bounds, shared authorization/cancellation
  errors, `CancellationToken`, reusable target-authorization ordering, recursive mapping/URL redaction,
  and deterministic `StructuredAuditRecord`. `UrllibHttpClient` now validates through this policy,
  supports `from_policy`, and checks cancellation before requests and retry waits. ARGUS privacy
  operations share the Core authorization contract and account concurrency bound. Athena constructs
  the policy from its immutable plan, uses per-job cancellation tokens, applies the previously ignored
  `max_retries` only to `unreachable`/`timeout`/`lookup_failed`, and redacts allowed audit target URLs
  before any sink stores them.
- **Files modified:** `src/olympus/core/execution.py`, `src/olympus/core/http.py`,
  `src/olympus/core/__init__.py`, `src/olympus/argus/application.py`,
  `src/olympus/athena/application/coordinator.py`, `src/olympus/athena/domain/audit.py`,
  `docs/execution-policy.md`, `README.md`, `README-IT.md`,
  `tests/unit/test_core_execution.py`, `tests/unit/test_core_http.py`,
  `tests/unit/test_athena_engine.py`, `tests/unit/test_athena_contracts.py`, and `upgrade.md`.
- **Tests executed:** focused Core HTTP/policy, ARGUS application, and Athena contracts/engine/adapters/
  CLI suite: `121 passed`; complete offline suite: `596 passed`; Ruff: clean; strict mypy: clean
  across 115 source files (using a fresh cache after the local generated cache database was corrupt).
- **Real execution evidence:** the installed package constructed a policy with explicit timeout,
  deadline, concurrency, and retry budget and serialized a structured audit record in which the token
  query value was replaced while the non-sensitive target remained. The installed ARGUS account CLI
  still exited 4 before a site request when metadata authorization was absent. Offline coordinator
  evidence proves a retry budget of 2 performs exactly three attempts and persists the final failure.
- **Residual limitations:** cooperative cancellation cannot forcibly terminate arbitrary Python
  threads, so every adapter must retain hard transport/subprocess timeouts. Retry backoff for Athena
  tool adapters is not yet scheduled through an injected sleeper; remaining modules still use local
  policy fragments and are not represented as adopted.
- **Next activity:** migrate Helios and Artemis first because both are network-active, then apply the
  same policy/redaction/cancellation boundary to the remaining offline and subprocess modules.

### Cycle 27 — enforce shared execution policy in Helios and Artemis

- **Status:** `VERIFIED`; the repository-wide policy and application-boundary items remain
  `IN PROGRESS` pending the remaining modules and vendored/native execution surfaces.
- **Objective:** make every HELIOS and ARTEMIS network path fail closed on authorization, retain each
  dedicated scope dialect, enforce cancellation/deadline/retry/rate limits around real adapters, and
  move the primary scan/fetch use cases behind command-independent application services.
- **Component:** Core structured audit persistence, HELIOS scanner/scope/application/CLI/export path,
  ARTEMIS DNS-pinned HTTP/content/fingerprint/Metabase/XSS paths, reference/policy docs, and tests.
- **Dependencies:** shared `ExecutionPolicy` and cancellation protocol; HELIOS CIDR scope and socket
  connector; ARTEMIS URL/path plus resolved-IP scope, resolver and pinned transport; versioned
  observation/finding exports; and append-only local audit logs.
- **Completion criteria:** malformed limits fail before traffic; every live CLI and lower-level web API
  requires explicit authorization; scope is applied before connector/DNS/transport calls and again on
  redirects; cancellation is observed before and between work; transport-only retries and rate waits
  cannot escape the overall deadline; scope denials are structured/redacted; CLI and application
  services consume the same real results; tests and a real loopback execution prove both stacks.
- **Implementation:** added `SurfaceScanService` and `ScopedFetchService` request/outcome boundaries;
  HELIOS now validates/deduplicates ports before authorization, checks CIDR scope before TCP, raises the
  shared cancellation signal between probes, accepts bounded timeout/authorization CLI options, and
  exports the same real observations/findings from the service. ARTEMIS `fetch`/`fingerprint` now use
  the application service, while content, Metabase and XSS receive the same explicit policy. The
  low-level web functions no longer infer authorization. The HTTP engine caps each attempt by remaining
  deadline, retries only `HttpClientError`, checks cancellation before retry/rate waits, and revalidates
  every redirect URL and resolved address. Shared audit serialization now redacts the top-level target
  URL and has an append helper used by HELIOS/ARTEMIS scope denials.
- **Files modified:** `src/olympus/core/execution.py`, `src/olympus/core/__init__.py`,
  `src/olympus/helios/scanner.py`, `src/olympus/helios/scope.py`,
  `src/olympus/helios/application.py`, `src/olympus/helios/cli.py`,
  `src/olympus/artemis/http.py`, `src/olympus/artemis/scope.py`,
  `src/olympus/artemis/application.py`, `src/olympus/artemis/cli.py`,
  `src/olympus/artemis/content.py`, `src/olympus/artemis/metabase.py`,
  `src/olympus/artemis/xss.py`, `docs/execution-policy.md`, `docs/reference.md`,
  `tests/unit/test_core_execution.py`, `tests/unit/test_helios.py`,
  `tests/unit/test_artemis_http.py`, `tests/unit/test_artemis_content.py`,
  `tests/unit/test_artemis_metabase.py`,
  `tests/unit/test_artemis_xss.py`, and `upgrade.md`.
- **Tests executed:** focused Core/HELIOS/ARTEMIS policy and adapter suite: `70 passed`; complete
  offline suite: `604 passed`; Ruff: clean; strict mypy: clean across 117 source files with a fresh
  generated cache directory.
- **Real execution evidence:** an ephemeral loopback HTTP server was opened on port 8765. The installed
  `olympus helios scan` command, with explicit authorization and a temporary loopback CIDR scope,
  detected that actual open socket and exported one strict `olympus.observation`; the installed
  `olympus artemis fetch`, with its independent URL/resolved-IP scope, completed a real pinned GET and
  returned HTTP 200 plus the actual body length. Both commands exited 0; the server was then stopped.
  Injected adapter tests additionally prove zero DNS/socket calls for unauthorized, out-of-scope, or
  pre-cancelled requests and two actual transport attempts for a one-retry transient failure.
- **Residual limitations:** no public or third-party target was probed because no live engagement scope
  was supplied. Cancellation remains cooperative and cannot interrupt a connector already inside its
  hard timeout. Full Typer separation for ARTEMIS content/Metabase/XSS and operation-completion audit
  records remain in the parent backlog; neither is represented as complete here.
- **Next activity:** inspect Proteus and Hermes for locally interpreted policy, secret/process hazards,
  and Typer-owned orchestration; implement their independent application boundaries before moving to
  Apollo, Minerva, Vulcan, and AEGIS.

### Cycle 28 — make Proteus campaigns fail closed and protect tracking artifacts

- **Status:** `DONE` for PROTEUS application/policy adoption; the repository-wide policy parent remains
  `IN PROGRESS` for HERMES and later modules.
- **Objective:** ensure a declared training simulation cannot target an unapproved sender, recipient,
  engagement or landing origin; remove Typer-owned orchestration; and prevent bearer tracking tokens
  or recipient addresses from leaking through stdout, weak files, audit logs, or malformed contracts.
- **Component:** PROTEUS scope/domain/application/CLI, campaign/report contracts, protected persistence,
  example configuration, policy/reference/security documentation, ecosystem inventory, and tests.
- **Dependencies:** shared authorization/cancellation and structured audit primitives, strict SemVer
  compatibility, standard-library IDNA/URL parsing, cryptographic token generation, and atomic local
  file replacement.
- **Completion criteria:** static input validates before authorization; campaign creation requires
  explicit authorization even below CLI; command/scope engagements match; sender and every recipient
  use an exact allowed domain; only an exact allowlisted HTTPS training origin can carry tokens; header
  injection and duplicate recipients/tokens fail; cancellation is observed; CLI orchestration is an
  application service; campaign/report documents are versioned and strictly loaded; legacy migration
  is explicit; token files are atomic/owner-only and normal stdout/audit contains no token/full email.
- **Implementation:** added `CampaignApplicationService` with build/page/email/report use cases and
  request/outcome contracts. Scope files now require exact `engagement`, `allowed_domains`, and
  `allowed_landing_origins`; conservative mailbox/IDNA and credential-free HTTPS URL normalization
  precede scope checks. Both service and builder enforce shared authorization; campaign-level scope is
  checked before recipient iteration, and cancellation is checked before every target/token. Tracking
  links replace any prior `t` parameter safely, email headers reject control/newline injection, and the
  training page remains static/no-capture. Campaign `1.0.0` and report `1.0.0` identities were added;
  the loader rejects unknown/incompatible/duplicate data with only the exact prior unversioned shape
  migrated. Export uses fsync, atomic replacement and mode `0600`. CLI output now exposes only counts;
  denial audits hash the address and retain only its domain, while completion audit stores counts.
- **Files modified:** `src/olympus/proteus/scope.py`, `src/olympus/proteus/campaign.py`,
  `src/olympus/proteus/application.py`, `src/olympus/proteus/cli.py`,
  `examples/input/proteus-scope.json`, `docs/proteus.md`, `docs/execution-policy.md`,
  `docs/reference.md`, `docs/ecosystem-audit.md`, `tests/unit/test_proteus.py`, and `upgrade.md`.
- **Tests executed:** focused PROTEUS scope/domain/application/CLI suite: `14 passed`; complete offline
  suite: `609 passed`; Ruff: clean; strict mypy: clean across 118 source files with a fresh cache.
- **Real execution evidence:** the installed CLI consumed a two-recipient file and the checked-in scope,
  accepted only the authorized Olympus demo domain, skipped/audited the external address, and emitted a
  `olympus.proteus-campaign` `1.0.0` document with one real cryptographically generated token. The file
  mode was verified as `0600`; stdout contained counts/path rather than the token; two NDJSON records
  captured the denial and successful completion without a full email address. Exit code was 0.
- **Residual limitations:** Proteus intentionally renders artifacts and metrics but does not deliver
  mail, host the training HTML, or collect clicks; those external systems need their own authorization,
  access control and retention policy. `0600` semantics are POSIX-specific, while non-POSIX deployments
  must enforce equivalent ACLs. These boundaries are documented and are not presented as delivery.
- **Next activity:** migrate HERMES behind a bounded application service, reject missing/symlink/device
  paths instead of returning false-clean, cap file/history work, make Git subprocess execution
  cancellation/timeout-aware, and keep every emitted value masked.

### Cycle 29 — bound Hermes file/history scans and eliminate false-clean coverage

- **Status:** `DONE` for HERMES application/policy adoption; the repository-wide policy parent remains
  `IN PROGRESS` for APOLLO, MINERVA, VULCAN, AEGIS and native integrations.
- **Objective:** ensure unsupported, missing, changed, oversized or only partially readable inputs can
  never be reported as clean; bound both filesystem and Git work; move orchestration out of Typer; and
  preserve only masked, stable evidence in SARIF/baselines.
- **Component:** HERMES scanner, application service, CLI, SARIF/baseline persistence, shared-policy
  documentation, command reference, ecosystem inventory, and offline/real-process tests.
- **Dependencies:** shared `ExecutionPolicy`/cancellation, standard-library no-follow file descriptors,
  argument-array subprocesses, Git patch format, SemVer compatibility, SARIF 2.1.0, and atomic files.
- **Completion criteria:** entropy/resource inputs validate below CLI; nonexistent/symlink/device paths
  fail; directory symlinks and Git metadata are not traversed; count/byte/deadline limits apply during
  enumeration and reads; output/baseline feedback is excluded; partial coverage exits non-clean; history
  requires one repository and has commit/output/stderr/process limits, no shell/pager/ext-diff/textconv,
  cancellation/timeout termination, and actionable locations; duplicate values do not inflate findings;
  SARIF contains no raw secret; baseline is strict/versioned/private with explicit legacy migration.
- **Implementation:** added `SecretScanService`, request/outcome contracts and an injected history port;
  Typer now supplies options, writes application results, presents coverage and maps stable exit codes.
  `scan_paths_bounded` validates 0–8 entropy, regular inputs, traversal/file byte/count bounds, shared
  deadline/cancellation, deduplicates overlapping roots, excludes requested artifacts, prunes `.git` and
  symlinks, uses `O_NOFOLLOW` where available, and distinguishes intentional binary ignores from partial
  read/size failures. The Git adapter runs a resolved executable without shell/stdin/pager/external diff
  or textconv, sanitizes interactive settings, caps commits/stdout/stderr, drains both pipes concurrently,
  and terminates on cancellation, deadline, overflow or timeout. Patch parsing emits introducing
  `git-history/<commit>/<path>` evidence. Fingerprints are stable across line moves and duplicate patch
  appearances. SARIF/baseline writes use unique fsynced atomic files; baselines are strict `1.0.0` with
  a bare-array migration and POSIX mode `0600`.
- **Files modified:** `src/olympus/hermes/scanner.py`, `src/olympus/hermes/application.py`,
  `src/olympus/hermes/cli.py`, `src/olympus/hermes/sarif.py`, `docs/hermes.md`,
  `docs/execution-policy.md`, `docs/reference.md`, `docs/ecosystem-audit.md`,
  `tests/unit/test_hermes.py`, and `upgrade.md`.
- **Tests executed:** focused HERMES engine/application/CLI/Git/SARIF/baseline suite: `13 passed`;
  complete offline suite: `614 passed`; Ruff: clean; strict mypy: clean across 119 source files with a
  fresh generated cache directory.
- **Real execution evidence:** a temporary real Git repository committed the synthetic documentation
  key, removed it in a second commit, and retained no secret in its working tree. The installed
  `olympus hermes scan --history` command scanned one working-tree file plus two bounded commits, found
  exactly one deduplicated history result, exited 1, and wrote SARIF 2.1.0 with commit/file location and
  no complete key. A second installed command against a nonexistent path exited 2 and wrote no false
  clean result. Unit execution separately forces the one-byte history cap and observes explicit failure.
- **Residual limitations:** text scanning intentionally ignores binary/non-UTF-8 content and reports the
  ignored count; specialized binary/archive secret extraction would require separate bounded adapters.
  Cooperative cancellation cannot interrupt an individual local file read, which is instead byte-capped;
  Git is terminated between short polling intervals. POSIX no-follow/mode flags require equivalent ACL
  controls on platforms that do not expose them.
- **Next activity:** inspect APOLLO rule/event parsing and Typer orchestration for version drift,
  unbounded streams, unsafe regex/evaluator behavior, false alerts, and missing application/policy
  boundaries; then connect its versioned alerts cleanly to MINERVA and VULCAN.

### Cycle 30 — bound Apollo rule/event evaluation and preserve detection provenance

- **Status:** `DONE` for APOLLO application/policy and versioned detection contracts; the
  repository-wide policy parent remains `IN PROGRESS` for MINERVA, VULCAN, AEGIS and native
  integrations.
- **Objective:** prevent catch-all or ambiguous rules, invented event identity, silently discarded
  telemetry, unbounded offline evaluation, unstable alert identity, and lost rule/MITRE provenance;
  keep one domain path behind CLI and downstream consumers.
- **Component:** APOLLO rule loader, event-stream adapter, detection engine, application service,
  CLI/output adapter, shared `Alert` contract, example rules, contract/policy/reference/audit docs,
  and offline integration tests.
- **Dependencies:** shared `ExecutionPolicy`/cancellation and SemVer compatibility, strict Pydantic
  contracts, YAML safe loading, no-follow regular-file descriptors, atomic files, SHA-256 stable IDs,
  and the existing MINERVA/VULCAN shared-alert consumers.
- **Completion criteria:** rules and events have exact supported schemas or one explicit unambiguous
  legacy migration; rule sets are non-empty with unique IDs and non-empty exact conditions; no regex,
  expression or shell evaluation occurs; files, rules, event records/bytes, evaluations, alerts and
  deadline are bounded below Typer; symlink/non-regular and input/output-conflicting paths fail;
  malformed/conflicting records are never silently skipped; exact duplicates do not inflate alerts;
  alerts retain rule/MITRE/time provenance and stable identity; partial streams export available
  alerts atomically but exit non-clean; MINERVA can consume the produced collection.
- **Implementation:** introduced `ApolloApplicationService` with typed test/run outcomes, cooperative
  cancellation and a shared overall deadline. Rule files now carry `olympus.apollo-rule` `1.0.0`,
  validate exact headers, bounded fields, at least one condition, unique IDs and MITRE identifiers,
  and use capped UTF-8 no-follow reads; the former headerless shape has one named migration. Event
  files/NDJSON are capped during physical-line streaming; legacy events require their complete
  identity instead of receiving invented IDs/timestamps; duplicate IDs require identical data;
  malformed records become line-numbered partial errors. Evaluation caps rule/event products and
  alerts, checks cancellation/deadline, and rejects duplicate rule IDs even for library callers.
  Alert IDs are stable hashes of rule/event IDs and now include `rule_id`, `mitre_attack`, and the
  observation time. Typer delegates to the service, exposes all resource limits, uses canonical exit
  codes, and writes unique fsynced atomic output without overwriting inputs.
- **Files modified:** `src/olympus/apollo/application.py`, `src/olympus/apollo/cli.py`,
  `src/olympus/apollo/engine.py`, `src/olympus/apollo/export.py`,
  `src/olympus/apollo/rules.py`, `src/olympus/core/models.py`, all 20 Apollo YAML fixtures under
  `examples/input`, `tests/unit/test_apollo.py`, `docs/apollo.md`, `docs/contracts.md`,
  `docs/execution-policy.md`, `docs/reference.md`, `docs/ecosystem-audit.md`, and `upgrade.md`.
- **Tests executed:** focused APOLLO plus downstream MINERVA/VULCAN suite: `52 passed`; complete
  offline suite: `618 passed`; Ruff: clean; strict mypy: clean across 120 source files with a fresh
  generated cache directory.
- **Real execution evidence:** installed `olympus apollo test` evaluated the versioned example pair,
  exited 0, and produced one `ALT-A533997F698B4F6BA4EE7B28` alert with
  `APL-DEMO-PWSH`/`T1059.001`. Installed `apollo run` read two identical physical records, reported
  one duplicate, emitted the same single deterministic alert and exited 1. A stream containing that
  valid event plus one identity-incomplete record preserved the alert, named the missing fields on
  line 2 and exited 2. Installed `olympus minerva triage` consumed the complete Apollo export,
  retained the identical alert ID in its incident and exited 0.
- **Residual limitations:** matching deliberately supports only exact scalar attributes on one event;
  temporal correlation, windows, numeric/range operators and reviewed regex would need a separate
  bounded operator grammar rather than executable/user-controlled expressions. Cooperative
  cancellation occurs between bounded file/evaluation operations; `O_NOFOLLOW` requires equivalent
  platform controls where unavailable. The optional alert provenance fields preserve compatibility
  with existing `1.0.0` readers; a future required-field transition needs a new major contract.
- **Next activity:** inspect MINERVA incident/custody and VULCAN aggregation/report paths for
  unbounded or symlinked inputs, ambiguous legacy contracts, mutable/partially verified evidence,
  unsafe report rendering, Typer-domain coupling, cancellation/deadline gaps, and cross-module
  provenance loss; then implement their common application/policy boundary and real Apollo-to-report
  proof.

### Cycle 31 — anchor Minerva custody and make Vulcan aggregation lossless and bounded

- **Status:** `DONE` for MINERVA and VULCAN application/policy adoption; the repository-wide policy
  parent remains `IN PROGRESS` for AEGIS and native/API/worker integrations.
- **Objective:** eliminate false verification of missing custody ledgers, bind custody history to the
  actual evidence digest, prevent concurrent lost updates and invalid state transitions, bound all
  incident/report inputs, stop lossy semantic deduplication, validate full producer envelopes, and
  preserve Apollo rule/MITRE provenance in every report view.
- **Component:** shared local file I/O, MINERVA triage/custody/application/CLI and example ledger,
  VULCAN aggregation/report/application/CLI, cross-module alert/report flow, contracts, execution
  policy, command reference, ecosystem inventory, dedicated docs, and tests.
- **Dependencies:** shared `ExecutionPolicy`/cancellation and strict SemVer contracts, Pydantic nested
  validation, no-follow regular-file descriptors, SHA-256, POSIX advisory locking with a process-local
  fallback, owner-only unique fsynced atomic files, and HTML/Markdown escaping.
- **Completion criteria:** a missing/symlink/non-regular/oversized ledger or input never verifies or
  reports clean; triage accepts only a bounded strict Apollo collection, rejects conflicting IDs and
  produces stable incidents; new custody entries anchor the evidence digest, validate sequence/hash/
  time/state/digest invariants, serialize concurrent appenders and are private/durable; legacy custody
  is honestly read-only. VULCAN caps file/item/aggregate/output resources, validates complete supported
  producer envelopes and nested objects, rejects incompatible/unknown contracts, deduplicates only
  exact stable IDs while rejecting conflicts, checks asset references when inventory is present,
  renders all assets/findings/alerts safely from one canonical model, and protects every output path.
- **Implementation:** added shared `read_regular_bytes`/`read_regular_text` and unique fsynced atomic
  write adapters. `MinervaApplicationService` now owns triage, evidence loading, record and inspection
  deadlines/cancellation/output conflicts. Triage validates exact collection fields, caps bytes/count,
  rejects conflicting duplicate IDs and derives stable incident identity/times from alerts. Custody
  `2.0.0` hashes lowercase `evidence_sha256` into every entry, enforces per-evidence transitions and
  digest immutability, locks a private stable sibling before re-verification/append, caps chain bytes/
  entries, writes mode `0600`, and makes `1.0.0` verifiable but read-only with exit 1. Missing chains
  exit 2. `VulcanApplicationService` preflights aggregate/file/output paths and limits, validates strict
  Argus fronting/assets, Athena result, Helios result/findings, Apollo alerts and security-report
  envelopes plus every nested contract, retains only exact duplicates, rejects conflicting IDs and
  orphan finding references, and renders JSON/Markdown/HTML from one `SecurityReport`. Markdown
  metacharacters and all HTML values are escaped; HTML now includes assets and alert provenance.
- **Files modified:** `src/olympus/core/fileio.py`, `src/olympus/minerva/application.py`,
  `src/olympus/minerva/cli.py`, `src/olympus/minerva/custody.py`,
  `src/olympus/minerva/triage.py`, `src/olympus/vulcan/application.py`,
  `src/olympus/vulcan/aggregate.py`, `src/olympus/vulcan/cli.py`,
  `src/olympus/vulcan/report.py`, `examples/output/minerva-custody.json`,
  `tests/unit/test_minerva_custody.py`, `tests/unit/test_minerva_triage.py`,
  `tests/unit/test_vulcan.py`, `docs/minerva.md`, `docs/vulcan.md`, `docs/contracts.md`,
  `docs/execution-policy.md`, `docs/reference.md`, `docs/ecosystem-audit.md`, and `upgrade.md`.
- **Tests executed:** focused MINERVA/VULCAN plus Apollo/Athena downstream suite: `68 passed`;
  complete offline suite: `629 passed`; Ruff: clean; strict mypy: clean across 123 source files with a
  fresh generated cache directory.
- **Real execution evidence:** installed `olympus minerva record` appended collected/analyzed events
  for the versioned example evidence; installed verify/timeline both exited 0. The resulting custody
  file was `2.0.0`, contained two entries with the expected 64-hex evidence digest, and had POSIX mode
  `0600`. Installed verify against a missing sibling exited 2 with a precise nonexistence failure.
  Installed triage consumed the Cycle 30 Apollo export and emitted stable incident
  `INC-5253A3432671E76148986D0C` linked to `ALT-A533997F698B4F6BA4EE7B28`. Installed Vulcan consumed
  that same versioned export and wrote JSON, Markdown, and self-contained HTML with one shared
  generation time, one alert, `APL-DEMO-PWSH`, and `T1059.001`; every command exited 0.
- **Residual limitations:** an unkeyed hash chain detects changes only while a trusted terminal hash
  exists outside an attacker's rewrite boundary; authentic non-repudiation requires externally
  anchoring/signing that head in a separately controlled case system. POSIX file locking/mode/no-follow
  semantics require equivalent ACL/locking controls on other platforms. JSON/Markdown/HTML are each
  atomic, but a filesystem failure between their separate replacements cannot create a cross-file
  transaction; canonical JSON is the machine source of truth. Bare arrays/single objects remain an
  explicit legacy VULCAN read adapter until their producers are migrated to versioned envelopes.
- **Next activity:** audit the Olympus-native AEGIS execution layer, the vendored FastAPI/Celery
  boundary, scanner registry/adapters and web/API/worker/database/report paths for authorization and
  scope drift, simulated-result leakage, unsafe subprocess/environment handling, unbounded results,
  contract mismatch, dependency/service truthfulness, and parity gaps; then implement the next
  independent real-adapter/policy slice and verify it without requiring unavailable external engines.

### Cycle 32 — add native capability routing, CTI cases and bounded recon pipelines

- **Status:** `DONE` for the six requested reference reviews and their independent native
  implementations. ARGUS and the Vulnerability Assessment Platform remain pinned to their current
  upstream heads and complete in their vendored standalone boundaries.
- **Objective:** review useful architecture and workflows from `pentest-ai-agents`, `cti-expert`,
  `Anthropic-Cybersecurity-Skills`, `Cybersecurity-Projects`, BBOT and GhostTrack, then implement the
  selected capabilities inside Olympus without runtime links, imports or copied source.
- **Implementation:** added METIS with a deterministic, explainable 14-capability router, safe
  non-executing engagement plans, a bounded owner-only SQLite CTI case store, normalized IOC
  extraction, sourced/confidence-scored findings, correlations, safe private reports and guided
  native labs. Added the Argus typed-event pipeline with strict presets, recursion, stable event IDs,
  deduplication, provenance edges, blacklist/depth/event limits, private atomic output and shared
  authorization plus per-pivot scope enforcement for injected active modules. Existing native Argus
  IP, phone, username/account and public-IP paths already cover the reviewed GhostTrack concepts with
  stronger scope and audit controls.
- **Reference and licence review:** pinned all six reviewed revisions in
  `docs/parity/reference-implementations.json`. MIT/Apache concepts were independently redesigned;
  AGPL sources were not copied into the MIT-native package, and GhostTrack was treated as
  unlicensed (`NOASSERTION`). Corrected the vendored Vulnerability Assessment Platform licence from
  the previously mislabelled MIT value to its actual `GPL-3.0-only` component licence and added
  `THIRD_PARTY_NOTICES.md`.
- **ARGUS/VAP verification:** the vendored ARGUS revision
  `1c7a8310ee64e005878dfa183ca8a384760706c6` and VAP revision
  `6c6b395d79f358372e028fe7094cc673374dd88f` are the current repository heads. Contract tests retain
  every ARGUS module and all 24 VAP scanner integrations, their entrypoints, licences and complete
  source boundaries. This does not misrepresent the complementary native AEGIS runner: it still has
  six real local adapters while the complete 24-scanner platform is the vendored web/worker app.
- **Files added/modified:** `src/olympus/metis/`, `src/olympus/argus/pipeline.py`, their CLI/schema
  registration, example preset, tests, bilingual README, provenance/parity/licence/audit docs, and
  the AEGIS audit-redaction fix in `src/olympus/core/execution.py`.
- **Verification:** the complete 654-test offline suite passes and Ruff is clean across `src` and
  `tests`. Mypy 2.3.1 initially identified one protocol-comprehension type mismatch, which was fixed;
  it then aborted with its own internal error because the inherited workspace runs Python 3.11
  against a broken Python 3.12 virtual environment. No mypy success is claimed.
- **Residual limitations:** external scanner binaries, commercial engines, Redis workers and a
  Docker daemon are not available in this workspace, so live 24-scanner execution is not claimed.
  METIS routing is intentionally deterministic and local; it does not execute autonomous agents or
  send data to model APIs. Active Argus pipeline extensions must be explicitly injected and gated.
- **Next activity:** continue the open AEGIS native/API/worker policy work and add authorized opt-in
  live-network smoke coverage in an environment with the required services and scanner engines.

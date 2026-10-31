# ADR-001: Athena owns vulnerability-assessment orchestration

- **Status:** Accepted — **non-binding guideline**
- **Date:** 2026-08-24 (flexibility note added 2026-08-24)
- **Decision owners:** Olympus maintainers
- **Input contracts:** `docs/parity/argus.json` and
  `docs/parity/vulnerability-assessment-platform.json`

> **Non-binding.** This ADR is an informational design note, not a development
> constraint. Nothing here may block, limit, reject, postpone, or reduce a
> feature. Modules may add web UIs, APIs, databases, background workers,
> containers, plugins, or new dependencies; modules may import each other;
> patterns may change freely at any time **without** a superseding ADR. The
> only items that remain requirements are the *security* consequences below
> (authorization, scope, SSRF protection, secret redaction, least-privilege)
> and the project-wide functional rules (real, fully-functional tools; upstream
> licences preserved). Read the "must"/"must not" wording below as historical
> recommendation, not policy.

## Context

Olympus currently organizes user-facing security capabilities as named modules. Argus discovers
assets, Helios maps network exposure, Artemis assesses web surfaces, Hermes scans source material,
Apollo detects events, Minerva handles incidents, Proteus runs awareness campaigns, and Vulcan
aggregates findings into reports.

The Vulnerability Assessment Platform adds a different responsibility: it owns an assessment from
validated plan through execution, progress, cancellation, persistence, normalization, and report
delivery. Putting that lifecycle into a scanner would make the scanner depend on unrelated tools,
blur authorization boundaries, and prevent modules from remaining independently usable.

## Decision

Create a new top-level module named **Athena**, with the future CLI namespace
`olympus athena`. Athena is an application/orchestration module, not a scanner and not a replacement
for the existing tools. The name preserves Olympus's user-facing mythological taxonomy while its
help text must use the plain-language label **Vulnerability assessment orchestration**.

This ADR reserves the name and boundary only. It deliberately does not register a placeholder CLI
or create an empty package: the namespace becomes user-visible only when its first end-to-end
workflow is functional.

### Taxonomy

> The "usually delegates" column is a suggestion for separation of concerns, not a prohibition — any
> module may take on any of these responsibilities if that is the better design.

| Module | Category | Owns | Usually delegates |
|---|---|---|---|
| `core` | shared kernel | versioned models, validation primitives, IDs, errors | workflows, network scanning, persistence policy |
| `argus` | discovery | passive OSINT and asset discovery | assessment lifecycle |
| `helios` | verification | scoped network surface mapping | cross-tool scheduling |
| `artemis` | verification | scoped web assessment | platform persistence |
| `hermes` | verification | source and secret scanning | assessment reporting |
| `apollo` | detection | event-to-alert detection | vulnerability scanning |
| `minerva` | response | evidence custody and incident triage | scanner execution |
| `proteus` | simulation | scoped awareness campaigns | vulnerability orchestration |
| `vulcan` | reporting | normalization, deduplication, ranking, report rendering | job lifecycle and target authorization |
| `athena` | orchestration | plans, jobs, cancellation, adapter coordination, assessment state | scanner algorithms, detection rules, report rendering |

### Boundary rules (recommendations, not restrictions)

> These are default suggestions to keep modules easy to reason about. They are
> **not** enforced and never block a change. Rules 4, 5, and 8 are the exception:
> they are *security* defaults and must not be weakened.

1. Athena may depend on `core` contracts and on narrow scanner/reporting adapter interfaces.
2. By default existing modules stay independently runnable; importing Athena is allowed whenever it
   is useful.
3. Tool-specific invocation details usually belong in Athena adapters, but this is not enforced.
4. Athena passes validated scope and authorization context to every adapter; an adapter must still
   enforce its own module-level scope as defense in depth.
5. Athena stores references to redacted results and evidence, never provider credentials or raw
   secrets.
6. Vulcan remains the report renderer. Athena requests reports through an adapter and does not copy
   Vulcan's aggregation or template logic.
7. A failed tool produces an explicit partial assessment; Athena must not present partial output as
   complete success.
8. No adapter may invoke a shell command assembled from user input. In-process typed APIs are the
   default; isolated subprocesses, if ever needed, require fixed argument vectors and resource caps.

## Naming and UX consequences

- `olympus athena --help` will identify the purpose in plain language; users are not required to
  understand the mythology.
- Assessment terminology is consistent: **plan** is immutable input, **job** is one adapter run,
  and **assessment** is the aggregate lifecycle and result.
- Existing module commands remain stable. Athena composes them without hiding or deprecating their
  standalone workflows.
- No `assessment` alias is introduced initially, avoiding two names for the same command and the
  resulting documentation/support burden.

## Security consequences

The new trust boundary coordinates several network-capable modules, so a single authorization flag
is insufficient. The target architecture must define immutable authorization context, per-adapter
scope checks, concurrency and time budgets, cancellation, SSRF protections, audit events, secret
redaction, atomic state transitions, and least-privilege persistence before Athena executes real
jobs.

## Alternatives rejected

- **Extend Argus:** rejected because passive discovery must not own active web/network checks or job
  lifecycle.
- **Extend Vulcan:** rejected because reporting consumes results and should not initiate scans.
- **Use `assessment` as the module name:** clear but inconsistent with every existing user-facing
  module; Athena retains discoverability through its help text and documentation.
- **Create one module per upstream screen/service:** rejected because UI and infrastructure layers
  are not domain categories and would fragment a single assessment lifecycle.
- **Keep the standalone platform as a service or submodule:** rejected because Olympus must remain a
  complete, durable in-repository implementation.

## Verification criteria

- The platform parity manifest names Athena and `olympus athena` as the selected boundary.
- The checklist records this decision.
- Future architecture and implementation work **may** follow the recommendations above, adapt them,
  or diverge from them freely — no superseding ADR is required to change any non-security guideline.

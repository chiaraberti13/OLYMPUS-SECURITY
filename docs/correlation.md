# Correlation across the shared contracts (`CORR-1`)

A single finding is one tool's view of one asset. The security picture emerges
from the **relationships** between findings — the same asset reported by several
tools, the same vulnerability spread across the estate. `olympus.vulcan.correlate`
is the single, tested place that derives those relationships from the shared
[`olympus.finding`](contracts.md) contract. It is pure and offline: it reads
already-loaded findings and opens no network connection.

## What a correlation is

Every correlation is a **versioned record** (`olympus.correlation` 1.0.0) and, per
`CORR-1`, is:

- **traceable** — it names the `members` (finding ids) and the `sources` it was
  built from;
- **motivated** — it carries a plain-language `reason`;
- **graded** — it carries a `confidence` and an
  [`EpistemicClass`](findings.md) (the same taxonomy as `EXPL-1`).

**A correlation is a relationship, never a claim of compromise.** The engine does
not assert that an attacker used a relationship; it states the relationship and how
it is known. Most kinds below are deterministic joins on identity, so they are
`deterministic_result` facts — not inferences and not hypotheses. One kind,
`ioc-event`, is a weaker threat-intel **lead** and carries `suggested_correlation`;
still weaker, inferred relationships (suggested exposure paths) will carry
`unverified_hypothesis` when later slices add them. A hypothesis is never presented
as a fact, and no match is ever presented as a compromise.

## Relationship kinds

| Kind | Fires when | `key` | `sources` | Class |
| --- | --- | --- | --- | --- |
| `asset-overlap` | one asset carries findings from **≥2 distinct tool sources** | the asset id | the tool sources | `deterministic_result` |
| `shared-cve` | one CVE appears on findings against **≥2 distinct assets** | the CVE id | the asset ids | `deterministic_result` |
| `shared-evidence` | one Minerva evidence artifact is cited by **≥2 distinct findings** | the evidence reference | the citing findings' tool sources | `deterministic_result` |
| `ioc-event` | a Metis indicator value is **observed in** an Apollo event | `type:value` of the indicator | the observing events' sources | `suggested_correlation` |

`shared-evidence` joins findings through a common custody artifact: the reference
carried in `Finding.evidence` points at an [`olympus.evidence`](contracts.md) id or
digest, so two findings citing the same artifact are corroborated by it. The join
is on the citation itself (a deterministic fact about the findings); blank
references link nothing. It is **not** a claim that the artifact proves compromise.

`ioc-event` is the first **cross-module** and the first **non-deterministic** kind:
a Metis [`Indicator`](contracts.md) value that appears in an Apollo
[`olympus.event`](contracts.md) (any attribute value, or the event's `asset_id`)
links threat intel to telemetry. Matching is exact on a normalised value
(whitespace-stripped, lower-cased — case-insensitive for domains, URLs, e-mails,
hashes and CVE ids; IP literals unaffected), so the *match* is deterministic — but
an IOC hit is a **lead**, not proof the event is the entity the intel meant
(addresses and domains are reused, shared and reassigned). It therefore carries
`suggested_correlation` with `medium` confidence and says so in its reason: a
hypothesis is never presented as a fact, and never as a compromise.

Findings are folded by logical identity first (one issue seen twice counts once),
indicators sharing a `type:value` are folded too, and the output is ordered
deterministically by `(kind, key)`.

```bash
# Correlate a set of findings; human table or --format json (the versioned
# olympus.correlations document).
olympus vulcan correlate --findings findings.json
olympus vulcan correlate --findings a.json --findings b.json --format json

# Cross-module IOC↔event: a Metis case's indicators observed in Apollo events.
olympus vulcan correlate --case case.json --events events.json --format json
```

## Surfaces

The same offline `correlations_document` core backs every surface, so the CLI and
the API return byte-identical documents (`CORR-2`):

- **CLI** — `olympus vulcan correlate` (table or `--format json`), above.
- **API** — `POST /api/v1/vulcan/correlate` (scope `findings:read`), body
  `{findings, indicators, events}` (bounded lists; at least `findings`, or both
  `indicators` and `events`, required), response the versioned
  `olympus.correlations` document. Pure and offline — the server never scans or
  reaches the network.
- **Report** — `olympus vulcan report --correlations PATH` writes a companion
  `olympus.correlations` document over the report's own ranked/filtered findings
  (the finding-join kinds), so the report ships its relationships alongside the
  findings without a separate call.

A Web view is the remaining `CORR-2` work (only via `WEB-8`).

## Decision: no dedicated Security Knowledge Graph (yet)

`CORR-1` asks whether a Security Knowledge Graph (a graph database/engine) is
needed. **Decision: no, not now** — correlation stays pure in-memory functions over
the shared contracts.

- **Need.** Today's correlations are bounded joins on identity over a loaded
  finding set (hundreds to low thousands of records per assessment), computed once
  for a CLI/report/API call. That is a `O(n)` fold, not a graph-traversal or
  multi-hop-query workload.
- **What already exists.** `olympus.argus.graph` already models host/subdomain
  relationships for recon, and persistence is covered by SQLite today with a
  Postgres path tracked under `TECH-3`; there is no query, volume or multi-user
  requirement a graph store would satisfy that these do not.
- **Cost.** A graph DB/framework would add a heavyweight dependency, a new storage
  and operational surface, and supply-chain/attack surface — against `DEC-6` (no
  database or framework is imposed) and the offline-first posture.
- **Revisit when** a measured need appears: multi-hop exposure-path queries across
  modules, cross-assessment history at scale, or concurrent multi-user querying. At
  that point reuse `argus.graph`/Postgres (`TECH-3`) before introducing a dedicated
  graph engine, and record the decision in an ADR.

## Remaining `CORR-1` work

- The relationship-kind corpus is complete: deterministic `asset-overlap`,
  `shared-cve` and `shared-evidence`, plus the cross-module
  `suggested_correlation` lead `ioc-event`. `unverified_hypothesis` is reserved
  for still weaker, inferred relationships.
- The CLI and the API (`POST /api/v1/vulcan/correlate`) expose every kind; a Web
  view and report integration are the remaining `CORR-2` work.

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
it is known. The kinds below are deterministic joins on identity, so they are
`deterministic_result` facts — not inferences and not hypotheses. Weaker, inferred
relationships (suggested exposure paths) will carry `suggested_correlation` or
`unverified_hypothesis` when later slices add them, so a hypothesis can never be
presented as a fact.

## Relationship kinds (first slice)

| Kind | Fires when | `key` | `sources` | Class |
| --- | --- | --- | --- | --- |
| `asset-overlap` | one asset carries findings from **≥2 distinct tool sources** | the asset id | the tool sources | `deterministic_result` |
| `shared-cve` | one CVE appears on findings against **≥2 distinct assets** | the CVE id | the asset ids | `deterministic_result` |

Findings are folded by logical identity first (one issue seen twice counts once),
and the output is ordered deterministically by `(kind, key)`.

```bash
# Correlate a set of findings; human table or --format json (the versioned
# olympus.correlations document).
olympus vulcan correlate --findings findings.json
olympus vulcan correlate --findings a.json --findings b.json --format json
```

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

- Further relationship kinds across modules: IOC (Metis) ↔ event/detection
  (Apollo), and Minerva evidence ↔ finding — each with its epistemic class.
- Surfaces (API/Web) and report integration land in `CORR-2`.

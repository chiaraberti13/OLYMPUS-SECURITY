# Findings and vulnerability intelligence

A **finding** is Olympus's record of a weakness, vulnerability or
misconfiguration attached to an asset. Every assessment module (Artemis,
Helios, Themis, …) produces findings against the **same** `olympus.finding`
contract, and every consumer (Athena, Vulcan, the report and PDF renderers)
reads that one contract — there is no per-module finding shape.

## Contract

`olympus.finding` (`src/olympus/core/models.py`) carries the descriptive core —
`finding_id`, `asset_id`, `source`, `title`, `description`, `severity`,
`status`, `cvss`, `evidence`, `remediation`, `references`, timestamps — plus an
**additive** layer of structured vulnerability intelligence (ROADMAP `WEB-C`):

| Field             | Type                 | Meaning                                                            |
| ----------------- | -------------------- | ----------------------------------------------------------------- |
| `cve`             | `list[str]`          | Canonical CVE ids, e.g. `["CVE-2021-44228"]`.                     |
| `cwe`             | `list[str]`          | Canonical CWE ids, e.g. `["CWE-502"]`.                            |
| `epss`            | `float \| None`      | FIRST EPSS exploit probability in `[0, 1]`.                        |
| `epss_percentile` | `float \| None`      | EPSS percentile in `[0, 1]`.                                       |
| `kev`             | `bool`               | Listed in the CISA Known Exploited Vulnerabilities catalogue.     |
| `confidence`      | `Confidence \| None` | Analyst confidence the finding is a true positive (`low`/`medium`/`high`). |

These fields are **optional with defaults**, so the contract stays at
`schema_version` `1.0.0`: a finding persisted before `WEB-C` (without any of
them) still validates, and the new fields simply default to empty/unset.

### Why these fields

CVSS tells you how *bad* a vulnerability is if exploited; it says nothing about
whether anyone is exploiting it. Risk-based triage needs both:

- **CVE** — [Common Vulnerabilities and Exposures](https://www.cve.org/), the
  public catalogue id. Olympus links each CVE to the
  [NIST NVD](https://nvd.nist.gov/) detail page in reports.
- **CWE** — [Common Weakness Enumeration](https://cwe.mitre.org/), the weakness
  *class* (e.g. CWE-79 Cross-site Scripting). Linked to the MITRE definition.
- **EPSS** — [FIRST Exploit Prediction Scoring System](https://www.first.org/epss/):
  a daily probability (0–1) that a CVE will be exploited in the next 30 days.
- **KEV** — [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  confirmed in-the-wild exploitation; the strongest "fix this now" signal.

Validation (Pydantic v2 field validators — see the official
[Pydantic validators docs](https://docs.pydantic.dev/latest/concepts/validators/)):
`cve`/`cwe` entries are upper-cased and must match the `CVE-YYYY-NNNN(NNN)` /
`CWE-N` patterns; `epss` and `epss_percentile` must lie in `[0, 1]`. A malformed
id or an out-of-range probability raises a `ValidationError`.

## Structured first, free text as a fallback

Two helper methods resolve a finding's identifiers:

```python
finding.cves()  # -> sorted, de-duplicated CVE ids
finding.cwes()  # -> sorted, de-duplicated CWE ids
```

Each helper returns the **structured** field when it is set; otherwise it falls
back to scanning the finding's free text (`title`, `description`, `references`,
`evidence`) with the CVE/CWE regexes. This keeps pre-`WEB-C` findings — where a
scanner only mentioned `CVE-2021-44228` in prose — working exactly as before,
while letting newer producers populate the structured fields directly.

**Example.** A finding whose title says *"mentions CVE-2000-1111"* but whose
`cve` field is `["CVE-2021-44228"]` resolves to `["CVE-2021-44228"]`: the
structured field wins, and the stray text id is ignored.

## Contextual risk score

`Finding.risk_score()` returns a single scalar in `[0, 100]` that blends the
finding's fields in the same priority order Vulcan uses to rank findings
(**KEV > EPSS > CVSS > severity**, see `olympus.vulcan.enrichment.prioritize`),
so a UI or report can sort and threshold on one number:

- **base** = `cvss × 10` when a CVSS is present, else a severity band
  (`info` 10, `low` 30, `medium` 50, `high` 75, `critical` 90);
- **CISA KEV** membership (confirmed in-the-wild exploitation) raises the score
  to at least **95** — it dominates everything else;
- otherwise **EPSS** (predicted exploitation probability) lifts the floor to
  `epss × 100`, so a likely-exploited finding outranks a merely severe one;
- **confidence** is a mild modifier only (`high` +5, `low` −10): it nudges, it
  never decides.

It is **computed on demand** from the current fields — never stored, so never
stale, and no addition to the wire/storage contract. The PDF report shows it on
each finding's metadata line (`Risk NN/100`).

```python
finding.risk_score()  # e.g. 95.0 for a KEV-listed CVE, 30.0 for a quiet low finding
```

## Lifecycle state machine

A finding is not static: it is triaged, confirmed or dismissed, remediated,
accepted as a known risk, or re-opened on recurrence. `core/finding_lifecycle.py`
is the single source of truth for which `FindingStatus` changes are legal, so
CLI, TUI, API and the Web UI enforce the **same** workflow rather than letting
any code set `status` to any value.

The transitions are defined over the existing seven `FindingStatus` states (no
new states, so no schema change):

| From | May move to |
| --- | --- |
| `new` | `triaged`, `confirmed`, `false_positive`, `accepted`, `closed` |
| `triaged` | `confirmed`, `false_positive`, `accepted`, `closed` |
| `confirmed` | `in_remediation`, `accepted`, `false_positive`, `closed` |
| `false_positive` | `confirmed` (only, if it turns out real) |
| `accepted` | `confirmed`, `closed` |
| `in_remediation` | `closed`, `confirmed` (retest failed), `accepted` |
| `closed` | `confirmed` (recurrence / retest required) |

A transition to the **same** status is rejected, so a no-op never masquerades as
a workflow step.

```python
from olympus.core.enums import FindingStatus
from olympus.core.finding_lifecycle import transition, can_transition

if can_transition(finding.status, FindingStatus.CONFIRMED):
    finding = transition(finding, FindingStatus.CONFIRMED)  # returns an updated copy
```

`transition(finding, target)` returns a **copy** with the new status and a
refreshed `last_seen` (the original is untouched); an illegal move raises
`FindingTransitionError` naming both states.

### Audit trail

A finding carries only its *current* status; the durable trail of **how it got
there** lives in append-only `olympus.finding-transition` records. Use
`record_transition` to apply a move and capture its audit record together:

```python
from olympus.core.enums import FindingStatus
from olympus.core.finding_lifecycle import record_transition
from olympus.findings.store import SqliteFindingTransitionStore

moved, record = record_transition(
    finding, FindingStatus.ACCEPTED, actor="analyst@team", reason="accepted risk until Q3"
)
store = SqliteFindingTransitionStore(Path("./workspace/finding_transitions.db"))
store.append(record)  # append-only, owner-only (0600)
store.history(finding.finding_id)  # every transition, oldest first
```

Each `FindingTransition` records `from_status`, `to_status`, `actor`, an optional
`reason` (the rationale for a suppression or accepted-risk decision),
`occurred_at`, and the finding's `engagement_id`. The store is **append-only**:
records are inserted, never replaced or deleted, so the history cannot be
rewritten through the API (a duplicate `transition_id` is rejected). This answers
"who accepted this risk, and when?" without trusting the mutable finding.

### Suppression

Suppressing a finding (accepting the risk, or dismissing it as a false positive)
removes it from the active worklist, so Olympus refuses to do it silently — a
**justification is required**:

```python
from olympus.core.enums import FindingStatus
from olympus.core.finding_lifecycle import suppress, unsuppress, is_suppressed

moved, record = suppress(finding, actor="analyst@team", reason="accepted until Q3")
# or dismiss as a false positive:
moved, record = suppress(
    finding,
    actor="analyst@team",
    reason="duplicate of FND-X",
    as_status=FindingStatus.FALSE_POSITIVE,
)
is_suppressed(moved)  # True  (status in {accepted, false_positive})
reopened, record = unsuppress(moved, actor="analyst@team", reason="resurfaced on retest")
```

`suppress` requires a non-empty `reason` and a suppression target status
(`accepted` or `false_positive`); `unsuppress` re-opens a suppressed finding to
`confirmed`. Both go through the lifecycle state machine and produce an audit
record, so a suppression is always both legal and justified.

## Cross-scanner deduplication

Two scanners often report the *same* vulnerability on the same asset with
different `finding_id`s. `vulcan.aggregate.merge_duplicate_findings` collapses
those into one finding **without losing evidence** (a `WEB-C` completion
criterion):

- **Identity.** Findings are grouped by `(asset_id, vulnerability)`, where the
  vulnerability is the set of CVEs when any are known (structured or
  text-derived), else the normalized title. This is conservative: with no shared
  CVE, only identical titles merge, so distinct issues are never collapsed.
- **Lossless merge.** Evidence, references, CVE and CWE ids are unioned; the most
  urgent signal wins for each scalar (max severity, CVSS, EPSS; KEV if any source
  saw it; highest confidence). The representative (highest severity, then risk,
  then stable id) supplies the title, description, remediation, status and id;
  timestamps widen to the group's real span.

It runs in the Vulcan aggregation pipeline after the exact-id `dedupe_findings`,
and is stable and idempotent (a finding with no duplicate passes through
unchanged).

## Tagging, search and filters

Findings carry free-form `tags` (operator labels for triage and grouping —
additive and optional, like `Asset.tags`; trimmed, de-duplicated and emptied of
blanks on validation). `vulcan/search.py` is the single, tested place that
decides what a filter means, so the CLI, TUI and Web UI narrow findings the same
way.

`FindingFilter` is an immutable value object; every criterion is optional and an
unset one does not constrain the result:

| Criterion | Matches when |
| --- | --- |
| `statuses` | the finding's `status` is in the set |
| `sources` | the finding's `source` is in the set |
| `min_severity` | severity ≥ the threshold |
| `engagement_id` | the finding is linked to that engagement |
| `kev_only` | the finding is KEV-listed |
| `has_cve` | the finding has (or lacks) any CVE |
| `tags` | the finding carries **all** these tags (case-insensitive) |
| `text` | case-insensitive substring over title, description, references, CVE/CWE, tags and the asset/finding ids |
| `min_risk_score` | `risk_score()` ≥ the threshold |

```python
from olympus.core.enums import FindingStatus, Severity
from olympus.vulcan.search import FindingFilter, search_findings

query = FindingFilter(
    statuses=frozenset({FindingStatus.CONFIRMED}),
    min_severity=Severity.HIGH,
    kev_only=True,
)
urgent = search_findings(all_findings, query)  # AND semantics, input order kept
```

Criteria combine with **AND**; `search_findings` preserves input order (rank
separately with `rank_findings` or `risk_score`).

## Finding view

Browsing findings — in the CLI, the TUI or the Web UI — must show the same
columns, derive them the same way, and be **honest about absence**: a datum the
finding does not carry (no CVSS yet, no EPSS overlay, no remediation written) is
not the same as a present-but-empty one, and must never render as a fabricated
`0` or a blank that reads like "none found". `vulcan/view.py` is the single,
tested place that projects an `olympus.finding` into presentation-ready values
(the same "one source of meaning" principle `search.py` applies to filtering):

```python
from olympus.vulcan.view import FindingView, rank_by_risk

view = FindingView(finding)
view.row()  # compact one-line cells for a table (LIST_COLUMNS)
view.display_items()  # ordered (label, value) pairs for a detail view
view.detail()  # full JSON-serialisable projection (absent scalars stay None)
ordered = rank_by_risk(findings)  # descending risk_score, stable for ties
```

A missing scalar is kept as `None` in `detail()` (machine types preserved) and
rendered as `—` (`view.ABSENT`) in `row()`/`display_items()`, so every interface
can tell absent from empty. The view carries the full `WEB-C` column set — title,
severity, status, asset, source, CVE, CWE, CVSS, EPSS, CISA KEV, confidence,
evidence, first/last seen, remediation, references, tags — plus the contextual
`risk_score`. There is no separate *scanner* field on the contract: `source` is a
finding's provenance (the producing engine, e.g. `themis`), so it carries that
column.

### CLI

`olympus vulcan findings` reuses the filter and the view, so the CLI narrows and
renders findings exactly like the TUI and Web UI will:

```bash
# List, filtered and ordered by descending risk (absent data shown as "—")
olympus vulcan findings list --findings findings.json --kev-only --min-severity high

# Any FindingFilter criterion is a flag: --status, --source, --engagement,
# --has-cve/--no-cve, --tag (repeatable), --text, --min-risk. --format json
# emits the full detail() projection for scripting.
olympus vulcan findings list --findings findings.json --format json

# Inspect one finding with every column
olympus vulcan findings show FND-1234 --findings findings.json
```

## Evidence browser

A finding is only as trustworthy as the material behind it, so an operator must
be able to walk from a finding to its evidence — and judge whether that evidence
is tamper-evident — identically from the CLI, the TUI or the Web UI.
`vulcan/evidence_view.py` is the single, tested place that projects a finding's
`evidence` list into a navigable view, reusing [Minerva's chain of
custody](minerva.md) (the same "one source of meaning" principle `view.py`
applies to columns and `search.py` to filters).

Two kinds of evidence reference can appear on a finding:

- a **structured** reference `EVD-YYYY-NNNNN` that names an `olympus.evidence`
  record and, through Minerva, a tamper-evident chain of custody — its digest,
  the collection/transfer/analysis/archive events, and the ledger's signature
  state;
- an **inline** snippet an adapter attached directly (`scanner=nmap`, `url=...`),
  which is target-influenced free text.

Everything is defanged. Inline snippets and resolved URIs are stripped of
terminal control sequences and passed through `redact_text` (so a hostile target
cannot rewrite the operator's terminal or leak a query secret — see
[`SEC-H`](../ROADMAP.md)), and the raw bytes an evidence reference points at are
never read or printed — only the digest and custody metadata. Absence is told
honestly: an evidence id with no custody record renders as `no-custody`, a
digest that disagrees with the ledger as `digest-mismatch`, and an unsigned or
unverified ledger says so rather than showing a reassuring blank.

The chain-of-custody signature surfaced here is the Minerva ledger's
`HMAC-SHA256` head signature; a verified custody timeline can additionally be
exported and Ed25519-signed with `olympus minerva timeline --export --sign-key`
for third-party verification.

```python
from olympus.vulcan.evidence_view import build_finding_evidence_view

view = build_finding_evidence_view(
    finding,
    custody_records=ledger_entries,  # verified Minerva custody entries (optional)
    evidence_records={evd.evidence_id: evd},  # olympus.evidence records (optional)
    signed=True,
    signature_verified=True,
)
view.rows()  # compact table cells, one per evidence reference
view.custody_signature()  # "HMAC-SHA256 signature verified", "unsigned", ...
view.detail()  # full JSON-serialisable projection
```

```bash
# Browse one finding's evidence against the verified custody ledger.
# Set OLYMPUS_CUSTODY_HMAC_KEY to also verify a signed ledger's HMAC.
olympus vulcan findings evidence FND-1234 \
  --findings findings.json \
  --ledger minerva-custody.json \
  --evidence evidence.json

# --format json emits the full detail() projection for scripting.
olympus vulcan findings evidence FND-1234 --findings findings.json --format json
```

`--ledger` and `--evidence` are both optional: with neither, structured
references still render honestly as `no-custody` rather than disappearing.

## How reports use the fields

- **Vulcan enrichment** (`src/olympus/vulcan/enrichment.py`): `extract_cves()`
  now reads `finding.cves()`, so the live CISA KEV / FIRST EPSS overlay keys off
  the structured CVEs when present, and off the text otherwise.
- **PDF report** (`src/olympus/vulcan/pdf.py`): the per-CVE vulnerability table
  and each finding's metadata line prefer the live enrichment overlay, then fall
  back to the finding's own `epss` / `epss_percentile` / `kev`. This means a
  report shows real exploit intelligence **even when no live enrichment was
  run** (offline or air-gapped engagements). `confidence`, when set, is shown on
  the finding's metadata line.

See [`docs/vulcan.md`](vulcan.md) for the report pipeline and the KEV/EPSS feeds.

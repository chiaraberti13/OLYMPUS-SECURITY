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

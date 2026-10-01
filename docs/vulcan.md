# Vulcan bounded aggregation and reporting

Vulcan is the offline reporting capstone. One application service loads shared
producer contracts, applies exact deduplication and severity filtering, builds
one canonical `olympus.security-report`, and renders JSON, Markdown and HTML
from that same timestamped model.

## Accepted inputs

Vulcan validates complete versioned envelopes and every nested object for:

- Argus assets and fronting results;
- Athena assessment results;
- Helios finding and observation/finding results;
- Apollo alert collections;
- existing Olympus security reports;
- direct versioned `Asset`, `Finding`, and `Alert` objects.

The original bare array or bare single-object forms remain one explicit legacy
adapter. Unsupported/wrong schemas, unknown envelope fields, incompatible
versions, symlinks, devices, malformed JSON and invalid nested objects fail.
Errors omit raw Pydantic input values.

Per-file bytes/items, aggregate bytes/items, file count, output bytes and the
overall deadline are finite. Defaults are 50 MB per file, 200 MB total input,
100 files, 100,000 items per file, 200,000 total items, 100 MB per output, and a
120-second report deadline. Input/output overlaps and duplicate output paths
fail before writing.

## Provenance and rendering

Assets, findings and alerts are deduplicated only when the same stable ID has
exactly the same contract. A conflicting repeated ID is an error; different
records with similar titles are retained, so evidence/remediation is never
silently lost. When an asset inventory is supplied, every finding must refer to
one of its asset IDs.

JSON, Markdown and self-contained HTML include assets, ranked findings and
alerts. Alert rule IDs and MITRE ATT&CK techniques survive the Apollo-to-report
path. HTML escapes every untrusted value and has no external assets; Markdown
collapses control whitespace and escapes active markup characters. Each file
uses a unique fsynced atomic replacement.

```bash
olympus vulcan rank --findings helios-findings.json --format json

olympus vulcan report --engagement ENG-2026-001 \
  --assets argus-assets.json \
  --findings helios-findings.json \
  --alerts apollo-alerts.json \
  --output report.json --markdown report.md --html report.html --pdf report.pdf
```

Supplying JSON plus optional Markdown/HTML/PDF is prevalidated and rendered fully
before the first write. The individual atomic replacements are durable, but a
filesystem failure between separate output replacements cannot provide a
cross-file transaction; the canonical JSON report remains the machine source
of truth.

## Formatted PDF report (`OPS-SCAN`)

`--pdf` writes a designed, presentation-ready report — a branded cover, an
executive summary with KPI tiles and a proportional severity-distribution bar
with a labelled legend, the ranked findings as cards (a severity chip, a
severity-coloured left accent rule, a monospace evidence box and a remediation
callout) and the asset/alert inventories — from the same canonical model as
every other format. `athena run --report` produces it too when the plan's
`output.report_formats` lists `pdf`.

Severity colour is a validated ordinal scale (critical → info). Because it is a
status scale, every mark that carries it also carries its text label (the chip
text, the bar and legend labels), so meaning is never colour-alone, and each
chip's text colour is chosen by WCAG contrast against its own fill.

The renderer uses [ReportLab](https://docs.reportlab.com/), a pure-Python engine
with no system binaries, so the PDF stays fully offline and reproducible. It ships
in the optional `report` extra:

```bash
pip install "olympus-security[report]"
```

Without the extra the PDF format reports a clear, actionable error and the other
formats are unaffected. Every target-controlled value (finding titles,
descriptions, evidence, asset labels, alert text) is XML-escaped before it reaches
the document, so a hostile banner can never inject markup or forge report
structure (`ROADMAP.md` `SEC-H`).

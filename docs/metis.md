# Metis — planning and cyber threat intelligence

Metis adds local, deterministic planning and CTI casework to Olympus. It does
not call an AI provider, run shell commands, or contact a target. Active work is
represented as a plan step with an explicit authorization state and is executed
only by the existing scope-aware Olympus modules.

## Capability routing

```bash
olympus metis capabilities
olympus metis recommend "correlate malware IOCs and write a CTI report"
olympus metis recommend "review incident evidence" --advisory-only
```

The scorer tokenizes the objective, weights exact catalog tags more heavily
than prose, and returns matched terms and a numeric score. The result is
repeatable and explainable.

## Engagement plans

Advisory/passive plan:

```bash
olympus metis plan "map the external domain exposure" --output plan.json
```

Include active capabilities only with an explicit request. A step stays
`authorization-required` until both a scope and confirmation are present:

```bash
olympus metis plan "scan the authorized web application" \
  --include-active \
  --scope https://lab.example \
  --i-am-authorized \
  --output plan.json
```

The plan is data, not execution. Operators can review it and then invoke the
listed Athena, Themis, Artemis, Helios or other commands themselves.

## CTI cases

```bash
olympus metis case init .metis/cases.sqlite3
CASE_ID=$(olympus metis case create .metis/cases.sqlite3 "Phishing cluster")
olympus metis case ingest .metis/cases.sqlite3 "$CASE_ID" evidence.txt \
  --source "mail-gateway export" --confidence 70
olympus metis case show .metis/cases.sqlite3 "$CASE_ID"
olympus metis case report .metis/cases.sqlite3 "$CASE_ID" report.md
# DFIR sweep: does this artifact contain any of the case's known IOCs?
olympus metis case sweep .metis/cases.sqlite3 "$CASE_ID" suspect.log
```

`case sweep` extracts observables from a local artifact with the **same
normalization** used at ingest and reports which ones match the case's stored
indicators (by type and value, never substring), with each hit's source and
confidence. It exits `1` when any IOC is found and `0` when the artifact is
clean — usable directly as a triage gate in a script.

Local ingestion recognizes and normalizes URLs, domains, email addresses,
IPv4/IPv6 addresses, CVEs and MD5/SHA-1/SHA-256 hashes, including common
`hxxp`/`[.]` defanging. It performs no enrichment request. Analysts can add
sourced findings and link indicator IDs; findings sharing an indicator are
correlated deterministically in the case document.

The SQLite database and exported reports are owner-only (`0600`), foreign keys
are enabled, inputs are bounded, evidence files must be regular non-symlink
files, and every finding retains source and confidence.

## STIX / MISP import (API and Web)

The Themis API and Web control plane expose the same STIX 2.1 and MISP import
parsers over the network, so threat intelligence can be normalized into Olympus
indicators from the browser without dropping to a terminal:

- `POST /api/v1/metis/import` accepts `source_format` (`stix` or `misp`) and a
  single JSON `document` (≤ 60 KiB) and returns the versioned
  `olympus.metis-import` `1.0.0` contract — the faithfully recovered indicators
  plus the objects deliberately **skipped**, each with a recorded reason. It
  requires the `metis:run` scope.
- `GET /metis` / `POST /metis/import` is the browser workbench backed by the
  exact same parsers (`bundle_to_indicators`, `event_to_indicators`). The page
  requires `metis:read`; submitting an import requires `metis:run` and is
  CSRF-protected and audited.

Parsing is offline and deterministic: no network access, nothing persisted, and
the same import-the-subset / refuse-the-rest discipline as the CLI. A compound
STIX pattern or an unmapped MISP attribute type is never guessed, and the absence
of an indicator does not imply the source was clean. See [`web.md`](web.md).

## Guided labs

```bash
olympus metis labs
olympus metis labs --level beginner --json
```

Labs are a small native catalog of reproducible Olympus workflows. They do not
download or execute third-party project repositories.

## Argus event pipeline

The complementary offline pipeline is configured independently:

```bash
olympus argus pipeline \
  --preset examples/input/argus-pipeline.json \
  --output pipeline.json \
  --audit pipeline.ndjson
```

Built-in modules map URL → host/domain, email → domain, subdomain → parent and
normalize phone metadata. The engine owns event identity, deduplication,
provenance edges, blacklist, maximum depth and maximum event count.

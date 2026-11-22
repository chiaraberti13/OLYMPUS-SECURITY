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

## CTI live — TAXII 2.1

```bash
# Poll a TAXII 2.1 collection, write the collected STIX bundle, print a summary.
olympus metis taxii poll https://feed.example/taxii2/api1 <collection-id> \
  --token-env OLYMPUS_TAXII_TOKEN --output feed.stix.json
# Feed the bundle into a case with its own analyst-visible provenance.
olympus metis case stix-import .metis/cases.sqlite3 "$CASE_ID" feed.stix.json \
  --source "TAXII: feed.example/<collection-id>"
# Next run: only what is new, using the printed next_added_after cursor.
olympus metis taxii poll https://feed.example/taxii2/api1 <collection-id> \
  --added-after 2026-11-21T10:00:00Z --output feed.stix.json
```

`taxii poll` is the **only networked** Metis surface, and it is deliberately
narrow: it fetches STIX objects and hands them to the **same offline parser**
used by `case stix-import`, so a live poll and an import of the written bundle
yield the identical IOCs (simple-equality patterns imported, compound ones
reported as skipped, never mangled).

Three properties keep the fetch safe to point at the public internet:

- **Pinned, guarded egress.** The connection reuses the vetted address-pinning
  stack: the destination is resolved once, inside the socket call, and refused
  if it is private or loopback — closing the SSRF and DNS-rebinding windows. A
  **private** TAXII server (a local lab) is reachable only when the active lab
  policy declares its range, exactly like the live-scan gate. No HTTP proxy is
  permitted.
- **Bounded reads.** Response size, page count (`--max-pages`) and object count
  (`--max-objects`) all have hard caps; pagination follows the envelope's
  `more`/`next` only within them.
- **No secret in the repo.** `--token-env` names the environment variable that
  holds the feed's bearer token; the token itself is never a committed value and
  never logged. A collection that declares a token env var whose value is unset
  fails closed rather than polling unauthenticated.

Provenance is a stable `taxii://<host>/<collection>` label, and
`--added-after` with the printed `next_added_after` cursor (from the server's
`X-TAXII-Date-Added-Last`) makes each subsequent poll incremental.

## CTI live — MISP

```bash
# Pull MISP events (published only), write the merged event, print a summary.
olympus metis misp pull https://misp.example \
  --token-env OLYMPUS_MISP_KEY --tag tlp:white --output feed.misp.json
# Feed the pulled event into a case with its own analyst-visible provenance.
olympus metis case misp-import .metis/cases.sqlite3 "$CASE_ID" feed.misp.json \
  --source "MISP: misp.example"
# Next run: only events updated since, using the printed next_since cursor.
olympus metis misp pull https://misp.example \
  --token-env OLYMPUS_MISP_KEY --since 1700000001 --output feed.misp.json
```

`misp pull` is the MISP counterpart of `taxii poll`: it pulls events via the
MISP REST API (`POST /events/restSearch`), merges their attributes into a single
event, and hands it to the **same offline parser** used by `case misp-import`,
so a live pull and an import of the written event yield the identical IOCs.

The same three properties keep the pull safe:

- **Pinned, guarded egress** — resolve-once in the socket, private/loopback
  refused, no HTTP proxy; a **private** MISP instance (a local lab) is reachable
  only when the active lab policy declares its range.
- **Bounded reads** — response size, page count (`--max-pages`) and event count
  (`--max-events`) all capped; MISP has no "more" flag, so a short page ends the
  pagination.
- **No secret in the repo** — MISP always authenticates, so `--token-env` is
  required; it names the environment variable holding the API key (sent in the
  `Authorization` header as the **raw** key, MISP's convention), never a
  committed value, and the pull fails closed when the variable is unset.

Provenance is a stable `misp://<host>` label; `--since` (a unix second or a MISP
relative value such as `1d`) with the printed `next_since` cursor makes each
subsequent pull incremental.

## CTI live — OpenCTI

```bash
# Pull OpenCTI indicators (GraphQL), write the STIX bundle, print a summary.
olympus metis opencti pull https://opencti.example \
  --token-env OLYMPUS_OPENCTI_TOKEN --output feed.stix.json
# Feed the bundle into a case with its own analyst-visible provenance.
olympus metis case stix-import .metis/cases.sqlite3 "$CASE_ID" feed.stix.json \
  --source "OpenCTI: opencti.example"
# Next run: only indicators updated since, using the printed next_since cursor.
olympus metis opencti pull https://opencti.example \
  --token-env OLYMPUS_OPENCTI_TOKEN --since 2026-11-21T10:00:00Z --output feed.stix.json
```

`opencti pull` completes the live CTI trio. OpenCTI indicators already carry a
STIX `pattern`, so the client fetches them over GraphQL, maps each one back into
a STIX indicator object, and hands the bundle to the **same offline parser** used
by `case stix-import` — a live pull and an import of the written bundle yield the
identical IOCs.

The same three properties keep the pull safe:

- **Pinned, guarded egress** — resolve-once in the socket, private/loopback
  refused, no HTTP proxy; a **private** OpenCTI instance (a local lab) is
  reachable only when the active lab policy declares its range.
- **Bounded reads** — response size, page count (`--max-pages`) and indicator
  count (`--max-indicators`) all capped; Relay pagination follows
  `hasNextPage`/`endCursor` only within them.
- **No secret in the repo** — OpenCTI always authenticates, so `--token-env` is
  required; it names the environment variable holding the API token (sent as
  `Authorization: Bearer`), never a committed value, and the pull fails closed
  when the variable is unset.

A **revoked** indicator is excluded from the bundle: a revoked IOC is no longer
valid and must not be imported as active. Provenance is a stable
`opencti://<host>` label; `--since` (an ISO timestamp) with the printed
`next_since` cursor (the newest `updated_at` seen) makes each subsequent pull
incremental.

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

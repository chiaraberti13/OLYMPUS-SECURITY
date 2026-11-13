# Apollo bounded detection evaluation

Apollo evaluates local detection rules against normalized Olympus events. It is
offline work: no network authorization is invented, while the shared execution
policy still enforces deadlines and cooperative cancellation.

## Contracts and matching

Rules use `olympus.apollo-rule` version `1.0.0`. Every rule has a unique
`APL-...` identifier, a non-empty exact-match condition map, a bounded event
type, and optional validated MITRE ATT&CK technique identifiers. Partial or
incompatible contract headers fail. The former unversioned rule shape has one
explicit migration when both header fields are absent.

Events use the shared `olympus.event` contract. An unversioned legacy event is
accepted only when all identity fields (`event_id`, `event_type`, `source`,
`observed_at`, and `attributes`) are present; Apollo never invents an event ID
or timestamp. Rule conditions compare scalar attributes for exact equality.
They are data, never regular expressions, Python expressions, or shell input.

A match produces an `olympus.alert` with a deterministic ID derived from the
rule and event IDs, the source `rule_id`, validated `mitre_attack` techniques,
and the event observation time. Re-evaluating the same pair therefore does not
create a new identity. The output is directly consumable by Minerva and Vulcan.

## Ingesting real telemetry

`apollo ingest` is the front door that turns real telemetry into the
`olympus.event` NDJSON the engine consumes, so the same rules, ATT&CK mapping and
SIEM export apply to operational data. Parsing is bounded and *skip, never
guess*: a line that is not a valid record for the chosen format is reported and
skipped, never coerced into a bogus event.

Both `apollo test` and `apollo run` can additionally write the resulting alerts
in five SIEM-ingestable formats, selected by option (each to its own
owner-only `0o600` file): `--ecs` (Elastic Common Schema, newline-delimited
JSON), `--ocsf` (OCSF Detection Findings), `--hec` (Splunk HTTP Event
Collector envelopes, one JSON event per line, with the ECS document embedded as
the `event` payload) and `--elastic-bulk` (an Elasticsearch `_bulk` request body
— a `create` action line keyed by the alert id, then the ECS document, ready to
POST to `_bulk` with no log shipper; the index defaults to `olympus-apollo` and
is set with `--elastic-index`) and `--sentinel` (Azure Monitor Logs Ingestion
API JSON **array** of flat records, not NDJSON; requires a matching Data
Collection Rule stream declaration and custom Log Analytics table schema,
e.g. `OlympusApollo_CL`). All five are pure, offline formatters — they
write files, they never open a network connection; delivering them to a live SIEM
is a separate, scope- and authorization-gated step. The Sentinel record fields
are `TimeGenerated`, `AlertId`, `EventId`, `Title`, `Source`, `Severity`,
`Status`, `RuleId`, `MitreAttackIds`, `EvidenceIds`: all strings; the two
list fields are JSON-encoded strings. A matching DCR must map them to columns
with those exact names and string types (and `TimeGenerated` as datetime),
prior to ingestion. This export creates neither Sentinel incidents nor DCRs.

The BLUE-2 delivery boundary is also available as an **injected Python port**:
`olympus.apollo.dispatch.deliver_alerts`. It accepts a `SiemTransport` object,
an `ExecutionPolicy` with `authorized=True` and a non-empty
`approval_reference`, and a mandatory destination-scope authorizer callback.
The endpoint must be HTTPS with no credentials, query or fragment, and its path
must match the chosen SIEM ingestion API. Tokens come exclusively from an
environment variable named `OLYMPUS_SIEM_*`; they are never put in the URL.
Batch size and response size are bounded, and Splunk HEC / Elasticsearch bulk
responses are checked for application-level failure. Calls are single-attempt;
redirect/retry handling is the responsibility of a future audited adapter.
**No live HTTP transport is packaged and no CLI option sends network traffic.**
The scope callback must be provided by the engagement's authorized egress
checker, not a no-op; tests use no-op/failing callbacks only with fake transports.
Live delivery requires a reviewed adapter and an authorized-lab validation.

The first format is `access-log` — HTTP access logs in the Apache/nginx *Common*
and *Combined* Log Formats and the Python `http.server` variant — mapped to
`event_type="http.request"` with string attributes (`client_ip`, `method`,
`path`, `query`, `protocol`, `status`, `bytes`, and, for Combined, `referer` and
`user_agent`). The end-to-end flow is:

```bash
olympus apollo ingest --format access-log --input access.log --output events.ndjson
olympus apollo run --rules ./rules --events events.ndjson --output alerts.json
```

The second format is `zeek-json` — Zeek JSON-streaming logs (one record per
line). The record's `_path` selects the log kind: `conn`, `dns`, `http` and `ssl`
map to `network.connection`, `dns.query`, `http.request` and `tls.session`
events, using documented Zeek fields only (read both as flat `id.orig_h` keys and
the nested `{"id": {"orig_h"}}` form). A line with no known `_path` or no mappable
field is skipped, never guessed; the epoch `ts` is anchored to UTC.

```bash
olympus apollo ingest --format zeek-json --input conn.log --output events.ndjson
olympus apollo run --rules ./rules --events events.ndjson --output alerts.json
```

The third format is `windows-json` — Windows Event / Sysmon records (one JSON
object per line), as produced by `Get-WinEvent | ConvertTo-Json` or an
EVTX-to-JSON exporter. Records use the established rule taxonomy: Sysmon records
become `windows.sysmon` events and Security-auditing records become
`windows.security` events, with the `EventID` preserved as an `event_id`
attribute (so a rule matches `event_type: windows.sysmon` + `event_id: "1"`,
exactly like the shipped rules). The provider/channel must match the expected
family, so a different provider that reuses a low id is skipped, not guessed.
Documented ids are Sysmon `1` (process create), `3` (network connection), `11`
(file create), `13` (registry set), `22` (DNS query) and Security `4624`/`4625`
(logon / failed logon); fields are read from the `EventData` object first, then
the flat record, and the executable basename is exposed as `process_name`
alongside the full `image`. A line that is not a JSON object, has an unknown or
provider-mismatched id, or carries no mappable field is skipped, never guessed;
the ISO-8601 `TimeCreated` is anchored to UTC.

```bash
olympus apollo ingest --format windows-json --input sysmon.jsonl --output events.ndjson
olympus apollo run --rules examples/input/apollo-sysmon --events events.ndjson --output alerts.json
```

Ingested Windows telemetry drives the shipped Sysmon/Security detection rules in
`examples/input/apollo-sysmon` (C2 DNS query, Run-key persistence, failed
privileged logon) end to end. The parser is proven offline against a
format-faithful synthetic fixture (`tests/fixtures/apollo/ingest/windows.jsonl`);
validation against **real** Windows telemetry in an authorized lab stays tracked
in [`ROADMAP.md`](../ROADMAP.md) as `BLUE-1`.

## ATT&CK detection coverage (`OPS-PURPLE`)

`olympus apollo coverage` answers a Purple-team question that a rule count alone
cannot: *for each ATT&CK technique a rule claims to cover, is the telemetry it
needs actually being ingested?* It correlates each rule's technique and its
`event_type` with the event types present in a telemetry stream (`--events` NDJSON
and/or repeatable `--telemetry` flags) and classifies every technique as:

- `covered` — every rule targeting it fires on an event type that is present;
- `partial` — some of its rules can fire, some are blind (their telemetry is absent);
- `no-telemetry` — a rule targets it but none of the needed telemetry is present,
  so the technique is undetectable however many rules exist.

```bash
olympus apollo coverage --rules ./rules --events events.ndjson
olympus apollo coverage --rules ./rules --telemetry network.dns --strict   # exit 1 on blind spots
```

The analysis is pure and offline; `--strict` exits non-zero when any technique is
a `no-telemetry` blind spot, so a CI or Purple exercise fails on a real gap. The
matrix measures the detection set against available telemetry — it does not
invent techniques for which no rule exists.

### Coverage trend over time (`VAL-3`)

`olympus apollo coverage-trend` runs that same matrix across an ordered series of
telemetry snapshots — the rule set is held fixed and measured against each
`--snapshot` NDJSON file in turn (oldest first) — and reports how defensive
coverage evolved: per snapshot the structural coverage, the techniques **newly
covered** or **newly blind** since the previous one, and the coverage delta.

```bash
olympus apollo coverage-trend --rules ./rules \
  --snapshot 2026-08.ndjson --snapshot 2026-09.ndjson --snapshot 2026-10.ndjson --strict
```

Each metric is self-describing — the JSON document carries `metric_definitions`
and an explicit `limit`. That limit matters: these are measures of **structural**
coverage (a rule exists *and* its telemetry is present), **not** proven
detection. A technique counted as `covered` is detectable on paper; demonstrating
its rule actually fires on a real attack needs an authorized simulation
(`PURPLE-1`), whose outcome is out of scope here. Crucially, a reopened blind spot
is **never averaged away**: if a log source stops between two snapshots the
affected technique is surfaced as `newly_blind` and the trend reports a
regression, even when the first and last snapshots show identical coverage.
`--strict` exits non-zero on any such regression.

## Streaming and limits

`apollo run` reads NDJSON incrementally from a non-symlink regular file. Rules,
events, total stream bytes, evaluations, alerts, and the overall deadline all
have finite limits. Defaults are:

| Resource | Default |
| --- | ---: |
| Rule file | 1,000,000 bytes |
| Rules | 1,000 |
| Event line | 1,000,000 bytes |
| Physical event records | 100,000 |
| Event stream | 100,000,000 bytes |
| Rule/event evaluations | 1,000,000 |
| Alerts | 100,000 |
| Run deadline | 600 seconds |

Exact duplicate event IDs are evaluated once and counted. A conflicting
duplicate or malformed record is reported with its line number and never
silently dropped. Available alerts are written atomically, then the command
exits `2` to mark partial input. Output paths cannot overlap their rule or event
inputs.

```bash
olympus apollo test examples/input/apollo-rule.yaml \
  examples/input/apollo-event.json --output apollo-test-alerts.json

olympus apollo run --rules examples/input/apollo-ad \
  --events events.ndjson --output apollo-alerts.json

olympus apollo rules --rules examples/input/apollo-ad --format json
```

`test` exits `0` after a valid evaluation whether or not it matches. `run` exits
`0` for a complete stream with no alerts, `1` for a complete stream with one or
more alerts, `2` for invalid input, `5` when malformed records make the stream
partial, and `7` when cancelled. Advanced temporal correlation is outside this
exact single-event engine and must use a separately bounded, reviewed operator
model.

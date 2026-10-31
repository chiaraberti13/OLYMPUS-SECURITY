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
ECS/OCSF export apply to operational data. Parsing is bounded and *skip, never
guess*: a line that is not a valid record for the chosen format is reported and
skipped, never coerced into a bogus event.

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

A further format (Sysmon/Windows Event) plugs into the same `core.Event` shape;
Sysmon capture needs real Windows telemetry, so it stays tracked in
[`ROADMAP.md`](../ROADMAP.md) as `OPS-BLUE` rather than declared here.

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

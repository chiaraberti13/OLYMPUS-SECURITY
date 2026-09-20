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

Additional formats (Sysmon/Windows Event, Zeek) can plug into the same
`core.Event` shape. Sysmon capture needs real Windows telemetry, so it is tracked
in `ROADMAP_OPERATIVA.md` rather than declared here.

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
more alerts, and `2` for invalid, incomplete, cancelled, timed-out, or otherwise
failed input. Advanced temporal correlation is outside this exact single-event
engine and must use a separately bounded, reviewed operator model.

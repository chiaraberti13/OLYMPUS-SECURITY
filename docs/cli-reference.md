# CLI reference

Every `olympus` command and its options, generated from the Typer command tree
(`olympus.cli:app`) — the single source of truth, so this page cannot drift from
the real CLI. Do not edit the generated block by hand; run
`python scripts/generate_cli_reference.py` (or `--check` in CI) instead.

<!-- GENERATED:cli-reference START -->
### `olympus aegis`

[DEPRECATED] Alias for 'olympus themis' — forwards all arguments.

### `olympus apollo attack-layer`

Emit a MITRE ATT&CK Navigator layer of the techniques the rules cover.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--rules` | option | no | — | Directory of YAML rules. |
| `--output` | option | yes | — | ATT&CK Navigator layer JSON output. |
| `--name` | option | no | `Olympus Apollo coverage` | — |
| `--max-rules` | option | no | `1000` | — |
| `--max-rule-bytes` | option | no | `1000000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus apollo coverage`

Report ATT&CK detection coverage against the telemetry actually available.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--rules` | option | no | — | Directory of YAML rules. |
| `--events` | option | no | — | NDJSON telemetry whose event types are taken as the data actually ingested. |
| `--telemetry` | option | no | — | Event type available as telemetry (repeatable); union-ed with --events. |
| `--format` | option | no | `table` | Render as table (human) or json (machine). |
| `--strict` | option | no | `False` | Exit non-zero when a technique has a rule but no telemetry (a hard blind spot). |
| `--max-rules` | option | no | `1000` | — |
| `--max-rule-bytes` | option | no | `1000000` | — |
| `--max-stream-bytes` | option | no | `100000000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus apollo ingest`

Normalize real telemetry into ``core.Event`` NDJSON for the detection engine.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--input` | option | yes | — | Telemetry source file (e.g. an HTTP access log). |
| `--output` | option | yes | — | NDJSON of core.Event, ready for `apollo run --events`. |
| `--format` | option | no | `access-log` | Telemetry format. Supported: access-log, zeek-json. |
| `--source` | option | no | `manual` | Source tag for the emitted events (an olympus source). |
| `--max-bytes` | option | no | `100000000` | — |
| `--max-line-bytes` | option | no | `1000000` | — |
| `--max-lines` | option | no | `1000000` | — |
| `--max-skip-details` | option | no | `20` | — |

### `olympus apollo rules`

Load, bound and validate a non-empty rule directory.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--rules` | option | no | — | Directory of YAML rules. |
| `--format` | option | no | `table` | Render as table (human) or json (machine). |
| `--max-rules` | option | no | `1000` | — |
| `--max-rule-bytes` | option | no | `1000000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus apollo run`

Evaluate a bounded rule set against a strict streaming NDJSON event source.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--rules` | option | no | — | Directory of YAML rules. |
| `--events` | option | yes | — | NDJSON file: one core.Event per line. |
| `--output` | option | no | — | Alerts JSON output. |
| `--ecs` | option | no | — | Also write alerts as newline-delimited ECS JSON for a SIEM. |
| `--ocsf` | option | no | — | Also write alerts as newline-delimited OCSF Detection Findings. |
| `--max-rules` | option | no | `1000` | — |
| `--max-rule-bytes` | option | no | `1000000` | — |
| `--max-event-bytes` | option | no | `1000000` | — |
| `--max-events` | option | no | `100000` | — |
| `--max-stream-bytes` | option | no | `100000000` | — |
| `--max-evaluations` | option | no | `1000000` | — |
| `--max-alerts` | option | no | `100000` | — |
| `--max-input-error-details` | option | no | `100` | — |
| `--deadline` | option | no | `600.0` | — |

### `olympus apollo sigma-import`

Convert a Sigma rule (faithful exact-match subset) into an Apollo rule.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `sigma` | argument | yes | — | Sigma rule YAML file to convert. |
| `--output` | option | yes | — | Apollo rule JSON output path. |
| `--max-bytes` | option | no | `1000000` | — |

### `olympus apollo test`

Evaluate one rule against one strict, normalized Event fixture.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `rule` | argument | yes | — | — |
| `event` | argument | yes | — | — |
| `--output` | option | no | — | — |
| `--ecs` | option | no | — | Also write alerts as newline-delimited ECS JSON for a SIEM. |
| `--ocsf` | option | no | — | Also write alerts as newline-delimited OCSF Detection Findings. |
| `--max-rule-bytes` | option | no | `1000000` | — |
| `--max-event-bytes` | option | no | `1000000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus argus accounts`

Enumerate in-scope handle(s) across a curated list of public sites.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--username` | option | no | — | Handle to enumerate across sites. |
| `--input` | option | no | — | File with one handle per line (batch mode). |
| `--scope` | option | no | — | JSON allowlist of authorized handles. |
| `--log` | option | no | — | Out-of-scope audit log. |
| `--sites` | option | no | — | JSON site registry to check. |
| `--metadata` | option | no | `False` | Also extract public profile metadata (needs --i-am-authorized). |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for metadata scraping. |
| `--concurrency` | option | no | `8` | Parallel site checks per handle. |
| `--rate` | option | no | `0.0` | Minimum seconds between requests (politeness rate limit). |
| `--output` | option | no | — | If set, export the account-intel bundle(s) as JSON to this path. |

### `olympus argus correlate`

Analyze an investigation graph: clusters, pivot hubs and value correlations.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `investigation` | argument | yes | — | Investigation JSON from `argus investigate`. |
| `--seed` | option | no | — | Entity id to expand neighbors from (e.g. 'ip:203.0.113.9'). |
| `--hops` | option | no | `1` | Neighbor expansion depth for --seed. |
| `--limit` | option | no | `10` | Top-N pivots to report. |
| `--max-bytes` | option | no | `20000000` | — |

### `olympus argus diff`

Compare two Argus asset snapshots without performing network activity.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `before` | argument | yes | — | — |
| `after` | argument | yes | — | — |

### `olympus argus dns`

Enumerate DNS records for an in-scope domain over DNS-over-HTTPS.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | option | yes | — | Domain to enumerate DNS records for. |
| `--types` | option | no | — | Comma-separated record types (default: A,AAAA,MX,TXT,NS,CNAME,SOA). |
| `--scope` | option | no | — | JSON scope file listing authorized domains. |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--output` | option | no | — | If set, export the DNS report as JSON to this path. |

### `olympus argus doctor`

Diagnose Argus: required libraries and optional enrichment API keys.

### `olympus argus email`

Analyze an email address offline; optionally run passive live enrichment.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--email` | option | yes | — | Email address to analyze. |
| `--enrich` | option | no | `False` | Run passive live MX + Gravatar checks (network, opt-in). |
| `--scope` | option | no | — | JSON scope file (domain must be in scope to enrich). |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--i-am-authorized` | option | no | `False` | Confirm authorization for the live enrichment. |
| `--output` | option | no | — | If set, export the email-intel bundle as JSON to this path. |

### `olympus argus fronting`

Passively check whether an in-scope domain is CDN/WAF-fronted and leaks its origin IP.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | option | yes | — | Domain to assess for CDN/WAF fronting. |
| `--scope` | option | no | — | JSON scope file listing authorized domains. |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--asset-id` | option | no | `AST-ARGUS-FRONT-1` | core.Asset id to attach findings to. |
| `--output` | option | no | — | Fronting report JSON. |

### `olympus argus investigate`

Build an OSINT investigation graph by pivoting from a seed entity (flowsint-style).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--seed-type` | option | yes | — | Seed entity type (domain/host/ip/email/phone/username). |
| `--seed-value` | option | yes | — | Seed entity value. |
| `--name` | option | no | `investigation` | Investigation name. |
| `--depth` | option | no | `1` | How many pivot hops to expand. |
| `--sites` | option | no | — | Site registry for username transforms. |
| `--domain-scope` | option | no | — | JSON scope for domain/host DNS and Certificate Transparency pivots. |
| `--ip-scope` | option | no | — | JSON CIDR scope for optional IP geolocation pivots. |
| `--account-scope` | option | no | — | JSON handle scope for public-account pivots. |
| `--geo` | option | no | `False` | Enable IP geolocation/ASN (third-party). |
| `--log` | option | no | — | Investigation audit log. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for the fan-out. |
| `--output` | option | no | — | Graph JSON output. |
| `--mermaid` | option | no | — | If set, also write a Mermaid diagram of the graph. |
| `--dot` | option | no | — | If set, also write a Graphviz DOT graph. |
| `--graphml` | option | no | — | If set, also write a GraphML graph (Gephi/Neo4j/yEd). |

### `olympus argus ip`

Profile in-scope IP address(es): offline classification + opt-in geolocation.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--ip` | option | no | — | IPv4/IPv6 address to profile. |
| `--input` | option | no | — | File with one IP per line (batch mode). |
| `--scope` | option | no | — | JSON scope file of authorized CIDR networks. |
| `--log` | option | no | — | Out-of-scope audit log. |
| `--geo` | option | no | `False` | Geolocation/ASN via encrypted ipwho.is (third-party, keyless). |
| `--i-am-authorized` | option | no | `False` | Confirm authorization for the third-party geo lookup. |
| `--output` | option | no | — | If set, export the IP-intel bundle(s) as JSON to this path. |

### `olympus argus mac`

Classify a MAC address offline; optionally resolve its vendor from the OUI registry.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--mac` | option | yes | — | MAC address to classify. |
| `--vendor` | option | no | `False` | Resolve the OUI to a vendor via macvendors.com (network). |
| `--scope` | option | no | — | JSON scope file whose OUI allowlist authorizes the vendor lookup. |
| `--log` | option | no | — | Path to the out-of-scope MAC audit log. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for the live vendor lookup. |
| `--output` | option | no | — | If set, export the MAC-intel bundle as JSON to this path. |

### `olympus argus myip`

Discover this machine's own public IP address (and optionally geolocate it).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--geo` | option | no | `False` | Classify and geolocate the discovered public IP (network). |
| `--output` | option | no | — | If set, export the result as JSON to this path. |

### `olympus argus phone`

Profile in-scope phone number(s): offline parsing + opt-in real lookups.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--number` | option | no | — | E.164 (e.g. +14155550123) or national with --region. |
| `--input` | option | no | — | File with one number per line (batch mode). |
| `--region` | option | no | — | ISO region (e.g. US, IT) for national-format numbers. |
| `--scope` | option | no | — | JSON scope file of authorized E.164 prefixes. |
| `--log` | option | no | — | Out-of-scope audit log. |
| `--enrich` | option | no | `False` | Carrier/line-type via Numverify (needs OLYMPUS_NUMVERIFY_KEY). |
| `--breach` | option | no | `False` | Breach-intelligence exposure lookup (keyless third-party API). |
| `--messaging` | option | no | `False` | Messaging-platform presence (needs OLYMPUS_RAPIDAPI_KEY). |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for real lookups. |
| `--output` | option | no | — | If set, export the phone-intel bundle(s) as JSON to this path. |

### `olympus argus pipeline`

Run the bounded offline event/preset reconnaissance pipeline.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--preset` | option | yes | — | Versioned Argus pipeline preset JSON. |
| `--output` | option | no | — | Owner-only result JSON path. |
| `--audit` | option | no | — | Owner-only structured audit path. |

### `olympus argus scan`

Run passive DNS/MX/SPF/DMARC recon against a single in-scope domain.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | option | yes | — | Domain to run passive DNS recon against. |
| `--scope` | option | no | — | Path to the JSON scope file listing authorized domains. |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--output` | option | no | — | Path for the core.Asset-compatible JSON export. |

### `olympus argus web`

Fetch an in-scope URL once and report its passive HTTP security posture.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | Target URL or host for passive HTTP recon. |
| `--scope` | option | no | — | JSON scope file listing authorized domains. |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--output` | option | no | — | If set, export the web-intel bundle as JSON to this path. |

### `olympus argus whois`

Query registration data (registrar, dates, name servers) for an in-scope domain via RDAP.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--domain` | option | yes | — | Domain to query registration data for. |
| `--scope` | option | no | — | JSON scope file listing authorized domains. |
| `--log` | option | no | — | Path to the out-of-scope audit log. |
| `--output` | option | no | — | If set, export the WHOIS report as JSON to this path. |

### `olympus artemis check-scope`

Validate URL authorization without performing a network request.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | — |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |

### `olympus artemis content`

Discover existing paths/files under an authorized base URL (real dirbusting).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | Authorized base URL to discover paths under. |
| `--wordlist` | option | yes | — | Newline-delimited candidate paths. |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--timeout` | option | no | `5.0` | — |
| `--max-bytes` | option | no | `1000000` | — |
| `--rate` | option | no | `0.0` | Minimum seconds between requests (politeness throttle). |
| `--jitter` | option | no | `0.2` | Fraction of --rate to randomize each wait by (0 disables), so pacing is not a metronome. |
| `--deadline` | option | no | — | Overall budget for the whole run, in seconds. |
| `--asset-id` | option | no | `AST-ARTEMIS-CONTENT-1` | core.Asset id to attach findings to. |
| `--i-am-authorized` | option | no | `False` | Confirm you are authorized to test this target. |
| `--output` | option | no | — | Export findings JSON to this path. |

### `olympus artemis fetch`

Perform one bounded, scope-safe GET flow and print metadata only.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | — |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--timeout` | option | no | `5.0` | — |
| `--max-bytes` | option | no | `1000000` | — |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for this live fetch. |

### `olympus artemis fingerprint`

Identify the technology stack from one scope-safe GET (passive, no extra requests).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | Base URL to fetch once and fingerprint. |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--timeout` | option | no | `5.0` | — |
| `--max-bytes` | option | no | `1000000` | — |
| `--asset-id` | option | no | `AST-ARTEMIS-FP-1` | core.Asset id to attach findings to. |
| `--i-am-authorized` | option | no | `False` | Confirm you are authorized to test this target. |
| `--output` | option | no | — | Export findings JSON to this path. |

### `olympus artemis metabase`

Non-exploitatively check a Metabase instance for CVE-2026-72898 exposure.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | Base URL of the Metabase instance to fingerprint. |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--i-am-authorized` | option | no | `False` | Confirm you are authorized to test this target. |
| `--output` | option | no | — | Export findings JSON to this path. |

### `olympus artemis xss`

Non-destructively test URL parameters for reflected XSS (marker reflection only).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--url` | option | yes | — | URL to probe (with query params to test). |
| `--param` | option | no | — | Parameter to test; if omitted, every query parameter is tested. |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--i-am-authorized` | option | no | `False` | Confirm you are authorized to test this target. |
| `--output` | option | no | — | Export findings JSON to this path. |

### `olympus athena adapters`

List the assessment adapters available in the closed registry.

### `olympus athena cancel`

Cancel a persisted, non-terminal assessment and its open jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `assessment_id` | argument | yes | — | Assessment ID to cancel. |
| `--storage` | option | yes | — | Directory for the Athena database. |

### `olympus athena plan validate`

Validate a plan file against the Athena contract and adapter registry.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `path` | argument | yes | — | Path to the assessment plan JSON file. |

### `olympus athena recover`

Settle assessments left running after a crash (interrupted jobs fail closed).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--storage` | option | yes | — | Directory for the Athena database. |

### `olympus athena run`

Execute an assessment plan end to end and persist its results.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `path` | argument | yes | — | Path to the assessment plan JSON file. |
| `--storage` | option | yes | — | Directory for the Athena database. |
| `--report` | option | no | `False` | Write a findings report into the storage directory. |
| `--enrich-kev` | option | no | — | Local CISA KEV catalogue JSON: overlay known-exploited status on findings (offline). |
| `--enrich-epss` | option | no | — | Local FIRST EPSS response JSON: overlay exploit-probability on findings (offline). |

### `olympus athena status`

Print the persisted state of an assessment and its jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `assessment_id` | argument | yes | — | Assessment ID to inspect. |
| `--storage` | option | yes | — | Directory for the Athena database. |

### `olympus config validate`

Validate configuration and print only redacted effective values.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--file` | option | no | — | Validate this TOML file instead of automatic discovery. |

### `olympus core export-schemas`

Print the legacy bundle, or publish the versioned JSON Schema catalog.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `output_dir` | argument | no | — | Optional directory for the versioned catalog; prints the legacy bundle when omitted. |

### `olympus core keygen`

Generate an Ed25519 keypair for signing artifacts (provenance).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--private` | option | yes | — | Owner-only Ed25519 private key output. |
| `--public` | option | yes | — | Ed25519 public key output (distributable). |

### `olympus core lock`

Emit a hash-pinned ``pip --require-hashes`` constraints file.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--output`, `-o` | option | no | — | Write the constraints here instead of stdout. |
| `--extra` | option | no | — | Include an optional-dependency extra (e.g. --extra themis). Repeatable. |

### `olympus core migrations`

Print every explicit persisted-contract migration edge.

### `olympus core sbom`

Emit a CycloneDX SBOM of the installed Olympus runtime closure.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--output`, `-o` | option | no | — | Write the SBOM here instead of stdout. |
| `--extra` | option | no | — | Include an optional-dependency extra (e.g. --extra themis). Repeatable. |
| `--reproducible` | option | no | `False` | Omit the timestamp and serial number for a byte-stable document. |

### `olympus core sign`

Produce a detached Ed25519 signature so a third party can verify provenance.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `artifact` | argument | yes | — | File to sign (ledger, evidence, SBOM, report...). |
| `--key` | option | yes | — | Ed25519 private key PEM. |
| `--output`, `-o` | option | yes | — | Signature envelope output (owner-only). |
| `--max-bytes` | option | no | `500000000` | — |

### `olympus core verify`

Verify a detached Ed25519 signature against a trusted public key.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `artifact` | argument | yes | — | File whose signature to check. |
| `signature` | argument | yes | — | Signature envelope from `core sign`. |
| `--pubkey` | option | yes | — | TRUSTED Ed25519 public key PEM to pin. |
| `--max-bytes` | option | no | `500000000` | — |

### `olympus doctor`

Diagnose the Olympus environment (binaries, services, deps).

### `olympus engagement create`

Create and persist a new engagement; print its id, scope and digest.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--name` | option | yes | — | Human-readable engagement name. |
| `--include` | option | yes | — | Authorized in-scope target (repeatable). |
| `--exclude` | option | no | — | Explicitly out-of-scope target (repeatable). |
| `--client` | option | no | — | Client or owner name. |
| `--authorization-reference` | option | no | — | Contract/approval id (never a secret). |
| `--status` | option | no | `active` | Engagement lifecycle status. |
| `--storage` | option | yes | — | Directory for the engagements database. |

### `olympus engagement export`

Export engagements to portable, versioned NDJSON (one per line, sorted by id).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--storage` | option | yes | — | Directory for the engagements database. |
| `--output`, `-o` | option | yes | — | NDJSON file to write. |
| `--id` | option | no | — | Export only this engagement id (repeatable); default: all. |

### `olympus engagement import`

Import engagements from portable NDJSON into the store (upsert by id).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--storage` | option | yes | — | Directory for the engagements database. |
| `--input`, `-i` | option | yes | — | NDJSON file to import. |

### `olympus engagement list`

List every stored engagement (most recent first).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--storage` | option | yes | — | Directory for the engagements database. |

### `olympus engagement show`

Print the full stored engagement document, or fail if it does not exist.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `engagement_id` | argument | yes | — | Engagement id to display. |
| `--storage` | option | yes | — | Directory for the engagements database. |

### `olympus helios scan`

Perform bounded TCP discovery only after scope authorization.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `target` | argument | yes | — | — |
| `--ports` | option | no | `80,443` | — |
| `--scope` | option | no | — | — |
| `--log` | option | no | — | — |
| `--asset-id` | option | no | `AST-HELIOS-00001` | core.Asset id to attach findings to. |
| `--output` | option | no | — | — |
| `--timeout` | option | no | `1.0` | Per-port TCP connect timeout. |
| `--deadline` | option | no | — | Overall budget for the whole scan, in seconds. |
| `--concurrency` | option | no | `1` | How many ports to probe in parallel (1-64). |
| `--banner` | option | no | `False` | Read (never send) the greeting of services that speak first, to identify them. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for this live scan. |

### `olympus hermes pre-commit`

Scan staged (or given) files and block the commit on any finding.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `paths` | argument | no | — | Files to scan; when omitted, the Git-staged files are scanned. |
| `--entropy-threshold` | option | no | `4.5` | — |
| `--baseline` | option | no | — | — |
| `--allowlist` | option | no | — | — |
| `--max-file-bytes` | option | no | `10000000` | — |
| `--max-files` | option | no | `10000` | — |

### `olympus hermes scan`

Scan a path and optionally its Git history, emitting masked SARIF.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `paths` | argument | yes | — | — |
| `--output` | option | no | — | — |
| `--entropy-threshold` | option | no | `4.5` | — |
| `--history` | option | no | `False` | — |
| `--baseline` | option | no | — | JSON baseline of accepted fingerprints to ignore. |
| `--allowlist` | option | no | — | JSON allowlist of path globs / value regexes to suppress by shape. |
| `--write-baseline` | option | no | — | Write current findings' fingerprints as a baseline. |
| `--timeout` | option | no | `30.0` | Per-Git-process timeout in seconds. |
| `--deadline` | option | no | `600.0` | Overall scan deadline in seconds. |
| `--max-file-bytes` | option | no | `10000000` | — |
| `--max-files` | option | no | `10000` | — |
| `--max-history-bytes` | option | no | `20000000` | — |
| `--max-commits` | option | no | `1000` | — |

### `olympus metis capabilities`

List the independently implemented Olympus capability catalog.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--json` | option | no | `False` | Emit the strict catalog as JSON. |

### `olympus metis case backup`

Write a consistent owner-only snapshot of the whole case store.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | Live SQLite case database. |
| `output` | argument | yes | — | Owner-only snapshot destination. |
| `--encrypt` | option | no | `False` | Encrypt the snapshot under OLYMPUS_METIS_KEY (authenticated). |

### `olympus metis case create`

Create a new CTI case and print its stable identifier.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `title` | argument | yes | — | — |

### `olympus metis case decrypt`

Decrypt a case document produced by ``export-encrypted`` back to JSON.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `encrypted` | argument | yes | — | Encrypted case document to decrypt. |
| `output` | argument | yes | — | Decrypted JSON output (owner-only). |
| `--max-bytes` | option | no | `50000000` | — |

### `olympus metis case export-encrypted`

Export a case as an authenticated-encrypted document (sensitive CTI at rest).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `output` | argument | yes | — | Encrypted case document output (owner-only). |

### `olympus metis case finding`

Record a sourced analytic finding and optional IOC links.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `--title` | option | yes | — | — |
| `--assessment` | option | yes | — | — |
| `--source` | option | yes | — | — |
| `--confidence` | option | yes | — | — |
| `--indicator` | option | no | — | Linked IOC ID; repeatable. |

### `olympus metis case ingest`

Extract normalized indicators from one bounded local evidence file.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `evidence` | argument | yes | — | — |
| `--source` | option | yes | — | Analyst-visible evidence provenance. |
| `--confidence` | option | no | `50` | — |

### `olympus metis case init`

Initialize or verify an owner-only case database.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | SQLite case database. |

### `olympus metis case misp-export`

Export a case's indicators as a conservative (org-only) MISP event.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `output` | argument | yes | — | MISP event JSON output path (owner-only). |

### `olympus metis case misp-import`

Import the mappable IOCs from a MISP event into a case.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `event` | argument | yes | — | MISP event JSON to import. |
| `--source` | option | yes | — | Analyst-visible provenance for imported IOCs. |
| `--confidence` | option | no | `50` | — |
| `--max-bytes` | option | no | `50000000` | — |

### `olympus metis case report`

Export an owner-only CTI case report.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `output` | argument | yes | — | — |
| `--format` | option | no | `markdown` | markdown or json. |

### `olympus metis case restore`

Restore a verified snapshot into a database, replacing its contents.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `backup` | argument | yes | — | Snapshot file to restore from (plain or encrypted). |
| `database` | argument | yes | — | Destination database (contents replaced). |
| `--max-bytes` | option | no | `500000000` | — |

### `olympus metis case show`

Print one strict, portable CTI case document.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |

### `olympus metis case stix-export`

Export a case's indicators as a deterministic STIX 2.1 bundle.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `output` | argument | yes | — | STIX 2.1 bundle output path (owner-only). |

### `olympus metis case stix-import`

Import the faithful (simple-equality) IOCs from a STIX 2.1 bundle into a case.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `bundle` | argument | yes | — | STIX 2.1 bundle JSON to import. |
| `--source` | option | yes | — | Analyst-visible provenance for imported IOCs. |
| `--confidence` | option | no | `50` | — |
| `--max-bytes` | option | no | `50000000` | — |

### `olympus metis case sweep`

Sweep a local artifact for a case's known IOCs (offline threat-intel match).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `database` | argument | yes | — | — |
| `case_id` | argument | yes | — | — |
| `observations` | argument | yes | — | Local artifact/log to sweep for the case's known IOCs. |
| `--source` | option | no | `sweep` | Provenance label for the swept observables. |

### `olympus metis case verify-backup`

Confirm a snapshot is a real Metis store and print its row counts.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `backup` | argument | yes | — | Snapshot file to validate. |

### `olympus metis labs`

List safe guided labs built from native Olympus capabilities.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--level` | option | no | — | foundation, beginner, intermediate or advanced. |
| `--json` | option | no | `False` | — |

### `olympus metis plan`

Build a safe, non-executing engagement plan.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `objective` | argument | yes | — | Security objective to plan. |
| `--scope` | option | no | — | Authorized scope entry; repeatable. |
| `--include-active` | option | no | `False` | Include active capabilities in the plan. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for the supplied scope. |
| `--output` | option | no | — | Owner-only JSON output path. |

### `olympus metis recommend`

Route an objective to the best matching local capabilities.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `task` | argument | yes | — | Free-form security objective. |
| `--limit` | option | no | `5` | — |
| `--advisory-only` | option | no | `False` | Exclude active-execution capabilities. |

### `olympus minerva capture`

Hash a local artifact and write an evidence reference anchored to its bytes.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `artifact` | argument | yes | — | — |
| `output` | argument | yes | — | — |
| `--type` | option | yes | — | e.g. memory-image, pcap, disk-image. |
| `--uri` | option | no | — | Provenance URI; defaults to the artifact's file:// path. |
| `--max-bytes` | option | no | `268435456` | — |
| `--force` | option | no | `False` | Overwrite an existing evidence file (default: refuse). |

### `olympus minerva record`

Append an evidence-digest-anchored event after verifying the complete chain.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `evidence` | argument | yes | — | — |
| `ledger` | argument | yes | — | — |
| `--actor` | option | yes | — | — |
| `--action` | option | yes | — | — |
| `--max-evidence-bytes` | option | no | `1000000` | — |
| `--max-ledger-bytes` | option | no | `50000000` | — |
| `--max-entries` | option | no | `100000` | — |
| `--provenance` | option | no | — | Strict acquisition JSON; required for the first/collected custody event. |
| `--max-provenance-bytes` | option | no | `1000000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus minerva timeline`

Print a verified custody timeline, including evidence digest provenance.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `ledger` | argument | yes | — | — |
| `--format` | option | no | `table` | Render as table (human) or json (machine). |
| `--export` | option | no | — | Write the verified timeline as a canonical JSON artifact. |
| `--sign-key` | option | no | — | Ed25519 private key PEM: also write a detached signature of the export (requires --export), verifiable with `olympus core verify`. |
| `--max-ledger-bytes` | option | no | `50000000` | — |
| `--max-entries` | option | no | `100000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus minerva triage`

Create a stable Incident from one strict, bounded Apollo alert export.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `alerts` | argument | yes | — | — |
| `--output` | option | no | — | — |
| `--title` | option | yes | — | — |
| `--owner` | option | no | — | — |
| `--max-alert-bytes` | option | no | `50000000` | — |
| `--max-alerts` | option | no | `100000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus minerva verify`

Verify every hash, digest, state, timestamp and (if signed) the signature.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `ledger` | argument | yes | — | — |
| `--max-ledger-bytes` | option | no | `50000000` | — |
| `--max-entries` | option | no | `100000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus policy diff`

Show only the bounds this policy changes, and which layer changed them.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--profile` | option | no | `default` | Bounds profile to resolve; named profiles overlay [bounds.default]. |
| `--file` | option | no | — | Use this policy file instead of automatic discovery. |

### `olympus policy edit`

Create the policy file from a commented template, then open it.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--file` | option | no | — | Use this policy file instead of automatic discovery. |
| `--open` | option | no | `True` | Launch $VISUAL/$EDITOR after ensuring the file exists. |

### `olympus policy show`

Print the effective, redacted policy for one profile as JSON.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--profile` | option | no | `default` | Bounds profile to resolve; named profiles overlay [bounds.default]. |
| `--file` | option | no | — | Use this policy file instead of automatic discovery. |

### `olympus policy validate`

Validate the policy document and every bound it resolves.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--profile` | option | no | `default` | Bounds profile to resolve; named profiles overlay [bounds.default]. |
| `--file` | option | no | — | Use this policy file instead of automatic discovery. |

### `olympus proteus campaign`

Build an authorized simulation campaign (unique token per in-scope target).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--engagement` | option | yes | — | Engagement name. |
| `--targets` | option | yes | — | File with one recipient email per line. |
| `--landing-url` | option | yes | — | Base URL of the training page. |
| `--subject` | option | no | `Action required: confirm your account` | Lure email subject. |
| `--sender` | option | no | `it-support@example.com` | Lure sender address. |
| `--scope` | option | no | — | Authorized email-domain allowlist. |
| `--log` | option | no | — | Out-of-scope audit log. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for the engagement. |
| `--output` | option | no | — | Campaign JSON output. |

### `olympus proteus email`

Render the simulated lure email for one target token.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--campaign` | option | yes | — | Campaign JSON from `proteus campaign`. |
| `--token` | option | yes | — | Target token to render the lure email for. |

### `olympus proteus page`

Render the training/awareness page a clicker lands on (captures nothing).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--engagement` | option | yes | — | Engagement name for the page. |
| `--output` | option | no | — | Training-page HTML output. |

### `olympus proteus report`

Summarize campaign click-through (a training metric, never secrets).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--campaign` | option | yes | — | Campaign JSON from `proteus campaign`. |
| `--clicked` | option | no | — | Token(s) recorded as clicked (repeatable). |

### `olympus themis api`

Serve the authenticated native Themis API.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--scope-directory` | option | no | — | — |
| `--host` | option | no | `127.0.0.1` | — |
| `--port` | option | no | `8443` | — |
| `--max-concurrent-requests` | option | no | `64` | — |
| `--api-key-env` | option | no | `OLYMPUS_THEMIS_API_KEY` | — |
| `--api-key-scopes` | option | no | `capabilities:read` | Comma-separated permissions for the shared API key (default: capabilities:read). |
| `--identities` | option | no | — | Identity register with scoped, revocable credentials. |
| `--oidc-issuer` | option | no | — | Pinned HTTPS OIDC issuer. |
| `--oidc-audience` | option | no | — | Required OIDC audience. |
| `--oidc-jwks` | option | no | — | Pinned local JWKS file; discovery is disabled. |
| `--audit` | option | no | — | Redacted per-request audit log. |
| `--engagement-storage` | option | no | — | Directory holding the shared engagements database; enables the engagement read endpoints and engagement-derived scope enforcement. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key; requires --engagement-storage and signed manifests on API job submissions. |
| `--ssl-certfile` | option | no | — | — |
| `--ssl-keyfile` | option | no | — | — |

### `olympus themis capabilities`

Report what Themis can actually execute, and how far each engine is proven.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--strict` | option | no | `False` | Exit non-zero when no scanner integration is ready for a live job. |
| `--min-maturity` | option | no | — | Exit non-zero unless at least --count integrations reach this stage: catalog-only \| adapter-ready \| offline-tested \| live-tested \| production-ready |
| `--count` | option | no | `1` | How many integrations must reach --min-maturity. |

### `olympus themis deps`

Report Themis runtime dependencies: web stack, services, and scanner binaries.

### `olympus themis doctor`

Diagnose the Themis runtime, or one scanner with ``--scanner``.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--scanner` | option | no | — | Diagnose one scanner (binary/version/deps, adapter, maturity, readiness), or 'all' for every catalogued engine, instead of the runtime. |

### `olympus themis identities add`

Add one scoped identity and print its secret exactly once.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `identity_id` | argument | yes | — | Identity name, e.g. 'ops-console'. |
| `--scopes` | option | no | `jobs:read` | Comma-separated scopes granted to this identity. |
| `--rate-limit` | option | no | `120` | — |
| `--expires-in-days` | option | no | `90` | Mandatory lifetime of the newly issued credential. |
| `--file`, `-f` | option | no | — | — |
| `--audit` | option | no | — | — |

### `olympus themis identities init`

Create an empty identity register (owner-only).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--file`, `-f` | option | no | — | — |

### `olympus themis identities list`

List identities, their scopes and status.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--file`, `-f` | option | no | — | — |

### `olympus themis identities revoke`

Revoke an identity immediately, including any secret still rotating.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `identity_id` | argument | yes | — | — |
| `--file`, `-f` | option | no | — | — |
| `--audit` | option | no | — | — |

### `olympus themis identities rotate`

Issue a new secret, keeping the old one valid for a bounded overlap.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `identity_id` | argument | yes | — | — |
| `--overlap-seconds` | option | no | `300` | How long the previous secret keeps working; 0 revokes it immediately. |
| `--expires-in-days` | option | no | `90` | Mandatory lifetime of the replacement credential. |
| `--file`, `-f` | option | no | — | — |
| `--audit` | option | no | — | — |

### `olympus themis info`

Show where Themis lives and whether its stack is importable.

### `olympus themis jobs cancel`

Cancel queued work or request cooperative cancellation of running work.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `job_id` | argument | yes | — | — |
| `--database`, `-d` | option | no | — | — |

### `olympus themis jobs init`

Initialize the private native job database.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |

### `olympus themis jobs list`

List durable jobs, optionally filtered by lifecycle state.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--state` | option | no | — | — |
| `--limit` | option | no | `100` | — |

### `olympus themis jobs prune`

Delete finished jobs past the retention window; queued/running work is kept.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--older-than-days` | option | no | `30` | Keep finished jobs for this long. |
| `--database`, `-d` | option | no | — | — |
| `--dry-run` | option | no | `False` | Report what would be deleted. |

### `olympus themis jobs recover`

Requeue (or fail) jobs whose worker stopped renewing its lease.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |

### `olympus themis jobs status`

Return one durable job and its normalized result when complete.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `job_id` | argument | yes | — | — |
| `--database`, `-d` | option | no | — | — |

### `olympus themis jobs submit`

Persist one manifest-authorized scan job without executing it.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `scanner` | argument | yes | — | — |
| `--target` | option | yes | — | — |
| `--kind` | option | no | `host` | — |
| `--scope` | option | yes | — | — |
| `--database`, `-d` | option | no | — | — |
| `--idempotency-key` | option | no | — | Resubmitting the same key returns the existing job instead of queueing a second. |
| `--max-attempts` | option | no | `1` | Execution attempts before the job is failed. |
| `--signed-manifest` | option | no | — | Signed engagement manifest authorizing this exact target and scanner. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key used to verify the manifest. |
| `--engagement-storage` | option | no | — | Directory holding the durable signed-manifest and revocation store. |
| `--i-am-authorized` | option | no | `False` | — |

### `olympus themis jobs work`

Claim and execute at most one job; safe for cron/systemd/container loops.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--audit` | option | no | — | — |
| `--worker-id` | option | no | — | Stable identity for this worker's leases. |

### `olympus themis legacy-approve`

Approve selected legacy records for later historical import; create no jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--source` | option | yes | — | Archived VAP SQLite database. |
| `--backup` | option | yes | — | Verified snapshot SQLite backup. |
| `--manifest`, `-m` | option | yes | — | Verified snapshot manifest. |
| `--plan` | option | yes | — | Verified create-only conversion plan. |
| `--signed-manifest` | option | yes | — | Current signed engagement manifest. |
| `--manifest-public-key` | option | yes | — | Pinned Ed25519 approver public key. |
| `--migration-key` | option | yes | — | Reviewed terminal record to approve; repeat as needed. |
| `--revoked` | option | no | — | Revoked manifest identifier; repeat as needed. |
| `--output`, `-o` | option | yes | — | Create-only approval receipt. |

### `olympus themis legacy-import`

Import approved terminal history; never queue or execute a scanner.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--source` | option | yes | — | Archived VAP SQLite database. |
| `--backup` | option | yes | — | Verified snapshot SQLite backup. |
| `--manifest`, `-m` | option | yes | — | Verified snapshot manifest. |
| `--plan` | option | yes | — | Verified conversion plan. |
| `--approval` | option | yes | — | Signed-scope import approval receipt. |
| `--signed-manifest` | option | yes | — | Current signed engagement manifest. |
| `--manifest-public-key` | option | yes | — | Pinned Ed25519 approver public key. |
| `--database`, `-d` | option | no | — | Native Themis job database. |
| `--revoked` | option | no | — | Revoked manifest identifier; repeat as needed. |
| `--output`, `-o` | option | yes | — | Create-only import receipt. |

### `olympus themis legacy-plan`

Plan a reviewed legacy conversion without creating executable jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--source` | option | yes | — | Archived VAP SQLite database. |
| `--backup` | option | yes | — | Verified snapshot SQLite backup. |
| `--manifest`, `-m` | option | yes | — | Verified snapshot manifest. |
| `--output`, `-o` | option | yes | — | Create-only review plan. |

### `olympus themis legacy-snapshot`

Inventory a legacy VAP database without creating executable jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--source` | option | yes | — | Read-only archived VAP SQLite database. |
| `--backup` | option | yes | — | Create-only consistent SQLite backup. |
| `--output`, `-o` | option | yes | — | Create-only migration manifest. |

### `olympus themis legacy-verify`

Verify all legacy snapshot artifacts without modifying or importing them.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--source` | option | yes | — | Archived VAP SQLite database. |
| `--backup` | option | yes | — | Snapshot SQLite backup. |
| `--manifest`, `-m` | option | yes | — | Snapshot manifest. |

### `olympus themis matrix`

Render the scanner matrix from the registry, or check/rewrite the doc.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--check` | option | no | `False` | Exit non-zero if docs/scanner-matrix.md differs from the generated output. |
| `--write` | option | no | `False` | Rewrite docs/scanner-matrix.md in place instead of printing it. |

### `olympus themis maturity`

Render the maturity status block from the ledger, or check/rewrite the doc.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--check` | option | no | `False` | Exit non-zero if the maturity status block in docs/scanner-maturity.md differs from the generated output. |
| `--write` | option | no | `False` | Rewrite the generated maturity status block in docs/scanner-maturity.md in place. |

### `olympus themis migrate`

Create or upgrade the native SQLite job schema without losing jobs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |

### `olympus themis retention prune`

Enforce an age/count/size budget over an artefact directory.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `directory` | argument | yes | — | Directory of artefacts to bound. |
| `--pattern` | option | no | `*` | Filename glob within that directory. |
| `--older-than-days` | option | no | — | Delete artefacts older than this. |
| `--max-files` | option | no | — | Keep at most this many, oldest deleted. |
| `--max-bytes` | option | no | — | Keep at most this many bytes, oldest deleted. |
| `--no-overwrite` | option | no | `False` | Unlink without overwriting the contents first. |
| `--dry-run` | option | no | `False` | — |

### `olympus themis retention rotate-log`

Roll an audit log once it passes a size budget, securely dropping the oldest.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `path` | argument | yes | — | Append-only log to roll over. |
| `--max-bytes` | option | no | `50000000` | — |
| `--keep` | option | no | `5` | Generations to retain. |
| `--no-overwrite` | option | no | `False` | — |

### `olympus themis run`

Run a real scanner with explicit execution states (never implicit simulation).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `scanner` | argument | yes | — | Scanner name (see 'olympus themis run --list'). |
| `--target` | option | no | — | Authorized target (host/url/domain). |
| `--kind` | option | no | `host` | Target kind: host, url, or domain. |
| `--scope` | option | no | — | Versioned Themis scope JSON file. |
| `--timeout` | option | no | `300.0` | Per-process timeout in seconds. |
| `--deadline` | option | no | `600.0` | Overall scan deadline in seconds. |
| `--max-scope-bytes` | option | no | `1000000` | — |
| `--max-output-bytes` | option | no | `5000000` | — |
| `--max-findings` | option | no | `10000` | — |
| `--output` | option | no | — | Optional private versioned result JSON. |
| `--audit` | option | no | — | Redacted structured audit log. |
| `--signed-manifest` | option | no | — | Signed engagement manifest required for direct live execution. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key required for direct live execution. |
| `--engagement-storage` | option | no | — | Directory holding the durable signed-manifest and revocation store. |
| `--lab-policy` | option | no | — | Explicit signed policy file for a direct live scan limited to declared lab CIDRs. |
| `--i-am-authorized` | option | no | `False` | Confirm documented authorization for a real scan. |
| `--simulate` | option | no | `False` | Explicitly produce ILLUSTRATIVE output (never a real scan). |
| `--list` | option | no | `False` | List scanners with a native execution adapter and exit. |

### `olympus themis scan`

Submit authorized work to the native Themis API.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--target` | option | yes | — | Authorized target to scan. |
| `--scanner` | option | yes | — | Ready specialist engine. |
| `--scope-id` | option | yes | — | Server-registered scope identifier. |
| `--kind` | option | no | `host` | Target kind: host, domain or url. |
| `--url` | option | no | — | Base URL of the native Themis API. |
| `--api-key-env` | option | no | `OLYMPUS_THEMIS_API_KEY` | — |
| `--i-am-authorized` | option | no | `False` | — |

### `olympus themis scanners`

List the complete Themis scanner catalogue (all 24 integrations).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--check` | option | no | `False` | Also report whether each scanner's binary is available. |

### `olympus themis serve`

Serve the native Themis web control plane (browser UI over the same core).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--scope-directory` | option | no | — | — |
| `--host` | option | no | `127.0.0.1` | — |
| `--port` | option | no | `8600` | — |
| `--max-concurrent-requests` | option | no | `64` | — |
| `--api-key-env` | option | no | `OLYMPUS_THEMIS_API_KEY` | — |
| `--api-key-scopes` | option | no | `capabilities:read` | Comma-separated permissions for the shared API key (default: capabilities:read). |
| `--identities` | option | no | — | Identity register with scoped, revocable credentials. |
| `--oidc-issuer` | option | no | — | Pinned HTTPS OIDC issuer. |
| `--oidc-audience` | option | no | — | Required OIDC audience. |
| `--oidc-jwks` | option | no | — | Pinned local JWKS file; discovery is disabled. |
| `--audit` | option | no | — | Redacted per-request audit log. |
| `--engagement-storage` | option | no | — | Directory holding the shared engagements database; enables the engagement pages and engagement-derived scope enforcement. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key; requires --engagement-storage and makes every Web job require a signed manifest. |
| `--findings-directory` | option | no | — | Directory of core.Finding JSON bundles to review in the browser; enables the Findings pages (read-only producer artifacts). |
| `--findings-storage` | option | no | — | Append-only SQLite finding-lifecycle store; enables recording triage decisions (status transitions) from the browser. |
| `--baseline-directory` | option | no | — | Directory of core.Finding JSON bundles from an earlier run; enables the Scan diff page (new/resolved/persistent vs the current findings). |
| `--ssl-certfile` | option | no | — | — |
| `--ssl-keyfile` | option | no | — | — |

### `olympus themis smart-scan`

Propose a deterministic, scope- and policy-aware scan pipeline.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--objective` | option | yes | — | What to achieve: recon \| web-app \| network \| full. Each expands to a reviewed, ordered pipeline of native activities. |
| `--target` | option | yes | — | The target to plan against. |
| `--target-kind` | option | no | `host` | Target kind: host, domain or url. |
| `--max-risk` | option | no | `active` | Risk ceiling: passive \| active \| intrusive. A scanner louder than the ceiling is dropped with a reason; intrusive is never planned unless selected here explicitly. |
| `--engagement-storage` | option | no | — | Directory holding the shared engagements database; enables engagement scope enforcement on the proposal. |
| `--engagement` | option | no | — | Engagement id (ENG-YYYY-NNNNN); the target must fall inside its scope or the plan proposes nothing. |
| `--format` | option | no | `table` | Output format: table (human) or json (machine). |

### `olympus themis web`

Serve the native Themis web control plane (browser UI over the same core).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--scope-directory` | option | no | — | — |
| `--host` | option | no | `127.0.0.1` | — |
| `--port` | option | no | `8600` | — |
| `--max-concurrent-requests` | option | no | `64` | — |
| `--api-key-env` | option | no | `OLYMPUS_THEMIS_API_KEY` | — |
| `--api-key-scopes` | option | no | `capabilities:read` | Comma-separated permissions for the shared API key (default: capabilities:read). |
| `--identities` | option | no | — | Identity register with scoped, revocable credentials. |
| `--oidc-issuer` | option | no | — | Pinned HTTPS OIDC issuer. |
| `--oidc-audience` | option | no | — | Required OIDC audience. |
| `--oidc-jwks` | option | no | — | Pinned local JWKS file; discovery is disabled. |
| `--audit` | option | no | — | Redacted per-request audit log. |
| `--engagement-storage` | option | no | — | Directory holding the shared engagements database; enables the engagement pages and engagement-derived scope enforcement. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key; requires --engagement-storage and makes every Web job require a signed manifest. |
| `--findings-directory` | option | no | — | Directory of core.Finding JSON bundles to review in the browser; enables the Findings pages (read-only producer artifacts). |
| `--findings-storage` | option | no | — | Append-only SQLite finding-lifecycle store; enables recording triage decisions (status transitions) from the browser. |
| `--baseline-directory` | option | no | — | Directory of core.Finding JSON bundles from an earlier run; enables the Scan diff page (new/resolved/persistent vs the current findings). |
| `--ssl-certfile` | option | no | — | — |
| `--ssl-keyfile` | option | no | — | — |

### `olympus themis workers`

Run the native worker; SIGINT/SIGTERM cancel the active scan and stop.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--database`, `-d` | option | no | — | — |
| `--audit` | option | no | — | — |
| `--engagement-storage` | option | no | — | Directory holding signed manifests and their revocation register. |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 approver public key used to revalidate bound manifests. |
| `--worker-id` | option | no | — | Stable lease owner. |
| `--max-concurrent-jobs` | option | no | `1` | Shared cap for running jobs across workers using this database. |
| `--poll-interval` | option | no | `1.0` | — |
| `--once` | option | no | `False` | Process at most one job and exit. |

### `olympus ui`

Open the keyboard-first interface for every Olympus tool.

### `olympus vap`

[DEPRECATED] Alias for 'olympus themis' — forwards all arguments.

### `olympus version`

Print the Olympus version.

### `olympus vulcan attack`

Map offensive findings to MITRE ATT&CK techniques (OPS-RED).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--findings` | option | yes | — | core.Finding JSON file(s) to map to ATT&CK (repeatable). |
| `--reviews` | option | no | — | Optional human-review JSON ({finding_id: [{technique,name,tactic,confidence,rationale}]}); reviewed associations override the automatic mapping. |
| `--output` | option | no | — | Overlay JSON output. |
| `--navigator` | option | no | — | Also write an ATT&CK Navigator layer of the techniques these findings cover. |
| `--format` | option | no | `table` | Render the associations as table or json. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan diff`

Compare two assessment runs: what is new, resolved and still persistent.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--baseline` | option | yes | — | Earlier-run core.Finding JSON file(s) (repeatable). |
| `--current` | option | yes | — | Later-run core.Finding JSON file(s) (repeatable). |
| `--format` | option | no | `table` | Render as a table (human) or json (machine). |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan enrich`

Overlay CVE risk (CISA KEV + FIRST EPSS) onto findings and rank by urgency.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--findings` | option | yes | — | core.Finding JSON file(s) to enrich (repeatable). |
| `--kev` | option | no | — | Local CISA KEV catalogue JSON (offline enrichment). |
| `--epss` | option | no | — | Local FIRST EPSS API JSON response (offline enrichment). |
| `--fetch` | option | no | `False` | Fetch KEV and EPSS live instead of reading local files. |
| `--output` | option | no | — | Overlay JSON output. |
| `--format` | option | no | `table` | Render the ranked view as table or json. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |
| `--max-feed-bytes` | option | no | `50000000` | — |

### `olympus vulcan export`

Export findings or assets to portable, versioned NDJSON (one record per line).

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--kind` | option | yes | — | What to export: 'findings' or 'assets'. |
| `--input`, `-i` | option | yes | — | core.Finding/Asset JSON bundle(s) to read (repeatable). |
| `--output`, `-o` | option | yes | — | Portable NDJSON file to write. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan findings evidence`

Browse one finding's evidence, resolved against Minerva's chain of custody.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `finding_id` | argument | yes | — | The finding_id whose evidence to browse. |
| `--findings` | option | yes | — | core.Finding JSON file(s) to search (repeatable). |
| `--ledger` | option | no | — | Minerva custody ledger JSON: resolves the chain of custody for structured EVD-* evidence (verified; HMAC checked when the key is set). |
| `--evidence` | option | no | — | core.Evidence JSON file(s) to resolve type/URI/digest (repeatable). |
| `--format` | option | no | `table` | Render as a table (human) or json (machine). |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |
| `--max-ledger-bytes` | option | no | `50000000` | — |
| `--max-entries` | option | no | `100000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus vulcan findings list`

List findings, filtered and ordered by descending risk.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--findings` | option | yes | — | core.Finding JSON file(s) to view (repeatable). |
| `--format` | option | no | `table` | Render as a table (human) or json (machine). |
| `--status` | option | no | — | Keep only findings in these statuses (repeatable). |
| `--source` | option | no | — | Keep only findings from these sources (repeatable). |
| `--min-severity` | option | no | — | Keep only findings at or above this severity. |
| `--engagement` | option | no | — | Keep only findings linked to this engagement id. |
| `--kev-only` | option | no | `False` | Keep only CISA KEV-listed findings. |
| `--has-cve` | option | no | — | Keep only findings that have (or lack) any CVE. |
| `--tag` | option | no | — | Require ALL of these tags, case-insensitive (repeatable). |
| `--text` | option | no | — | Case-insensitive substring across finding fields. |
| `--min-risk` | option | no | — | Keep only findings with risk score >= this. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan findings show`

Show one finding's full view, with every column and absent data as ``—``.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `finding_id` | argument | yes | — | The finding_id to inspect. |
| `--findings` | option | yes | — | core.Finding JSON file(s) to search (repeatable). |
| `--format` | option | no | `table` | Render as a field table (human) or json (machine). |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan import`

Import findings or assets from portable NDJSON into a JSON bundle.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--kind` | option | yes | — | What to import: 'findings' or 'assets'. |
| `--input`, `-i` | option | yes | — | Portable NDJSON file to read. |
| `--output`, `-o` | option | yes | — | core.* JSON bundle to write. |

### `olympus vulcan notify`

Build redacted notifications from findings and optionally deliver them.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--findings` | option | yes | — | core.Finding JSON file(s) to announce (repeatable). |
| `--webhook` | option | no | — | Operator webhook URL (http/https). Omit to preview only — notifications are OFF by default and nothing leaves the host without it. |
| `--email-to` | option | no | — | E-mail recipient(s) (repeatable). Requires --email-from/--smtp-host. |
| `--email-from` | option | no | — | E-mail sender address. |
| `--smtp-host` | option | no | — | SMTP server host. |
| `--smtp-port` | option | no | `25` | SMTP server port. |
| `--min-severity` | option | no | `medium` | Announce only findings at or above this severity. |
| `--format` | option | no | `table` | Render the notifications as table or json. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan rank`

Load strict findings and print exact-ID-deduplicated severity ranking.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--findings` | option | yes | — | core.Finding JSON file(s) to rank (repeatable). |
| `--format` | option | no | `table` | Render as a table (human) or json (machine). |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-total-input-bytes` | option | no | `200000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |
| `--deadline` | option | no | `60.0` | — |

### `olympus vulcan report`

Aggregate strict inputs into consistent JSON, Markdown, HTML and PDF views.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--engagement` | option | yes | — | Engagement name for the report. |
| `--assets` | option | no | — | core.Asset JSON file(s) to include (repeatable). |
| `--findings` | option | no | — | core.Finding JSON file(s) to include (repeatable). |
| `--alerts` | option | no | — | core.Alert JSON file(s) to include (repeatable). |
| `--themis-result` | option | no | — | Manifest-bound olympus.themis-result 1.2.0 file(s) (repeatable). |
| `--signed-manifest` | option | no | — | Signed engagement manifest file(s) matching the Themis results (repeatable). |
| `--manifest-public-key` | option | no | — | Pinned Ed25519 public key used to verify report authorization provenance. |
| `--output` | option | no | — | JSON report output path. |
| `--markdown` | option | no | — | If set, also write a Markdown report to this path. |
| `--html` | option | no | — | If set, also write a self-contained HTML report to this path. |
| `--pdf` | option | no | — | If set, also write a formatted PDF report (needs the 'report' extra). |
| `--kev` | option | no | — | Local CISA KEV catalogue JSON: adds KEV flags to the PDF (offline). |
| `--epss` | option | no | — | Local FIRST EPSS response JSON: adds EPSS scores to the PDF (offline). |
| `--min-severity` | option | no | — | Only include findings at or above this severity. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-total-input-bytes` | option | no | `200000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |
| `--max-output-bytes` | option | no | `100000000` | — |
| `--deadline` | option | no | `120.0` | — |

### `olympus vulcan sarif-export`

Export findings as a SARIF 2.1.0 document for any SARIF consumer.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--input`, `-i` | option | yes | — | core.Finding JSON bundle(s) to export (repeatable). |
| `--output`, `-o` | option | yes | — | SARIF 2.1.0 JSON file to write. |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |

### `olympus vulcan sarif-import`

Import a third-party SARIF 2.1.0 report as a core.Finding JSON bundle.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--input`, `-i` | option | yes | — | SARIF 2.1.0 JSON file to import. |
| `--output`, `-o` | option | yes | — | core.Finding JSON bundle to write. |
| `--asset-id` | option | yes | — | Olympus asset id these SARIF results pertain to. |
| `--source` | option | no | `manual` | Provenance stamped on the imported findings. |

### `olympus vulcan trend`

Show the finding severity trend across an ordered series of runs.

| Name | Kind | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `--snapshot` | option | yes | — | A core.Finding JSON bundle for one run, oldest first (repeatable, min 2). |
| `--format` | option | no | `table` | Render as a table (human) or json (machine). |
| `--max-files` | option | no | `100` | — |
| `--max-input-bytes` | option | no | `50000000` | — |
| `--max-items-per-file` | option | no | `100000` | — |
| `--max-total-items` | option | no | `200000` | — |
<!-- GENERATED:cli-reference END -->

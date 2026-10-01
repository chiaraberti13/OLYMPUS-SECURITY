# Olympus ecosystem audit

_Audit date: 2026-08-27. Scope: every Olympus-native module, the temporary VAP
compatibility boundary, and the specialist-engine integration layer._

> Method: the CLI tree was introspected live (`typer`/`click`), module sources
> and imports were read, the 24 vendored scanners were parsed for their real
> external binaries, and the vendored THEMIS web app was booted to confirm routes
> and migrations. Presence of source files is **not** treated as completeness.

## 1. Status legend

- **source present** — code exists in the repo.
- **integration connected** — wired into the `olympus` CLI and imports resolve.
- **dependency installed** — required Python/system deps present in this env.
- **startup verified** — the tool starts / a command runs here.
- **basic execution verified** — a real (non-simulated) command produced output here.
- **e2e verified** — a representative end-to-end workflow ran here.
- **not executable here** — blocked by a sandbox limitation (no daemon, no binary, no network).

## 2. Tool inventory (overview)

| Tool | Kind | Purpose | CLI entry | Integrated | Tests | Status here |
| --- | --- | --- | --- | --- | --- | --- |
| core | native | Shared data contract (models, enums, ids, http, config, output) | `olympus core` | ✅ | 8 files | basic execution verified |
| argus | native | Scope-first OSINT & passive recon | `olympus argus` | ✅ | 29 files | basic execution verified |
| athena | native | Assessment orchestration (plans, jobs, SQLite, audit) | `olympus athena` | ✅ | 5 files | e2e verified (offline) |
| helios | native | Scoped network attack-surface mapping | `olympus helios` | ✅ | 1 file | basic execution verified |
| artemis | native | Scoped web assessment (fingerprint, content, XSS) | `olympus artemis` | ✅ | 8 files | basic execution verified |
| proteus | native | Scoped social-engineering campaign modelling | `olympus proteus` | ✅ | 1 file | basic execution verified |
| hermes | native | Secret / sensitive-data scanning (SARIF) | `olympus hermes` | ✅ | 1 file | basic execution verified |
| apollo | native | Detection rules engine (red/blue) | `olympus apollo` | ✅ | 5 files | basic execution verified |
| minerva | native | Incident triage & chain of custody | `olympus minerva` | ✅ | 2 files | basic execution verified |
| vulcan | native | Aggregation, dedup, ranking, reporting | `olympus vulcan` | ✅ | 1 file | basic execution verified |
| metis | native | Capability routing, planning, CTI cases and guided labs | `olympus metis` | ✅ | 1 file | e2e verified (offline) |
| themis | native + temporary VAP compatibility | Specialist-engine control plane | `olympus themis` | ✅ | execution/jobs/capability contracts | native jobs e2e verified (offline) |

Ruff and the complete automated test suite are blocking CI checks.

## 3. Per-tool detail

### Native Olympus modules

All eleven native modules are real implementations (no TODO/NotImplementedError/
placeholder found in `src/olympus`). They share the `core` contract, use
injected HTTP/DNS ports (offline-testable), and enforce scope on network-active
commands.

| Module | Subcommands | Key deps | External binaries | Services/DB | Config/env | Outputs | Docker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| core | export-schemas | pydantic | none | none | OLYMPUS_CONFIG, olympus.toml | JSON schemas | n/a |
| argus | accounts, diff, dns, doctor, email, fronting, investigate, ip, mac, myip, phone, pipeline, scan, web, whois | pydantic, dnspython, phonenumbers, rich | none (stdlib HTTP) | none | scope/pipeline JSONs; OLYMPUS_NUMVERIFY_KEY, OLYMPUS_RAPIDAPI_KEY (optional) | Asset/Finding JSON, versioned event graphs, NDJSON audit, Mermaid/DOT/GraphML | n/a |
| athena | plan validate, run, status, cancel, recover, adapters | pydantic, typer | none | SQLite (local file) | plan JSON, --storage dir | assessment JSON, audit, reports | n/a |
| helios | scan | pydantic | none | none | scope JSON | findings JSON | n/a |
| artemis | check-scope, content, fetch, fingerprint, metabase, xss | pydantic | none | none | scope JSON, wordlists | findings JSON | n/a |
| proteus | campaign, email, page, report | core policy/contracts | none | none | recipient/sender/landing scope JSON | protected versioned campaign JSON, report JSON, training HTML | n/a |
| hermes | scan | core policy/contracts | Git (optional history) | none | paths, versioned baseline, resource limits | masked SARIF, private baseline | n/a |
| apollo | rules, run, test | core policy/contracts, pydantic | none | none | versioned YAML rules, versioned NDJSON events, strict resource limits | versioned atomic alert JSON with rule/MITRE trace | n/a |
| minerva | record, timeline, triage, verify | core policy/contracts | none | private locked custody file | strict Apollo/evidence contracts, file/item/deadline limits | stable private incident JSON; custody 2.0 anchored to evidence digest | n/a |
| vulcan | rank, report | core policy/contracts | none | none | strict producer envelopes, aggregate byte/item/deadline limits | one canonical report; atomic JSON/safe Markdown/self-contained HTML | n/a |
| metis | capabilities, recommend, plan, labs, case | core file safety, pydantic, SQLite | none | private SQLite case store | strict objectives, scope entries, source/confidence and ingest limits | versioned plans/cases, safe Markdown and JSON reports | n/a |

### ARGUS (native migration complete) — `olympus argus`

- **Source:** `src/olympus/argus/`; last compared standalone revision
  `1c7a831…`. No duplicated source or runtime passthrough remains under
  `vendor/`.
- **CLI:** `accounts, diff, dns, doctor, email, fronting, investigate, ip, mac,
  myip, phone, pipeline, scan, web, whois`.
- **Deps:** `phonenumbers, rich` and optional `dnspython`; no standalone ARGUS
  package, external binary or service is required.
- **Verified here:** the full suite passes while `vendor/argus` is absent;
  `tests/unit/test_argus_native_replacement.py` prevents restoration of the
  removed passthrough and checks the complete native command surface.
- **Pipeline:** deterministic typed event expansion, recursive deduplication,
  blacklist and resource bounds. Active pivots require authorization and a
  scope gate.

### THEMIS (native control plane + temporary VAP compatibility) — `olympus themis`

- **Source:** `vendor/vulnerability-assessment-platform/` (upstream rev
  `6c6b395…`, GPL-3.0-only). Complete FastAPI app (~40 routes), 24 scanners, SQLAlchemy +
  3 Alembic migrations, Celery/Redis, report generator, templates, static,
  assets, tests.
- **Native CLI:** capability readiness, real scanner execution and durable job
  operations (`init`, `submit`, `list`, `status`, `cancel`, `work`). Every
  worker job passes through the same scope, authorization, SSRF, bounds and
  audit application service as synchronous execution.
- **Temporary compatibility CLI:** `serve, migrate, workers, scan, info` keeps
  the VAP web surface available while its required API/report contracts migrate.
- **Deps:** `pip install -e ".[themis]"` (or the vendored `requirements.txt`).
  **Services:** Redis (broker/result/cache) + Celery worker for queued scans;
  SQLite (default) or Postgres via `VAP_DATABASE_URL`. **DB:** Alembic
  migrations.
- **Config/env:** `VAP_*` (host/port, DB URL, Celery URLs, reports dir, live
  scans, HTTPS, secrets). Documented in `.env.docker.example` and
  `vendor/.../.env.example`.
- **Verified here:** the web app **booted**, auto-ran all 3 migrations, and
  served `/`, `/api/v1/scan-catalog`, `/api/v1/scans` (HTTP 200); Redis absent →
  clear "broker unreachable" warning (graceful). Docker Compose config validated
  (`docker compose config`); a live `up` was **not** run (no Docker daemon here).
- **Docs:** README (EN/IT) native+Docker, `docs/scanner-matrix.md`,
  `docs/install.md`, `docs/vap-to-themis-rename.md`, `docs/provenance.md`.

## 4. Incomplete, unverified, or simulated components (honest findings)

- **The temporary vendored web app still simulates by default** (upstream behaviour,
  preserved verbatim). **Resolved for the Olympus-native path:** `olympus themis
  run` is a new native execution layer with explicit states
  (`live`/`unavailable`/`failed`/`disabled`/`simulation`) that **never** emits a
  simulated finding unless `--simulate` (or `AEGIS_SIMULATION_MODE=true`) is
  explicitly given. Six scanners have real native adapters (nmap, nikto, wafw00f,
  sqlmap, whatweb, testssl); four were verified live end-to-end here against a
  local lab (see `docs/themis-execution-evidence.md`). The remaining 18 native
  adapters are pending. `olympus themis doctor`
  reports the live-scan flag and binary availability so the operator knows which
  scanners can run for real.
- **No scanner binaries are installed in this sandbox** and there is **no Docker
  daemon**, so **no live scan and no container `up` was executed here.** Scanner
  live execution is therefore "not executable here"; it is reproducible outside
  the sandbox via `docker-compose.scanners.yml` / the vendored `installer.sh`.
- **`olympus themis scan`** is an authenticated client for the native
  `/api/v1/jobs` endpoint. It requires an explicit authorization confirmation,
  a server-registered scope id and HTTPS for non-loopback servers. The API-to-
  SQLite lifecycle is verified offline; live execution still requires a ready
  specialist engine.
- **5 scanners are API/commercial** (zap, openvas, nessus, burp, acunetix) and
  cannot be auto-installed; they retain their integration and require manual
  setup (see `docs/scanner-matrix.md`).
- **Athena** live-network end-to-end tests are opt-in and were not run; its
  offline e2e (plan→run→report via SQLite) is verified.

## 5. Missing dependencies / services for full operation

| Need | For | How to obtain |
| --- | --- | --- |
| Redis | THEMIS queued scans (Celery) | `docker compose up` (bundled) or `apt-get install redis-server` |
| Scanner binaries (19 OSS) | live THEMIS scans | `docker-compose.scanners.yml` / `installer.sh` / `olympus themis deps` |
| Commercial engines (5) | nessus/burp/acunetix/zap/openvas | manual install + licence/API config |
| Docker daemon | container operation | host Docker Engine (absent in this sandbox) |
| `.[themis]` extra | temporary VAP web/worker compatibility | `bash scripts/setup-vendored-tools.sh` |

## 6. Verification commands run in this environment

See `docs/scanner-matrix.md` for the per-scanner matrix and
`docs/vap-to-themis-rename.md` for the rename verification. Ecosystem-level:

- `python -m olympus.cli --help` / `themis --help` — CLI tree present.
- `olympus themis scanners --check` — all 24 listed with binary availability.
- `olympus doctor` / `olympus themis doctor` / `olympus argus doctor` — real diagnostics.
- `olympus argus phone --number +390212345678` — real offline OSINT output.
- `olympus themis jobs submit/list/status/cancel/work` — durable native lifecycle.
- THEMIS web app booted + migrated + served 3 routes (HTTP 200).
- `docker compose config` (both files) — valid; daemon absent so no `up`.
- Full test suite and Ruff pass as blocking CI checks.

## 7. Confirmation

No tool in this audit is represented as complete **solely because its source is
present**. Each row above records the *verified* status (integration, imports,
startup, execution) reached in this environment, and every simulated-by-default
or not-executable-here limitation is stated explicitly rather than hidden.

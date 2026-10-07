<p align="center">
  <img src="assets/banner.svg" alt="Olympus-security" width="100%">
</p>

<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-F2C94C?style=flat-square" alt="Project status: active">
  <img src="https://img.shields.io/badge/category-CYBERSECURITY-22D3EE?style=flat-square" alt="CYBERSECURITY">
  <img src="https://img.shields.io/badge/stack-Python%203.11%2B-8B949E?style=flat-square" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/languages-EN%20%7C%20IT-8B5CF6?style=flat-square" alt="English and Italian">
  <img src="https://img.shields.io/badge/licence-GPL--3.0-2EA043?style=flat-square" alt="GPL-3.0 + third-party licences">
</p>

> One scope-safe CLI for security assessment, detection, evidence collection and reporting.

<p align="center"><a href="SECURITY.md">Security</a> · <a href="LICENSE">Primary licence</a> · <a href="THIRD_PARTY_NOTICES.md">Third-party licences</a></p>

---

## Quick Navigation

- **[What is Olympus?](#what-is-olympus)** — what it does, and who it's for.
- **[Modules](#-modules)** — every tool, what it does, and its entry point.
- **[Installation](#-installation)** — one command, Python 3.11+.
- **[Quick start](#-quick-start)** — a verified recon → assessment → report path.
- **[Configuration](#-configuration)** — scope files, config, and secrets.
- **[Project structure](#-project-structure)** — how the repository is laid out.
- **[Development](#-development)** — required CI checks and local commands.
- **[Security model](#-security-model)** — scope, authorization, SSRF, audit.
- **[Migration](#-migration--specialist-engines)** — native ARGUS, THEMIS and specialist engines.
- **[Licences](#-licence-scope)** — GPL-3.0 native code plus preserved third-party licences.
- **[Legal & ethical use](#-legal--ethical-use)** — authorized-only, in practice.

---

## What is Olympus?

Olympus is an offensive-and-defensive security platform driven through a single
binary. Instead of a drawer of unrelated scripts, every capability is a
sub-command of one CLI and speaks the **same data contract** — the same
`Asset`, `Finding`, `Event`, `Evidence`, `Alert` and `Incident` produced by one
module can be consumed by any other without translation.

Two design rules run through the whole project:

- **Offline-first, injected I/O.** Domain logic never talks to the network
  directly; it depends on small typed ports (HTTP client, DNS resolver, tool
  runner) so tests are deterministic and offline, and production wires in the
  real transport.
- **Scope-safe by construction.** Every command that touches a live target
  checks it against an explicit authorized scope first, blocks out-of-scope
  targets, and writes an audit record — never a silent drop.

```console
$ olympus --help
$ olympus argus dns --domain example.com --scope scope.json
$ olympus athena run plan.json --storage ./.athena
```

## 🧰 Modules

| Module | Entry point | What it does |
| --- | --- | --- |
| **Argus** | `olympus argus` | OSINT & passive recon: DNS, WHOIS/RDAP, web headers, IP, phone, email, MAC, accounts, CDN fronting, investigation graphs. |
| **Athena** | `olympus athena` | Assessment **orchestration & lifecycle**: validated plans, bounded job execution, durable SQLite storage, audit trail, reporting. |
| **Helios** | `olympus helios` | Scoped surface scanning and finding export. |
| **Artemis** | `olympus artemis` | Web application probing (fingerprint, content, XSS) within scope. |
| **Proteus** | `olympus proteus` | Social-engineering campaign modelling (authorized, simulated). |
| **Hermes** | `olympus hermes` | Secret & sensitive-data scanning with SARIF output. |
| **Apollo** | `olympus apollo` | Detection rules engine (red/blue) over normalized events. |
| **Minerva** | `olympus minerva` | Incident triage and chain-of-custody records. |
| **Vulcan** | `olympus vulcan` | Aggregation, deduplication, ranking and report rendering. |
| **Metis** | `olympus metis` | Deterministic capability routing, engagement plans, CTI cases, IOC correlation and operational reports. |
| **core** | `olympus core` | Shared data-contract utilities (`export-schemas`, versioned migration manifest). |
| **THEMIS** | `olympus themis` | Scope-gated scanner orchestration, capability readiness and maturity, durable SQLite jobs, cancellation, audit and explicit execution states. Native for 15 of 24 catalogued engines; `serve`/`migrate`/`workers` still need `vendor/`. |
| **Unified TUI** | `olympus ui` | Keyboard-first interface over every real Olympus command, with streamed output and process cancellation. |

> [!TIP]
> Run any module with `--help` to see its commands, or
> `olympus <module> <command> --help` for a command's options.

## 🚀 Installation

Olympus requires **Python 3.11+**.

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"      # or: make install
olympus --version
olympus ui
```

## 🎯 Quick start

Every network-active command needs a scope file naming the domains you are
authorized to touch:

```bash
cat > scope.json <<'JSON'
{ "engagement": "demo-2026", "allowed_domains": ["example.com"] }
JSON
```

Passive recon with Argus (writes a `core.Asset`/`core.Finding` bundle):

```bash
olympus argus dns   --domain example.com --scope scope.json
olympus argus whois --domain example.com --scope scope.json
olympus argus web   --url https://example.com --scope scope.json --output web.json
```

Orchestrate a whole assessment with Athena, then read the results:

```bash
olympus athena plan validate examples/input/athena-plan.json
olympus athena run examples/input/athena-plan.json --storage ./.athena --report
olympus athena status <ASSESSMENT_ID> --storage ./.athena
```

Athena uses the same canonical exit codes as every other module, so it scripts
cleanly in CI:

| Code | Meaning |
| --- | --- |
| `0` | Clean: full coverage, nothing to report. |
| `1` | Findings the caller may want to act on. |
| `2` | Usage or input error (bad flag, unreadable or invalid file, malformed scope). |
| `3` | Blocked: the target is outside the authorized scope, and it was logged. |
| `4` | Refused: an authorization or consent flag was required but not given. |
| `5` | Partial: coverage was lost, so any findings are **not** exhaustive. |
| `6` | Failed: nothing completed, so the result carries no information. |
| `7` | Cancelled on request before finishing. |

Codes `5` and `6` exist so a caller can tell "we looked everywhere and found
nothing" from "we could not look". A run that produced findings *and* lost
coverage exits `5`, not `1`: the findings are still printed, but the run must
not be read as exhaustive. A partial run is never reported as a clean one; see
[run status and coverage](docs/run-status.md).

### Platforms actually tested

Honesty over breadth — `requires-python = ">=3.11"` states what installs, not
what is verified:

| | Verified in CI | Not verified |
| --- | --- | --- |
| **OS** | Ubuntu portable suite plus dedicated POSIX sandbox suite; macOS and Windows portable CLI smoke | Linux-only sandbox guarantees on macOS/Windows |
| **Python** | portable suite on 3.11–3.14; POSIX sandbox suite on 3.11 | future Python releases; POSIX sandbox on 3.12–3.14 |

Olympus is developed and exercised on Linux. The core and CLI are written to be
portable, and the sandbox layer (`olympus.themis.sandbox`) is POSIX-specific by
design — user drop and `setrlimit` have no Windows equivalent. Its real-kernel
tests are isolated under `tests/platform/posix/`, use strict registered markers
and run in a dedicated Ubuntu CI job. Widening this matrix further is tracked in
[`ROADMAP.md`](ROADMAP.md) as `DEV-C`.

## ⚙️ Configuration

- **Scope files** (JSON) authorize targets per engagement:
  `{"engagement": "...", "allowed_domains": [...], "excluded_domains": [...]}`.
  Argus IP/phone/account scopes use their own keys — see
  [`examples/input/`](examples/input).
- **`olympus.toml`** (optional) sets shared HTTP defaults and redaction-first
  observability (`none`, authenticated Prometheus, or OTLP); resolution order is
  `OLYMPUS_CONFIG` → `./olympus.toml` → `~/.olympus.toml`.
- **`olympus.policy.toml`** (optional) makes the execution bounds editable per
  engagement — timeout, deadline, concurrency, retries, backoff, interval,
  jitter — plus named profiles and an opt-in `lab` allowlist for private ranges
  you declare you own. Resolution order is `OLYMPUS_POLICY` →
  `./olympus.policy.toml` → `~/.olympus/policy.toml`. A policy may only *lower*
  a compiled-in ceiling; a file that exceeds one is rejected, never clamped.
  Inspect it with `olympus policy show|validate|diff|edit` — see
  [`docs/policy.md`](docs/policy.md).
- **Secrets** are read only from environment variables (e.g.
  `OLYMPUS_NUMVERIFY_KEY`) and are **never** logged, exported, or placed in
  reports.

See [`docs/configuration.md`](docs/configuration.md) for precedence and
validation, and [`docs/observability.md`](docs/observability.md) for bounded
metrics, authenticated scraping and trace correlation.

## 🗂️ Project structure

```text
src/olympus/
├── cli.py            # unified `olympus` entry point
├── tui/              # unified keyboard-first terminal interface
├── core/             # shared contract: models, enums, http, config, policy, ids
├── argus/            # OSINT & passive recon (incl. ARGUS integration)
├── athena/           # assessment orchestration (VAP integration)
│   ├── domain/       # immutable plans, jobs, state machines, audit
│   ├── application/  # coordinator, registry, planning use cases
│   ├── adapters/     # sqlite, audit, reporting, and tool adapters
│   └── cli.py
├── helios/ artemis/ proteus/ hermes/ apollo/ minerva/ vulcan/
docs/                 # architecture (ADRs), parity manifests, reference
examples/             # scope files, plans, sample inputs/outputs
tests/                # offline, deterministic unit & contract tests
```

See the [terminal interface guide](docs/tui.md) for navigation, execution and
security behaviour.

## 🧪 Development

Ruff, strict type checking, portable pytest, POSIX sandbox tests and a first-party
branch-coverage floor are mandatory CI gates. Functional readiness additionally
requires real execution evidence; a green CI run alone is not called parity.

```bash
make lint      # Ruff; required in CI
make test      # pytest on the current host
make test-coverage # pytest + branch coverage gate; required in CI
make type      # strict mypy gate over first-party code
make check     # run the complete local quality suite
```

Generate a CycloneDX SBOM of the installed runtime — no external tool needed:

```bash
olympus core sbom --reproducible          # byte-stable CycloneDX 1.5 on stdout
olympus core sbom -o sbom.json --extra themis
olympus core lock -o constraints.txt      # pip --require-hashes constraints (real PyPI hashes)
```

See [`docs/architecture/`](docs/architecture) for the accepted design decisions,
[`docs/contracts.md`](docs/contracts.md) for the versioned wire/storage compatibility rules,
[`docs/execution-policy.md`](docs/execution-policy.md) for shared authorization and runtime bounds,
[`docs/observability.md`](docs/observability.md) for redacted metrics and trace correlation,
[`docs/threat-model.md`](docs/threat-model.md) for the threat model and security architecture,
[`docs/sbom.md`](docs/sbom.md) for the native SBOM generator,
[`docs/parity/`](docs/parity) for the upstream capability manifests, and
[`docs/professional-platform.md`](docs/professional-platform.md) for the
professional control-plane migration.

## 🔐 Security model

- **Scope enforcement** precedes any live lookup; blocked targets are audited.
- **Explicit authorization** (`--i-am-authorized`) gates privacy-sensitive
  OSINT (e.g. phone/email enrichment about a real person).
- **SSRF guard**: Athena adapters reject targets resolving to non-global IP
  literals and re-validate scope before every request.
- **Bounded execution**: shared HTTP timeouts/retries/rate limits, and Athena
  concurrency, per-job timeouts and overall deadlines with safe maxima.
- **Redacted audit trail**: append-only events with allowlisted metadata only —
  never credentials, bodies, or raw findings.

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model,
the control behind each threat, and an honest list of what is not yet covered.

## 🔁 Migration & specialist engines

The standalone **ARGUS** migration is complete. Its maintained implementation is
`src/olympus/argus/`, exposed only as `olympus argus`; the duplicated
`vendor/argus` source and the `argus-native` passthrough have been removed.

THEMIS now runs its API, Web UI (`serve`/`web`), schema migrations and continuous
workers from the installed native wheel. Scope, authorization, adapters, durable
SQLite jobs, cancellation and redacted audit share one implementation, without
Redis/Celery or runtime imports from `vendor/`. The archived VAP source remains
for the pending full endpoint/data parity review (`SEC-A`); legacy database import
and advanced Web milestones are separate roadmap work. See the bilingual
[native runtime guide](docs/themis-runtime.md) for configuration and rollback.

**How much of the catalogue actually executes.** The 24-scanner registry is a
catalogue, not an implementation claim. Today:

| Maturity | Count | Meaning |
| --- | --- | --- |
| `catalog-only` | 10 | Registry entry only; nothing executes. |
| `adapter-ready` | 0 | Adapter registered, parser unproven. |
| `offline-tested` | 2 | Parser proven against recorded output (`testssl`, `whatweb`). |
| `live-tested` | 12 | Run end to end against a real engine (`nmap`, `nikto`, `sqlmap`, `wafw00f`, `httpx`, `nuclei`, `katana`, `dalfox`, `dirsearch`, `commix`, `arjun`, `xsstrike`). |
| **`production-ready`** | **0** | Live-tested **and** the full Definition of Done met. |

No adapter is `production-ready` yet: the Definition of Done — per-adapter
evidence manifest with digests, SBOM, vulnerability scan and documented version
compatibility — is not met for any engine. `olympus themis capabilities` reports
this per engine, and a CI job can enforce it with
`olympus themis capabilities --min-maturity live-tested --count 12`. The
declarations are cross-checked against the repository on every test run, so the
table cannot quietly drift; see [`docs/scanner-maturity.md`](docs/scanner-maturity.md).

Specialist scanner engines are **integrated and governed, not copied**. Olympus
detects their installed versions, validates configuration, executes them within
an authorized scope, normalizes their output and records evidence. Their own
licences and installation channels remain authoritative.

```bash
olympus argus --help                       # native OSINT/recon surface
olympus argus doctor                       # dependency/config readiness

olympus themis capabilities                 # ready state here + project maturity
olympus themis doctor --scanner nuclei      # one engine: binary/version, adapter, maturity
olympus themis doctor --scanner all         # the same, for every catalogued engine
olympus themis matrix                       # classification matrix, generated from the registry
olympus themis matrix --check               # CI gate: fail if docs/scanner-matrix.md drifted
olympus themis jobs init                    # durable local job store
olympus themis jobs submit nmap --target example.com --scope scope.json --i-am-authorized
olympus themis jobs work                    # process one queued job
OLYMPUS_THEMIS_API_KEY='<32+ random chars>' olympus themis api --scope-directory .olympus/scopes
olympus themis scanners                     # specialist-engine catalogue
olympus themis migrate                       # apply the VAP database migrations
olympus themis serve --host 127.0.0.1 --port 8000   # serve the full VAP web app
```

### Running the native control plane

```bash
pip install -e ".[themis]"
olympus themis migrate --database .olympus/themis-jobs.sqlite3
# Configure the API credential/identity register and registered scopes first:
olympus themis api --scope-directory .olympus/scopes
olympus themis serve --scope-directory .olympus/scopes \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
olympus themis workers --database .olympus/themis-jobs.sqlite3
```

`serve` and `web` are identical. Browser sessions use HTTPS. Every queued job
still needs explicit authorization and scope; live scans default to disabled.
`workers --once` preserves canonical job exit codes, while the continuous worker
continues after individual failures and handles SIGINT/SIGTERM cooperatively.

After preparing scopes, scoped identities and TLS files as described in
[`docs/themis-runtime.md`](docs/themis-runtime.md):

```bash
docker compose up --build
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
docker compose down
```

| Aspect | Native deployment |
| --- | --- |
| Services | `themis-migrate`, `themis-api`, `themis-app`, `themis-worker`; SQLite, no broker |
| Ports | API `https://localhost:8443`, Web `https://localhost:8600`; published only on host loopback |
| Storage | `themis-data`; keep legacy VAP data separate, native migration refuses foreign databases |
| Security | Mandatory identities/TLS, non-root, read-only rootfs, capabilities dropped, live scans disabled |
| Scanners | Optional scanner image only on the worker; missing dependencies produce explicit partial coverage |
| Validation | Clean-wheel smoke plus an executable container suite in CI; all checks use loopback without live scans |

**Real scans, never fabricated:** `olympus themis run <scanner> --target <t> --scope s.json --i-am-authorized` runs a real scanner with explicit states — `live` / `unavailable` / `failed` / `disabled` / `simulation`. Simulation is produced **only** with `--simulate` (or `THEMIS_SIMULATION_MODE=true`); a missing binary yields `unavailable`, never a fake finding. See [`docs/scanner-matrix.md`](docs/scanner-matrix.md) and [`docs/themis-execution-evidence.md`](docs/themis-execution-evidence.md).

External scanner **binaries** are installed independently or through the
optional native worker image. The maintained runtime does not use the archived
VAP installer or its Redis/Celery stack.

Olympus ships **native** implementations: `olympus argus …` (scope-first OSINT),
`olympus themis …` (specialist-engine control) and `olympus athena …`
(assessment orchestration). Their
capability contracts and provenance are pinned in
[`docs/parity/`](docs/parity) and [`docs/provenance.md`](docs/provenance.md);
Athena's architecture is [ADR-002](docs/architecture/adr-002-athena-target-architecture.md).
Exhaustive walkthroughs live in [`docs/reference.md`](docs/reference.md).

## 📄 Licence scope

Olympus-native code, including native ARGUS and THEMIS, is licensed under **GNU GPL-3.0** — see
[LICENSE](LICENSE). Vendored and third-party components retain their own applicable licences; the
root licence does not overwrite third-party licensing terms.
See [third-party notices](THIRD_PARTY_NOTICES.md) and
[provenance](docs/provenance.md).

## ⚠️ Legal & ethical use

Olympus performs **authorized** security testing. Passive modules query only
publicly available information; active modules connect only to targets inside a
declared scope. Use it exclusively where you have **documented permission**
(your own systems, a signed engagement, or a lab you control). Misuse is your
responsibility alone.

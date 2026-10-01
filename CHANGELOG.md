# Changelog

All notable changes to Olympus are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): once a first
tagged release exists, breaking changes bump MAJOR, backward-compatible features
bump MINOR, and fixes bump PATCH.

Signed release tags, database migrations and a documented rollback procedure are
still open (see `ROADMAP.md`: `SEC-F`, `DEV-D`, `DEV-F`); until a release is tagged,
everything below lives under **Unreleased**.

## [Unreleased]

### Changed
- **Variabili d'ambiente THEMIS_* con fallback (`DEV-I`, Milestone 1c).** Le
  variabili di configurazione sono ora canonicamente `THEMIS_*`, con risoluzione
  centralizzata `THEMIS_*` → `AEGIS_*` → `VAP_*` in `olympus.themis.config`
  (resolver bidirezionale; impostare due nomi a valori diversi è rifiutato come
  ambiguo). Aggiornati i call site (sandbox, nuclei, capabilities,
  scanner-doctor, chiave API della CLI), `docker-compose.yml` e la
  documentazione; aggiunto un test del fallback. Le deployment esistenti che
  usano `AEGIS_*` o `VAP_*` continuano a funzionare senza modifiche. Completa
  `DEV-I` (rename AEGIS → Themis).
- **Migrazione schema-name e provenance AEGIS→Themis (`DEV-I`, Milestone 1b).**
  Gli schema name versionati sono ora `olympus.themis-*` e il valore provenance
  `Source` è `"themis"`. Un canonicalizzatore
  (`core.contracts.canonicalize_schema_name`, usato in `migrate_document`, in
  `validate_contract_header` e nel caricamento delle identità) riscrive i
  documenti persistiti sotto i vecchi nomi `olympus.aegis-*`, e il membro
  deprecato `Source.AEGIS = "aegis"` mantiene validi i record storici: nessun
  contratto diventa illeggibile. Schema catalog e golden rigenerati; aggiunti
  test di migrazione e di provenance. Le variabili d'ambiente `AEGIS_*` restano
  invariate (migrazione a `THEMIS_*` con fallback in Milestone 1c).
- **Rinominato il sottosistema AEGIS in Themis (`DEV-I`, Milestone 1).** Il
  control plane degli scanner specialistici ora vive in `src/olympus/themis/`,
  con comando `olympus themis` e API `olympus.themis.api`; classi, funzioni, tag
  FastAPI, doc (`docs/themis-*.md`), servizi docker (`themis-*`) e file di test
  sono stati migrati. `olympus aegis` resta un **alias deprecato** che emette un
  warning e inoltra a `olympus themis` (una sola implementazione), verificato da
  un CLI backward-compatibility test. Per non invalidare i dati persistiti, gli
  **schema name** versionati (`olympus.aegis-*`), il valore provenance `Source`
  `"aegis"` e le **variabili d'ambiente** `AEGIS_*` restano invariati in questa
  milestone e migreranno in M1b con migrazione e fallback dedicati (vedi
  `ROADMAP.md` `DEV-I`). Nessun contratto dati rotto; Ruff/Mypy/Pytest/schema
  catalog/golden verdi.

### Added
- **Report PDF formattato (`OPS-SCAN`)** — Vulcan rende un report PDF minimal e
  presentabile: copertina brandizzata, summary (overall risk, conteggi per
  severità con barra di distribuzione, totali), una **tabella delle vulnerabilità
  note** e i finding come blocchi tipografici puliti, più inventario asset/alert,
  dallo stesso modello canonico degli altri formati.
  - **Riferimenti NIST/CVE/CVSS/EPSS** — la tabella elenca una riga per CVE
    (`CVE · CVSS · EPSS · percentile · KEV`) con link cliccabili al NIST NVD; nei
    finding i CVE risolvono al NVD e i CWE a MITRE CWE. EPSS e KEV provengono
    dall'overlay di enrichment, mai inventati: in `olympus vulcan report --pdf`
    via `--kev/--epss`, e in `athena run --report` automaticamente quando la run è
    arricchita. `FindingEnrichment` ora conserva anche l'EPSS per singolo CVE
    (`per_cve`).
  - I colori di severità sono una scala ordinale validata e ogni chip sceglie il
    colore del testo per contrasto, così il significato non è mai affidato al solo
    colore. Ogni valore proveniente dal target è XML-escapato prima di entrare nel
    documento (`SEC-H`).
  - Motore ReportLab (Python puro, offline, nessun binario di sistema) nell'extra
    opzionale `report`; senza l'extra il PDF restituisce un errore chiaro e gli
    altri formati restano invariati. Primo passo del nuovo intervento `OPS-SCAN`,
    che allinea l'esperienza a una suite tipo pentest-tools.com.
- **Resilience fault injection (`DEV-E`)** — integration tests now exercise a
  worker crash and restart, concurrent idempotent submissions, real SQLite writer
  contention, interrupted schema migration rollback and cancellation of an
  already-running external process. AEGIS schema DDL and its version bump now
  commit atomically without blocking ordinary WAL readers.
- **Osservabilità sicura (`DEV-E`)** — metriche con label limitate e prive di
  target, identità, errori e ID; backend opzionali Prometheus e OTLP/HTTP,
  `/metrics` AEGIS autenticato, textfile atomico per processi brevi e trace che
  correlano assessment, job, evidence e report tramite soli ID Olympus validati.
- **Streaming e backpressure (`DEV-E`)** — Apollo normalizza i log e valuta gli
  eventi NDJSON in modo incrementale. Lettura e scrittura applicano limiti
  globali/per-riga, rollback atomico e diagnostica degli scarti limitata; la
  deduplicazione conserva fingerprint compatte invece dell'intero input.
- **Performance baseline (`DEV-E`)** — harness deterministico offline per ingest
  Apollo, deduplicazione Vulcan, rendering dei report e lifecycle della coda
  SQLite AEGIS; misura latenza, CPU e memoria Python, con profili quick/standard
  e budget espliciti attivabili senza vincolare la CI a runner rumorosi.
- **Contratto degli esiti (`DEV-D`)** — gli stati terminali `clean`, `findings`,
  `partial`, `failed` e `cancelled` e gli exit code 0–7 sono ora centralizzati
  nel core. Athena, AEGIS, Apollo e Hermes applicano lo stesso mapping; gli exit
  code legacy/esterni sconosciuti diventano `failed` e un contract test AST
  impedisce ai moduli CLI di reintrodurre numeri locali.
- **Explicit persisted-contract migrations** — a central fail-closed registry and
  versioned CLI manifest migrate legacy AEGIS scopes/jobs, Athena plans, evidence
  references and METIS cases without inventing missing provenance (`DEV-D`).
- **Golden interface contracts** — blocking deterministic fixtures now protect
  CLI JSON/NDJSON, AEGIS OpenAPI, Athena SQLite, and Vulcan JSON/Markdown reports;
  the compatibility policy defines explicit deprecation and support windows
  (`DEV-D`).
- **Versioned contract catalog** — deterministic Draft 2020-12 JSON Schemas are
  published by contract SemVer with stable identifiers, SHA-256 manifest entries,
  a compatibility bundle and a blocking drift check (`DEV-D`).
- **Security-boundary mutation tests** — CI tests mutations in scope validation,
  secret redaction, Nmap parsing, exit-code mapping and Athena job transitions.
- **Test engineering** — unit, contract and offline integration suites now run
  independently in CI. Container and authorized live-lab test collections are
  explicit opt-in and currently contain no cases (`DEV-C`).
- **Quality gates** — Mypy strict sul codice first-party e
  `ruff format --check` sono ora controlli CI bloccanti; il codice è stato
  normalizzato e le incompatibilità di tipo emerse sono state corrette. Pytest
  copre Python 3.11–3.14 su Ubuntu; build della wheel e smoke test CLI verificano
  inoltre le superfici portabili su macOS e Windows. I test real-kernel della
  sandbox sono ora isolati in una suite POSIX con marker strict e job Ubuntu
  dedicato; una soglia del 75% di branch coverage first-party è bloccante in CI
  (`DEV-C`).
- **Governance** — manifest versionato delle label GitHub (`area:*`, `P0`–`P3`,
  `roadmap`, `bug`) e workflow a privilegi minimi che crea o aggiorna soltanto le
  label gestite, senza cancellare quelle esterne al manifest (`DEV-H`).
- **Athena** — AEGIS **scan stage** in the assessment pipeline: `aegis` is now a
  plan adapter, so a single `athena run` chains recon → scan → enrich → report.
  It delegates to a real AEGIS scanner, double scope-gated (Athena guard + AEGIS
  `ensure_allowed`); with `AEGIS_ENABLE_LIVE_SCANS` off it uses AEGIS's own
  scope-gated simulation mode (labelled findings, no binary run), and runs the
  real tool when live scanning is enabled. Scanner is nmap for now.
- **Athena** — offline KEV/EPSS enrichment stage in the assessment pipeline
  (`athena run --enrich-kev/--enrich-epss`): overlays CISA KEV and FIRST EPSS
  from **local** feed files (no network), re-orders the report by real-world
  risk (KEV → EPSS → CVSS → severity), and writes a `<assessment_id>.enriched.json`
  overlay sidecar. Reuses `olympus.vulcan.enrichment`; scope/audit unchanged.
- **Minerva** — HMAC-SHA256 signed custody ledger (schema 2.1.0,
  `OLYMPUS_CUSTODY_HMAC_KEY`) detecting truncation and full rewrite; consistent
  `backup`/`verify-backup`/`restore` of the SQLite case store via the online
  backup API.
- **AEGIS** — native **wapiti** adapter (web vulnerability scanner), taking the
  catalogue to 15/24 native engines. Parses wapiti's JSON report into findings;
  validated `offline-tested` against a REAL captured report from a bounded scan
  of the bundled `labs/mars` target (a genuine reflected-XSS finding).
- **Metis** — IOC sweep (`case sweep`): match a local artifact against a case's
  known indicators using the same normalization as ingest (type+value, never
  substring); reports each hit's source/confidence and exits 1 on any match, 0
  when clean — a scriptable DFIR triage gate.
- **Minerva** — signed timeline export (`timeline --export [--sign-key]`): the
  verified custody timeline is written as a deterministic
  `olympus.minerva-timeline` JSON artifact and, optionally, an Ed25519 signature
  envelope over its exact bytes (reuses `core.signing`), so a third party can
  confirm provenance and detect tampering via `olympus core verify`.
- **Metis** — STIX 2.1 and MISP export/import of indicators (deterministic,
  faithful-subset with explicit skips); backup/restore of the case store;
  authenticated encryption of a case document at rest (`export-encrypted` /
  `decrypt`, `OLYMPUS_METIS_KEY`); optional encrypted whole-store backups
  (`backup --encrypt`, auto-detected and decrypted by `restore`).
- **Core** — `core.crypto`: authenticated symmetric encryption (Fernet + scrypt)
  over the vetted `cryptography` library; `core.signing`: Ed25519 detached
  signatures with pinned-public-key verification (`core keygen`/`sign`/`verify`)
  for third-party verifiable provenance on any artifact (ledger, evidence, SBOM,
  report).
- **Vulcan** — `enrich` overlay adding CISA KEV and FIRST EPSS to findings and
  ranking them by real-world risk (KEV → EPSS → CVSS → severity).
- **Hermes** — shape-based allowlist (path globs / value regexes) and a
  `pre-commit` hook command with a `.pre-commit-hooks.yaml` declaration,
  completing baseline + allowlist + entropy + SARIF + pre-commit/CI.
- **Argus** — investigation-graph correlation (`argus correlate`): connected
  components, degree-ranked pivots, n-hop neighbors, and shared-value
  correlation, plus a JSON round-trip loader for the graph.
- **Apollo** — ECS and OCSF (Detection Finding) NDJSON export for SIEM ingestion,
  a MITRE ATT&CK Navigator layer export, and dependency-free import of the
  faithful subset of Sigma rules.
- **Apollo** — telemetry **ingest** (`apollo ingest --format access-log`): bounded,
  skip-never-guess normalization of real HTTP access logs (Apache/nginx Common &
  Combined, and the Python `http.server` variant) into `core.Event` NDJSON that
  `apollo run` consumes end to end. First front door for operational telemetry;
  additional formats (Sysmon, Zeek) can plug into the same shape.
- **Core** — evidence digests computed from real artifact bytes at capture
  (`core.evidence`, `minerva capture`); pre-write target validation and race-free
  create-only atomic writes (`core.fileio.ensure_write_target`).
- **Supply chain** — CycloneDX SBOM (`core sbom`), hash-pinned constraints
  (`core lock`), a blocking pip-audit CI job, and digest-pinned container images.
- **Governance** — CODEOWNERS on security-critical paths and a grounded threat
  model (`docs/threat-model.md`).

### Testing
- Test offline della validazione del manifest e del piano non distruttivo di
  sincronizzazione delle label GitHub.
- Property-based (fuzz) tests over the SSRF address guard and the audit/evidence
  redaction (`tests/unit/test_property_security.py`, Hypothesis): the guard never
  accepts a non-global destination — including one wrapped in IPv6 — and no
  secret survives redaction at any nesting depth. `hypothesis` added as a dev
  dependency.
- Adapter parsers validated against REAL captured tool output rather than
  invented fixtures: `whatweb`, `wafw00f`, `nmap` and `testssl` run against a
  local authorized target (HTTP and a self-signed HTTPS endpoint), output saved
  verbatim under `tests/fixtures/aegis/live/` and consumed by
  `tests/unit/test_aegis_adapters_live_capture.py`.

### Changed
- All Argus persistence writes routed through atomic, owner-only, no-symlink
  writes (`core.fileio.atomic_write_text`).
- `docker-compose.yml` core services hardened with `no-new-privileges`,
  `cap_drop: [ALL]` and resource limits; the ZAP engine requires an API key
  (`AEGIS_ZAP_API_KEY`) instead of disabling it; a dedicated `backend` network.

### Security
- Closed the custody-ledger truncation/rewrite gap via HMAC signing.
- Removed the unauthenticated ZAP API default.
- Bounded the scrypt KDF parameters read from an encryption envelope, so a
  hostile document cannot turn decryption into a memory-exhaustion bomb
  (self-review finding).
- Pinned HTTP clients no longer inherit an environment proxy for any scheme, so
  a plain-HTTP request cannot be silently unpinned via an HTTP_PROXY (the HTTPS
  CONNECT tunnel was already refused).
- Import parsers (Sigma, MISP) refuse a non-scalar value instead of
  stringifying it into a bogus rule/indicator.
- Audit/metadata redaction now reaches URL query secrets nested inside list
  values (and nested lists), not only a URL that is the immediate value of a
  key (self-review finding).
- Scanner-output evidence redaction now removes the credential *after* an
  `Authorization`/`Proxy-Authorization` scheme word (`Bearer <token>`,
  `Basic <b64>`), instead of redacting only the scheme name and leaking the
  token (self-review finding).

_Runtime-dependent items (live scanner runs, container runtime behaviour, remote
feeds) are tracked with their blockers in `ROADMAP.md` (prerequisites D1–D12)._

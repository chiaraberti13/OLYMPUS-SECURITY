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
- **Web control plane nativo (`WEB-A`).** Nuova interfaccia browser
  `olympus.themis.web` (FastAPI + Jinja2 + server-sent events) servita da
  `olympus themis web`, costruita **sopra** l'API THEMIS esistente senza
  duplicare logica di sicurezza: un job avviato dal browser passa per lo stesso
  `ThemisJobStore`, la stessa risoluzione dello scope registrato, la stessa
  execution policy, sandbox, rate limit, retention e audit trail redatto della
  CLI — indistinguibile per policy e audit. Nessun `POST /run-command` né shell
  arbitraria: solo richieste tipizzate (`scanner`/`target`/`scope`) validate con
  lo stesso contratto `JobSubmission`. Hardening P0: sessione via cookie firmato
  `HttpOnly`/`Secure`/`SameSite=Strict` emesso solo da una credenziale valida;
  token CSRF sincronizzatore su ogni form che cambia stato; Content-Security-
  Policy restrittiva senza script/stile inline più header di sicurezza e body
  limitato; scope enforcement per rotta; streaming SSE degli stati del job con
  pulsante **Cancel** collegato alla cancellazione reale. Testo influenzato dal
  target ripulito da sequenze di controllo del terminale e segreti URL, con
  autoescaping HTML (`SEC-H`). `jinja2`/`python-multipart` spostati nell'extra
  `api`. Aggiunti test di web-security e job-lifecycle e `docs/web.md`;
  threat model aggiornato.
- **Workflow di suppression dei finding (`WEB-C`).** `core/finding_lifecycle`
  espone `suppress`/`unsuppress`/`is_suppressed`: sopprimere un finding
  (accepted-risk o false-positive) **esige una motivazione non vuota** e uno stato
  di suppression, passa comunque per la macchina a stati e produce il record
  d'audit; `unsuppress` riapre un finding soppresso a `confirmed`. Completa il
  ciclo di vita dei finding di `WEB-C`. Aggiunti test e documentazione
  (`docs/findings.md`).
- **Wiring engagement_id in Athena/Themis (`WEB-B`, completa slice 2).** Il
  coordinator Athena marca gli oggetti prodotti (asset + finding, path Themis
  incluso) con l'`engagement_id` del piano **solo quando è un id canonico**
  (`ENG-YYYY-NNNNN`, nuovo helper `core.models.is_canonical_engagement_id`); le
  etichette libere dei piani (`ENG-DEMO-2026`, `ENG-1`) non vengono marcate, così
  nessuna fixture/golden si rompe. I due namespace restano distinti per disegno:
  l'id di piano Athena è un'etichetta locale, l'`engagement_id` core referenzia un
  record `olympus.engagement`. Aggiunti test del coordinator e dell'helper.
- **Audit trail del ciclo di vita dei finding (`WEB-C`).** Nuovo contratto
  versionato `olympus.finding-transition` (`FindingTransition`: `from_status`,
  versionato `olympus.finding-transition` (`FindingTransition`: `from_status`,
  `to_status`, `actor` single-line, `reason` opzionale, `occurred_at`, scoped
  all'`engagement_id`), `core/finding_lifecycle.record_transition` che applica una
  transizione legale e ne restituisce insieme il record immutabile, e lo store
  SQLite **append-only** owner-only `findings/store.SqliteFindingTransitionStore`
  (`append`/`history`, rifiuta id duplicati, valida l'header on load). Risponde a
  "chi ha accettato questo rischio e quando?" senza fidarsi del finding mutabile.
  Nuovo prefisso id `FTR`. Schema catalog e golden rigenerati; aggiunti test e
  documentazione (`docs/findings.md`).
- **Tagging, ricerca e filtri sui finding (`WEB-C`).** Nuovo campo
  `Finding.tags` (additivo e retro-compatibile — schema resta `1.0.0` — con
  normalizzazione: trim, scarto dei vuoti, de-duplica preservando l'ordine) e
  nuovo modulo `vulcan/search.py` con `FindingFilter` (value object immutabile:
  stato, source, severità minima, `engagement_id`, KEV, has-CVE, tag
  case-insensitive "tutti", testo libero su titolo/descrizione/reference/CVE/CWE/
  tag/id, risk score minimo) e `search_findings`. I criteri si combinano in AND,
  i criteri non impostati non vincolano, e l'ordine d'ingresso è preservato
  (il ranking resta separato). Fonte unica dei predicati per CLI/TUI/Web. Schema
  catalog e golden rigenerati; aggiunti test e documentazione
  (`docs/findings.md`).
- **Deduplica cross-scanner lossless dei finding (`WEB-C`).**
  `vulcan/aggregate.merge_duplicate_findings` fonde i finding che descrivono la
  stessa vulnerabilità sullo stesso asset (identità: stesso `asset_id` + stesso
  set di CVE, o titolo normalizzato quando non ci sono CVE) in un unico finding
  **senza perdere evidenza**: evidence, reference, CVE e CWE vengono unite e per
  ogni scalare vince il segnale più urgente (max severity/CVSS/EPSS, KEV se visto
  da una qualsiasi fonte, confidence più alta); il rappresentante (severità più
  alta, poi risk, poi id stabile) fornisce titolo/descrizione/remediation/stato/
  id, e i timestamp si allargano allo span reale del gruppo. Integrata nel
  pipeline di aggregazione Vulcan dopo il dedup per ID; stabile e idempotente.
  Aggiunti test e documentazione (`docs/findings.md`).
- **Macchina a stati del ciclo di vita dei finding (`WEB-C`).** Nuovo modulo
  `core/finding_lifecycle.py` che definisce le transizioni legali tra i 7 stati
  `FindingStatus` (triage, confirmed, false-positive, accepted-risk,
  in-remediation, closed, con riapertura su recurrence/retest). Espone
  `can_transition`/`allowed_transitions` e `transition(finding, target)`, che
  ritorna una **copia** aggiornata (con `last_seen` rinfrescato) e rifiuta mosse
  illegali o no-op con `FindingTransitionError`. È la fonte unica del workflow
  per CLI/TUI/API/Web; nessun cambio di contratto (usa l'enum esistente).
  Aggiunti test e documentazione (`docs/findings.md`). Resta da fare: persistenza
  dell'audit trail delle transizioni e deduplica cross-scanner.
- **Risk score contestuale sui finding (`WEB-C`).** Nuovo metodo calcolato
  `Finding.risk_score()` che restituisce un punteggio `[0, 100]` combinando
  severity, CVSS, EPSS, KEV e confidence nell'ordine di priorità di
  `vulcan/enrichment.prioritize` (KEV domina, poi EPSS alza il floor a
  `epss×100`, poi CVSS/severità come base, confidence come modificatore lieve).
  È calcolato on-demand dai campi correnti — mai stale e senza aggiunte al
  contratto wire/storage — ed è mostrato nei metadati di ogni finding nel report
  PDF (`Risk NN/100`). Aggiunti test e documentazione (`docs/findings.md`).
- **Primitive di associazione all'engagement (`WEB-B`, slice 2).** Il modello
  `Engagement` espone `stamp()`/`stamp_all()` (ritornano una **copia** degli
  oggetti scoped collegata all'engagement, senza mutare l'originale e
  preservandone il tipo) e `covers()` (scope-check che inoltra a
  `EngagementScope.covers`); `SqliteEngagementStore.require()` risolve un
  `engagement_id` o solleva `EngagementStoreError`, così un id sconosciuto
  fallisce all'origine invece di lasciare riferimenti pendenti. Aggiunti test e
  documentazione (`docs/engagements.md`). Resta da fare: far **chiamare** queste
  primitive da Athena/Themis al momento della produzione.
- **Collegamento degli oggetti all'engagement (`WEB-B`, slice 2 — fondamenta
  dati).** I contratti scoped (`Asset`, `Finding`, `Event`, `Evidence`, `Alert`,
  `Incident`, `Observation`) acquisiscono un campo opzionale `engagement_id` via
  la base condivisa `EngagementScopedModel`, che tiene insieme gli oggetti del
  medesimo engagement su CLI/TUI/API/Web. Il campo è additivo e
  retro-compatibile (schema resta `1.0.0`, gli oggetti pre-`WEB-B` validano con
  `engagement_id=None`); quando valorizzato è normalizzato e validato come
  `ENG-YYYY-NNNNN`. Aggiunti test, nota in `docs/engagements.md`; schema catalog
  e golden rigenerati.
- **Finding con intelligence strutturata (`WEB-C`, fondamenta).** Il contratto
  `olympus.finding` acquisisce campi opzionali tipizzati — `cve`, `cwe`, `epss`,
  `epss_percentile`, `kev` e `confidence` (nuovo enum `Confidence`) — con
  validazione (pattern CVE/CWE, probabilità EPSS in `[0,1]`). I campi sono
  additivi e retro-compatibili: lo schema resta `1.0.0` e i finding persistiti
  prima di `WEB-C` validano ancora (i campi default a vuoto). Gli helper
  `Finding.cves()`/`cwes()` preferiscono il campo strutturato e ricadono sul
  free-text estratto via regex. `vulcan/enrichment.extract_cves` usa i campi
  strutturati, e il report PDF (`vulcan/pdf.py`) mostra EPSS/KEV/confidence
  nella tabella CVE e nei metadati dei finding **anche senza** overlay di
  enrichment live (engagement offline/air-gapped). Aggiunti test (unit) e
  `docs/findings.md`; schema catalog e golden rigenerati.
- **Engagement come entità di primo livello (`WEB-B`, slice 1).** Nuovo
  contratto condiviso versionato `olympus.engagement` (`Engagement` +
  `EngagementScope` con perimetro incluso/escluso e `covers()`), store SQLite
  owner-only e comandi `olympus engagement create|list|show`. Un solo modello e
  un solo database per CLI/TUI/API/Web. Aggiunti schema catalog, golden, test
  (unit + integration) e `docs/engagements.md`. Le slice successive collegano
  asset/job/finding all'`engagement_id` ed espongono gli engagement via API/Web.
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

### Fixed
- **Flake d'ordine nel test TUI.** `test_tui.py::test_command_screen_executes_real_cli_without_shell`
  attendeva solo ~2s il completamento di un subprocess reale
  (`python -m olympus.cli ...`); sotto carico della suite completa l'avvio a
  freddo dell'interprete supera i 2s e l'assert falliva. Budget d'attesa reso
  generoso (fino a ~30s, polling invariato): l'assert riflette l'esito reale del
  comando, non la latenza di scheduling. Nessuna modifica al prodotto.

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

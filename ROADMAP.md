# 🏛️ OLYMPUS-SECURITY — Roadmap (canonica)

> Questo documento **sostituisce integralmente** la roadmap precedente. La
> versione storica resta disponibile nella cronologia Git (`git log -- ROADMAP.md`)
> come fonte conoscitiva, non vincolante. Progettata dal team multidisciplinare il
> 2026-11-01, è l'**unico documento di pianificazione canonico** del progetto.

**Legenda stato:** `[x]` implementato e verificato (test/CI nello scope indicato —
non è un claim di produzione/lab live); `[~]` parziale o in corso; `[ ]` da fare.
Gli ID sono stabili.

**Livelli di verifica** (vocabolario delle note di stato; ogni dichiarazione indica il
livello raggiunto, mai uno superiore): `implementato` (il codice esiste) → `verificato
offline` (test/fixture automatici) → `verificato in CI` (check verdi sullo SHA indicato)
→ `validato in lab` (esecuzione reale in laboratorio autorizzato, evidenza committata) →
`operativo` (in uso in un deployment con i controlli attivi). `[x]` non supera
«verificato in CI», salvo criteri espliciti della voce. I **sotto-ID** (`TOOLS-4.1`,
`SEC-4.2`…) scompongono una voce esistente: l'ID padre resta stabile. **Priorità:** `P0`
sicurezza e integrità · `P1` consolidamento operativo · `P2` evoluzione funzionale · `P3`
esperienza d'uso · `P4` evoluzioni differite (mappa in §21.2).

---

## 0. Governance e principi (vincolante)

Le decisioni tecniche e operative — moduli, architettura, stack, framework,
integrazioni, interfacce, priorità, infrastrutture — appartengono al **team**.
Non esistono vincoli autoimposti che vietino nuovi moduli, riscritture,
sostituzioni di stack o riprogettazioni: ogni scelta nasce da una valutazione
tecnica (sicurezza, costi, prestazioni, manutenibilità, scalabilità).

Restano **irrinunciabili** solo i requisiti di qualità, integrità e sicurezza:

- **Riuso quando conviene**, nuovi moduli quando sono la scelta migliore.
- **Priorità motivata**: prima i problemi critici (sicurezza/integrità/P0).
- **Documentazione IT/EN** coerente con ciò che è realmente implementato.
- **Test, coverage e quality gate** mantenuti, mai disabilitati per nascondere errori.
- **Distinzione netta** tra dichiarato, implementato e realmente verificato.
- **Cronologia Git protetta**: niente force-push distruttivi o riscrittura di `main`; rispetto del lavoro concorrente.
- **Logging, audit, tracciabilità e isolamento** integri.
- **Stati ed esiti veritieri**: `partial`/`failed` mai spacciato per pulito.

**Disclaimer d'uso (tutti i tool):** «Strumento destinato a finalità didattiche,
formative e di ricerca nell'ambito della cybersecurity. L'utilizzo è consentito
esclusivamente su sistemi propri o esplicitamente autorizzati, nel rispetto delle
normative applicabili.» Il disclaimer non giustifica funzionalità incomplete e non
sostituisce l'autorizzazione: le attività attive restano gated da autorizzazione
(engagement manifest firmato, scope registrato, `--i-am-authorized`).

---

## 1. Visione e obiettivi

OLYMPUS-SECURITY è una **piattaforma integrata Red/Blue/Purple Team**, realmente
funzionante, modulare, sicura, aggiornata, scalabile, usabile da **Web UI
completa** e, in alternativa, da **CLI** per scripting. Documentata IT/EN, con
strumenti concreti e una **demo professionale su Vercel**.

Obiettivi irrinunciabili: tool operativi (non simulazioni), Web UI per tutti i
tool, CLI come alternativa, demo navigabile su Vercel, architettura scelta su
basi tecniche, sicurezza/qualità/tracciabilità/documentazione, sviluppo concreto
pubblicato su `main`.

**Direzione (revisione 2026-11-03).** Da ecosistema di strumenti a piattaforma integrata
di conoscenza, correlazione e verifica continua della sicurezza: scoprire e comprendere gli
asset; identificare vulnerabilità ed esposizioni; contestualizzarle; correlare informazioni
offensive, difensive e di threat intelligence; distinguere fatti osservati da ipotesi;
conservare evidenze verificabili; valutare l'efficacia dei controlli; misurare l'evoluzione
della sicurezza nel tempo; supportare remediation e verifica successiva; offrire workflow
completi via Web UI e CLI. L'obiettivo non è moltiplicare i moduli ma farli collaborare in
modo coerente, affidabile e verificabile; il consolidamento dell'esecuzione reale (P0/P1)
precede le evoluzioni (P2–P4). Dettaglio in §21.

## 2. Stato verificato dei componenti

Verificato = coperto da test automatici verdi in CI (unit/integration/contract),
non necessariamente provato in lab live.

| Area | Componente | Stato | Nota |
|---|---|---|---|
| Core | `core.models`/contratti versionati, migrazioni, redaction, crypto, signing | [x] | contratti golden + schema catalog |
| Recon | **Argus** (DNS/WHOIS/CT/OSINT, SSRF-safe) | [x] | nativo, test offline; workbench Web `/argus` (sottodomini CT) + API `/api/v1/argus/ct-subdomains` |
| Orchestrazione | **Athena** (piani firmabili, job, profili Light/Deep) | [x] | `athena profiles`, `plan from-profile`; pianificatore Web `/athena` + API `/api/v1/athena/plan` |
| Scanner plane | **Themis** (registry 24 engine, maturity ladder, sandbox, job SQLite, API, Web) | [~] | adapter a maturità diversa; ledger: 12/24 live-tested, 3 offline-tested, 1 adapter-ready, 8 catalog-only, 0 production-ready (`docs/scanner-maturity.md`) |
| Web attiva | **Artemis** (fingerprint/header/XSS checks) | [x] | offline-tested; workbench Web `/artemis` (fingerprint passivo) + API `/api/v1/artemis/fingerprint` |
| Blue Team | **Apollo** (ingest access-log/Zeek, detection, ATT&CK, coverage) | [~] | manca ingest Windows/Sysmon |
| CTI | **Metis** (IOC, STIX/MISP import, case) | [~] | estrazione IOC su API+Web (`/metis`, `/api/v1/metis/extract`); manca CTI live (TAXII/MISP/OpenCTI) |
| Evidenze | **Minerva** (timeline firmata Ed25519) | [x] | verify offline |
| Reporting | **Vulcan** (aggregazione, JSON/MD/HTML/PDF, SARIF, enrichment KEV/EPSS, sezioni da manifest) | [x] | test completi |
| Altri | Helios, Hermes, Proteus | [~] | superfici parziali |
| Interfacce | CLI (Typer), TUI (Textual), API (FastAPI tipizzata), Web (Jinja2+SSE) | [~] | Web copre un sottoinsieme dei tool |
| Catalogo | `olympus catalog` (coverage present/simulated/missing, derivata e onesta) | [x] | gate anti-sovrastima |
| Distribuzione | anteprima statica + demo a fixture su Vercel (`public/`, `vercel.json`) | [x] | deploy live = import owner |
| Qualità | CI: 14 check `ci` + CodeQL + `scanner-image` = 16 check su `783f2bb`; ~3110 test raccolti (esclusi container/live_lab) | [x] | verde su `main` @ `783f2bb` (verifica 2026-11-03; i check sono partiti dopo il merge, non lo hanno condizionato) |
| Engine esterni | Governance engine: `engine.toml` ×24, `engines list/doctor`, evidenza firmata per run, SBOM engine, immagine scanner | [~] | vedi `TOOLS-4`: implementato e verificato in CI; **non** operativi preflight, evidenze nei percorsi job/API/Web/worker, `doctor --strict` in build |

### Verifica dello stato reale — 2026-11-03

Riferimento: `main` @ `783f2bb` (merge della PR #118), letto da remoto all'inizio della
revisione. Lo SHA è un'istantanea: va riletto prima di usare questa sezione come base di
lavoro. Ogni riga dichiara cosa è stato verificato e cosa no.

| Verifica | Esito | Livello / limite |
|---|---|---|
| PR #118 | Unita in `main` (merge commit `783f2bb`) dall'owner alle 10:20:08Z, 11 s dopo l'apertura; stesso schema per #116 e #117 | verificato via API |
| Check su `783f2bb` | 16/16 `success`: `ruff · format · mypy`, `pytest` 3.11/3.12/3.13/3.14, `first-party branch coverage`, `security-boundary mutation`, `POSIX sandbox`, `CLI smoke` macOS e Windows, `wheel · clean-install`, `native THEMIS container`, `pip-audit`, `gitleaks`, `CodeQL`, `scanner-image` | verificato in CI; i check sono partiti **dopo** il merge (10:20:11Z) |
| `scanner-image` | `build · engine smoke test` verde su `main` (run 11) e sul branch (run 9: build 7 min 35 s, smoke 9 s); aveva fallito 8 volte prima dei fix, ognuna per un problema reale | verificato in CI: l'immagine builda e ogni engine distribuito risponde al probe e al commit pinnato. **Non** dimostra scansioni reali nel container |
| Pilota nuclei | Adapter, argv da allow-list, `partial` (`olympus.themis-result` 1.3.0 additivo), evidenza firmata, SBOM con template, `engines doctor`, dati pinnati, test offline su output reale: implementati e verificati in CI. Test `live_lab` (3) e scansione con 14.104 template eseguiti **una volta, in locale, dall'autore** su loopback | validato in lab solo in senso debole: nessuna evidenza committata in `docs/themis-execution-evidence.md`, `live_lab` non gira in CI. Misure in `docs/themis-sandbox.md` e `docs/engines/INVENTORY.md` |
| Manifest e adapter | 24 `engine.toml`, 3 `mandatory`, 0/24 `upstream_verified`, 1/24 adapter `reviewed` (nuclei), 0 manifest con `required_for_commands`; hint `install` degli adapter derivati dal pin del manifest (nessun `@latest`, nessun pacchetto errato) | verificato offline (test di coerenza, di drift e `test_engine_install_hints`) |
| Preflight | Assente. `ExitCode.ENGINE_MISSING` (8) è prodotto solo da `engines doctor`; nessun comando che esegue scansioni lo controlla; `--allow-missing-engines` non esiste | verificato per ispezione del codice |
| Evidenze firmate | Solo `themis run --evidence`. Nessuna evidenza per job persistenti, worker, API `/jobs`, Web, Athena. Minerva ha un proprio ledger di custodia (sistema distinto) | verificato per ispezione del codice |
| Protezioni di `main` | Nessun ruleset applicabile (`rulesets=[]`, `rules/branches/main=[]`). Protezione classica **non verificabile** (HTTP 403: l'integrazione non ha il permesso). Check obbligatori: **non determinabili**. Repo: auto-merge off; merge, squash e rebase consentiti; `delete_branch_on_merge` off | verificato dove indicato; non si concludono né presenza né assenza della protezione classica. Nessun controllo GitHub è stato modificato |
| Non verificabile | Permessi e ambienti Actions (negati dal proxy), deploy Vercel (HTTP 403, già in §19), ogni validazione in lab non committata | dichiarato, nessuna conclusione |

Differenze rilevate tra roadmap, implementazione e CI: il conteggio test (~2663) e «CI 14
job» erano obsoleti (ora ~3110 test; 16 check includendo `scanner-image`, il cui workflow
`docker-build.yml` non era censito in `CICD-1`); `TOOLS-4` elencava come «da fare» il pilota
nuclei ed `engines doctor` (esistono, nei limiti sopra); `SEC-4` presentava la protezione del
branch come sola azione owner, senza distinguere workflow presente / eseguito / obbligatorio
(ora `SEC-4.1–4.4`). Le voci `WEB-5`/`WEB-6` restano `[ ]`: esistono pagine di anteprima
(`/assessments/new`, `/assessments/smart`) ma non l'esecuzione guidata end-to-end.

## 3. Architettura di riferimento

**Scelta del team:** *monolite modulare* Python come nucleo di dominio (core +
moduli), con **control plane** tipizzato (`themis.api`, FastAPI) e interfacce
multiple sullo stesso core (CLI/TUI/Web). Per l'operatività Web reale si adotta
un modello **split**: UI su hosting statico/edge (Vercel), **Execution backend**
(API + worker + scanner) su host con processi persistenti e disco. Nessuna logica
di sicurezza nel frontend.

- **ARCH-1** [x] Core di dominio I/O-free con contratti versionati.
- **ARCH-2** [~] Confini `domain → application → ports → adapters` formalizzati per tutti i moduli.
- **ARCH-3** [ ] Execution Engine esplicito e documentato (job, worker, code, cancellazione) come servizio separabile.
- **ARCH-4** [ ] Contratto UI↔API stabile e versionato per tutti i tool.

## 4. Strategia di evoluzione tecnologica

- **TECH-1** [x] Backend Python 3.11+ (Pydantic v2, Typer, FastAPI, Textual) confermato: adeguato e maturo.
- **TECH-2** [ ] Frontend Web: valutare e selezionare uno stack moderno (SSR/SPA) integrato realmente all'API; decisione del team su basi tecniche (oggi la Web UI è Jinja2+SSE, adeguata ma limitata).
- **TECH-3** [ ] Persistenza: SQLite come default locale; astrazione verso Postgres per deployment multiutente/concorrente.
- **TECH-4** [ ] Coda/worker: valutare un broker esplicito per job long-running fuori Vercel.

## 5. Piano moduli Red / Blue / Purple

- **RED-1** [~] Recon attiva ProjectDiscovery/OSINT: adapter `subfinder`, `dnsx`, `naabu`, `amass`, `theHarvester`.
- **RED-2** [~] Adapter web residui. **`wpscan` fatto** (adapter nativo + parser
  JSON `--format json` → `core.Finding`, token API solo da secret d'ambiente,
  registrato, maturity `adapter-ready`, provato offline su report sintetico
  format-fedele): la capability CMS passa da *missing* a *simulated* in
  `olympus catalog`. **Resta:** `nosqlmap`; promozione di `wpscan`/Wapiti a
  *live-tested* in lab WordPress/NoSQL autorizzato (output reale registrato).
- **RED-3** [ ] Password auditor (capacità assente oggi): nuovo tool/adapter, scope-gated.
- **BLUE-1** [~] Apollo ingest Sysmon/Windows Event. Parser `windows-json`
  implementato (Sysmon 1/3/11/13/22 + Security 4624/4625, gating per provider,
  *skip-never-guess*), allineato alla tassonomia delle regole (`windows.sysmon`/
  `windows.security` + `event_id`, `process_name` derivato), provato **offline**
  su fixture format-fedele (`tests/fixtures/apollo/ingest/windows.jsonl`). CLI
  `apollo ingest --format windows-json`; regole di detection reali in
  `examples/input/apollo-sysmon` (C2 DNS, persistenza Run-key, logon privilegiato
  fallito) guidate end-to-end dall'ingest. **Resta:** validazione contro
  telemetria Windows **reale** in lab autorizzato (promozione a live-tested).
  Zeek e access-log già fatti.
- **BLUE-2** [~] Connettori SIEM/EDR (Splunk HEC, Elastic, Sentinel) via porte iniettate, test offline. **Formatter offline fatti:** export alert in ECS (`--ecs`), OCSF (`--ocsf`), **Splunk HEC** (`--hec`, envelope HEC con documento ECS nel payload `event`) ed **Elasticsearch `_bulk`** (`--elastic-bulk` + `--elastic-index`, nuovo: `alerts_to_elastic_bulk`, action `create` per-alert_id + documento ECS, pronto per l'API `_bulk` senza log shipper) e **Azure Monitor / Microsoft Sentinel** (`--sentinel`, array JSON per Logs Ingestion API; richiede DCR e tabella custom coerenti), su `apollo test`/`apollo run`, file owner-only `0o600`, puri e deterministici (nessuna rete). **Dispatch offline implementato:** `apollo.dispatch.deliver_alerts` via `SiemTransport` iniettato, policy con autorizzazione e approval reference, gate di scope sul destination URL, token `OLYMPUS_SIEM_*`, URL HTTPS e dimensioni bounded, controlli dei successi applicativi HEC/Elastic; test solo con fake transport, nessun adapter HTTP fornito. **Resta:** adapter HTTPS di produzione con egress/scope enforcement verificabile, gestione dei redirect vietati e validazione in lab autorizzato prima di qualsiasi enablement live.
- **BLUE-3** [ ] CTI live in Metis (TAXII 2.1, MISP, OpenCTI) con provenance/caching/isolamento.
- **PURPLE-1** [ ] `athena purple`: attacco simulato scope-safe → ingest Apollo → valutazione detection → report gap. È il veicolo delle simulazioni di `VAL-2` e della misura di copertura di `VAL-3` (§21.4): si estende questa voce, non si crea un motore parallelo.
- **PURPLE-2** [ ] Profilo lab ripetibile (`labs/mars`) con seed/versioni/output atteso. È anche il bersaglio autorizzato per il livello L3 di `TOOLS-4.2` e per le promozioni di `QA-3`.

## 6. Inventario dei tool e capacità

Fonte unica e onesta: **`olympus catalog`** (stato derivato dal codice). Sintesi
capability-prodotto: *present* website scanner, SSL scanner, port scanner,
subdomain finder, domain finder; *missing* network-vuln scanner, CMS scanner,
password auditor. La maturità per-engine è in
[`scanner-maturity.md`](docs/scanner-maturity.md).

- **TOOLS-1** [x] Catalogo capability allineato e verificabile.
- **TOOLS-2** [ ] Colmare le capability *missing* con adapter/moduli reali (vedi RED/BLUE).
- **TOOLS-3** [ ] Promuovere adapter a *live-tested* in lab autorizzato (con evidenze committate).
- **TOOLS-4** [~] (P0/P1) Governance supply-chain degli engine esterni: `engine.toml` per engine (pin esatto, commit/checksum/digest, `mandatory`/`required_for_commands`), preflight fail-closed con `ExitCode.ENGINE_MISSING` (8), `olympus engines list|doctor|check-updates|update`, SBOM ed evidence manifest per run, immagine scanner riproducibile e verificata da `engines doctor`. Dettaglio e stato per-engine in `docs/engines/INVENTORY.md`.
  - **Stato (2026-11-03, `main` @ `783f2bb`).** *Implementato e verificato in CI:* schema `engine.toml` + 24 manifest (3 `mandatory`: nmap, nuclei, httpx; 5 engine API/commerciali solo manifest), dipendenza dati `_data/nuclei-templates.toml`, `ExitCode.ENGINE_MISSING`=8 (prodotto **solo** da `engines doctor`), `probe()`/`recognises()`/`coverage_loss()`/`failure_hint()` in `ScannerAdapter`, `partial` in `olympus.themis-result` 1.3.0 (additivo: i risultati non parziali restano 1.2.0), `engines list|doctor`, argv da allow-list del manifest (solo nuclei), evidenza firmata `olympus.engine-run-evidence` 1.0.0 (solo `themis run --evidence`), `core sbom --engines`, Dockerfile fail-closed e job `scanner-image`. *Validato in lab:* nulla di committato (il pilota nuclei è stato eseguito una volta in locale, v. §2). *Non esistono:* invocazione **automatica** del preflight nei percorsi di esecuzione (il servizio condiviso `olympus.engines.preflight` e il comando `engines preflight` esistono — v. *Fatto* — ma run/preview/API/Web/worker non li chiamano ancora), uso effettivo di `required_for_commands` (0 manifest), `--allow-missing-engines`, `check-updates`/`update`, `upstream_verified` (0/24), `reviewed` (1/24), `doctor --strict` nel Dockerfile, evidenze nei percorsi job/API/Web/worker, scansioni reali nel container, osv-scanner per gli engine, adapter per nosqlmap/subfinder/theharvester (→ `RED-1`/`RED-2`). **Fatto (2026-11-03):** `docs/engines/UPDATES.md` (procedura di aggiornamento **manuale** e criterio di policy patch/minor/major; l'automazione `check-updates`/`update` resta pianificata); le stringhe `install` degli adapter **e del catalogo** `integrations.scanners` sono ora derivate dal pin del manifest (`ScannerAdapter.install` e `ScannerSpec.install` → `engines.loader.install_hint`), eliminando i riferimenti `@latest` (dalfox/httpx/katana/nuclei) e i suggerimenti al pacchetto PyPI errato per `commix`/`theHarvester`; guardia di regressione `tests/unit/test_engine_install_hints.py`.
  - **TOOLS-4.1** [~] (P0) Preflight fail-closed condiviso (CLI, API, Web, worker, step Athena).
    - *Stato (2026-11-03):* consegnato il **nucleo** della decisione (`DEC-2`: servizio puro condiviso `olympus.engines.preflight`, I/O iniettato, offline) e il comando operatore/CI `olympus engines preflight` (richiede mandatory + `--engine` nominati; exit 8 con install pinnato, 0 se pronto; api non bloccano mai; fail-closed senza avviare processi). Coperto da `tests/unit/test_engine_preflight.py`. **Primo cablaggio (2026-11-04):** `themis preview` riporta la prontezza dell'engine (solo PATH, nessuna esecuzione) in output umano e JSON e offre il flag opt-in `--require-engine` → exit 8 se l'engine governato manca (`tests/unit/test_themis_preview_cli.py`). **Restano:** invocazione automatica in run/API/Web/worker con `ENGINE_MISSING` come stato job e risposta HTTP, mappa `required_for_commands` + `--allow-missing-engines` per le opzionali, e la parità cross-interfaccia + verifica CI/lab dell'accettazione sotto.
    - *Requisiti:* un unico servizio applicativo, invocato **prima di qualsiasi attività di rete sul target** (risoluzione DNS inclusa), da tutte le interfacce che avviano scansioni; mappa esplicita comando/funzionalità → engine tramite `required_for_commands` (identificatori da definire con test che fallisce se un comando referenziato non esiste); l'engine nominato esplicitamente è sempre richiesto e i `mandatory` sono sempre controllati; distinzione obbligatori/opzionali; stati di rifiuto distinti per `missing`, `unusable`, `wrong-tool`, `version-mismatch`, `commit-mismatch`, `data-problem` e per versioni non verificate (`version_check=unknown`) con politica dichiarata per ciascuno; `ENGINE_MISSING` (8) con audit record (engine mancanti, comando di installazione derivato dal manifest, nessun dato sensibile); `--allow-missing-engines` **limitato alle dipendenze opzionali**, con conferma interattiva in TUI, audit con motivazione, run marcato `degraded=true` ed esito parziale (exit 5), mai per un `mandatory` (decisione 2026-11-03: restringe l'ipotesi iniziale che ammetteva l'override anche sui mandatory); funzionalità non disponibili e copertura parziale rappresentate fedelmente nei risultati; **un assessment eseguito senza una dipendenza obbligatoria non può essere classificato completo né pulito**; sostituzione delle stringhe `install` degli adapter con il testo del manifest.
    - *Dipende da:* `TOOLS-4` (manifest), `TOOLS-4.4` (stati), `API-3` (worker), decisione `DEC-2`.
    - *Accettazione:* per ogni interfaccia, test con resolver/transport iniettati che **falliscono se invocati** dimostrano zero traffico quando un engine obbligatorio manca, è l'engine sbagliato (httpx omonimo), ha versione o commit diversi dal pin o ha i template al commit sbagliato; audit record verificato; exit/HTTP/stato job coerenti tra interfacce (test di parità); `--allow-missing-engines` rifiutato per i mandatory e, per gli opzionali, produce `degraded=true` + exit 5; test di contratto sul vocabolario di exit 0–8; CI verde sullo SHA; verifica in lab su un'immagine privata di un engine obbligatorio.
  - **TOOLS-4.2** [~] (P1) Diagnostica rigorosa: `olympus engines doctor --strict`.
    - *Stato:* `engines list|doctor` verificati in CI e su binari reali locali (nuclei, httpx, nmap): presenza, probe nel runner sandbox, engine omonimo, versione/commit, dati pinnati, nota sul limite memoria del sandbox, exit 8. `--strict` esiste ma non è nel Dockerfile né in CI.
    - *Da fare:* integrità dei manifest (validazione + coerenza con registry, inventario, Dockerfile); prerequisiti runtime (es. `ps`/`hexdump` per testssl, `XML::Writer` per nikto, HOME e directory di lavoro scrivibili, permessi); template e dati; compatibilità dell'ambiente (OS, architettura, runtime Python/Go/Ruby/Perl); variabili d'ambiente indispensabili (solo nomi, mai valori); capacità del sandbox di soddisfare i requisiti dichiarati (memoria, processi, file, timeout: `TOOLS-4.3`); corrispondenza tra engine distribuiti e inventario (`in_scanner_image`); output strutturato con schema versionato, utilizzabile nei controlli CI/CD. **Tre livelli riportati separatamente per engine:** *L1 presenza* (binario, versione, commit), *L2 avvio* (probe eseguito nell'utente e nell'ambiente del runtime reale), *L3 scansione autorizzata reale* (run end-to-end su bersaglio di laboratorio in scope con evidenza firmata). L3 non si deduce mai da L1/L2 e il livello raggiunto da ciascun engine è dichiarato in `INVENTORY.md`. Inserimento come ultimo passo del Dockerfile e come step CI dopo lo smoke test; decisione su assorbimento o coesistenza di `scripts/smoke_scanner_image.py` (`DEC-11`).
    - *Dipende da:* `TOOLS-4.1` (controlli condivisi), `TOOLS-4.3`, `PURPLE-2`/`QA-3` (bersaglio L3).
    - *Accettazione:* `doctor --strict` fallisce con exit 8 su immagini a cui manca o è alterato un engine (test negativi: binario rimosso, commit diverso, `ps` assente, template al commit sbagliato, limite memoria insufficiente); JSON validato da schema; build dell'immagine fallisce se `doctor --strict` fallisce; L1/L2 verdi per tutti gli engine distribuiti in CI; L3 eseguito e documentato (evidenza committata) almeno per i 3 mandatory.
  - **TOOLS-4.3** [ ] (P1) Risorse, timeout e profili per engine.
    - *Stato:* misure del pilota nuclei v3.11.1 con 14.104 template (Linux x86_64, 4 vCPU, 15 GB RAM, sandbox come utente `nobody`, loopback, 2026-11-03): `RLIMIT_AS` 2 GiB → out of memory in ~5 s (exit 2, riportato `failed`); 4 GiB e 8 GiB → completa (live, non parziale, ~415–422 s sandboxed; 365 s senza sandbox; ~36 s di CPU; ~0,9 GB residenti). **Sono misure di un solo ambiente, non garanzie universali.** `min_memory_bytes`/`timeout_seconds` sono dichiarati e `reviewed` solo per nuclei; `themis run` usa il timeout del manifest solo per gli engine rivisti; job, API, Web, worker e Athena usano i default propri; i valori degli altri 23 manifest sono stime.
    - *Requisiti:* distinguere memoria virtuale (`RLIMIT_AS`), memoria fisica effettiva (RSS/cgroup) e limiti del container, misurando e documentando tutte e tre; profili di risorse configurabili per engine e per profilo operativo (es. set di template completo vs ridotto); **il manifest esprime una richiesta/minimo, la policy di sicurezza il massimo**: un valore del manifest non può mai superare i tetti di `SEC-1`/execution policy e il sandbox non si alza automaticamente (richiesta > tetto → rifiuto fail-closed con messaggio che nomina l'impostazione); valori marcati `measured` vs `estimated` con metadati dell'ambiente di misura (OS, architettura, CPU, RAM, versioni di engine e dati, data, metodo) e rimisurazione quando cambiano pin o ambiente; preflight delle risorse prima dell'esecuzione (estensione di `TOOLS-4.1`); timeout per engine e profilo; propagazione coerente a CLI, API e worker; terminazione sicura (process group, file temporanei, zombie) e cleanup; test di comportamento con risorse insufficienti (limite memoria basso, timeout breve, output oltre il limite, disco pieno) con stato e exit corretti (`failed`/`partial`, mai pulito).
    - *Dipende da:* `SEC-1` (tetti), `TOOLS-4.1`, `TOOLS-4.2`, `API-3`, decisione `DEC-4`.
    - *Accettazione:* tabella dei profili in docs con colonna `measured/estimated` e ambiente; test che dimostrano che un manifest non supera i tetti; test negativi di risorse insufficienti su CLI, API e worker con esiti equivalenti; nessun processo orfano dopo timeout/cancellazione (test POSIX); rimisurazione riproducibile con script versionato.
  - **TOOLS-4.4** [ ] (P0) Gestione rigorosa degli output e stati canonici.
    - *Stato:* il parser nuclei salta i record JSON malformati e rende il run `partial` (exit 5); **chiuso il gap sulle righe non-JSON su stdout**: `nuclei` gira con `-jsonl -silent`, quindi stdout trasporta solo record JSONL — ogni riga non vuota che non inizia con `{` è ora conteggiata come record scartato (non più ignorata come rumore), così un errore o un diagnostico stampato lì rende il run `partial` (exit 5) e non può mai leggersi come esito pulito; i diagnostici legittimi restano su stderr. Regressione coperta da `test_an_error_line_on_stdout_makes_the_run_partial_not_clean`. **Adapter nmap migrato** (2026-11-05): un XML valido ma non-`<nmaprun>` → `failed`; `<runstats><finished exit="error">` (nmap esce 0 ma dichiara il fallimento) → `failed` con l'`errormsg` di nmap; scansione senza trailer di successo, host `state!=up` o nessun host restituito → `partial` via `coverage_loss`, così «zero porte aperte» non si legge mai come target pulito quando la scansione non è stata completa/raggiunta. Regressioni in `tests/unit/test_nmap_output_grammar.py`. **Adapter httpx migrato** (2026-11-06): httpx gira con `-json -silent -no-color` (solo JSONL su stdout) — ogni riga non-JSON su stdout e ogni record JSONL non-probe (senza `url`) sono ora conteggiati come record scartati (`_skipped_records`) → `partial` via `coverage_loss`, mentre un output senza alcun probe resta `failed` (collisione col binario Python, `_WRONG_TOOL`) e un probe `failed:true` resta un esito legittimo (host non raggiungibile), non uno scarto. Regressioni in `tests/unit/test_themis_adapters_projectdiscovery.py`. **Adapter non-mandatory, batch 1 — katana e dalfox migrati** (2026-11-06): katana (JSONL crawler) conta come record scartati le righe non-JSON su stdout e i record senza `endpoint` → `partial`, mantenendo `failed` per output senza alcun crawl record; dalfox (array JSON) preserva il padding `[{}]` come esito pulito (mai scarto) e conta come scartato ogni altro elemento dell'array privo di `payload` o non-oggetto → `partial`, mantenendo `failed` per output senza array JSON. **Adapter non-mandatory, batch 2 — wapiti, wafw00f, testssl migrati** (2026-11-06): wapiti (report JSON) conta come scartati le categorie il cui valore non è una lista e i finding non-oggetto → `partial`; wafw00f (array JSON) rende `failed` un root non-array e conta come scartati gli elementi non-oggetto, mantenendo `detected:false` come esito legittimo; testssl (array JSON) rende `failed` un root non-array, ignora come rumore atteso le righe informative (`OK`/`INFO`/`DEBUG`) e conta come scartate le righe di errore/sconosciute (es. `FATAL`) → `partial`. Regressioni in `tests/unit/test_themis_output_grammar.py`. **Adapter whatweb migrato** (2026-11-06): il parser leggeva solo la prima riga di fingerprint con `[`, scartando in silenzio le successive — su un redirect (`301`→`200`) il fingerprint della pagina finale andava perso e un target che divulga tecnologie poteva leggersi come «nessuna tecnologia»; ora analizza tutte le righe fingerprint con de-duplicazione delle divulgazioni identiche (mantiene `failed` l'output senza alcuna riga). Regressioni in `tests/unit/test_themis_execution.py`. **Adapter a exit-code, batch 1 — sqlmap e nikto migrati** (2026-11-06): sqlmap distingue il `[CRITICAL]` di connessione/accesso (target mai testato → `failed` se nessun finding, `partial` se con finding) dal `[CRITICAL]` legittimo «all tested parameters do not appear to be injectable» (resta esito pulito, nessun falso fallimento); nikto rende `partial` un run il cui summary riporta `N error(s)` con N>0 o che è stato interrotto (`Scan terminated`, es. `-maxtime`), così «zero finding» non si legge come pulito quando la scansione non è stata completa. Regressioni in `tests/unit/test_themis_execution.py`. **Adapter wpscan migrato** (2026-11-06): WPScan emette un JSON valido con il solo `scan_aborted` (e il banner) quando non ha potuto valutare il sito (target non WordPress, bloccato, rate-limited, errore) — senza contenitori di vulnerabilità, quindi si leggeva come «nessuna vulnerabilità WordPress» su un sito mai valutato; ora `scan_aborted` → `failed` (ParseError) con il motivo di WPScan, mentre un report normale resta invariato. Regressioni in `tests/unit/test_wpscan_adapter.py`. **Adapter commix migrato** (2026-11-06): commix (derivato da sqlmap) logga a `[critical]` sia l'esito pulito «All tested parameters do not appear to be injectable» sia gli errori di connessione/accesso; applicato lo stesso schema dell'adapter sqlmap — un `[critical]` di connessione (`unable to connect`, `connection timed out`, …) significa target mai testato → `failed` se nessun finding, `partial` se con finding, mentre il `[critical]` «not injectable» resta un esito pulito (nessun falso fallimento). Regressioni in `tests/unit/test_themis_adapters_dirsearch_commix.py`. **Migrati: 3/3 mandatory (nmap, nuclei, httpx) + 10 non-mandatory (katana, dalfox, wapiti, wafw00f, testssl, whatweb, sqlmap, nikto, wpscan, commix)**. Non migrati, per **scelta tecnica motivata**: `dirsearch` ha già il guard fail-closed (`output ma nessuna riga di risultato → failed`); `arjun` e `xsstrike` hanno l'esito vuoto come risultato legittimo e **nessun marcatore d'errore release-stable su stdout** (arjun scrive il JSON su file e stampa solo le righe di rilevamento; xsstrike non ha output machine-readable), quindi aggiungere euristiche d'errore introdurrebbe falsi fallimenti — violando «né un output innocuo diventi un falso fallimento». Resteranno così finché non esista un segnale verificabile (es. output catturato reale o un formato di report stabile); `INT-1` (contract test e fuzzing dei parser) è fatta.
    - *Requisiti:* per ogni adapter una grammatica dichiarata e verificabile che distingue messaggi informativi, diagnostici, errori e record di risultato su stdout/stderr; riconoscimento di record malformati o incompleti con conteggio degli scarti; gestione esplicita dell'output troncato (limite di byte o terminazione); registrazione di exit code e record scartati; conservazione sicura delle evidenze diagnostiche e redazione dei segreti nei log; normalizzazione verso gli stati canonici **già esistenti** (`RunStatus`, `ExecutionState`, `OutcomeKind`, `JobState`, `docs/run-status.md`) con una tabella unica di corrispondenza, senza nuovo vocabolario; classificazione per **regole verificabili** (rumore noto → ignora; errore noto → `failed`; non riconosciuto → `partial` con conteggio, soglie documentate) in modo che né un errore sconosciuto diventi un esito pulito né un output innocuo diventi un falso fallimento; fail-closed quando la completezza non è garantibile; test di compatibilità dei contratti (`themis-result` 1.2.0/1.3.0, risultato dei job, Vulcan).
    - *Dipende da:* `INT-1`; ordine di adozione: nmap, nuclei, httpx (mandatory) poi gli altri per maturità.
    - *Accettazione:* corpus di fixture reali per engine con classi «rumore noto / errore noto / sconosciuto» e risultati attesi; fuzzing sul classificatore; nessuna regressione sui contratti golden; per ogni adapter migrato un test dimostra che un output sconosciuto non produce mai `clean`.
  - **TOOLS-4.5** [~] (P0) Evidenze firmate e coerenza tra percorsi di esecuzione.
    - *Stato:* `themis run --evidence` produce `olympus.engine-run-evidence` 1.0.0 firmato Ed25519 (`core.signing`; chiave indicata da variabile d'ambiente come percorso; nessuna evidenza non firmata; digest di stdout/stderr, comando redatto, hash di manifest e dati, hash dello scope), legato all'audit tramite l'`execution_id`. Verificato in CI e sul percorso locale del pilota. **Non** coperti: `themis jobs`/worker, API, Web, Athena.
    - *Requisiti:* un unico servizio di evidenza condiviso da CLI, API, Web, job persistenti, worker e attività asincrone, che riusa `core.signing` e converge con la custodia Minerva (precedente: `INT-3`) senza implementazioni parallele; ogni esecuzione collegabile in modo verificabile a identificativo univoco, engagement e autorizzazione, target e scope, engine e versione (e commit), configurazione e parametri effettivi redatti, timestamp, stato finale, evidenze prodotte, manifest e digest, limitazioni e risultati parziali; verifica crittografica con chiave pubblica pinnata; gestione sicura delle chiavi (rotazione, revoca, storage, nessuna chiave nel repository o nei log); compatibilità e versionamento dei contratti; idempotenza (un retry non duplica né sovrascrive); protezione dall'alterazione (collegamento con il log di audit: un run con audit e senza evidenza è un segnale esplicito); decisione sull'evidenza dei run rifiutati (`DEC-3`).
    - *Dipende da:* `TOOLS-4.4`, `DATA-3`, `API-3`, decisione `DEC-3`.
    - *Accettazione:* test di parità: lo stesso run da CLI, API, Web e worker produce evidenze con gli stessi campi, tutte verificabili da un unico verificatore; test di alterazione (campo, firma, chiave diversa) e di idempotenza; prova che un segreto passato come parametro non compare nell'evidenza né nei log; verifica in lab di una catena run → audit → evidenza → report (Vulcan).
  - **TOOLS-4.6** [~] (P1) Supply chain e distribuzione.
    - *Stato:* pin esatti nei 24 manifest, Dockerfile senza `|| true` e senza engine via apt, `core sbom --engines` (engine e template, con `bom-ref` univoci), `pip-audit` sulla chiusura Python di Olympus, `docker/NOTICE`, `redistributable="conditional"` per nmap e nikto. `upstream_verified`=false ovunque (i 21 repo GitHub rispondevano a `git ls-remote` il 2026-11-03, ma non è verifica formale).
    - *Da fare:* `engines check-updates` (risoluzione URL e tag compatibili col pin, `upstream_verified` come esito) ed `engines update <nome> --to <tag>` (manifest + lock + test + diff di audit), con rollback documentato in `docs/engines/UPDATES.md` (creato il 2026-11-03 con la procedura manuale e il rollback; da estendere ai comandi automatici quando esisteranno); eliminazione degli installatori non deterministici (`@latest` negli adapter, `pip install commix`); verifica delle dipendenze transitive di pip/gem/Go per engine (ambienti con hash o lock); SBOM completo (transitive degli engine, SBOM dell'immagine accanto a quello applicativo) pubblicato come artefatto CI; scansione di vulnerabilità di engine, template e immagine (oggi coperta solo la chiusura Python); aggiornamenti controllati con criterio di policy patch/minor/major; provenienza degli artefatti e riproducibilità della build (digest di base, attestazioni → `SEC-4.5`); revisione delle condizioni di ridistribuzione (NPSL di nmap, database non GPL di nikto, AGPL-3.0 di arjun, GPL): **un componente non è redistribuibile solo perché installabile o usabile localmente**.
    - *Dipende da:* `SEC-4.1–4.4`, `TOOLS-4.2`, decisione `DEC-5`.
    - *Accettazione:* `check-updates` segnala un URL errato come fallimento esplicito; un `update` di prova produce un diff riproducibile (manifest + lock + test) e un rollback provato; nessun `latest`/`main`/`master` o tag mobile in manifest, Dockerfile, adapter (test); scansione vulnerabilità bloccante con registro di waiver documentato; due build indipendenti dello stesso commit producono lo stesso insieme di digest dei componenti (o differenze spiegate); parere sulle licenze registrato prima di qualunque pubblicazione dell'immagine.
- **TOOLS-5** [ ] Debito tecnico dell'immagine scanner e degli engine (TOOLS-4):
  - **Chiuso il blocker "immagine mai buildata"**: il job CI `scanner-image` (`.github/workflows/docker-build.yml`) ha il primo run verde (run 9, commit `11e246c`: build 7 min 35 s + `scripts/smoke_scanner_image.py`, che verifica probe e commit di ogni engine distribuito). Prima di arrivarci ha trovato sei problemi reali (vedi `docs/engines/INVENTORY.md`). Resta non provato: scansioni vere dentro il container e `engines doctor --strict` come ultimo passo del Dockerfile.
  - **Debito legale**: nmap è sotto Nmap Public Source License 0.95 (non OSI) e nikto ha codice GPL con database non GPL; `redistributable = "conditional"` nel registry e `docker/NOTICE` nell'immagine, ma la decisione di pubblicare l'immagine spetta a chi la pubblica. Valutare anche l'AGPL-3.0 di arjun.
  - **Toolchain Go**: `GOTOOLCHAIN=go1.26.10` richiede un `golang-go` di bootstrap >= 1.21 (il guard del Dockerfile lo verifica); la base `python:3.11-slim@sha256:9534e5a8...` è Debian trixie (dedotto dal log CI: `ruby 1:3.3+b1`), quindi `golang-go` 1.24 e Ruby 3.3 bastano.
  - Base Python 3.12 (theHarvester 4.x e wapiti3 3.3.x, ora fermo a 3.2.3); build verificata di nikto 2.6.1 (richiede `XML::Writer`) e NoSQLMap; ambienti con hash per engine per le dipendenze transitive di pip/gem; `engines doctor --strict` come ultimo step del Dockerfile.
  - **Valori stimati**: `timeout_seconds` e `resource_profile` di ogni adapter sono stime (`reviewed = false` nei manifest) fino alla revisione con evidenza, a partire dal pilota nuclei.

  - **Collegamenti (revisione 2026-11-03, nessun duplicato):** `doctor --strict` nel Dockerfile → `TOOLS-4.2`; ambienti con hash e licenze/redistribuzione → `TOOLS-4.6` e `SEC-4.4`; valori stimati dei manifest → `TOOLS-4.3`. Priorità: P1.

## 7. Piano di integrazione dei tool

- **INT-1** [x] Contract test per ogni adapter registrato; fuzzing dei parser; esito fail-closed. La classificazione degli output (rumore/errore/record malformato/troncato) e la tabella unica degli stati canonici sono pianificate in `TOOLS-4.4`.
- **INT-2** [ ] Template SDK plugin stabile e documentato per adapter esterni (entry-point discovery).
- **INT-3** [~] Ogni tool espone un contratto input/output tipizzato riusabile da CLI, API e Web. Precedente concreto: la verifica custody Minerva usa un unico core I/O-free (`inspect_ledger_text`) condiviso da CLI (`minerva verify`), API (`/api/v1/minerva/verify-ledger`) e Web (`/minerva`); restano gli altri moduli. Gli stessi contratti condivisi sostengono correlazione (`CORR-1`) e spiegabilità (`EXPL-1`).

## 8. Web UI completa (obiettivo portante)

Ogni tool deve essere pienamente utilizzabile da Web: configurazione parametri,
avvio, monitoraggio, risultati/progressi, log, errori, evidenze, filtri/ricerca,
export, storico, documentazione. La CLI resta alternativa, non unico accesso.

- **WEB-1** [x] Web control plane nativo sopra l'API tipizzata (submit job, SSE, cancel), con security headers/CSP/CSRF/sessioni.
- **WEB-2** [~] Pagine operative dei tool esistenti (Themis scan, findings, diff, trend, report, engagement).
- **WEB-3** [~] Copertura Web di **tutti** i tool dell'ecosistema (Argus, Apollo, Metis, Minerva, Athena, Artemis…) con pagine dedicate operative. **Vulcan:** associazioni CWE→ATT&CK consultabili in `/findings/attack`, con provenienza, finding non mappati ed export Navigator; riuso del motore offline, accesso `findings:read`. **Apollo:** workbench operativo `/apollo` sul rule pack configurato dal server, input `olympus.event` NDJSON limitato, valutazione offline reale, scope `apollo:read`/`apollo:run`, CSRF e audit; ingest Web di access log HTTP, Zeek JSON e Windows/Sysmon JSON tramite parser esistenti, limite di 500 righe fisiche e scarti visibili, verifica offline con fixture e regole Sysmon incluse. **Minerva:** workbench `/minerva` di verifica della catena di custodia — si incolla un ledger `olympus.custody` e la catena di hash è verificata offline dallo stesso motore della CLI (`inspect_ledger_text`), firma Ed25519 verificata quando il server è configurato con la chiave pubblica; scope `minerva:read`, CSRF, nessun input di chiavi/evidenze dal browser. **Metis:** workbench CTI `/metis` che estrae e normalizza IOC da testo libero, bundle STIX 2.1 ed eventi MISP tramite il motore condiviso offline, con elenco degli elementi scartati e motivazione; scope `metis:read`, CSRF, rate limit e bound su input e item. **Athena:** pianificatore `/athena` che elenca i profili di scansione (target-free) e costruisce un piano firmabile `olympus.athena.plan` dallo stesso core della CLI (`ScanProfile.build_plan`) — profilo + target autorizzato + scope + autorizzazione confermata → piano deterministico e offline (nessuna esecuzione); scope `athena:read`, CSRF, rate limit. **Argus:** workbench `/argus` che estrae i sottodomini in-dominio da un export Certificate Transparency (crt.sh JSON) con lo stesso core offline (`parse_crtsh_response`) — nessuna query CT inviata; scope `argus:read`, CSRF. **Artemis:** workbench `/artemis` che effettua il fingerprint passivo di una risposta HTTP acquisita (status/header/body) contro le signature tecnologiche con lo stesso core offline (`fingerprint_response`) — nessuna richiesta inviata; scope `artemis:read`, CSRF. **Copertura per-tool completa:** ogni tool dell'ecosistema (Vulcan, Apollo, Minerva, Metis, Athena, Argus, Artemis, Themis) ha ora una pagina Web dedicata; le funzionalità operative più profonde proseguono in `WEB-4` (dashboard, **fatto**), `WEB-5` (wizard end-to-end) e `WEB-6` (configurazione guidata).
- **WEB-4** [x] Dashboard principale (`/`): stato sistema (versione piattaforma, versione mappa ATT&CK, stato per-sottosistema configurato/non configurato), job attivi e istogramma stati, avanzamento assessment, findings per severità/sorgente/asset, prontezza scanner, incidenti per stato e **coverage ATT&CK per tattica** (tecniche distinte per tattica dal motore offline). Tutto deriva dalle sorgenti reali già esposte, gated per scope.
- **WEB-5** [ ] (P3) Wizard "New Assessment" end-to-end (engagement → scope → profilo → esecuzione → report) = **modalità guidata**. *Base esistente da censire (non conta come completamento):* `/assessments/new` + `/assessments/preview` e `/assessments/smart` (`olympus.integrations.activity`/`smartscan`) classificano il rischio e propongono una pipeline senza eseguirla; manca l'esecuzione guidata con stato, interpretazione dei risultati e report.
  - *Requisiti:* procedure guidate e progressive; selezione consapevole degli obiettivi; controlli preventivi di autorizzazione e scope (stessi di CLI/API); configurazioni comprensibili con spiegazione dei parametri rilevanti; stato dell'esecuzione in tempo reale; interpretazione dei risultati (con `EXPL-1` quando disponibile); indicazione esplicita di limitazioni, copertura parziale e attività non completate (stati di `TOOLS-4.4`); accesso a evidenze e report.
  - *Dipende da:* `API-3`, `ARCH-4`, `TOOLS-4.1`, `TOOLS-4.4`, `TOOLS-4.5`; decisione frontend `TECH-2`/`DEC-9`.
  - *Accettazione:* un assessment completo avviato dal wizard produce gli stessi audit, evidenze e stati dello stesso assessment avviato da CLI (test di parità); il wizard non consente di superare scope, autorizzazione o limiti di risorse; test E2E in browser reale (`QA-2`); revisione di accessibilità WCAG; documentazione IT/EN.
- **WEB-6** [ ] (P3) Configurazione guidata, feedback operazioni, gestione errori/eccezioni uniforme: un solo modello di errore (stesso di CLI/API: `ValidationReport`, exit code canonici) reso comprensibile in Web, con messaggi azionabili per engine mancante (`TOOLS-4.1`), risorse insufficienti (`TOOLS-4.3`) e risultati parziali.
- **WEB-7** [ ] (P3) **Modalità avanzata** per penetration tester, analyst, Red/Blue Team e operatori esperti, sullo **stesso backend** e con gli **stessi controlli** della modalità guidata.
  - *Requisiti:* configurazione dettagliata degli engine (entro i tetti di policy e l'allow-list del manifest: la modalità avanzata non apre flag arbitrari); gestione avanzata dello scope; controllo dei parametri; orchestrazione di workflow; gestione di job e automazioni (incl. `VAL-1`); monitoraggio dell'esecuzione; accesso a log ed evidenze autorizzate; correlazione e analisi dei risultati (`CORR-2`); export e integrazione con strumenti esterni.
  - *Dipende da:* `API-3`, `ARCH-3`, `ARCH-4`, `TOOLS-4.3`, `TOOLS-4.5`.
  - *Accettazione:* ogni azione avanzata è un'invocazione dello stesso servizio di orchestrazione usato da CLI e modalità guidata (nessuna logica di sicurezza nel frontend); test di autorizzazione per ruolo/scope; stati equivalenti tra modalità; la CLI resta completa e indipendente.
- **WEB-8** [ ] (P3) Esperienza coerente tra moduli: dashboard contestualizzate, visualizzazione delle correlazioni (`CORR-2`) e della spiegabilità (`EXPL-2`), linguaggio visivo e componenti condivisi, densità informativa adeguata a ciascuna modalità. *Accettazione:* revisione UX/UI documentata (accessibilità, comprensibilità, coerenza visiva, densità informativa, gestione degli errori, percorsi d'uso) con prove su percorsi reali; nessuna vista mostra una correlazione ipotetica come fatto dimostrato.
- **Requisiti condivisi delle due modalità.** Identici controlli di autorizzazione; medesimi contratti dati (`ARCH-4`); un unico sistema di orchestrazione (`API-3`); gli stessi meccanismi di audit; gestione coerente delle evidenze (`TOOLS-4.5`); stati di esecuzione equivalenti (`TOOLS-4.4`); regole di sicurezza e limiti di risorse condivisi (`TOOLS-4.3`). La Web UI **non** è un frontend che replica l'invocazione dei comandi CLI: è progettata sui workflow operativi reali, mentre la CLI resta interfaccia completa e indipendente. Le scelte di stack e design system restano al team (`TECH-2`, `DEC-9`).

## 9. Backend, API e orchestrazione

- **API-1** [x] API FastAPI tipizzata (auth per-scope, accountability, `/jobs`, `/capabilities`, health/ready/metrics).
- **API-2** [~] Estendere l'API a **tutti** i tool con contratti versionati (non solo Themis). **Apollo:** `GET /api/v1/apollo/rules` (`olympus.apollo-rule-list` 1.0.0) e `POST /api/v1/apollo/evaluate` (`olympus.apollo-evaluation` 1.0.0), rule pack server-owned e valutazione tipizzata/bounded. **Minerva:** `POST /api/v1/minerva/verify-ledger` (`olympus.minerva-ledger-verification` 1.0.0), verifica della catena di custodia in memoria, firma Ed25519 opzionale (chiave pubblica server-owned), scope `minerva:read`. **Metis:** `POST /api/v1/metis/extract` (`olympus.metis-extraction` 1.0.0), estrazione IOC offline tipizzata/bounded da testo/STIX/MISP condivisa con la Web UI, scope `metis:read`. **Athena:** `GET /api/v1/athena/profiles` (`olympus.athena-profile-list` 1.0.0) e `POST /api/v1/athena/plan` (`olympus.athena-plan` 1.0.0), costruzione offline di un piano firmabile da un profilo con digest piano/scope, scope `athena:read`. **Argus:** `POST /api/v1/argus/ct-subdomains` (`olympus.argus-ct-subdomains` 1.0.0), estrazione offline dei sottodomini in-dominio da un export crt.sh JSON, scope `argus:read`. **Artemis:** `POST /api/v1/artemis/fingerprint` (`olympus.artemis-fingerprint` 1.0.0), fingerprint passivo offline di una risposta HTTP acquisita, scope `artemis:read`. Restano i moduli senza slice API dedicata (Helios/Hermes/Proteus).
- **API-3** [ ] Execution Engine: worker persistente, coda, retry idempotenti, backpressure, checkpoint, cancellazione coerente CLI/TUI/API/Web. Preflight (`TOOLS-4.1`), limiti di risorse (`TOOLS-4.3`) ed evidenze firmate (`TOOLS-4.5`) devono vivere in questo motore, non nelle singole interfacce: è la condizione perché CLI, API, Web e worker abbiano comportamento, audit e stati equivalenti (`WEB-5`/`WEB-7`). Oggi i job persistenti esistono (SQLite, `themis workers`) ma non applicano preflight né evidenza firmata.
- **API-4** [~] CORS/origin policy verso il dominio Web di deploy; autenticazione multiutente. **Fatto:** policy CORS fail-closed sull'API Themis (`ApiSettings.cors_allowed_origins`, flag ripetibile `--cors-allow-origin`): nessun header `Access-Control-Allow-Origin` viene emesso di default, gli origin sono una allowlist esatta `scheme://host[:port]` (niente path/query/fragment/trailing-slash/userinfo), il wildcard `*` è rifiutato in `validate()` e l'origin non è mai riflesso; le credenziali sono ammesse solo contro l'allowlist esplicita, con metodi/header consentiti ristretti. Multiutente già disponibile via identity register scoped/revocabile (`API-1`). **Resta:** rotazione/federazione multiutente avanzata e policy per-origin per-scope.

## 10. Strategia Vercel e infrastrutture alternative

Vercel esegue statico + funzioni serverless effimere: adatto alla **UI** e alle
demo, non all'esecuzione reale (scanner subprocess, worker persistenti, SSE
long-lived, stato durevole). Modello adottato:

- **DEPLOY-1** [x] UI/anteprima statica pubblicabile su Vercel (`public/`, `vercel.json`).
- **DEPLOY-2** [ ] Architettura split: frontend su Vercel ↔ **Execution backend** su host container (Render/Railway/Fly.io/Cloud Run/VPS; `docker/Dockerfile` presente), un'unica Web UI per l'utente.
- **DEPLOY-3** [ ] Funzioni serverless solo come proxy/BFF verso il backend (nessuno scanner su Vercel).
- **DEPLOY-4** [ ] Documentare segreti, endpoint backend, persistenza e sicurezza delle comunicazioni.

## 11. Demo professionale su Vercel

- **DEMO-1** [x] Demo statica/fixture navigabile (panoramica, catalogo tool, pagine, report d'esempio nel formato reale) con banner «DEMO — nessuna esecuzione, dati sintetici».
- **DEMO-2** [~] Ampliare la demo: dashboard, identità visiva completa, flussi rappresentativi, grafici/visualizzazioni, esempi realistici etichettati. **Fatto:** pagina demo `public/dashboard.html` che riproduce la dashboard operativa (stato sistema con versioni reali, findings per severità e copertura ATT&CK per tattica dai motori reali su dati sintetici etichettati; conteggi job illustrativi). **Resta:** identità visiva completa, grafici/visualizzazioni, flussi rappresentativi aggiuntivi.
- **DEMO-3** [ ] Quando possibile, integrare funzioni realmente eseguibili via backend dedicato (split), senza confondere live e demo.

## 12. Database, persistenza ed evidenze

- **DATA-1** [x] SQLite transazionale per job/engagement/finding/audit; export portabile NDJSON/SARIF; backup/restore coordinato.
- **DATA-2** [ ] Astrazione repository/persistenza con **Postgres** opzionale per multiutente/concorrenza.
- **DATA-3** [ ] Retention/privacy di sistema e storicizzazione evidenze con catena di custodia verificabile. Le evidenze di esecuzione degli engine (`TOOLS-4.5`) e la storia dei finding (`VAL-1`, `EXPL-1`) devono rientrare in questa politica di retention.

## 13. Sicurezza e affidabilità del prodotto

- **SEC-1** [x] Scope/authorization gate, execution policy (tetti non alzabili), sandbox processi, redaction, audit firmato. I tetti sono il limite massimo dei profili di risorse di `TOOLS-4.3`.
- **SEC-2** [x] Manifest d'ingaggio firmati (Ed25519), gate di rischio, input non fidato trattato come ostile (anti terminal-injection, escaping export).
- **SEC-3** [~] Egress scanner/DNS vincolato allo scope a livello kernel/container — richiede validazione lab.
- **SEC-4** [ ] (P0) Release signing/SLSA/Cosign e branch protection come gate bloccanti (azione owner su GitHub). **Stato rilevato 2026-11-03:** nessun ruleset applicabile a `main`; protezione classica non verificabile (HTTP 403); #116, #117 e #118 unite entro ~8–11 s dall'apertura con i check ancora in corso (la #118 dall'owner); i 16 check di `783f2bb` sono verdi ma partiti dopo il merge. **Un workflow presente non è un workflow eseguito sul commit giusto né un workflow obbligatorio**: per `main` nessuno dei tre livelli è oggi dimostrato. Scomposta in:
  - **SEC-4.1** [ ] (P0) Ruleset su `main` (o strumento equivalente): pull request obbligatoria; blocco di force-push e cancellazione; politica di approvazione e di merge (`DEC-1`); permessi di bypass minimi, nominati e tracciati; eccezioni documentate con scadenza. *Accettazione:* l'API restituisce le regole attive per `main`; un push diretto è rifiutato; un merge con un check richiesto mancante o rosso è rifiutato (provato su una PR di prova, esito annotato). *Azione owner su GitHub.*
  - **SEC-4.2** [ ] (P0) Check obbligatori vincolati allo SHA corretto: `ruff · format · mypy`, `pytest` (matrice 3.11–3.14), `first-party branch coverage`, `security-boundary mutation`, `POSIX sandbox`, `wheel · clean-install`, `native THEMIS container`, `pip-audit`, `gitleaks`, `CodeQL` e, quando cambiano i percorsi interessati, `scanner-image` (strategia per i check con filtro di percorso, che altrimenti restano non eseguiti: `DEC-1`). Una tabella **presente / eseguito su questo SHA / obbligatorio** per ogni check, mantenuta in docs e verificata da script. *Accettazione:* una PR con SHA obsoleto o con un check non eseguito non è unibile; la tabella è generata e confrontata con i workflow e con le regole attive.
  - **SEC-4.3** [ ] (P0) Verifica post-merge e rollback: lettura dei run su `main` dopo ogni merge (verde sullo stesso SHA), procedura di revert documentata e provata, registro degli SHA noti-buoni, tag e release tracciabili (con `CICD-3`). *Accettazione:* runbook + un revert di prova su branch; segnalazione se un run su `main` fallisce.
  - **SEC-4.4** [ ] (P0) Nessuna pubblicazione di immagini non validate. Oggi nessun workflow pubblica immagini (verificato per ispezione dei workflow); il gate va stabilito **prima** che esista una pubblicazione: build + smoke + `doctor --strict` (`TOOLS-4.2`) verdi sullo stesso digest, riferimento per digest, ambiente protetto con approvazione, revisione di ridistribuzione completata (`TOOLS-4.6`). *Accettazione:* test su un workflow di pubblicazione di prova che rifiuta un digest non validato.
  - **SEC-4.5** [ ] (P2) Release signing, SLSA/Cosign, provenance degli artefatti (contenuto originale di `SEC-4`). Dipende da `SEC-4.1–4.4` e `CICD-3`.
- **SEC-5** [x] SAST CodeQL in CI; dependency-audit + secret-scan.

## 14. Quality Assurance e test

- **QA-1** [x] Suite unit/integration/contract (~2663 test) verde in CI; coverage gate ≥75%; mutation mirato; fuzzing parser.
- **QA-2** [ ] Test end-to-end Web (browser reali), accessibilità WCAG, responsive.
- **QA-3** [ ] Test degli adapter contro output reale in lab autorizzato (promozione live-tested). Requisiti aggiunti dalla revisione 2026-11-03: harness **riproducibile** (bersaglio di laboratorio versionato — `PURPLE-2`/`labs/mars` —, versioni di engine e dati pinnate, esito atteso), esecuzione dei test `live_lab` fuori dalla CI ordinaria ma con procedura documentata, ed **evidenza committata** (firmata, `TOOLS-4.5`) per ogni promozione; i risultati ottenuti solo in locale e senza evidenza non promuovono nulla. Fornisce il livello L3 di `TOOLS-4.2`.
  - **Esecuzione Nuclei su GitHub Actions (PR #142).** Dopo il merge del workflow sul branch predefinito, aprire **Actions → Nuclei live lab → Run workflow** su `main` e selezionare `authorized`. Il runner temporaneo installa Nuclei e il commit dei template dai manifest e il test avvia un bersaglio HTTP sintetico vincolato a `127.0.0.1`. Il percorso è disponibile anche per chi riprende il lavoro senza un laboratorio locale o senza il binario sul proprio PC. Non occorre fornire un target esterno. L'avvio resta esplicito e il job fallisce se i test vengono saltati.
  - **Criterio di chiusura per Nuclei.** Registrare il link al run verde e lo SHA effettivamente testato, con le versioni e l'evidenza firmata prevista da `TOOLS-4.5` prima della promozione a *live-tested*. La disponibilità del workflow non certifica un'esecuzione. Per gli altri adapter e per le integrazioni live restano necessari scenari autorizzati e verifiche dedicate.
- **QA-4** [~] Matrice OS/Python oltre a quella CI; performance/concorrenza sotto carico.

## 15. Documentazione e localizzazione

- **DOCS-1** [x] README IT/EN, docs per modulo, CLI reference generata, disclaimer d'uso.
- **DOCS-2** [ ] Guide Web UI per ogni tool; documentazione API completa; guida deploy split + Vercel.
- **DOCS-3** [ ] Sito doc statico bilingue (Pages/Vercel) dalla stessa fonte `docs/`.

## 16. Packaging, deployment e CI/CD

- **CICD-1** [x] CI 14 job (gate qualità, test multi-versione, coverage, mutation, sandbox, smoke, container, dependency-audit, secret-scan) + CodeQL + `scanner-image` (`docker-build.yml`: build dell'immagine scanner e smoke test degli engine, con filtro di percorso e `concurrency`). Verificato: 16 check verdi su `main` @ `783f2bb`. *Limiti dichiarati:* `live_lab` non gira in CI; l'obbligatorietà dei check non è dimostrata (→ `SEC-4.2`).
- **CICD-2** [x] `docker/Dockerfile` + immagine scanner; wheel/sdist; SBOM CycloneDX. L'SBOM include gli engine e i template (`core sbom --engines`, verificato offline); mancano SBOM dell'immagine, transitive degli engine e pubblicazione come artefatto per l'immagine (→ `TOOLS-4.6`).
- **CICD-3** [ ] Pipeline di release firmata e pubblicazione PyPI via Trusted Publishing; GitHub Action riutilizzabile passiva di default. Da collegare a `SEC-4.3` (tracciabilità e rollback) e `SEC-4.4` (nessuna pubblicazione di immagini non validate).
- **CICD-4** [ ] Deploy backend containerizzato documentato e riproducibile.

## 17. Priorità, milestone e dipendenze

- **M1 — Fondamenta operative Web (P0/P1):** API per tutti i tool (`API-2`), Execution Engine (`API-3`), split deploy (`DEPLOY-2`).
- **M2 — Web UI completa (P1):** `WEB-3/4/5/6` su tutti i tool con pagine operative reali.
- **M3 — Copertura capability (P1/P2):** RED/BLUE/PURPLE, `TOOLS-2`, promozioni live-tested (`QA-3`) in lab.
- **M4 — Demo & distribuzione (P2):** `DEMO-2/3`, `DOCS-3`, `CICD-3/4`, `SEC-4.5`.

Milestone aggiunte dalla revisione 2026-11-03 (sequenza e criteri in §21.8; M0 precede M1 perché
riguarda sicurezza e integrità):

- **M0 — Integrità e gate (P0):** `SEC-4.1–4.4`, `TOOLS-4.1`, `TOOLS-4.4`, `TOOLS-4.5`.
- **M5 — Consolidamento engine (P1):** `TOOLS-4.2`, `TOOLS-4.3`, `TOOLS-4.6`, `TOOLS-5`, `QA-3` (harness riproducibile).
- **M6 — Conoscenza e verifica continua (P2):** `EXPL-1/2`, `CORR-1/2`, `VAL-1/2/3`, `PURPLE-1/2`.
- **M7 — Esperienza d'uso (P3):** `WEB-5/6/7/8`.
- **M8 — Evoluzioni differite (P4):** `FUT-1/2/3`, da rivalutare solo a M0–M6 consolidate.

Dipendenze principali: `WEB-3` dipende da `API-2`; `DEPLOY-2` abilita `DEMO-3` e
l'operatività Web reale; `QA-3`/`TOOLS-3` richiedono lab autorizzato (gate esterno). Dipendenze
aggiunte dalla revisione (grafo completo in §21.6): `TOOLS-4.1` e `TOOLS-4.5` dipendono da
`TOOLS-4.4` e `API-3`; `TOOLS-4.2` dà il controllo che `SEC-4.4` richiede alle immagini;
`CORR-*`, `VAL-*` ed `EXPL-*` dipendono da stati e evidenze affidabili (`TOOLS-4.4/4.5`); `WEB-7/8`
dipendono da `API-3`, `ARCH-4`, `CORR-2` ed `EXPL-2`.

## 18. Criteri oggettivi di completamento

Una voce è `[x]` solo con: criteri funzionali soddisfatti, test automatici verdi
pertinenti, documentazione IT/EN aggiornata, nessun segreto nel diff, commit su
`main` e stato remoto verificato. «Realmente verificato» esclude mock spacciati
per esecuzioni e promozioni senza evidenza.

**Definition of Done per le implementazioni future.** Ogni voce introdotta o estesa dalla revisione
2026-11-03 elenca i criteri di accettazione pertinenti; quando applicabili, includono: implementazione
coerente con l'architettura e riuso di ciò che esiste; assenza di regressioni funzionali; contratti dati
e compatibilità verificati (golden/schema catalog, lettura delle versioni precedenti); controlli di
autorizzazione, scope e audit rispettati; test unitari, di integrazione e di contratto; validazione delle
condizioni di errore; test di sicurezza; verifica reale in laboratorio autorizzato con evidenze
riproducibili; CI/CD superata **sul commit corretto** (SHA riletto da remoto, non dedotto); documentazione
IT/EN aggiornata; tracciabilità delle modifiche; migrazioni e rollback dove servono. I requisiti non
pertinenti a una voce non si applicano. Una voce i cui criteri richiedono validazione operativa **non** è
`[x]` perché il codice è presente o i test offline sono verdi: resta `[~]` finché il livello richiesto
(«validato in lab» / «operativo») non è raggiunto e documentato.

## 19. Debito tecnico e rischi residui

### Incremento export SIEM Elasticsearch _bulk (BLUE-2) — 2026-11-04

- `BLUE-2`: aggiunto il formatter **Elasticsearch `_bulk`** accanto a
  ECS/OCSF/HEC. Nuovo `olympus.apollo.elastic` (`alerts_to_elastic_bulk`): per
  ogni alert una riga azione `{"create": {"_index": …, "_id": alert_id}}` seguita
  dal documento ECS, con newline finale come richiede l'API `_bulk`; l'azione
  `create` per-alert_id rende l'ingest idempotente (un alert ri-inviato è rifiutato
  come duplicato, non sovrascrive). `export_alerts_elastic_bulk` e le opzioni
  `--elastic-bulk`/`--elastic-index` (default `olympus-apollo`) su `apollo test`
  e `apollo run` scrivono file owner-only `0o600`.
- Puro e offline: scrive file, **nessuna chiamata di rete**; la consegna al
  cluster live resta un passo separato gated da scope/autorizzazione (parte
  rimanente di BLUE-2, con dispatch via transport iniettato e formatter Sentinel).
- QA: `tests/unit/test_apollo_elastic.py` (coppia azione/documento, newline finale,
  default/override indice, due righe per alert, `0o600` via CLI). Ruff/mypy verdi;
  `docs/cli-reference.md` rigenerato; `docs/apollo.md` aggiornato.

### Incremento export SIEM Splunk HEC (BLUE-2) — 2026-11-02

- `BLUE-2`: aggiunto il formatter **Splunk HTTP Event Collector** accanto a
  ECS/OCSF. Nuovo `olympus.apollo.hec` (`alert_to_hec`, `alerts_to_hec`): envelope
  HEC (`time` epoch, `host`/`source`/`sourcetype`, `event`) con il documento ECS
  riusato come payload (nessuna mappatura duplicata). `export_alerts_hec` e
  l'opzione `--hec` su `apollo test` e `apollo run` scrivono NDJSON owner-only
  `0o600`, come i formatter ECS/OCSF esistenti.
- Puro e offline: scrive file, **nessuna chiamata di rete**. La consegna a un SIEM
  live resta un passo separato, da implementare con transport iniettato e gating
  scope/autorizzazione (parte rimanente di BLUE-2, insieme a Elastic bulk/Sentinel
  dispatch e validazione in lab autorizzato).
- QA: `tests/unit/test_apollo_hec.py` (mappatura envelope, time=created_at, NDJSON
  una riga per alert, vuoto→vuoto, permessi `0o600` via CLI). Ruff/mypy verdi;
  `docs/cli-reference.md` rigenerato; `docs/apollo.md` aggiornato.

### Incremento demo dashboard (DEMO-2) — 2026-11-02

- `DEMO-2`: nuova pagina statica `public/dashboard.html` (voce nav "Dashboard")
  che riproduce la dashboard operativa WEB-4 nella demo Vercel. Stato sistema con
  le versioni reali (`olympus.__version__`, `ATTACK_MAP_VERSION`); findings per
  severità e copertura ATT&CK per tattica prodotti dai **motori reali**
  (`severity_breakdown`, `tactic_counts`, `associate_all`) su findings sintetici
  etichettati con CWE mappabili; conteggi job esplicitamente illustrativi (la demo
  statica non esegue job). Mantiene la coerenza fra demo e Web UI dopo WEB-4.
- Offline e senza rete; rigenerabile e coperta dal drift gate preview (14 pagine).
- QA: `tests/unit/test_build_preview.py` aggiornato (PAGES, conteggio pagine,
  asserzioni su stato sistema/severità/tattiche); Ruff lint/format verdi.
- Resta `DEMO-2` parziale: identità visiva completa, grafici/visualizzazioni e
  ulteriori flussi rappresentativi.

### Incremento dashboard WEB-4 (stato sistema + coverage ATT&CK per tattica) — 2026-11-02

- `WEB-4`: completata la dashboard principale `/`. Nuova card **System status**
  (versione piattaforma, versione mappa ATT&CK e stato onesto per-sottosistema —
  job store, catalogo/lifecycle/baseline findings, engagements, incidenti, rule
  pack Apollo — in base alla configurazione del server, mai un segreto o un
  target). Nuova sezione **Tactic coverage** nella card ATT&CK: tecniche distinte
  per tattica dal nuovo helper offline `olympus.vulcan.attack.tactic_counts`
  (ogni coppia tecnica/tattica contata una volta). Le altre widget (job, progresso,
  findings per severità/sorgente/asset, prontezza scanner, incidenti) erano già
  presenti.
- Tutto read-only e offline, dalle stesse sorgenti già esposte da CLI/API; nessuna
  nuova scansione, nessun accesso di rete. Le widget restano gated per scope.
- QA: nuovi test unit `tactic_counts` (dedup per tattica, insieme vuoto) e Web
  (card system-status, coverage per tattica); suite web/vulcan-attack verdi.
  `mypy --strict` e Ruff lint/format verdi sui file toccati. Verifiche offline con
  TestClient; nessun controllo o quality gate disabilitato.

### Incremento workbench Argus + Artemis (Web + API) — 2026-11-01

- `WEB-3`/`API-2`: ultimi due tool dell'ecosistema senza pagina Web. **Argus:**
  workbench `/argus` e `POST /api/v1/argus/ct-subdomains`
  (`olympus.argus-ct-subdomains` 1.0.0) — estrazione offline dei sottodomini
  in-dominio da un export Certificate Transparency (crt.sh JSON) con il core
  condiviso `parse_crtsh_response`; nessuna query CT inviata. **Artemis:**
  workbench `/artemis` e `POST /api/v1/artemis/fingerprint`
  (`olympus.artemis-fingerprint` 1.0.0) — fingerprint passivo di una risposta
  HTTP acquisita (status/header/body) contro le signature tecnologiche con il core
  condiviso `fingerprint_response`; nessuna richiesta inviata. Nuovi scope
  `argus:read` e `artemis:read`; CSRF, rate limit e bound su input mantenuti.
- Entrambe le analisi sono pure, deterministiche e senza rete: operano su dati che
  l'utente ha già raccolto, non eseguono né scansioni né query. Demo statiche
  `public/argus.html` e `public/artemis.html` generate dai motori reali su dati
  sintetici (dominio di laboratorio fittizio `acme.lab.invalid`), coperte dal drift
  gate preview.
- **Copertura Web per-tool di `WEB-3` completa:** ogni tool dell'ecosistema ha ora
  una pagina Web dedicata. Proseguono le funzionalità operative trasversali
  (`WEB-4` dashboard, `WEB-5` wizard, `WEB-6` configurazione guidata).
- QA: nuovi test API (estrazione/fingerprint, 422, scope-gating) e Web
  (estrazione/fingerprint, input malformato, scope, CSRF), più asserzioni preview;
  golden OpenAPI e manifest route parity rigenerati. `mypy --strict`, Ruff
  lint/format verdi. Verifiche offline con TestClient; nessun claim di test browser
  reale o di pubblicazione live. Nessun controllo o quality gate disabilitato.

### Incremento pianificatore Athena (Web + API) — 2026-11-01

- `WEB-3`/`API-2`/`INT-3`: pianificatore `/athena` e slice API `GET /api/v1/athena/profiles`
  (`olympus.athena-profile-list` 1.0.0) + `POST /api/v1/athena/plan`
  (`olympus.athena-plan` 1.0.0). Browser, API e CLI (`athena plan from-profile`)
  condividono lo stesso core offline `ScanProfile.build_plan`: il piano prodotto è
  byte-per-byte identico. Nuovo scope `athena:read`; CSRF, rate limit e bound su
  numero di target/domini mantenuti.
- La costruzione del piano è pura, deterministica e senza rete: produce un
  documento `olympus.athena.plan` firmabile (con digest piano e digest scope), non
  esegue alcuna scansione. Un profilo non si auto-autorizza mai: senza conferma
  esplicita dell'autorizzazione la richiesta è rifiutata (422), così come un target
  fuori forma, uno scope vuoto o un formato di report sconosciuto.
- Demo statica `public/athena.html` generata dal motore reale: elenca i profili e
  costruisce un piano d'esempio su un dominio di laboratorio fittizio
  (`app.acme.lab.invalid`, non risolvibile); rigenerabile e coperta dal drift gate.
- QA: nuovi test API (profili, piano, conferma obbligatoria, target malformato,
  scope-gating) e Web (build, conferma, messaggio statico, scope, CSRF), più
  asserzioni preview; golden OpenAPI e manifest route parity rigenerati. Ruff
  lint/format e mypy verdi sui file toccati. Verifiche offline con TestClient;
  nessun claim di test browser reale o di pubblicazione live. Nessun controllo o
  quality gate disabilitato.
- Resta parziale `WEB-3`: Argus e Artemis non hanno ancora pagine Web dedicate.

### Incremento verifica custody Minerva (Web + API) — 2026-11-01

- `WEB-3`/`API-2`/`INT-3`: workbench `/minerva` e `POST /api/v1/minerva/verify-ledger`
  per la verifica della catena di custodia `olympus.custody`. Il motore è stato
  rifattorizzato estraendo un core I/O-free `inspect_ledger_text(text, …)` che
  `inspect_ledger` (file) e le superfici API/Web condividono: la verifica dal
  browser è byte-per-byte quella della CLI. Nuovo scope `minerva:read`; firma
  Ed25519 verificata solo con chiave pubblica server-owned
  (`--minerva-custody-public-key`), altrimenti un ledger firmato è riportato come
  non verificato. Nessun input di chiavi, path o payload di evidenze dal client;
  body limitato a 64 KiB; CSRF e audit esistenti mantenuti.
- Demo statica ampliata con `public/minerva.html`, che verifica il ledger
  d'esempio incluso (`examples/output/minerva-custody.json`) con il motore reale;
  rigenerabile e coperta dal drift gate preview.
- Contratto golden OpenAPI, inventario route native e riferimento CLI rigenerati.
- QA: 11 nuovi test mirati (core/API/Web) verdi; suite Themis web/api/identity,
  custody, contract e preview verdi; Ruff lint/format e mypy sui moduli toccati.
  Verifiche offline con TestClient; nessun claim di test browser reale o di
  pubblicazione live su Vercel. Nessun controllo o quality gate disabilitato.
### Incremento estrazione CTI Metis (API + Web) — 2026-11-01

- `WEB-3`/`API-2`: nuovo motore condiviso offline
  `olympus.metis.extraction.extract_from_source` che unifica testo libero, STIX 2.1
  e MISP in un'unica forma onesta (indicatori normalizzati + scartati con
  motivazione). `POST /api/v1/metis/extract` espone `olympus.metis-extraction`
  1.0.0; la pagina Web `/metis` riusa lo stesso motore. Nuovo scope `metis:read`;
  CSRF, rate limit e bound su input (1 MB) e numero di item mantenuti.
- Parsing locale e deterministico: nessuna raccolta o chiamata di rete; set vuoto
  di indicatori ≠ input pulito quando ci sono elementi scartati. Demo statica
  `public/metis.html` generata dal motore reale su un campione sintetico.
- QA: `tests/unit/test_metis_extraction.py` (core: ordinamento/dedupe/bound/errori),
  test API e Web mirati, `tests/unit/test_build_preview.py` e drift gate preview,
  golden OpenAPI e manifest route parity rigenerati. Ruff lint/format e mypy verdi
  sui file toccati. Verifiche offline con TestClient; nessun claim di test browser
  reale o di promozione live-tested. Il test TUI
  `test_closing_tui_stops_running_command_process_tree` fallisce anche sulla
  baseline in questo ambiente (kill del process-tree), non correlato a questo
  intervento; nessun controllo di sicurezza o quality gate disabilitato.
- Resta parziale `WEB-3`: Argus e Artemis non hanno ancora pagine Web dedicate
  (Minerva e Athena ora sì); nessuna CTI live (TAXII/MISP/OpenCTI).

### Incremento Web Vulcan — 2026-11-01

- Dashboard e pagina operativa ATT&CK con export Navigator: riuso della mappa
  offline versionata, autorizzazione `findings:read`, provenienza automatica e
  distinzione esplicita dalla copertura difensiva. Nessuna scansione di rete.
- Demo statica ampliata con `public/attack.html`, rigenerabile e verificata dal
  drift gate. Verifica del deployment Vercel bloccata da HTTP 403 del provider;
  nessun claim di pubblicazione live.
- QA: test Web/Vulcan/preview e contratto inventario route; lint, formato e
  typing. I test di processo/sandbox di questo ambiente falliscono sul cambio
  proprietario `os.chown(..., 65534, 65534)` (EINVAL), anche sulla baseline:
  serve riesecuzione in un host che supporti l'isolamento richiesto. Nessun
  controllo di sicurezza o quality gate è stato disabilitato.
- `WEB-3` resta parziale; gli altri tool e la copertura detection Apollo
  richiedono ulteriori interventi. Nessuna promozione di adapter live-tested.

- Web UI copre solo un sottoinsieme dei tool → rischio "catalogo" se non si completa `WEB-3`.
- Operatività reale impossibile solo-su-Vercel → mitigato dallo split (`DEPLOY-2`).
- Molti adapter restano `catalog-only`/`offline-tested` → non promuovere senza lab.
- Persistenza SQLite single-writer → limite multiutente finché manca `DATA-2`.
- Dipendenza da azioni owner per release-signing, branch protection, import Vercel e lab autorizzato.
- Sviluppo concorrente sul repo → necessario riallineo Git frequente.
- `main` senza gate dimostrati (nessun ruleset; PR unite in pochi secondi con check in corso) → un'integrazione può precedere la verifica: mitigazione `SEC-4.1–4.3`.
- Workflow presente ≠ eseguito sullo SHA corretto ≠ obbligatorio → non dedurre protezione dall'esistenza dei workflow (`SEC-4.2`).
- Un assessment può partire senza engine obbligatori e senza evidenza firmata nei percorsi job/API/Web/worker → mitigazione `TOOLS-4.1`, `TOOLS-4.5`.
- Immagine scanner verificata con probe e commit ma non con scansioni reali nel container; misure di risorse ottenute in un solo ambiente → non generalizzare (`TOOLS-4.2`, `TOOLS-4.3`).
- Parser che ignorano righe non riconosciute possono nascondere errori → classificazione per regole verificabili (`TOOLS-4.4`).
- Rischio di complessità: correlazione, validazione continua, spiegabilità e AI non devono precedere il consolidamento P0/P1 né duplicare moduli esistenti (§21).

### Incremento ingest Web Apollo — 2026-11-01

- `WEB-3`: selezione formato, normalizzazione offline ed evaluation nel browser;
  righe scartate elencate senza estratti grezzi, input incompleto segnalato.
- Contratto API invariato (eventi normalizzati); CSRF, scope, rate limit, audit
  e limite body esistenti mantenuti. Nessuna raccolta di rete o claim live-tested.
- QA: 135 test Web/ingest verdi, 32 test mirati Apollo/preview verdi, Ruff
  lint/format, mypy Web e drift gate preview superati. Verifiche offline con
  TestClient, nessun claim di test browser reale o suite completa.
- Demo statica Apollo aggiornata e rigenerata, senza simulare invio/esecuzione.
- Verifica deployment Vercel impedita da HTTP 403 sui deployment del progetto;
  pubblicazione live non attestata.

## 20. Evoluzioni future

- Scheduling/monitoraggio ricorrente con diff dei finding.
- Modulo hardening/benchmark CIS (read-only).
- Orchestrazione exploitation controllata (solo post-manifest, no persistenza/DoS/evasione).
- Multi-tenant/RBAC completo e integrazioni SIEM/CTI live.

Collegamenti con la revisione 2026-11-03 (le voci sopra restano invariate): lo scheduling ricorrente con diff
dei finding è pianificato in `VAL-1`; l'orchestrazione di exploitation controllata, se mai affrontata, rientra
nelle simulazioni autorizzate di `VAL-2` con gli stessi vincoli (solo post-manifest, no persistenza/DoS/evasione);
le integrazioni SIEM/CTI live restano `BLUE-2`/`BLUE-3`.

Opportunità da **rivalutare**, non implementazioni immediate (P4; non sottraggono priorità al consolidamento):

- **FUT-1** [ ] Livello AI assistivo (interpretazione dei finding, suggerimenti di correlazione, supporto alla redazione dei report). Ingresso solo dopo `CORR-1` ed `EXPL-1`. Vincoli: poggiare su evidenze verificabili; distinguere dati osservati da contenuto generato; citare le fonti delle conclusioni; esplicitare incertezza e limiti; non inventare vulnerabilità o compromissioni; nessuna operazione attiva senza autorizzazione; rispetto di scope, privacy (incluso cosa lascia il perimetro verso modelli esterni), audit e sicurezza.
- **FUT-2** [ ] Ulteriori motori di scansione, solo se necessari ai workflow prioritari: criterio d'ingresso è una capability mancante in `olympus catalog` e la Definition of Done di §18, non il numero di engine.
- **FUT-3** [ ] Evoluzione verso microservizi, solo con un requisito misurato di scalabilità, isolamento o manutenzione; il monolite modulare (§3) resta l'architettura di riferimento e `ARCH-3` precede qualunque separazione.

## 21. Revisione 2026-11-03 — consolidamento e piattaforma di conoscenza

Questa sezione integra la roadmap con la revisione del 2026-11-03. È **solo pianificazione**: nessuna voce
qui è implementata e nessuna scelta tecnologica è anticipata (v. §21.7). Le voci esistenti non sono state
sostituite: dove una capacità era già coperta, la voce originale è stata estesa (`SEC-4`, `TOOLS-4/5`,
`WEB-5/6`, `API-3`, `CICD-1/2/3`, `PURPLE-1/2`, `QA-3`, `DATA-3`, `INT-1/3`) e qui compaiono solo i
riferimenti e le capacità effettivamente assenti (`CORR-*`, `VAL-*`, `EXPL-*`, `WEB-7/8`, `FUT-*`).
Ordine di lavoro: correzioni urgenti → consolidamento → integrazioni trasversali → evoluzioni
strategiche; le evoluzioni (P2–P4) non sottraggono priorità a P0/P1.

### 21.1 Stato di partenza e metodo

Lo stato reale è in §2 («Verifica dello stato reale»). Ogni voce distingue implementato, verificato
offline, verificato in CI, validato in lab e operativo (legenda in testa). Una priorità può essere
riordinata dal team se emergono dipendenze o rischi documentati, senza compromettere sicurezza e
obiettivi complessivi.

### 21.2 Mappa delle priorità

| Priorità | Tipo | Voci | Motivazione |
|---|---|---|---|
| P0 | correzione urgente | `SEC-4.1–4.4`, `TOOLS-4.1`, `TOOLS-4.4`, `TOOLS-4.5` | `main` non ha gate dimostrati; un assessment può partire senza engine obbligatori; stati ed evidenze non sono uniformi tra i percorsi |
| P1 | consolidamento | `TOOLS-4.2`, `TOOLS-4.3`, `TOOLS-4.6`, `TOOLS-5`, `API-3`, `QA-3`, `CICD-1/2/3` | rendono verificabile e ripetibile ciò che già esiste |
| P2 | integrazione trasversale / evoluzione | `EXPL-1/2`, `CORR-1/2`, `VAL-1/2/3`, `PURPLE-1/2`, `SEC-4.5` | richiedono contratti, stati ed evidenze affidabili (P0/P1) |
| P3 | esperienza d'uso | `WEB-5/6/7/8`, `TECH-2`, `QA-2` | stesso backend e stessi controlli delle altre interfacce |
| P4 | differite | `FUT-1/2/3` | solo se giustificate da requisiti reali |

### 21.3 Correlazione unificata (`CORR`)

*Perché:* i moduli producono dati su contratti condivisi ma nessun componente li collega tra loro. *Cosa
esiste già e va riusato:* `argus.graph` e `argus.correlation` (grafo di indagine, componenti connesse, pivot,
`correlate_by_value`), `vulcan.aggregate` (`finding_fingerprint`, deduplicazione), `vulcan.compare`,
Metis (IOC, STIX/MISP), Apollo (eventi, alert, coverage), Minerva (custodia, provenance), Athena
(piani/risultati), `core.models` (Asset, Finding, Event, Evidence, Observation).

- **CORR-1** [ ] (P2) Modello di correlazione sui contratti condivisi.
  - *Requisiti:* analizzare le relazioni tra asset (Argus), servizi e vulnerabilità (Themis), IOC e CTI (Metis), eventi e detection (Apollo), evidenze e catene di custodia (Minerva), risultati e report (Vulcan), assessment e workflow (Athena): sovrapposizioni, dipendenze, duplicazioni, possibili percorsi di esposizione. Ogni correlazione è **tracciabile** (fonti), **motivata** (regola o ragionamento), con **livello di affidabilità** e **classe epistemica** (la stessa di `EXPL-1`). Valutare se serve un **Security Knowledge Graph**, partendo dal fabbisogno (interrogazioni richieste, volumi, multiutente) e confrontandolo con l'estensione di ciò che esiste (`argus.graph`, SQLite/Postgres `TECH-3`); nessun database o framework è imposto (`DEC-6`). **Una correlazione ipotetica non è mai rappresentata come una compromissione dimostrata.**
  - *Dipende da:* `INT-3`, `ARCH-4`, `TOOLS-4.4` (stati), `EXPL-1` (classi epistemiche).
  - *Accettazione:* contratto versionato con JSON Schema nel catalogo; corpus di casi con esito atteso (stesso asset visto da Argus e Themis; IOC Metis ↔ evento Apollo; evidenza Minerva ↔ finding); ogni relazione porta `reason`, `sources`, `confidence`, `epistemic_class`; test di contratto che impediscono la promozione implicita di un'ipotesi a fatto; documento di decisione sul Knowledge Graph (sì/no e perché).
- **CORR-2** [ ] (P2) Motore di correlazione e superfici.
  - *Requisiti:* libreria I/O-free sui contratti esistenti, in sola lettura, deterministica e riproducibile; deduplicazione cross-tool (riuso di `finding_fingerprint`); percorsi di esposizione con profondità limitata; rispetto di engagement, scope e privacy (non correla dati fuori dall'ingaggio); esposta come CLI e API, e in Web solo con `WEB-8`.
  - *Dipende da:* `CORR-1`, `DATA-1`/`DATA-2`.
  - *Accettazione:* risultati identici su fixture a parità di input; nessuna chiamata di rete (test); budget di prestazioni definito dopo misura; audit delle interrogazioni; compatibilità dei contratti.

### 21.4 Validazione continua della sicurezza (`VAL`)

*Cosa esiste già e va riusato:* `argus.diff` (cambi della superficie), `vulcan.compare` e `vulcan.trend`
(nuovi / risolti / persistenti tra run, per identità logica), `core.finding_lifecycle` (sette stati
canonici; riapertura `closed → confirmed` su recidiva), `apollo.coverage` (`covered` / `partial` /
`no-telemetry`), `vulcan.attack` (CWE→ATT&CK, Navigator), Athena (profili e piani), `PURPLE-1/2`, lo
scheduling di §20. **Non si crea un motore parallelo.**

- **VAL-1** [~] (P2) Confronto tra assessment e monitoraggio ricorrente: asset diff e cambiamenti della superficie d'attacco; finding **nuovi, persistenti, risolti e ricomparsi** (oggi `vulcan.compare` distingue nuovi/risolti/persistenti; «ricomparso» va derivato da storico e lifecycle senza introdurre un nuovo stato canonico, se possibile); pianificazione ricorrente (`DEC-8`, `API-3`); report comparativi Vulcan. *Accettazione:* sequenza di tre assessment sintetici con classificazione attesa per ogni finding e asset; ricorrenza eseguita dallo stesso Execution Engine con preflight ed evidenza; nessuna scansione fuori scope. **Fatto:** motore di lifecycle dei finding su una storia ordinata (`vulcan.lifecycle.classify_lifecycle`, CLI `olympus vulcan lifecycle`): classifica l'ultimo snapshot contro l'intera storia in **nuovi / persistenti / ricomparsi / risolti**, con «ricomparso» derivato dallo storico e dall'identità logica condivisa (nessun nuovo stato canonico sul finding), `absent_for` e delta di severità dal momento dell'ultima comparsa; puro, offline, deterministico, riusa identità/folding/ordinamento del diff/trend; coperto dal test di accettazione a tre assessment. **Resta:** ricorrenza eseguita dall'Execution Engine (`API-3`) con preflight ed evidenza, asset diff della superficie d'attacco e report comparativi Vulcan.
- **VAL-2** [ ] (P2) Validazione delle remediation e simulazioni controllate e autorizzate: retest mirato scope-safe (stessa identità logica); chiusura `in_remediation → closed` solo con l'evidenza del retest; simulazioni soltanto con manifest e autorizzazione, senza persistenza, DoS o evasione, tramite `PURPLE-1`. *Accettazione:* un finding chiuso senza retest è rifiutato dal lifecycle; la simulazione genera evidenza firmata (`TOOLS-4.5`); lab riproducibile (`PURPLE-2`).
- **VAL-3** [ ] (P2) Copertura difensiva e gap: collegamento tecnica ATT&CK ↔ regola di detection ↔ telemetria ↔ esito della simulazione; gap di rilevamento; metriche di evoluzione del rischio e di efficacia dei controlli (formule documentate e serie temporali); report e evidenze comparativi. *Accettazione:* matrice di copertura riproducibile su un lab con risultati attesi; ogni metrica ha definizione, fonte e limiti; un gap non è mai nascosto da regole presenti «sulla carta» (principio già in `apollo.coverage`).
- *Dipende da (VAL):* `CORR-1` (relazioni), `TOOLS-4.4` (stati), `TOOLS-4.5` (evidenze), `QA-3`/`PURPLE-2` (lab). Valorizza l'integrazione Red/Blue/Purple.

### 21.5 Spiegabilità e provenienza dei risultati (`EXPL`)

- **EXPL-1** [ ] (P2) Modello unificato di spiegabilità dei finding, come **contratto dati condiviso** (non funzione grafica).
  - *Requisiti:* per ogni risultato rilevante ricostruire origine, engine e versione (e commit), parametri e contesto di esecuzione (redatti), evidenza tecnica, metodo di rilevamento, livello di affidabilità e limiti, correlazioni, possibile impatto, riferimenti a standard e tassonomie (CWE, CVE, ATT&CK…), verifiche necessarie per confermare, stato della remediation, evoluzione nel tempo. **Classi epistemiche distinte:** evidenza osservata · risultato deterministico · inferenza · correlazione suggerita · ipotesi non verificata. Riuso: `Finding.evidence`, `vulcan.provenance`, `vulcan.evidence_view`, evidenza engine-run (`TOOLS-4.5`), lifecycle, mappa CWE→ATT&CK. Estensione additiva di `olympus.finding` o documento separato: `DEC-7`.
  - *Dipende da:* `TOOLS-4.4`, `TOOLS-4.5`, `ARCH-4`.
  - *Accettazione:* contratto versionato e compatibile con i golden esistenti; ogni campo ha fonte e classe epistemica; test che un'ipotesi non può comparire come osservazione; fixture con almeno un finding per classe.
- **EXPL-2** [ ] (P2) Integrazione nel backend, in CLI, API, Web e reporting: stesso core per tutte le superfici (precedente: `inspect_ledger_text`), esportazione nei report Vulcan, assenza di logica di spiegazione duplicata nel frontend. *Accettazione:* CLI, API e report mostrano la stessa spiegazione per lo stesso finding (test di parità); la Web UI la visualizza solo tramite `WEB-8`.

### 21.6 Grafo delle dipendenze

- `SEC-4.1 → SEC-4.2 → SEC-4.3`; `SEC-4.4` richiede anche `TOOLS-4.2` e la revisione licenze di `TOOLS-4.6`; `SEC-4.5` richiede `SEC-4.1–4.4` e `CICD-3`.
- `TOOLS-4.4` precede `TOOLS-4.1` e `TOOLS-4.5` (gli stati devono essere affidabili prima di bloccare o firmare); `TOOLS-4.1` e `TOOLS-4.5` poggiano su `API-3` per i percorsi job/worker.
- `TOOLS-4.2` condivide i controlli di `TOOLS-4.1`; `TOOLS-4.3` usa le misure di `TOOLS-4.2` e i tetti di `SEC-1`; `TOOLS-4.6` si appoggia a `SEC-4` e `TOOLS-4.2`.
- `EXPL-1` e `CORR-1` dipendono da `TOOLS-4.4/4.5` e si definiscono insieme (classi epistemiche comuni); `CORR-2` da `CORR-1`; `EXPL-2` da `EXPL-1`; `VAL-*` da `CORR-1`, `TOOLS-4.4/4.5` e dal lab (`QA-3`/`PURPLE-2`).
- `WEB-5/6/7` dipendono da `API-3`, `ARCH-4` e dai servizi P0/P1; `WEB-8` da `CORR-2` ed `EXPL-2`.
- `FUT-*` dipendono da `CORR-1` ed `EXPL-1` e da una valutazione del rischio.

### 21.7 Decisioni architetturali rimandate

Da prendere nelle fasi di implementazione, con valutazione delle alternative disponibili, **senza anticiparne l'esito**:

- `DEC-1` Politica di merge su `main`: approvazioni con un solo owner, permessi di bypass, merge queue o branch aggiornato, cronologia lineare, gestione dei check con filtro di percorso.
- `DEC-2` Collocazione e contratto del preflight (nucleo condiviso vs servizio del piano Themis) e rappresentazione di `ENGINE_MISSING` come stato di job e risposta HTTP. **[deciso in parte 2026-11-03 — v. «Decisioni già prese» sotto]** collocazione risolta (servizio core puro condiviso `olympus.engines.preflight`); rappresentazione come stato di job / HTTP ancora **aperta** (si decide col cablaggio in `API-3`).
- `DEC-3` Servizio di evidenza: uno solo condiviso o convergenza con la custodia Minerva; formato della busta; gestione delle chiavi (file, keyring, KMS); evidenza dei run rifiutati.
- `DEC-4` Formato dei profili di risorse, rapporto manifest ↔ policy, metodo di misura (RLIMIT, cgroup, container).
- `DEC-5` Strumento di scansione vulnerabilità per engine e immagine e strategia di lock delle dipendenze transitive.
- `DEC-6` Necessità e storage di un Security Knowledge Graph (dopo `CORR-1`).
- `DEC-7` Rappresentazione della spiegabilità: estensione additiva di `olympus.finding` o documento separato.
- `DEC-8` Scheduling ricorrente: dentro l'Execution Engine (`API-3`) o scheduler esterno.
- `DEC-9` Stack frontend e design system per le due modalità (con `TECH-2`).
- `DEC-10` Fonte di verità per i livelli L1/L2/L3 di maturità degli engine (ledger esistente o estensione).
- `DEC-11` Assorbimento di `scripts/smoke_scanner_image.py` in `engines doctor --strict` o coesistenza.

#### Decisioni già prese (2026-11-03)

Decisioni assunte autonomamente dal team e **già implementate e verificate** (suite offline,
Ruff, mypy `--strict`, drift gate verdi). Ogni voce indica dove vive e il test che la
custodisce. Restano aperte solo le parti che richiedono CI/lab, segnalate esplicitamente.

- **`DEC-2` (parziale) — collocazione del preflight.** Il preflight è un **servizio core puro
  e offline** (`olympus.engines.preflight`), I/O iniettato via `doctor.Environment`, nessuna
  rete/target, riusabile da ogni interfaccia; **non** un servizio interno al solo piano
  Themis. Esposto dal comando `olympus engines preflight`. Guardia: `test_engine_preflight`.
  *Aperto:* `ENGINE_MISSING` come stato di job e risposta HTTP (con l'Execution Engine,
  `API-3`), e l'invocazione automatica in preview/run/API/Web/worker.
- **Regole di "engine richiesti" (parte di `TOOLS-4.1`).** Mandatory sempre richiesti; engine
  nominati esplicitamente sempre richiesti; `api`/commerciali mai bloccanti (nessun artefatto
  locale). Un richiesto non usabile → exit 8 con comando d'installazione **pinnato**, mai un
  segreto. `--allow-missing-engines` resterà limitato alle **sole** dipendenze opzionali
  (via `required_for_commands`), mai ai mandatory (già annotato in `TOOLS-4.1`).
- **Supply chain — sorgente unica degli hint d'installazione (`TOOLS-4`).** Sia
  `ScannerAdapter.install` sia `ScannerSpec.install` derivano dal pin del manifest
  (`engines.loader.install_hint`): niente `@latest`, niente pacchetto PyPI errato
  (commix/theHarvester). Guardia: `test_engine_install_hints`.
- **CI — least-privilege del `GITHUB_TOKEN`.** Ogni workflow dichiara `permissions` top-level
  con `contents: read`, elevando solo per-job dove serve. Guardia:
  `test_threat_model::test_every_workflow_sets_least_privilege_token_permissions`.
- **Supply chain — versione unica di gitleaks.** pre-commit e CI usano la stessa versione
  (`v8.28.0`). Guardia:
  `test_threat_model::test_gitleaks_version_is_consistent_between_pre_commit_and_ci`.
- **Docs — conteggio engine nativi bilingue.** README EN/IT dichiarano lo stesso numero di
  engine nativi (16/24), legato al conteggio reale degli adapter. Guardia:
  `test_themis_scanners::test_readme_native_engine_count_matches_reality`.
- **Docs — procedura di aggiornamento engine.** `docs/engines/UPDATES.md` documenta la
  procedura **manuale** attuale e il criterio di policy; l'automazione `check-updates`/
  `update` resta pianificata (Fase 4).

Le decisioni `DEC-3`, `DEC-4`, `DEC-5`, `DEC-6`, `DEC-7`, `DEC-8`, `DEC-9`, `DEC-10`, `DEC-11`
restano **aperte**: non sono state prese in questa sessione perché la loro accettazione
richiede capacità non disponibili qui (CI, lab autorizzato, rete verso terze parti) o
dipendono da workstream non ancora avviati.

### 21.8 Sequenza proposta di implementazione

Ogni tappa è implementabile separatamente (richiesta e PR distinte) e si chiude solo con i criteri indicati,
verificati sullo SHA corretto. «Fase 3» di `docs/engines/INVENTORY.md` corrisponde a T3 e a parte di T5.

| Tappa | Contenuto | Prerequisiti | Si chiude quando |
|---|---|---|---|
| T1 (P0) | Gate del repository: `SEC-4.1–4.4` | azione owner GitHub; `DEC-1` | regole attive leggibili da API; push diretto e merge con check mancante rifiutati; tabella presente/eseguito/obbligatorio vera; revert provato |
| T2 (P0) | Stati e output: `TOOLS-4.4` (prima nmap, nuclei, httpx) | nessuno | tabella unica degli stati; corpus per classi; nessun output sconosciuto → `clean`; contratti compatibili |
| T3 (P0) | Preflight: `TOOLS-4.1` | T2; `DEC-2`; `API-3` per i worker | parità CLI/API/Web/worker; zero traffico; exit 8 + audit; `--allow-missing-engines` solo opzionali |
| T4 (P0) | Evidenze condivise: `TOOLS-4.5` | T2; `DEC-3` | ogni percorso produce evidenza verificabile da un solo verificatore; chiavi e idempotenza provate |
| T5 (P1) | Doctor rigoroso e immagine: `TOOLS-4.2` | T3; `DEC-10`, `DEC-11` | `doctor --strict` ultimo passo del Dockerfile e step CI; L1/L2 per tutti gli engine distribuiti; L3 con evidenza committata per i 3 mandatory |
| T6 (P1) | Risorse: `TOOLS-4.3` | T3, T5; `DEC-4` | profili misurati con ambiente; preflight risorse; test a risorse insufficienti con esiti equivalenti |
| T7 (P1) | Supply chain: `TOOLS-4.6`, `TOOLS-5`, `CICD-1/2/3` | T1, T5; `DEC-5` | `upstream_verified`, lock transitive, scansione vulnerabilità bloccante, update/rollback provati, parere licenze registrato |
| T8 (P2) | Contratti di conoscenza: `EXPL-1`, `CORR-1` | T2, T4; `DEC-6`, `DEC-7` | schemi nel catalogo, corpus di casi, test di non-promozione ipotesi→fatto |
| T9 (P2) | Motori e verifica continua: `CORR-2`, `EXPL-2`, `VAL-1/2/3`, `PURPLE-1/2` | T8; lab riproducibile (`QA-3`) | risultati deterministici su fixture; validazione in lab con evidenze; metriche documentate |
| T10 (P3) | Esperienza d'uso: `WEB-5/6/7/8` | `API-3`, `ARCH-4`, T3–T6; T9 per `WEB-8`; `DEC-9` | percorsi equivalenti alla CLI (parità di audit/evidenze/stati); E2E in browser; revisione UX/accessibilità |
| T11 (P4) | Rivalutazione `FUT-1/2/3` | T8–T9 consolidate | decisione documentata di avviare o rimandare ciascuna |

T1 e T2 sono indipendenti e possono procedere in parallelo; T7 può cominciare dopo T1 e T5; nessuna tappa
P2–P4 deve essere avviata se una tappa P0 precedente è ancora aperta.

---

*Le evidenze storiche della pianificazione precedente restano in Git. Questa
roadmap è il riferimento unico; va aggiornata a ogni intervento completato.*

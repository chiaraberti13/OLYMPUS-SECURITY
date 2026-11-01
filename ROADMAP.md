# 🏛️ OLYMPUS-SECURITY — Roadmap (canonica)

> Questo documento **sostituisce integralmente** la roadmap precedente. La
> versione storica resta disponibile nella cronologia Git (`git log -- ROADMAP.md`)
> come fonte conoscitiva, non vincolante. Progettata dal team multidisciplinare il
> 2026-11-01, è l'**unico documento di pianificazione canonico** del progetto.

**Legenda stato:** `[x]` implementato e verificato (test/CI nello scope indicato —
non è un claim di produzione/lab live); `[~]` parziale o in corso; `[ ]` da fare.
Gli ID sono stabili.

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

## 2. Stato verificato dei componenti

Verificato = coperto da test automatici verdi in CI (unit/integration/contract),
non necessariamente provato in lab live.

| Area | Componente | Stato | Nota |
|---|---|---|---|
| Core | `core.models`/contratti versionati, migrazioni, redaction, crypto, signing | [x] | contratti golden + schema catalog |
| Recon | **Argus** (DNS/WHOIS/CT/OSINT, SSRF-safe) | [x] | nativo, test offline |
| Orchestrazione | **Athena** (piani firmabili, job, profili Light/Deep) | [x] | `athena profiles`, `plan from-profile` |
| Scanner plane | **Themis** (registry 24 engine, maturity ladder, sandbox, job SQLite, API, Web) | [~] | adapter a maturità diversa; pochi live-tested |
| Web attiva | **Artemis** (fingerprint/header/XSS checks) | [x] | offline-tested |
| Blue Team | **Apollo** (ingest access-log/Zeek, detection, ATT&CK, coverage) | [~] | manca ingest Windows/Sysmon |
| CTI | **Metis** (IOC, STIX/MISP import, case) | [~] | manca CTI live (TAXII/MISP/OpenCTI) |
| Evidenze | **Minerva** (timeline firmata Ed25519) | [x] | verify offline |
| Reporting | **Vulcan** (aggregazione, JSON/MD/HTML/PDF, SARIF, enrichment KEV/EPSS, sezioni da manifest) | [x] | test completi |
| Altri | Helios, Hermes, Proteus | [~] | superfici parziali |
| Interfacce | CLI (Typer), TUI (Textual), API (FastAPI tipizzata), Web (Jinja2+SSE) | [~] | Web copre un sottoinsieme dei tool |
| Catalogo | `olympus catalog` (coverage present/simulated/missing, derivata e onesta) | [x] | gate anti-sovrastima |
| Distribuzione | anteprima statica + demo a fixture su Vercel (`public/`, `vercel.json`) | [x] | deploy live = import owner |
| Qualità | CI 14 job + CodeQL; ~2663 test | [x] | verde su `main` |

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
- **RED-2** [~] Adapter web residui: `wpscan`, `nosqlmap`; portare Wapiti/altri a live-tested in lab autorizzato.
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
- **BLUE-2** [ ] Connettori SIEM/EDR (Splunk HEC, Elastic, Sentinel) via porte iniettate, test offline.
- **BLUE-3** [ ] CTI live in Metis (TAXII 2.1, MISP, OpenCTI) con provenance/caching/isolamento.
- **PURPLE-1** [ ] `athena purple`: attacco simulato scope-safe → ingest Apollo → valutazione detection → report gap.
- **PURPLE-2** [ ] Profilo lab ripetibile (`labs/mars`) con seed/versioni/output atteso.

## 6. Inventario dei tool e capacità

Fonte unica e onesta: **`olympus catalog`** (stato derivato dal codice). Sintesi
capability-prodotto: *present* website scanner, SSL scanner, port scanner,
subdomain finder, domain finder; *missing* network-vuln scanner, CMS scanner,
password auditor. La maturità per-engine è in
[`scanner-maturity.md`](docs/scanner-maturity.md).

- **TOOLS-1** [x] Catalogo capability allineato e verificabile.
- **TOOLS-2** [ ] Colmare le capability *missing* con adapter/moduli reali (vedi RED/BLUE).
- **TOOLS-3** [ ] Promuovere adapter a *live-tested* in lab autorizzato (con evidenze committate).

## 7. Piano di integrazione dei tool

- **INT-1** [x] Contract test per ogni adapter registrato; fuzzing dei parser; esito fail-closed.
- **INT-2** [ ] Template SDK plugin stabile e documentato per adapter esterni (entry-point discovery).
- **INT-3** [ ] Ogni tool espone un contratto input/output tipizzato riusabile da CLI, API e Web.

## 8. Web UI completa (obiettivo portante)

Ogni tool deve essere pienamente utilizzabile da Web: configurazione parametri,
avvio, monitoraggio, risultati/progressi, log, errori, evidenze, filtri/ricerca,
export, storico, documentazione. La CLI resta alternativa, non unico accesso.

- **WEB-1** [x] Web control plane nativo sopra l'API tipizzata (submit job, SSE, cancel), con security headers/CSP/CSRF/sessioni.
- **WEB-2** [~] Pagine operative dei tool esistenti (Themis scan, findings, diff, trend, report, engagement).
- **WEB-3** [~] Copertura Web di **tutti** i tool dell'ecosistema (Argus, Apollo, Metis, Minerva, Athena, Artemis…) con pagine dedicate operative. Vulcan: associazioni CWE→ATT&CK consultabili in `/findings/attack`, con provenienza, finding non mappati ed export Navigator; riuso del motore offline, accesso `findings:read`. Apollo: workbench operativo `/apollo` sul rule pack configurato dal server, input `olympus.event` NDJSON limitato, valutazione offline reale, scope `apollo:read`/`apollo:run`, CSRF e audit. Ingest Web di access log HTTP, Zeek JSON e Windows/Sysmon JSON tramite parser esistenti, limite di 500 righe fisiche e scarti visibili; verifica offline con fixture e regole Sysmon incluse. Restano gli altri flussi/moduli.
- **WEB-4** [ ] Dashboard principale con stato sistema, job attivi, findings per severità, coverage ATT&CK.
- **WEB-5** [ ] Wizard "New Assessment" end-to-end (engagement → scope → profilo → esecuzione → report).
- **WEB-6** [ ] Configurazione guidata, feedback operazioni, gestione errori/eccezioni uniforme.

## 9. Backend, API e orchestrazione

- **API-1** [x] API FastAPI tipizzata (auth per-scope, accountability, `/jobs`, `/capabilities`, health/ready/metrics).
- **API-2** [~] Estendere l'API a **tutti** i tool con contratti versionati (non solo Themis). Slice Apollo implementata: `GET /api/v1/apollo/rules` (`olympus.apollo-rule-list` 1.0.0) e `POST /api/v1/apollo/evaluate` (`olympus.apollo-evaluation` 1.0.0), rule pack server-owned e valutazione tipizzata/bounded; restano gli altri moduli.
- **API-3** [ ] Execution Engine: worker persistente, coda, retry idempotenti, backpressure, checkpoint, cancellazione coerente CLI/TUI/API/Web.
- **API-4** [ ] CORS/origin policy verso il dominio Web di deploy; autenticazione multiutente.

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
- **DEMO-2** [ ] Ampliare la demo: dashboard, identità visiva completa, flussi rappresentativi, grafici/visualizzazioni, esempi realistici etichettati.
- **DEMO-3** [ ] Quando possibile, integrare funzioni realmente eseguibili via backend dedicato (split), senza confondere live e demo.

## 12. Database, persistenza ed evidenze

- **DATA-1** [x] SQLite transazionale per job/engagement/finding/audit; export portabile NDJSON/SARIF; backup/restore coordinato.
- **DATA-2** [ ] Astrazione repository/persistenza con **Postgres** opzionale per multiutente/concorrenza.
- **DATA-3** [ ] Retention/privacy di sistema e storicizzazione evidenze con catena di custodia verificabile.

## 13. Sicurezza e affidabilità del prodotto

- **SEC-1** [x] Scope/authorization gate, execution policy (tetti non alzabili), sandbox processi, redaction, audit firmato.
- **SEC-2** [x] Manifest d'ingaggio firmati (Ed25519), gate di rischio, input non fidato trattato come ostile (anti terminal-injection, escaping export).
- **SEC-3** [~] Egress scanner/DNS vincolato allo scope a livello kernel/container — richiede validazione lab.
- **SEC-4** [ ] Release signing/SLSA/Cosign e branch protection come gate bloccanti (azione owner su GitHub).
- **SEC-5** [x] SAST CodeQL in CI; dependency-audit + secret-scan.

## 14. Quality Assurance e test

- **QA-1** [x] Suite unit/integration/contract (~2663 test) verde in CI; coverage gate ≥75%; mutation mirato; fuzzing parser.
- **QA-2** [ ] Test end-to-end Web (browser reali), accessibilità WCAG, responsive.
- **QA-3** [ ] Test degli adapter contro output reale in lab autorizzato (promozione live-tested).
- **QA-4** [~] Matrice OS/Python oltre a quella CI; performance/concorrenza sotto carico.

## 15. Documentazione e localizzazione

- **DOCS-1** [x] README IT/EN, docs per modulo, CLI reference generata, disclaimer d'uso.
- **DOCS-2** [ ] Guide Web UI per ogni tool; documentazione API completa; guida deploy split + Vercel.
- **DOCS-3** [ ] Sito doc statico bilingue (Pages/Vercel) dalla stessa fonte `docs/`.

## 16. Packaging, deployment e CI/CD

- **CICD-1** [x] CI 14 job (gate qualità, test multi-versione, coverage, mutation, sandbox, smoke, container, dependency-audit, secret-scan) + CodeQL.
- **CICD-2** [x] `docker/Dockerfile` + immagine scanner; wheel/sdist; SBOM CycloneDX.
- **CICD-3** [ ] Pipeline di release firmata e pubblicazione PyPI via Trusted Publishing; GitHub Action riutilizzabile passiva di default.
- **CICD-4** [ ] Deploy backend containerizzato documentato e riproducibile.

## 17. Priorità, milestone e dipendenze

- **M1 — Fondamenta operative Web (P0/P1):** API per tutti i tool (`API-2`), Execution Engine (`API-3`), split deploy (`DEPLOY-2`).
- **M2 — Web UI completa (P1):** `WEB-3/4/5/6` su tutti i tool con pagine operative reali.
- **M3 — Copertura capability (P1/P2):** RED/BLUE/PURPLE, `TOOLS-2`, promozioni live-tested (`QA-3`) in lab.
- **M4 — Demo & distribuzione (P2):** `DEMO-2/3`, `DOCS-3`, `CICD-3/4`, `SEC-4`.

Dipendenze principali: `WEB-3` dipende da `API-2`; `DEPLOY-2` abilita `DEMO-3` e
l'operatività Web reale; `QA-3`/`TOOLS-3` richiedono lab autorizzato (gate esterno).

## 18. Criteri oggettivi di completamento

Una voce è `[x]` solo con: criteri funzionali soddisfatti, test automatici verdi
pertinenti, documentazione IT/EN aggiornata, nessun segreto nel diff, commit su
`main` e stato remoto verificato. «Realmente verificato» esclude mock spacciati
per esecuzioni e promozioni senza evidenza.

## 19. Debito tecnico e rischi residui

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

---

*Le evidenze storiche della pianificazione precedente restano in Git. Questa
roadmap è il riferimento unico; va aggiornata a ogni intervento completato.*

# 🏛️ OLYMPUS-SECURITY — Roadmap

> Checklist canonica operativa per la piattaforma Red/Blue/Purple Team. Requisiti, criteri di accettazione, evidenze, decisioni e storico completi sono conservati nel [riferimento tecnico](docs/ROADMAP-REFERENCE.md). Non costituisce una seconda roadmap operativa.

## Regole di utilizzo

- `[x]` completato; `[ ]` aperto; **In corso** indica lo stato originale `[~]`, ora rappresentato con checkbox Markdown standard.
- Gli ID originali sono immutati. I suffissi `-check-N` identificano esclusivamente verifiche già presenti ma prive di ID; non introducono nuovi requisiti.
- Prima di lavorare su un task, leggere il relativo link tecnico, i prerequisiti e i criteri di accettazione; le note storiche non costituiscono una nuova verifica.
- Se un task padre ha sotto-task, chiuderlo soltanto dopo tutte le verifiche applicabili e la Definition of Done. Non contare due volte padre e figli.
- Se un task è bloccato, documentare causa, evidenza e condizione di sblocco; non spuntarlo. Non avviare P2–P4 con P0 precedente ancora aperta.
- Dopo ogni intervento aggiornare la checkbox, rimuovere **In corso** se concluso, registrare evidenza/SHA nel riferimento tecnico come nuova nota datata e aggiornare il riepilogo. Non riscrivere le evidenze storiche.
- Le checkbox sono compatibili con GitHub; la modifica persistente richiede un commit. Il riepilogo non è un calcolo automatico di Markdown.

## Visione

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

## Definition of Done

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

## Governance e limiti

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

## Fondamenta già disponibili

Consultare lo [stato verificato dei componenti](docs/ROADMAP-REFERENCE.md#2-stato-verificato-dei-componenti) e le relative istantanee: non sono task aggiuntivi.

## Ordine di implementazione

Le tappe originali T1–T13 e i criteri di chiusura restano vincolanti nei limiti delle dipendenze documentate. Consultare [priorità e dipendenze](docs/ROADMAP-REFERENCE.md#priorità-di-implementazione-e-dipendenze).

| Ordine | Tappa | Riferimento tecnico |
|---|---|---|
| T1 (P0) | Gate del repository: `SEC-4.1–4.4` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T2 (P0) | Stati e output: `TOOLS-4.4` (prima nmap, nuclei, httpx) | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T3 (P0) | Preflight: `TOOLS-4.1` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T4 (P0) | Evidenze condivise: `TOOLS-4.5` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T5 (P1) | Doctor rigoroso e immagine: `TOOLS-4.2` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T6 (P1) | Risorse: `TOOLS-4.3` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T7 (P1) | Supply chain: `TOOLS-4.6`, `TOOLS-5`, `CICD-1/2/3` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T8 (P2) | Contratti di conoscenza: `EXPL-1`, `CORR-1` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T9 (P2) | Motori e verifica continua: `CORR-2`, `EXPL-2`, `VAL-1/2/3`, `PURPLE-1/2` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T10 (P3) | Esperienza d'uso: `WEB-5/6/7/8` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T11 (P4) | Rivalutazione `FUT-1/2/3` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T12 (P2) | Fondamenta AI (21.9): `AI-0` (ADR+licenze), `AI-2` (router), `AI-3` (fact graph), `AI-7` (eval) | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |
| T13 (P2/P3) | Orchestrazione e agenti (21.9): `AI-1`, `AI-4`, `AI-5`, `AI-6` | [Prerequisiti e accettazione](docs/ROADMAP-REFERENCE.md#218-sequenza-proposta-di-implementazione) |

> T1/T2 indipendenti; T7 dopo T1/T5. Per T3/T4 rispettare i prerequisiti di `API-3`; T5/T6 vanno coordinati secondo i criteri tecnici. Le dipendenze prevalgono sulla numerazione dei cicli.

---

## Ciclo A — Integrità, sicurezza e governance degli engine

**Obiettivo:** Garantire autorizzazione, integrità degli esiti, supply chain e maturità verificabile.

**Priorità di riferimento:** P0/P1.


### Sicurezza e affidabilità del prodotto

- [x] **SEC-1** — Scope/authorization gate, execution policy (tetti non alzabili), sandbox processi, redaction, audit firmato · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
- [x] **SEC-2** — Manifest d'ingaggio firmati (Ed25519), gate di rischio, input non fidato trattato come ostile (anti terminal-injection, escaping export) · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
- [ ] **SEC-3** — Egress scanner/DNS vincolato allo scope a livello kernel/container — richiede validazione lab — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
- [x] **SEC-4** — Release signing, protezione di main e gate di pubblicazione · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
  - [x] **SEC-4.1** — (P0) Ruleset e protezione del branch `main` · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
  - [x] **SEC-4.2** — (P0) Check obbligatori vincolati allo SHA corretto · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
  - [x] **SEC-4.3** — (P0) Verifica post-merge, registro SHA e rollback · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
  - [x] **SEC-4.4** — (P0) Gate di pubblicazione per immagini validate · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
  - [x] **SEC-4.5** — (P2) Release signing, SLSA/Cosign, provenance degli artefatti (contenuto originale di `SEC-4`). Dipende da `SEC-4.1–4.4` e `CICD-3` · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)
- [x] **SEC-5** — SAST CodeQL in CI; dependency-audit + secret-scan · [Dettagli](docs/ROADMAP-REFERENCE.md#13-sicurezza-e-affidabilità-del-prodotto)

### Inventario dei tool e capacità

- [x] **TOOLS-1** — Catalogo capability allineato e verificabile · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
- [ ] **TOOLS-2** — Colmare le capability missing/simulated con strumenti reali — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
- [ ] **TOOLS-3** — Promuovere adapter a *live-tested* in lab autorizzato (con evidenze committate) · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
- [ ] **TOOLS-4** — Governance supply-chain degli engine esterni — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [ ] **TOOLS-4.1** — (P0) Preflight fail-closed condiviso (CLI, API, Web, worker, step Athena) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [ ] **TOOLS-4.2** — (P1) Diagnostica rigorosa: `olympus engines doctor --strict` — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [ ] **TOOLS-4.3** — (P1) Risorse, timeout e profili per engine — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [x] **TOOLS-4.4** — (P0) Gestione rigorosa degli output e stati canonici · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [ ] **TOOLS-4.5** — (P0) Evidenze firmate e coerenza tra percorsi di esecuzione — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
  - [ ] **TOOLS-4.6** — (P1) Supply chain e distribuzione — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)
- [ ] **TOOLS-5** — Debito tecnico immagine scanner ed engine · [Dettagli](docs/ROADMAP-REFERENCE.md#6-inventario-dei-tool-e-capacità)

### Piano di integrazione dei tool

- [x] **INT-1** — Contract test degli adapter, fuzzing e fail-closed · [Dettagli](docs/ROADMAP-REFERENCE.md#7-piano-di-integrazione-dei-tool)
- [x] **INT-2** — Template SDK plugin stabile e documentato per adapter esterni (entry-point discovery) · [Dettagli](docs/ROADMAP-REFERENCE.md#7-piano-di-integrazione-dei-tool)
- [ ] **INT-3** — Ogni tool espone un contratto input/output tipizzato riusabile da CLI, API e Web — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#7-piano-di-integrazione-dei-tool)

### Packaging, deployment e CI/CD

- [x] **CICD-1** — CI, quality gate, CodeQL e build/smoke scanner · [Dettagli](docs/ROADMAP-REFERENCE.md#16-packaging-deployment-e-cicd)
- [x] **CICD-2** — `docker/Dockerfile` + immagine scanner; wheel/sdist; SBOM CycloneDX · [Dettagli](docs/ROADMAP-REFERENCE.md#16-packaging-deployment-e-cicd)
- [ ] **CICD-3** — Release firmata e pubblicazione PyPI via Trusted Publishing — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#16-packaging-deployment-e-cicd)
- [x] **CICD-4** — Backend containerizzato documentato con [procedura Compose](docs/themis-runtime.md#avvio-riproducibile-con-compose), migrazione ripetuta in CI e smoke container nativo · [Dettagli](docs/ROADMAP-REFERENCE.md#16-packaging-deployment-e-cicd)

**Completato quando:** I gate, gli stati e le evidenze sono coerenti e verificati secondo i criteri SEC, TOOLS, INT e CICD.


---

## Ciclo B — Architettura, Execution Engine e persistenza

**Obiettivo:** Consolidare il nucleo condiviso, i contratti e l’esecuzione persistente.

**Priorità di riferimento:** P0/P1.


### Architettura di riferimento

- [x] **ARCH-1** — Core di dominio I/O-free con contratti versionati · [Dettagli](docs/ROADMAP-REFERENCE.md#3-architettura-di-riferimento)
- [ ] **ARCH-2** — Confini `domain → application → ports → adapters` formalizzati per tutti i moduli — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#3-architettura-di-riferimento)
- [ ] **ARCH-3** — Execution Engine esplicito e documentato (job, worker, code, cancellazione) come servizio separabile — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#3-architettura-di-riferimento)
- [ ] **ARCH-4** — Contratto UI/API stabile e versionato per tutti i tool — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#3-architettura-di-riferimento)

### Strategia di evoluzione tecnologica

- [x] **TECH-1** — Backend Python 3.11+ (Pydantic v2, Typer, FastAPI, Textual) confermato: adeguato e maturo · [Dettagli](docs/ROADMAP-REFERENCE.md#4-strategia-di-evoluzione-tecnologica)
- [x] **TECH-2** — Frontend Web: valutare e selezionare uno stack moderno (SSR/SPA) integrato realmente all'API; decisione del team su basi tecniche (oggi la Web UI è Jinja2+SSE, adeguata ma limitata) · [Dettagli](docs/ROADMAP-REFERENCE.md#4-strategia-di-evoluzione-tecnologica)
- [ ] **TECH-3** — Persistenza: SQLite come default locale; astrazione verso Postgres per deployment multiutente/concorrente — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#4-strategia-di-evoluzione-tecnologica)
- [x] **TECH-4** — Valutazione coda e worker fuori Vercel · [Dettagli](docs/ROADMAP-REFERENCE.md#4-strategia-di-evoluzione-tecnologica)

### Backend, API e orchestrazione

- [x] **API-1** — API FastAPI tipizzata (auth per-scope, accountability, `/jobs`, `/capabilities`, health/ready/metrics) · [Dettagli](docs/ROADMAP-REFERENCE.md#9-backend-api-e-orchestrazione)
- [ ] **API-2** — Estendere l'API a tutti i tool con contratti versionati (non solo Themis) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#9-backend-api-e-orchestrazione)
- [ ] **API-3** — Execution Engine: worker, retry, backpressure, checkpoint e cancellazione — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#9-backend-api-e-orchestrazione)
- [ ] **API-4** — CORS/origin policy verso il dominio Web di deploy; autenticazione multiutente — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#9-backend-api-e-orchestrazione)

### Database, persistenza ed evidenze

- [x] **DATA-1** — SQLite transazionale per job/engagement/finding/audit; export portabile NDJSON/SARIF; backup/restore coordinato · [Dettagli](docs/ROADMAP-REFERENCE.md#12-database-persistenza-ed-evidenze)
- [ ] **DATA-2** — Astrazione repository/persistenza con Postgres opzionale per multiutente/concorrenza — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#12-database-persistenza-ed-evidenze)
- [x] **DATA-3** — Retention/privacy di sistema e storicizzazione evidenze con catena di custodia verificabile · [Dettagli](docs/ROADMAP-REFERENCE.md#12-database-persistenza-ed-evidenze)

**Completato quando:** I contratti e i percorsi di esecuzione soddisfano i criteri ARCH, TECH, API e DATA.


---

## Ciclo C — Capacità Red, Blue e Purple Team

**Obiettivo:** Consolidare i moduli e le integrazioni operative senza confondere fixture e laboratorio.

**Priorità di riferimento:** P1/P2.


### Piano moduli Red / Blue / Purple

- [ ] **RED-1** — Recon attiva ProjectDiscovery/OSINT: adapter `subfinder`, `dnsx`, `naabu`, `amass`, `theHarvester` — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [ ] **RED-2** — Adapter web residui e validazione live — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [ ] **RED-3** — Password auditor Nemesis e validazione residua — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [x] **BLUE-1** — Apollo ingest Sysmon/Windows Event · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [ ] **BLUE-2** — Connettori SIEM/EDR (Splunk HEC, Elastic, Sentinel) via porte iniettate, test offline — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
  - [x] **BLUE-2-check-1** — Splunk HEC: prova live locale · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
  - [x] **BLUE-2-check-2** — Microsoft Sentinel: test HTTPS locale · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
  - [ ] **BLUE-2-check-3** — Microsoft Sentinel: ingest Azure e rilettura live · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [ ] **BLUE-3** — CTI live in Metis (TAXII 2.1, MISP, OpenCTI) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [ ] **PURPLE-1** — Workflow Purple autorizzato: simulazione, detection e report gap — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)
- [x] **PURPLE-2** — Profilo di laboratorio ripetibile `labs/mars` · [Dettagli](docs/ROADMAP-REFERENCE.md#5-piano-moduli-red--blue--purple)

**Completato quando:** I moduli raggiungono i livelli di verifica richiesti dalle rispettive voci.


---

## Ciclo D — Correlazione, spiegabilità e validazione continua

**Obiettivo:** Integrare conoscenza, evidenze e verifica continua sui contratti esistenti.

**Priorità di riferimento:** P2.


### Correlazione unificata (`CORR`)

- [ ] **CORR-1** — Modello di correlazione sui contratti condivisi — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#213-correlazione-unificata-corr)
- [ ] **CORR-2** — Motore di correlazione e superfici — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#213-correlazione-unificata-corr)

### Spiegabilità e provenienza dei risultati (`EXPL`)

- [ ] **EXPL-1** — Contratto dati condiviso per spiegabilità dei finding — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#215-spiegabilità-e-provenienza-dei-risultati-expl)
- [ ] **EXPL-2** — Spiegabilità su backend, CLI, API, Web e reporting — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#215-spiegabilità-e-provenienza-dei-risultati-expl)

### Validazione continua della sicurezza (`VAL`)

- [ ] **VAL-1** — Confronto assessment, asset diff e monitoraggio ricorrente — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#214-validazione-continua-della-sicurezza-val)
- [ ] **VAL-2** — Validazione remediation e retest autorizzato — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#214-validazione-continua-della-sicurezza-val)
- [ ] **VAL-3** — Copertura difensiva, gap e metriche di efficacia — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#214-validazione-continua-della-sicurezza-val)

**Completato quando:** I criteri CORR, EXPL e VAL sono soddisfatti senza promuovere ipotesi a fatti.


---

## Ciclo E — Web UI ed esperienza operativa

**Obiettivo:** Fornire flussi Web completi sul medesimo backend e con i medesimi controlli.

**Priorità di riferimento:** P1/P3.


### Web UI completa (obiettivo portante)

- [x] **WEB-1** — Web control plane nativo sopra l'API tipizzata (submit job, SSE, cancel), con security headers/CSP/CSRF/sessioni · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-2** — Pagine operative dei tool esistenti (Themis scan, findings, diff, trend, report, engagement) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-3** — Copertura Web di tutti i tool dell'ecosistema (Argus, Apollo, Metis, Minerva, Athena, Artemis…) con pagine dedicate operative — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [x] **WEB-4** — Dashboard principale (`/`): stato sistema (versione piattaforma, versione mappa ATT&CK, stato per-sottosistema configurato/non configurato), job attivi e istogramma stati, avanzamento assessment, findings · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-5** — Wizard New Assessment end-to-end (modalità guidata) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-6** — Configurazione guidata, feedback e gestione uniforme degli errori — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-7** — Modalità avanzata sullo stesso backend e controlli — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)
- [ ] **WEB-8** — Esperienza coerente, correlazioni e spiegabilità — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#8-web-ui-completa-obiettivo-portante)

**Completato quando:** Le superfici Web soddisfano i criteri di parità, sicurezza e operatività delle voci WEB.


---

## Ciclo F — Deployment, demo e documentazione

**Obiettivo:** Rendere distribuzione, demo e documentazione coerenti con l’operatività reale.

**Priorità di riferimento:** P1/P2.


### Strategia Vercel e infrastrutture alternative

- [x] **DEPLOY-1** — UI/anteprima statica pubblicabile su Vercel (`public/`, `vercel.json`) · [Dettagli](docs/ROADMAP-REFERENCE.md#10-strategia-vercel-e-infrastrutture-alternative)
- [ ] **DEPLOY-2** — Architettura split: frontend su Vercel ↔ Execution backend su host container (Render/Railway/Fly.io/Cloud Run/VPS; `docker/Dockerfile` presente), un'unica Web UI per l'utente · [Dettagli](docs/ROADMAP-REFERENCE.md#10-strategia-vercel-e-infrastrutture-alternative)
- [ ] **DEPLOY-3** — Funzioni serverless solo come proxy/BFF verso il backend (nessuno scanner su Vercel) — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#10-strategia-vercel-e-infrastrutture-alternative)
- [x] **DEPLOY-4** — Documentati segreti, endpoint backend, persistenza e sicurezza delle comunicazioni nel [runbook Themis](docs/themis-runtime.md#inventario-operativo-del-deployment) · [Dettagli](docs/ROADMAP-REFERENCE.md#10-strategia-vercel-e-infrastrutture-alternative)

### Demo professionale su Vercel

- [x] **DEMO-1** — Demo statica/fixture navigabile (panoramica, catalogo tool, pagine, report d'esempio nel formato reale) con banner «DEMO — nessuna esecuzione, dati sintetici» · [Dettagli](docs/ROADMAP-REFERENCE.md#11-demo-professionale-su-vercel)
- [ ] **DEMO-2** — Ampliare la demo: dashboard, identità visiva completa, flussi rappresentativi, grafici/visualizzazioni, esempi realistici etichettati — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#11-demo-professionale-su-vercel)
- [ ] **DEMO-3** — Quando possibile, integrare funzioni realmente eseguibili via backend dedicato (split), senza confondere live e demo · [Dettagli](docs/ROADMAP-REFERENCE.md#11-demo-professionale-su-vercel)

### Documentazione e localizzazione

- [x] **DOCS-1** — README IT/EN, docs per modulo, CLI reference generata, disclaimer d'uso · [Dettagli](docs/ROADMAP-REFERENCE.md#15-documentazione-e-localizzazione)
- [ ] **DOCS-2** — Guide Web UI per ogni tool; documentazione API completa; guida deploy split + Vercel — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#15-documentazione-e-localizzazione)
- [x] **DOCS-3** — Sito doc statico bilingue (Pages/Vercel) dalla stessa fonte `docs/` · [Dettagli](docs/ROADMAP-REFERENCE.md#15-documentazione-e-localizzazione)

**Completato quando:** I criteri DEPLOY, DEMO e DOCS sono soddisfatti, con separazione esplicita tra demo e live.


---

## Ciclo G — Quality Assurance e validazione in laboratorio

**Obiettivo:** Mantenere verifiche riproducibili, regressione, accessibilità e qualità.

**Priorità di riferimento:** P0–P3, trasversale.


### Quality Assurance e test

- [x] **QA-1** — Suite unit, contract e integration verdi su Ubuntu con Python 3.11–3.14 · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
- [ ] **QA-2** — Test end-to-end Web (browser reali), accessibilità WCAG, responsive — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-2-check-1** — Quattro test Chromium verificano gli stati degli archivi e la navigazione da tastiera su mobile e desktop · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-2-check-2** — La matrice Chromium verifica le 23 pagine HTML GET statiche, le tre pagine di dettaglio e due risposte 404 · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-2-check-3** — Due percorsi end-to-end verificano il recupero dopo un login rifiutato e il risultato dell’estrazione offline di indicatori in Metis · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-2-check-4** — Flussi dopo l'invio dei moduli (19 novembre 2026) · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [ ] **QA-2-check-5** — Resta la parità E2E del wizard guidato end-to-end (`WEB-5`, dipende da `API-3`) e la documentazione IT/EN della revisione di accessibilità · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
- [ ] **QA-3** — Validazione adapter su output reale in lab autorizzato — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
- [x] **QA-4** — Matrice OS/Python e performance/concorrenza sotto carico · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-4-check-1** — Contratti portabili superati in tutti gli otto ambienti macOS e Windows con Python 3.11–3.14 · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-4-check-2** — Profilo prestazionale standard completato su Ubuntu · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)
  - [x] **QA-4-check-3** — Avvio concorrente su database vuoto — corretto (2026-11-18) · [Dettagli](docs/ROADMAP-REFERENCE.md#14-quality-assurance-e-test)

**Completato quando:** I gate QA applicabili sono superati e le evidenze richieste sono registrate.


---

## Ciclo H — Orchestrazione AI-native multi-agente

**Obiettivo:** Evolvere lo strato AI opzionale senza sostituire i controlli deterministici.

**Priorità di riferimento:** P1–P3.


### Orchestrazione AI-native multi-agente (`AI`)

- [x] **AI-0** — (P2) Audit architetturale, gap analysis e ADR dedicato · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-1** — (P2) Strato di orchestrazione multi-agente — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-2** — (P1/P2) Model Router multi-provider — **In corso** · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-3** — (P2) Memoria/knowledge condivisa verificabile (Fact Graph): · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-4** — (P2) Agenti specializzati Red/Blue/Purple/CTI/QA + Verifier + Remediation · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-5** — (P2/P3) Self-healing / recovery: · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-6** — (P3) Console AI e osservabilità dei workflow · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)
- [ ] **AI-7** — (P1/P2) Benchmark, regression ed eval riproducibile degli agenti: · [Dettagli](docs/ROADMAP-REFERENCE.md#219-orchestrazione-ai-native-multi-agente-ai)

**Completato quando:** Sono rispettati i criteri AI e i prerequisiti deterministici, autorizzativi e di audit.


---

## Ciclo I — Evoluzioni differite

**Obiettivo:** Rivalutare le opportunità future solo sulla base dei prerequisiti e dei requisiti reali.

**Priorità di riferimento:** P4.


### Evoluzioni future

- [ ] **FUT-1** — AI assistiva (assorbita dalla famiglia AI; nessun lavoro duplicato) · [Dettagli](docs/ROADMAP-REFERENCE.md#20-evoluzioni-future)
- [ ] **FUT-2** — Ulteriori motori di scansione, solo se necessari ai workflow prioritari: criterio d'ingresso è una capability mancante in `olympus catalog` e la Definition of Done di §18, non il numero di engine · [Dettagli](docs/ROADMAP-REFERENCE.md#20-evoluzioni-future)
- [ ] **FUT-3** — Evoluzione verso microservizi, solo con un requisito misurato di scalabilità, isolamento o manutenzione; il monolite modulare (§3) resta l'architettura di riferimento e `ARCH-3` precede qualunque separazione · [Dettagli](docs/ROADMAP-REFERENCE.md#20-evoluzioni-future)

**Completato quando:** Ogni opportunità è rivalutata e la decisione documentata secondo i criteri FUT.


---


## Requisiti trasversali (continui, non milestone)

- [ ] Preservare scope, autorizzazione, isolamento, audit e fail-closed.
- [ ] Mantenere test, coverage, quality gate e documentazione IT/EN.
- [ ] Distinguere osservazioni, risultati deterministici, correlazioni e ipotesi; non sovrastimare maturità o validazione.
- [ ] Proteggere segreti, privacy, cronologia Git e integrità delle evidenze.
- [ ] Applicare la Definition of Done e verificare lo SHA effettivo.

Questa checklist sintetizza i vincoli originari e resta aperta perché continua.

## Avanzamento per ciclo

Conteggio dei soli task padre; ricavato dagli stati originali, non da una verifica tecnica nuova.

| Ciclo | Completati | In corso | Da fare | Totale |
|---|---:|---:|---:|---:|
| Ciclo A — Integrità, sicurezza e governance degli engine | 10 | 5 | 2 | 17 |
| Ciclo B — Architettura, Execution Engine e persistenza | 7 | 8 | 0 | 15 |
| Ciclo C — Capacità Red, Blue e Purple Team | 2 | 6 | 0 | 8 |
| Ciclo D — Correlazione, spiegabilità e validazione continua | 0 | 7 | 0 | 7 |
| Ciclo E — Web UI ed esperienza operativa | 2 | 6 | 0 | 8 |
| Ciclo F — Deployment, demo e documentazione | 5 | 3 | 2 | 10 |
| Ciclo G — Quality Assurance e validazione in laboratorio | 2 | 2 | 0 | 4 |
| Ciclo H — Orchestrazione AI-native multi-agente | 1 | 2 | 5 | 8 |
| Ciclo I — Evoluzioni differite | 0 | 0 | 3 | 3 |
| **Totale** | **29** | **39** | **12** | **80** |

---

© Chiara Berti — 2026

# Triage di chiusura per criterio — 2026-11-27

Companion operativo del [Piano di chiusura per dipendenze](../ROADMAP.md#piano-di-chiusura-per-dipendenze).
Mentre il piano ordina le tappe `T*` per dipendenze, questo documento classifica le
**voci aperte** per *criterio di chiusura*: capire in anticipo quali hanno già codice e
test sufficienti e quali no è il primo risparmio, perché evita di aprire una sessione di
sviluppo su ciò che è bloccato altrove.

La classificazione si basa sullo stato già committato in [ROADMAP](../ROADMAP.md) e
[ROADMAP-REFERENCE](ROADMAP-REFERENCE.md), sul ledger di
[maturità scanner](scanner-maturity.md) (gate automatico) e su verifiche puntuali del
codice. Dove la riga dice **da confermare**, serve una rilettura di codice+test prima di
promuovere lo stato: non è ancora un'evidenza, è un candidato.

Vocabolario di verifica invariato (`docs/ROADMAP-REFERENCE.md`): `implementato` →
`verificato offline` → `verificato in CI` → `validato in lab` → `operativo`. Una voce i cui
criteri richiedono `validato in lab` non diventa `[x]` solo perché il codice esiste o i test
offline passano.

## Convenzione per le voci bloccate su laboratorio (Bucket 2)

Per ogni voce il cui criterio di chiusura richiede un laboratorio autorizzato, traffico
live, infrastruttura esterna o un'azione dell'owner:

1. **Implementare e verificare la fetta offline** (adapter con porte iniettate, contratti,
   test deterministici) e portarla fino a `verificato in CI`.
2. **Lasciare la voce `[~]`** con annotato, in modo esplicito: il livello massimo raggiunto
   (mai oltre `verificato in CI`), *cosa* manca (accesso lab / server live / infra / owner) e
   *quale prova* chiuderebbe la fetta residua.
3. **Non riaprire** la voce come «codice da scrivere»: la parte residua non è sviluppo, è
   accesso esterno. Così nessuna sessione futura ci spende lavoro di codice.

Questo mantiene veri gli stati (`partial`/`[~]` mai spacciati per puliti) e rende il blocker
una decisione tracciata, non una dimenticanza.

## Bucket 0 — Codice e test già sufficienti (chiusura a costo basso)

Manca solo una passata di verifica, la documentazione o la promozione dello stato. Nessun
laboratorio. È qui il risparmio immediato.

| Voce | Evidenza già presente | Residuo per `[x]` | Confidenza |
|---|---|---|---|
| **TOOLS-4.1** Preflight fail-closed | ~~Preflight condiviso cablato su CLI, API, Web, worker, Athena e TUI; sei motivi di blocco (exit 8) e job degradato (exit 5, parziale persistente) con audit e stato persistente.~~ **Chiuso `[x]` il 2026-11-27**: accettazione completa in CI (zero-traffico per interfaccia, parità e vocabolario `{0,5,8}` reificati) e clausola lab coperta dall'evidenza L3 committata. | — | — |
| **TOOLS-4.5** Evidenze firmate e coerenza tra percorsi | ~~Produttore/verificatore condivisi, firma Ed25519, tentativi immutabili; catena job→audit→report provata offline.~~ **Chiuso `[x]` il 2026-11-27**: catena job→audit→evidenza→report Vulcan provata offline (test API) + rotazione provata; procedura rotazione/revoca documentata nel runbook; clausola lab coperta dall'evidenza L3 committata. | — | — |
| **ARCH-3** Execution Engine come servizio documentato | ~~Job, worker, coda, cancellazione, `EngineHealth`: implementati e molto testati.~~ **Chiuso `[x]` il 2026-11-27**: deliverable completo (ADR-009, osservabilità, preflight ed evidenze firmate nel motore). Backpressure/checkpoint e tetti risorse confermati fuori scope (API-3/TOOLS-4.3). | — | — |

## Bucket 1 — Chiudibili ora con sviluppo offline

Lavoro reale ma interamente verificabile qui e in CI, senza laboratorio. È dove va speso il
grosso del tempo produttivo.

- **INT-3 / ARCH-4 / API-2** — contratto I/O tipizzato per *tutti* i tool: estendere il
  pattern già usato per Themis, riusando schema catalog e golden.
- **TOOLS-4.2** (`engines doctor --strict`) e **TOOLS-4.3** (risorse, timeout, profili per
  engine): il preflight ispeziona l'host tramite `Environment` iniettato, quindi offline.
- **WEB-2 / WEB-3** pagine operative per i tool mancanti; **WEB-5 / WEB-6 / WEB-7 / WEB-8**
  wizard e modalità avanzata (WEB-5 dipende da API-3). I test Chromium di QA-2 girano offline
  su loopback.
- **CORR-1** (contratto dati) — **chiuso `[x]` il 2026-11-27**: alla verifica il modello di
  correlazione risultava già completo (5 kind, classi epistemiche, contratto pubblicato, test
  anti-promozione, documento KG); i residui del suo "Resta" erano scope di `CORR-2`. **EXPL-1**
  (contratto dati): avanzato (campo `verifications`, contratto 1.1.0); resta la provenance
  engine-run (DEC-7), tracciata. **CORR-2** ed **EXPL-2** — **chiusi `[x]` il 2026-11-27**:
  motore/superfici di correlazione (audit via middleware API, no-network test, budget misurato)
  e spiegabilità su CLI/API/Web/report (parità con un unico core) completi; la UX trasversale
  più ampia resta scope di `WEB-8`.
- **DATA-2 / TECH-3** astrazione repository con backend Postgres opzionale: astrazione più
  test con backend iniettato, senza database reale in CI.
- **API-3** (retry, backpressure, checkpoint, cancellazione) e **API-4** (CORS/origin, auth
  multiutente); **ARCH-2** (formalizzare i confini `domain → application → ports → adapters`).
- **AI-2** (model router), **AI-3** (fact graph), **AI-7** (eval): fondamenta T12, offline con
  provider finti. Poi **AI-1 / AI-4 / AI-5 / AI-6** (orchestrazione, T13).
- **DEMO-2** (ampliamento della demo statica a fixture), **DOCS-2** (guide Web/API/deploy).
- Fette offline di **RED-1/2/3** (adapter), **BLUE-2** (connettori con porte iniettate),
  **VAL-1** (asset diff), **VAL-3** (metriche di copertura).

## Bucket 2 — Bloccate su laboratorio, live, infra esterna o azione owner

Non chiudibili qui né in CI. Si applica la convenzione sopra: fetta offline più blocker
esplicito.

| Voce | Blocker |
|---|---|
| **SEC-3** | Egress scanner/DNS a livello kernel/container: richiede validazione in laboratorio. |
| **TOOLS-3** | Promozione adapter a `live-tested` con evidenza committata (lab). Ledger attuale: 12 live-tested, 3 offline-tested, 1 adapter-ready, 8 catalog-only, 0 production-ready. |
| **QA-3** | Validazione adapter su output reale in lab autorizzato. |
| **RED-1 / RED-2 / RED-3** | Fetta *live*: esecuzione reale contro bersagli autorizzati. Gli adapter offline stanno nel Bucket 1. |
| **BLUE-2-check-3** | Microsoft Sentinel: ingest Azure e rilettura live. |
| **BLUE-3** | CTI live (TAXII 2.1, MISP, OpenCTI): richiede server reali. |
| **PURPLE-1** | Workflow Purple autorizzato end-to-end (profilo `labs/mars` già presente). |
| **VAL-2** | Retest autorizzato con remediation verificata (lab). |
| **CICD-3** | Pubblicazione PyPI via Trusted Publishing: environment e azione owner. |
| **DEPLOY-2 / DEPLOY-3 / DEMO-3** | Backend di esecuzione su host container esterno e proxy serverless: infrastruttura e owner. |

## Dove sta il risparmio

1. **Raccogliere il Bucket 0** per primo (a partire da TOOLS-4.1, già verificato): chiusure
   P0 senza nuovo codice rischioso.
2. **Non trattare il Bucket 2 come sviluppo**: chiudere la fetta offline, marcare il blocker,
   fermarsi.
3. **Ordinare il Bucket 1 per dipendenze**: i contratti (INT-3, ARCH-4, EXPL-1, CORR-1)
   sbloccano Web, correlazione e AI a valle, quindi hanno il ritorno più alto.

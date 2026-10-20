# Roadmap di prodotto — OLYMPUS-SECURITY

> **Direzione:** evolvere Olympus in una piattaforma Red/Blue/Purple Team autorizzata, usabile via CLI, TUI e web. Le interfacce che la valutazione sceglierà di mantenere devono rispettare gli stessi requisiti di sicurezza, autorizzazione, scope, audit e qualità dei risultati.
>
> **Snapshot:** 20 ottobre 2026. Gli stati riprendono il cruscotto della roadmap precedente; prima di iniziare ogni issue il team verifica il codice e aggiorna lo stato con prove. La presenza di un modulo o di un adapter non dimostra che sia pronto per uso operativo.

## Mandato di valutazione architetturale

Il repository contiene già CLI, TUI, API FastAPI e web control plane THEMIS/Jinja2 con aggiornamenti SSE. Queste sono prove dello stato attuale, non vincoli sulla soluzione futura.

Il team deve stabilire quale prodotto e architettura servono meglio agli utenti e agli obiettivi di sicurezza. Può raccomandare di mantenere e migliorare l'impianto, migrare gradualmente, sostituire linguaggi e framework, oppure riprogettare il prodotto e ricostruirne parti da zero. Nessuna opzione è esclusa in partenza.

La decisione deve confrontare alternative concrete rispetto a requisiti e prove: sicurezza e isolamento, esperienza d'uso web, accessibilità e localizzazione, funzionalità desktop/CLI, prestazioni, facilità di installazione e aggiornamento, manutenzione, competenze disponibili, costo e rischio della migrazione, integrazione degli scanner e qualità dei test. Motivare la scelta, riportare trade-off e condizioni che potrebbero farla cambiare.

Gli obiettivi di prodotto restano: consentire a un utente autorizzato di gestire engagement, scope, asset, valutazioni, job, risultati ed evidenze tramite una UI comprensibile, conservando interfacce automatizzabili quando sono utili.

## Regole per mantenere questa roadmap

- Gli ID `SEC-*`, `DEV-*`, `WEB-*`, `UX-*`, `OPS-*` tracciano il lavoro esistente. Il team può mantenerli, accorparli o sostituirli se la soluzione lo richiede, documentando la corrispondenza e conservando la storia.
- Lo stato iniziale del vecchio cruscotto era: Baseline/qualità parziali; Security hardening parziale; architettura/release parziali; UX operativa aperta; capability Red/Blue/Purple parziali; production readiness scanner aperta; distribuzione/observability parziali; fase Web in corso, con `WEB-A`…`WEB-E` indicate completate e `WEB-F`…`WEB-J` residue. Verificare l'effettivo stato di ciascun intervento contro `main` prima di pianificarlo.
- `[x]` richiede prove nel codice, test e documentazione; `[~]` indica un risultato parziale con gap esplicito; `[ ]` non implementato; `[⏸]` bloccato da prerequisito nominato.
- Ogni attività deve avere scope, dipendenze, criteri d'accettazione osservabili e piano di test. Aggiornare dashboard e descrizione nella stessa PR.
- `upgrade.md` conserva lo storico. Questa è la fonte per lavoro futuro.

## Obiettivo di prodotto

Con un percorso guidato, un utente autorizzato deve poter:

1. creare un engagement e registrare proprietario, autorizzazione, perimetro e scadenza;
2. vedere gli asset e le relative fonti di provenienza;
3. selezionare solo capacità realmente installate e verificate, distinguendo scansioni passive, attive e intrusive;
4. esaminare target risolti, scope, impatto, limiti e durata prevista prima di confermare;
5. avviare, seguire e annullare job con stati comprensibili, senza invio di comandi shell arbitrari;
6. consultare findings, evidenze, copertura, audit trail e report esportabili;
7. ripetere il flusso da CLI o TUI con gli stessi controlli e risultati strutturati.

Uso mobile: consultazione e monitoraggio responsive. Configurazione di assessment e gestione dettagliata restano ottimizzate per desktop.

## Fasi e priorità

### Fase 0 — Baseline verificata e piano incrementale `[~]`

**Riferimenti:** `DEV-G`, `DEV-H`, `DEV-C`.

- Confrontare tutte le voci con codice, test, workflow CI e documenti su `main); eliminare conteggi e affermazioni obsolete.
- Ricostruire le dipendenze tra moduli nativi, API, web, CLI, TUI e alberi vendor.
- Per ogni adapter scanner, riportare separatamente stato catalogato, adattato, disponibile, pronto e verificato su lab autorizzato.
- Aprire issue per i gap con criteri d'accettazione, rischio, dipendenze e responsabile; conservare gli ID stabili.
- Verificare che `make check` e gli altri gate documentati corrispondano alla CI attuale.

**Accettazione:** ogni item della roadmap ha uno stato verificato o è marcato come da riesaminare; ogni claim di readiness è collegato a un test o a una prova riproducibile.

### Fase 1 — Confini di sicurezza e autorizzazione `[~] P0`

**Riferimenti:** `SEC-A`, `SEC-B`, `SEC-C`, `SEC-G`, `SEC-H`, `UX-B`.

- Completare il ritiro delle superfici/runtime legacy e dimostrare parità delle funzioni che si mantengono.
- Applicare isolamento egress per scanner e valutare seccomp/AppArmor o controlli equivalenti; non dichiarare un confine forte se non è imposto dal runtime.
- Rendere gli engagement manifest verificabili, con scope, approvatore, scadenza e revoca; bloccare l'esecuzione alla scadenza o se i target effettivi escono dal perimetro.
- Rendere il dry-run e la classificazione d'impatto coerenti tra interfacce; ogni azione attiva presenta target risolti, scope, profilo, limiti e conseguenze e richiede conferma proporzionata.
- Fuzzare e testare i parser di dati controllati dal target (XML, banner, output scanner); neutralizzare input ostile in terminale, web, report e log.
- Conservare cancellazione affidabile dei processi, limiti di risorse, redazione, audit e gestione esplicita della copertura parziale.

**Accettazione:** test avversari provano out-of-scope, redirect/DNS rebinding, input malevolo, output eccessivo, timeout, annullamento e revoca. Nessuna interfaccia può aggirare policy o scope.

### Fase 2 — Architettura e fondamenta di prodotto `[~] P0/P1`

**Riferimenti:** `DEV-A`, `DEV-D`, `DEV-I`, `WEB-B`, `WEB-C`, `WEB-H`, `SEC-A`.

- Definire requisiti funzionali e non funzionali prima di scegliere confini, linguaggi, framework, database, modello di deployment e architettura.
- Confrontare: evoluzione dell'impianto corrente, migrazione significativa e riprogettazione/riscrittura mirata o completa. Stimare costi, tempi, rischi, debito tecnico, sicurezza e transizione.
- Progettare il modello dati per engagement, scope, asset, job, findings ed evidenze, con provenienza, migrazioni e recupero; riusare i contratti correnti solo se soddisfano i requisiti.
- Stabilire i confini tra interfacce, dominio, API e runtime; evitare endpoint generici che eseguono comandi arbitrari.
- Scegliere storage e distribuzione sulla base di concorrenza, affidabilità, installazione e operatività misurate, non sulla familiarità con lo stack esistente.
- Definire un percorso per migrare o sostituire gli elementi esistenti e criteri di ritiro verificabili.

**Accettazione:** percorso end-to-end testato attraverso API/web e CLI sullo stesso store e gli stessi servizi; nessuna perdita di scope, audit o versionamento nei passaggi.

### Fase 3 — Flussi web e UX affidabili `[~] P1`

**Riferimenti:** `WEB-A`…`WEB-E` (verificare stato), `WEB-G`, `WEB-J`, `UX-A`…`UX-G).

- Chiudere i flussi di engagement, findings, strumenti e wizard con stati vuoti, errori, caricamento, successo e copertura parziale.
- Migliorare la dashboard con job recenti, trend leggibili, findings prioritari e collegamenti alle evidenze; ogni numero mostra periodo e fonte.
- Guidare l'utente in scope e profilo di assessment, mostrare preview di rischio e rendere la conferma esplicita e non ambigua.
- Aggiungere filtri, ricerca, stato/assegnatario, deduplicazione, cronologia e confronto tra assessment; preservare evidenze e provenienza.
- Rendere lingua IT/EN coerente fra web, TUI, CLI help e messaggi; nessun testo essenziale o stato deve dipendere solo dal colore.
- Verificare accessibilità WCAG 2.2 AA: tastiera e screen reader, focus visibile, contrasto, label, errori comprensibili, tabelle utilizzabili e reduced motion.
- Validare i flussi con persone che non conoscono i nomi interni dei moduli greci.

**Accettazione:** test browser sui percorsi principali e controlli automatici più revisione manuale di tastiera e screen reader; completamento wizard e annullamento job senza usare terminale.

### Fase 4 — Lavori e integrazioni verificabili `[~] P1`

**Riferimenti:** `WEB-F`, `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE`, `OPS-SCAN`, `DEV-B`.

- Progettare Smart Scan come piano esplicito con selezione di capacità pronte, prerequisiti, ordine, limiti, costo/tempo stimato e approvazione; nessuna scansione nascosta o espansione automatica dello scope.
- Rendere scheduler, worker e recupero job idempotenti, cancellabili, osservabili e con isolamento coerente; documentare i limiti di concorrenza per processo/nodo.
- Crescere gli adapter uno alla volta. Un adapter non è production-ready finché test di lab autorizzato, timeout, parsing ostile, coverage, documentazione e compatibilità non passano.
- Ampliare i flussi Blue/Purple su eventi normalizzati, CTI e DFIR senza confondere simulazione con attività live.
- Preferire integrazioni piccole e sostituibili; non introdurre un modulo di dominio o dipendenza infrastrutturale senza caso d'uso e costo di manutenzione espliciti.

**Accettazione:** ogni esecuzione registra capacità realmente invocata, versione, stato, scope, limiti, output normalizzato, errori e copertura; la modalità offline non simula successo live.

### Fase 5 — Evidenze, risultati e report `[~] P1/P2`

**Riferimenti:** `SEC-E`, `WEB-I`, `UX-F`, `WEB-C`.

- Collegare ogni finding all'assessment, asset, adapter, timestamp e riferimenti alle evidenze; calcolare digest e rendere visibili provenienza e integrità.
- Completare export JSON/CSV/HTML/PDF/SARIF dove applicabile, con escaping, redazione e metadati di copertura.
- Distinguere chiaramente “nessun risultato” da “scansione incompleta”, errore o capacità non disponibile.
- Aggiungere confronto tra run e notifiche solo dopo aver definito semantica, permessi e gestione dei falsi positivi.

**Accettazione:** un report può essere ricostruito dai dati persistiti; output verificato contro XSS, injection, segreti e affermazioni di copertura fuorvianti.

### Fase 6 — Release, supply chain e operazioni `[~] P1/P2`

**Riferimenti:** `SEC-D`, `SEC-F`, `SEC-I`, `DEV-C`, `DEV-E`, `DEV-F`, `DEV-G`.

- Completare controlli CI bloccanti coerenti con la policy: test, type/lint, coverage, dependency audit, secret scanning, SAST e build pulita.
- Firmare release e immagini e pubblicare attestazioni/provenienza verificabili; documentare rotazione credenziali e risposta agli incidenti.
- Monitorare errori, code, durata, cancellazioni e coverage con log/metriche redatti e accesso protetto.
- Testare installazione e aggiornamento su ambiente pulito; documentare backup, restore e compatibilità.
- Pubblicare solo capability e piattaforme supportate da prove, senza sovrastimare la prontezza.

**Accettazione:** release riproducibile, SBOM, attestazione/firma verificabile, note di rilascio, procedura di upgrade e restore provata.

## Registro compatto degli interventi esistenti

| ID | Ambito | Priorità | Stato ereditato dal cruscotto precedente |
| --- | --- | --- | --- |
| `SEC-A` | ritiro runtime VAP legacy | P0 | Parziale |
| `SEC-B` | isolamento scanner | P0 | Parziale |
| `SEC-C` | engagement manifest firmato | P1 | Parziale |
| `SEC-D` | credenziali e identità | P1 | Da verificare |
| `SEC-E` | integrità e catena di custodia | P1 | Da verificare |
| `SEC-F` | supply chain e firme release | P1 | Parziale |
| `SEC-G` | guardrail capacità offensive | P1 | Da verificare |
| `SEC-H` | input ostile dei target | P1 | Parziale |
| `SEC-I` | sicurezza operativa progetto | P2 | Da verificare |
| `DEV-A`…`DEV-I` | architettura, contratti, qualità, release e governance | P0–P2 | Usare prove per ogni ID |
| `WEB-A`…`WEB-E` | control plane, engagement, findings, tools, wizard | P0/P1 | Segnate concluse; riconvalidare |
| `WEB-F`…`WEB-J` | smart scan, dashboard/i18n, persistenza, reporting, operabilità | P2 | Aperte |
| `UX-A`…`UX-G` | form, safety preview, wizard, monitoraggio, accessibilità, report, onboarding | P0–P2 | Aperte o parziali, verificare |
| `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE`, `OPS-SCAN` | capability operative | P1 | Parziali |

## Definition of Done comune

Un intervento si chiude solo quando:

1. codice e test coprono esiti positivi, errori, input ostile, annullamento e confini d'autorizzazione pertinenti;
2. la CLI, la TUI, l'API e la UI interessate usano gli stessi servizi e rispettano la stessa policy;
3. documentazione e schemi sono aggiornati; cambi di contratto hanno versionamento e migrazione;
4. output, log, report e telemetria non espongono segreti o dati non autorizzati;
5. accessibilità e traduzioni sono verificate per ogni flusso UI modificato;
6. la CI pertinente passa e la PR collega ID, prove e rischi residui;
7. ogni limitazione è visibile all'utente e non viene presentata come successo o copertura completa.

## Rischi da tenere visibili

- Un catalogo ampio di scanner può sembrare più maturo delle prove reali: pubblicare lo stato di readiness per singola capability.
- Un control plane web aumenta la superficie d'attacco: minimizzare endpoint e privilegi, mantenere protezioni CSRF/sessione e testare output ostile.
- Parallelismo e storage distribuito complicano audit e consistenza: introdurli solo dopo requisiti concorrenti misurati.
- La sostituzione di superfici legacy può perdere flussi in uso: confronto e migrazione prima della rimozione.
- Le scansioni attive possono impattare sistemi: scope, limiti, preview e conferma devono essere enforcement applicativo e runtime, non solo UX.

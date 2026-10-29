# 🏛️ OLYMPUS-SECURITY Roadmap

> **Obiettivo:** consolidare Olympus come piattaforma Red/Blue/Purple Team sicura,
> verificabile, distribuibile e usabile in contesti professionali autorizzati.
>
> **Stato rilevato:** audit trasversale del branch `main` effettuato il 28 ottobre 2026 (baseline `b5cc491`).
> Le priorità qui indicate sono basate sul codice e sulla documentazione realmente
> presenti nel repository, non sulla precedente versione monolitica `OLYMPUS.py`.

## Riconciliazione audit 2026-10-28

Questa sezione è lo **stato canonico aggiornato** delle disposizioni dell'audit;
prevale sulle descrizioni storiche delle sezioni successive. Gli ID madri restano
stabili; gli ID figli identificano incrementi autonomi. [Audit](docs/ecosystem-audit.md),
[inventario baseline](docs/verify/audit-2026-10-28-inventory.json) e
[verifiche](docs/verification-status.md) distinguono osservazione da dimostrazione.
Nessun conteggio storico di test, adapter o claim CI costituisce prova attuale.

Correzioni di stato: `SEC-D` riaperto `[~]` per log TUI; `DEV-B` `[~]` per wiring
runtime/abstract/duplicati oltre alla firma; `DEV-G`/`DEV-H` `[~]` per deriva e ADR;
`UX-A` schema implementato ma consumer TUI/Web mancanti; `OPS-PURPLE` matrice
presenza telemetria implementata, catena tecnica→regola→test non completata.
`UX-G` doctor globale già implementato; resta onboarding. `UX-F` report multilivello
presente in Vulcan/Web, resta validazione utenti. `SEC-A`/`DEV-A` runtime nativo
presente; `D3` non è più bloccato dall'assenza vendor, eventuale parità storica resta
nel manifest dedicato. `[x]` indica criteri testati nello scope indicato, non
production readiness. I gate CI, SBOM/hash lock e wheel automatici delle vecchie
sezioni sono **non attivi** dopo rimozione workflow: `DEV-C-01` aperto.

Milestone aggiornate: **M1** integrità dati/controlli locali e claim verificabili;
**M2** confinamento e stato affidabile; **M3** flussi end-to-end, recovery e UX;
**M4** integrazioni/release/scalabilità motivate. Uscita = tutti i criteri delle
slice associate soddisfatti con evidenze, senza promuovere attività bloccate.
Priorità: `SEC-E-01` P0 riprodotto e indipendente per primo; `SEC-B-01` P0 rimane
bloccato per validazione kernel/lab e richiede implementazione articolata. Nessun
P1 sostituisce il P0 implementabile. Dipendenze solo tra figli o prerequisiti D;
D1–D13 sono gate esterni, non completamenti delle madri (evita cicli).

Campi comuni per tutte le schede: tipo **correzione** salvo DEV-C/DEV-D/WEB-J/UX-A/
UX-E/OPS-SCAN (**integrazione/verifica/potenziamento**); incertezza media, alta
per L/XL e per lab; DoD = criteri+test indicati, documentazione IT/EN pertinente,
nessun segreto, diff revisionato, commit tracciato e stato remoto esplicito.
I dettagli sotto sono normativi per ciascuna riga, non task generici senza owner.

| ID | Titolo | Priorità | Owner | Taglia | Milestone | Stato |
|---|---|---|---|---|---|---|
| `SEC-E-01` | Audit Athena durevole dopo restart | P0 | Data/Backend/AppSec | M | M1 | [x] |
| `SEC-B-01` | Egress scanner e DNS vincolati allo scope | P0 | Security/Scanner/SRE | XL | M2 | [⏸] |
| `SEC-H-01` | Rifiuto directory symlink API | P1 | AppSec/Backend | S | M1 | [ ] |
| `SEC-H-02` | Letture FIFO non bloccanti | P1 | AppSec/Backend | S | M1 | [ ] |
| `SEC-D-01` | Redazione argomenti nel log TUI | P1 | AppSec/UX | S | M1 | [ ] |
| `SEC-G-01` | Cancellazione TUI completa | P1 | Backend/QA | M | M2 | [ ] |
| `DEV-E-01` | Transizioni Athena concorrenti e audit atomico | P1 | Data/Architect | L | M2 | [ ] |
| `SEC-E-02` | Verifica digest risultati in lettura | P1 | Data/AppSec | S | M1 | [ ] |
| `DEV-B-01` | Plugin concreti e realmente integrati | P1 | Scanner/Architect | L | M3 | [ ] |
| `DEV-D-01` | Versionamento fisico degli store | P1 | Data | L | M3 | [ ] |
| `WEB-J-01` | Backup e restore coordinato | P1 | Data/SRE/Privacy | L | M3 | [ ] |
| `WEB-J-02` | Retention e privacy di sistema | P2 | Privacy/Data | L | M3 | [ ] |
| `DEV-C-01` | Ripristino enforcement qualità e release | P1 | QA/SRE | L | M1 | [ ] |
| `SEC-F-01` | Build scanner riproducibile e licenze | P1 | SRE/Governance | L | M2 | [⏸] |
| `SEC-F-02` | Chiusura dipendenze SBOM conforme ai marker | P1 | Supply-chain/Backend | M | M1 | [ ] |
| `DEV-G-01` | Riconciliazione dichiarazioni e inventario | P1 | Writer/QA/Product | M | M1 | [~] |
| `UX-A-01` | Parità TUI e consumer form | P1 | UX/Frontend/Product | L | M3 | [ ] |
| `WEB-A-01` | Ripresa SSE visibile | P1 | Frontend/Backend | M | M3 | [ ] |
| `WEB-B-01` | Store guasto distinto da vuoto | P1 | Frontend/UX | M | M3 | [ ] |
| `WEB-G-01` | Conteggi dashboard corretti | P2 | Data/Frontend | S | M3 | [ ] |
| `OPS-PURPLE-01` | Coverage telemetria distinta da detection | P1 | Detection/QA | M | M2 | [ ] |
| `UX-E-01` | Accessibilità e parità IT/EN dimostrate | P1 | Accessibility/I18n/QA | L | M3 | [ ] |
| `DEV-E-02` | Modello single-node e soglie scalabilità | P2 | Architect/SRE | L | M4 | [ ] |
| `DEV-E-03` | Allocazione ID atomica engagement/finding | P2 | Data/Backend | M | M3 | [ ] |
| `OPS-SCAN-01` | Integrazioni motivate e promozione maturità | P2 | Product/Scanner/Blue | XL | M4 | [⏸] |

### SEC-E-01 — Audit Athena durevole dopo restart

- Componente/superfici: Athena / CLI.
- Problema/evidenza: Dinamica: sqlite.append_audit sostituisce la stessa chiave; coordinator._sequence riparte da zero.
- Gravità/probabilità/impatto e motivo P0: Perdita dello storico durante recover/cancel; probabilità alta al riavvio, impatto probatorio alto.
- Soluzione: INSERT rigoroso e allocazione sequenza atomica nel sink persistente.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Duplicati rifiutati; prefisso invariato dopo recover/cancel; due connessioni senza perdita.
- Test: unit duplicate/rollback/concurrency e integrazione CLI restart.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

Implementazione 2026-10-29: `append_audit(..., sequence=None)` assegna la
sequenza sotto `BEGIN IMMEDIATE`; il sink persistente non usa il contatore locale.
INSERT esplicito rifiuta duplicati. Quattro regressioni fallivano prima della
correzione; 51 test mirati sono passati il 28 ottobre. Verifica finale sul merge: 51 test mirati passati, lint/type/schema/mutation
passati. La slice è `[x]`; la suite generale mantiene gli stessi 17 fallimenti
ambientali baseline (2468 passati), non è dichiarata verde. [ADR-008](docs/architecture/adr-008-durable-athena-audit.md).
Nessuna migrazione; prefisso esistente preservato, eventi già persi non recuperati.
La madre `SEC-E` e l'atomicità stato/audit `DEV-E-01` restano aperte.

### SEC-B-01 — Egress scanner e DNS vincolati allo scope

- Componente/superfici: Themis / container / adapter.
- Problema/evidenza: Statica: base.py valida DNS; nmap.py usa ancora hostname; scan-egress senza allowlist.
- Gravità/probabilità/impatto e motivo P0: Possibile traffico fuori scope; impatto critico, probabilità dipende dal motore; exploit non eseguito.
- Soluzione: Pinning compatibile con ogni protocollo ed egress per-job fail-closed.
- Dipendenze/blocchi: D1,D11: runtime isolato e lab.
- Accettazione misurabile: DNS variabile, redirect e endpoint non autorizzato non ricevono traffico; cancellazione pulisce policy.
- Test: lab negativo packet capture; nessun mock come prova egress.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-H-01 — Rifiuto directory symlink API

- Componente/superfici: Themis API/Web.
- Problema/evidenza: Statica e semantica stdlib: api.ApiSettings.validate resolve prima di is_symlink.
- Gravità/probabilità/impatto e motivo P1: Controllo inefficace su directory configurate; impatto alto, probabilità dipende da accesso locale.
- Soluzione: Validare path originale e documentare parent symlink/TOCTOU.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Quattro directory rifiutano link validi/rotti; directory normali accettate.
- Test: test startup API parametrizzati.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-H-02 — Letture FIFO non bloccanti

- Componente/superfici: core.fileio / consumer.
- Problema/evidenza: Primitiva OS riprodotta: open FIFO blocca prima di fstat; fileio.py:65,110.
- Gravità/probabilità/impatto e motivo P1: DoS locale con input speciale; probabilità condizionata, impatto disponibilità alto.
- Soluzione: Aprire senza blocco e verificare descriptor; mantenere no-follow e limiti.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Entrambe le API rifiutano FIFO entro deadline; file normali e link testati.
- Test: subprocess locale con timeout e cleanup.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-D-01 — Redazione argomenti nel log TUI

- Componente/superfici: TUI / core.
- Problema/evidenza: Statica: tui/app.py stampa argv grezzo.
- Gravità/probabilità/impatto e motivo P1: Potenziale esposizione token/URL nel terminale; probabilità condizionata, impatto alto.
- Soluzione: Formatter condiviso redatto senza alterare argv eseguito.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Token sintetici assenti da log e errori; comando riceve argomenti originali.
- Test: pilot TUI e URL/userinfo/query fixtures.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-G-01 — Cancellazione TUI completa

- Componente/superfici: TUI / subprocess.
- Problema/evidenza: Statica: terminate solo figlio immediato, nessun gruppo/cleanup robusto.
- Gravità/probabilità/impatto e motivo P1: Rischio figli sopravvissuti, non riprodotto; impatto alto.
- Soluzione: Lifecycle gruppo processi e terminate/wait/kill bounded multipiattaforma.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Nessun figlio sintetico resta dopo cancel/errore/chiusura.
- Test: processi locali e test Windows/POSIX.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-E-01 — Transizioni Athena concorrenti e audit atomico

- Componente/superfici: Athena / SQLite.
- Problema/evidenza: Statica: transizioni senza CAS; stato e append audit in transazioni separate.
- Gravità/probabilità/impatto e motivo P1: Race o crash può lasciare stato senza audit; rischio dedotto alto.
- Soluzione: CAS sullo stato persistito e unità di lavoro stato+audit; outbox se necessaria.
- Dipendenze/blocchi: SEC-E-01.
- Accettazione misurabile: Due writer non applicano transizioni incompatibili; fault injection non perde audit di stato.
- Test: concorrenza e crash injection.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-E-02 — Verifica digest risultati in lettura

- Componente/superfici: Athena / result store.
- Problema/evidenza: Statica: load_result legge document senza sha256/length salvati.
- Gravità/probabilità/impatto e motivo P1: Corruzione JSON valida non rilevata; probabilità non misurata, impatto alto.
- Soluzione: Verificare digest/lunghezza e binding identity prima del consumo.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Alterazione sintatticamente valida rifiutata; risultato integro leggibile.
- Test: tamper e compatibilità.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-B-01 — Plugin concreti e realmente integrati

- Componente/superfici: Themis/Athena/preview/capabilities.
- Problema/evidenza: Dinamica: classe astratta accettata; statica: available_adapters non consumata dal runtime.
- Gravità/probabilità/impatto e motivo P1: Plugin dichiarato integrato non eseguibile; impatto funzionale alto.
- Soluzione: Rifiuto abstract/duplicati; resolver unico, metadata distribuzione/versione; no override native.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Plugin fixture percorre preview/run/capabilities; duplicati/abstract rifiutati prima import quando possibile.
- Test: contract plugin, fake offline; provenienza firmata resta SEC-F.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-D-01 — Versionamento fisico degli store

- Componente/superfici: Athena/engagements/findings.
- Problema/evidenza: Statica: CREATE IF NOT EXISTS; solo job store ha user_version.
- Gravità/probabilità/impatto e motivo P1: Upgrade futuro non controllato; rischio dedotto.
- Soluzione: Versioni fisiche, migrazioni transazionali e rifiuto schema futuro.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Fixture vecchie migrate senza perdita; future rifiutate; rollback documentato.
- Test: upgrade/interruption/restore.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### WEB-J-01 — Backup e restore coordinato

- Componente/superfici: Tutti gli store/evidenze/identità.
- Problema/evidenza: Statica: backup Metis parziale; verify_backup non esegue integrity_check/FK.
- Gravità/probabilità/impatto e motivo P1: Recovery piattaforma non dimostrato; impatto alto.
- Soluzione: Snapshot coerente con digest/versioni, chiavi separate, integrity/FK e restore drill.
- Dipendenze/blocchi: DEV-D-01.
- Accettazione misurabile: Ripristino engagement/job/finding/custody coerente; RPO/RTO misurati su dataset dichiarato.
- Test: backup concorrente, corruzione, restore in directory pulita.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### WEB-J-02 — Retention e privacy di sistema

- Componente/superfici: core/Metis/Minerva/store/backup.
- Problema/evidenza: Statica: primitive retention presenti, applicazione globale non dimostrata.
- Gravità/probabilità/impatto e motivo P2: Policy diverse possono cancellare prove o lasciare copie; rischio dedotto.
- Soluzione: Policy per engagement, legal hold, minimizzazione, chiavi e backup; documentare accessi e finalità.
- Dipendenze/blocchi: WEB-J-01.
- Accettazione misurabile: Dry-run/hold rispettati e job attivi preservati; nessuna promessa di cancellazione fisica assoluta.
- Test: fixture retention e review governance senza claim conformità.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-C-01 — Ripristino enforcement qualità e release

- Componente/superfici: CI/packaging/Python/OS.
- Problema/evidenza: Statica: solo labels.yml; make check locale, nessun lock runtime committato.
- Gravità/probabilità/impatto e motivo P1: Release non automaticamente verificata; impatto alto.
- Soluzione: Workflow least privilege con pin SHA, matrice 3.11–3.14/OS, wheel, test, coverage/mutation, schema/link/security; branch policy verificata.
- Dipendenze/blocchi: runner/repository policy per enforcement remoto.
- Accettazione misurabile: Run remoti verdi sul commit pubblicato e check richiesti; nessuna riduzione soglie.
- Test: CI reale, wheel clean install, container separato. Il 29 ottobre la suite locale mantiene 17 fallimenti sandbox EINVAL/chown già osservati al baseline; rieseguire su host POSIX idoneo senza ridurre i gate. Gitleaks assente, hash lock timed out: verifiche ancora aperte.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-F-01 — Build scanner riproducibile e licenze

- Componente/superfici: Docker/catalogo/release.
- Problema/evidenza: Statica: pip/git/gem mobili e || true; WPScan non-OSI classificato OSS.
- Gravità/probabilità/impatto e motivo P1: Composizione immagine e diritto distribuzione non dimostrati; impatto alto.
- Soluzione: Pin/hash/versioni, manifest installato, mandatory vs optional, revisione licenze per versione; SBOM/advisory/signing.
- Dipendenze/blocchi: D11,D12.
- Accettazione misurabile: Due build confrontabili; dipendenze obbligatorie mancanti falliscono; licenze provenienti da fonti upstream.
- Test: container/SBOM/pip-audit/Gitleaks/SAST; verifica legale separata.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### SEC-F-02 — Chiusura dipendenze SBOM conforme ai marker

- Componente/superfici: core.sbom/core.lockfile.
- Problema/evidenza: Statica: _direct_dependencies interpreta extra con regex, non marker PEP 508 completi.
- Gravità/probabilità/impatto e motivo P1: SBOM/lock possono includere/escludere dipendenze errate; rischio dedotto.
- Soluzione: Parser standard requisiti e propagazione extra transitivi; schema CycloneDX validato.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Marker piattaforma/Python/extra complessi e dipendenze transitive corrispondono installazione.
- Test: unit marker matrix e clean-install closure.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-G-01 — Riconciliazione dichiarazioni e inventario

- Componente/superfici: Docs/README/roadmap/ADR.
- Problema/evidenza: Statica: audit storico, testing, verification-status e roadmap contengono claim CI obsoleti.
- Gravità/probabilità/impatto e motivo P1: Operatori possono confondere codice/test storico con readiness.
- Soluzione: Snapshot attuale distinto; inventario generato, link gate, completare ADR 003–005 e policy mypy coerente.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Nessun claim CI corrente senza run; stati aggiornati e ID tracciabili.
- Test: doc links, confronto registry/documenti e revisione bilingue.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### UX-A-01 — Parità TUI e consumer form

- Componente/superfici: CLI/TUI/Web.
- Problema/evidenza: Dinamica: config/engagement/policy assenti TUI; statica: cli_forms non consumato.
- Gravità/probabilità/impatto e motivo P1: Onboarding incompleto e claim intero albero falso.
- Soluzione: Navigazione completa e form realmente collegati mantenendo escape hatch.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Configurazione→engagement→assessment→report guidati; campi tipizzati/parità errori.
- Test: pilot e E2E offline, test usabilità.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### WEB-A-01 — Ripresa SSE visibile

- Componente/superfici: Web JS / API events.
- Problema/evidenza: Statica: app.js close su error, server termina stream dopo 300s.
- Gravità/probabilità/impatto e motivo P1: Job lunghi perdono aggiornamenti; probabilità alta oltre limite.
- Soluzione: Retry bounded, stato connessione, refresh manuale e terminal close.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Disconnessione/ripresa e job oltre 300s aggiornano stato senza duplicazione.
- Test: browser reale SSE interrotto.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### WEB-B-01 — Store guasto distinto da vuoto

- Componente/superfici: Web engagement/dashboard.
- Problema/evidenza: Statica: eccezioni convertite in [] o widget omessi.
- Gravità/probabilità/impatto e motivo P1: Guasti mascherati da assenza dati; impatto decisionale alto.
- Soluzione: Stati unavailable/not-configured/empty distinti con errori redatti.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Store corrotto non mostra onboarding vuoto; widget non disponibili espliciti.
- Test: TestClient negativo e browser.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### WEB-G-01 — Conteggi dashboard corretti

- Componente/superfici: Web/store.
- Problema/evidenza: Statica: list(limit=200) etichettata jobs total.
- Gravità/probabilità/impatto e motivo P2: Conteggi parziali fuorvianti con più job.
- Soluzione: Aggregati SQL o etichetta finestra esplicita, nessuna omissione job attivi.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Fixture >200 job produce totali veri o finestra chiaramente dichiarata.
- Test: integrazione dashboard.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### OPS-PURPLE-01 — Coverage telemetria distinta da detection

- Componente/superfici: Apollo/Athena/Purple.
- Problema/evidenza: Dinamica: dict solo event_type accettato e JSON malformato ignorato.
- Gravità/probabilità/impatto e motivo P1: Falsa fiducia copertura; impatto alto.
- Soluzione: Validare Event, contare scarti/troncamento; distinguere presence/schema/match/test pass.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Input invalidi non covered; test detection lega atteso/osservato e FP.
- Test: contratti negativi e regressione regole; lab D8 separato.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### UX-E-01 — Accessibilità e parità IT/EN dimostrate

- Componente/superfici: TUI/Web/docs.
- Problema/evidenza: Statica: lang=en/stringhe EN; TestClient non browser; live region assente.
- Gravità/probabilità/impatto e motivo P1: Fruibilità non dimostrata, impatto utenti alto.
- Soluzione: Cataloghi IT/EN, tastiera/focus/live region, browser axe e review screen reader/contrasto.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Flussi critici in due lingue; zero issue critiche automatiche e checklist manuale registrata.
- Test: browser/keyboard/screen reader; nessuna certificazione presunta.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-E-02 — Modello single-node e soglie scalabilità

- Componente/superfici: Web sessioni/rate limit/SQLite.
- Problema/evidenza: Statica: chiave sessione e rate limiter locali al processo.
- Gravità/probabilità/impatto e motivo P2: Multiworker incoerente; rischio dedotto.
- Soluzione: Documentare single-worker; misurare p95/lock/errori prima di session store/Postgres.
- Dipendenze/blocchi: DEV-E-01.
- Accettazione misurabile: Carico dichiarato e SLO misurati; migrare solo se SQLite viola budget riproducibile.
- Test: load/recovery/multiworker.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### OPS-SCAN-01 — Integrazioni motivate e promozione maturità

- Componente/superfici: Themis/Apollo/Metis/Vulcan.
- Problema/evidenza: Inventario: 24 catalogati, 15 adapter; live storico non rieseguito.
- Gravità/probabilità/impatto e motivo P2: Espansione non verificata accresce manutenzione e rischio.
- Soluzione: Completare adapter e flussi prima di nuovi tool; schede proposta e gate per ogni livello.
- Dipendenze/blocchi: SEC-B-01,SEC-F-01; D1–D13 secondo capability.
- Accettazione misurabile: Ogni promozione ha fixture, compatibilità, licenza, lab e owner; nessuna catalogazione chiamata integrazione.
- Test: contract/offline/lab/release secondo livello.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).

### DEV-E-03 — Allocazione ID atomica engagement/finding

- Tipo: correzione; componenti/superfici: engagement create e lifecycle finding CLI/API/Web.
- Evidenza statica: commit remoti f55825d/91d60d4 allocano next_*_id con SELECT separato dall'INSERT; non prenotano ID per writer simultanei. La perdita per sovrascrittura è già corretta dal create/append insert-only.
- Problema/P2: conflitti operativi possibili sotto concorrenza, probabilità condizionata al carico e impatto su disponibilità; nessuna race dinamica dichiarata.
- Soluzione/alternative: allocazione+create transazionali, oppure UUID compatibili con i contratti dopo ADR; non presentare la sola MAX+1 letta come garanzia concorrente.
- Dipendenze: nessuna; owner Data/Backend, M/incertezza media, milestone M3.
- Accettazione/test: due connessioni sincronizzate creano due record distinti senza perdita o errori duplicato; test restart, concorrenza e rollback, preservare contratti ID.
- DoD: criteri e campi comuni, test/documentazione, commit e verifica remota; stato `[ ]`. Link: [audit](docs/ecosystem-audit.md).

### Schede proposte e maturità — OPS-SCAN-01

Tutte sono **proposte**, salvo cataloghi/adapter già inventariati. Nessuna nuova
licenza/versione è attestata: verifica upstream della versione selezionata prima
distribuzione, registrazione in THIRD_PARTY_NOTICES e budget manutenzione obbligatori.
Contratto comune scanner: ScannerAdapter/ScanRequest→ScanResult→Finding/Evidence
versionati, readiness distinta da maturity, parser bounded, capability offline o
network-active esplicita, argv senza shell e scope/manifest per attività attive.
Manutenzione: owner Scanner con review trimestrale versioni/CVE/parser, fixture per
ogni versione supportata; stime L/alta incertezza per ciascun nuovo adapter.
Accettazione comune: fixture positive/negative, timeout/cancel/partial, nessun
clean su errore, SBOM/licenza/manifest, lab autorizzato per promozione; milestone
M4 dopo SEC-B-01/SEC-F-01, DoD comune. Alternative e benefici specifici:

| Proposta / utenti e problema | Destinazione e capability | Alternative/decisione | Requisiti, rischi e test specifici |
|---|---|---|---|
| SAST per sviluppatori engagement | Themis adapter Semgrep o Bandit → Finding/SARIF | scegliere su corpus, non installare entrambi senza delta; CodeQL resta SAST progetto | regole/versioni/licenze da verificare; checkout read-only senza esecuzione; fixture false positive e path traversal |
| SCA/container/IaC per AppSec | Themis Trivy oppure OSV-Scanner, core SBOM | prima correggere SBOM nativo; Syft/Grype solo se necessario input immagini/SPDX, Checkov/KICS solo se IaC non coperto | DB offline versionato, freshness esplicita, niente socket Docker privilegiato; fixture vulnerabile/corretta e DB assente |
| DAST per operatori Web | completare ZAP catalogato in Themis | nessun nuovo modulo; preferire adapter esistente ove sufficiente | daemon isolato, auth API, contesto scope, limiti crawl; redirect/cancel/lab D1 |
| Recon per assessment | Argus + adapter subfinder/theHarvester/dnsx/naabu/amass | selezionare lacuna rispetto Argus/Nmap, non cinque wrapper automatici | D4, sorgenti e licenze/API; rate limit/provenance e target scoped |
| WordPress/NoSQL | Themis wpscan/nosqlmap catalogati | differire finché caso utente e laboratorio disponibili | D5, token secret provider/licenza WPScan; fixture/versioni e false positive |
| TLS/fuzzing Web | Themis sslscan/ffuf opzionali | differiti P3: sovrapposizione testssl/dirsearch, richiedere delta misurabile | richieste bounded e scope path/host; benchmark comparativo su lab |
| SIEM/EDR, CTI per SOC | Apollo ECS/OCSF, Metis STIX/MISP/TAXII/OpenCTI | completare import/export offline prima dei client remoti | D9/D10, identità least privilege, dedup/provenance/retention; contract replay e sandbox server |
| Purple validation | Athena orchestration + Apollo/Minerva, Atomic Red Team | prima OPS-PURPLE-01; Metasploit RPC solo nel gate D6 esistente | D8/D6, allowlist tecniche, snapshot endpoint, undo e telemetria; atteso/osservato e FP/FN |
| File pattern / hardening | YARA via Apollo/Minerva; Hephaestus solo se dominio autonomo motivato | P3; preferire adapter/config check esistente, non creare modulo ora | corpus benigno/malevolo sintetico, licenze regole/benchmark e risorse bounded |
| Scheduling/notifiche/ticketing | Themis jobs, core.notifications e Vulcan | completare WEB-I/WEB-J e D13; no Iris/Chronos duplicati | outbox/idempotenza, approvazione scope ad ogni run, segreti redatti; retry/offline/expiry tests |

Non intervento motivato: duplicati Hermes/Hestia, Aegis/Themis, Oracle/risk engine,
Prometheus/observability e scanner già esclusi da OPS-SCAN restano esclusi. Cloud
Prowler/ScoutSuite e verifica live segreti TruffleHog non entrano nello scope
corrente senza nuovo threat model/mandato. Criterio di riesame: caso d'uso documentato,
delta capability misurato, owner e controlli/lab disponibili. Nessun tool terzo
rinominato. Catalogato→implementato→offline verificato→lab verificato→candidato
release→rilasciato richiede evidenza distinta ad ogni passo; nessun tag disponibile
nel clone dimostra una release in questa sessione.

### Snapshot concorrente 2026-10-28, riconciliato il 29 ottobre

I quattro commit remoti 91d60d4, 108a30b, f55825d, e177498 sono preservati.
Le verifiche del ciclo concorrente riportate sotto sono storiche e non sono
state rieseguite dal presente audit sul loro ambiente. Lo stato corrente è
nella riconciliazione e in docs/verification-status.md. La precedente conclusione
“nessun nuovo P0/P1” è superata dai finding SEC-E-01 e dalle altre slice.

Audit 360° di codice, contratti, sicurezza e dichiarazioni. **Verificato pulito:**
`ruff check` e `ruff format` sull'intero repo; `mypy --strict` su 213 file
first-party; suite completa (unit/contract/integration, esclusi container/live_lab
opt-in) verde con branch coverage ~81–82% (≥75%); nessuno stub/placeholder o
`except: pass` sospetto (i soli riscontri sono testo di documentazione, placeholder
legittimi di templating e fallback `fsync` coperti da `pragma`); superficie di
terminal-injection della CLI sanitizzata (`core.output.render_table` + echo
first-party/enum); kill del process-group dello scanner (`themis/runner` usa
`start_new_session` + `os.killpg`); store SQLite dei finding indicizzato sulla
query hot. **Lacune confermate aperte** (con
disposizione): SEC-B blocco egress a livello namespace → **bloccato** (richiede
container runtime); ripristino workflow CI → **bloccato** (decisione owner, commit
`58ba209`); RFC-3161/SLSA/Cosign/branch-protection → dipendono da servizi/infra
esterni; DEV-A confini architetturali, WEB-H Postgres/RBAC, UX-E accessibilità/i18n,
WEB-J backup/restore → interventi ampi pianificati. **Finding dell'audit risolti in
questo ciclo:** (1) parità CLI/Web del ciclo di vita finding — mancava un comando
CLI per registrare una transizione di stato (presente solo in API/Web) → aggiunto
`olympus vulcan transition`; (2) **difetto di unicità id cross-processo** — `new_id`
riparte da `…00001` in ogni processo, quindi un chiamante a vita breve (CLI, worker
riavviato) rigenererebbe id già presenti nel ledger append-only dei finding →
aggiunto `SqliteFindingTransitionStore.next_transition_id` che alloca l'id dal
contenuto persistito; il gestore transizioni **Web** usa ora lo stesso allocatore
(follow-up chiuso il 2026-10-28), quindi un worker riavviato non collide più con
il ledger esistente — vedi `WEB-C`; (3) **perdita di dati negli engagement (P0)** —
lo stesso difetto `new_id` cross-processo colpiva lo store engagement in modo più
grave: due invocazioni `olympus engagement create` coniavano entrambe
`ENG-<anno>-00001` e il `save()` basato su `INSERT OR REPLACE` sovrascriveva
silenziosamente il primo engagement con il secondo (perdita del perimetro
autorizzato). Risolto con `SqliteEngagementStore.next_engagement_id` (alloca l'id
dallo stato persistito) + `create()` insert-only fail-closed (rifiuta di
sovrascrivere un id esistente, ultima linea di difesa); la CLI `create` usa ora
entrambi — vedi `WEB-B`; (4) **cifratura a riposo dei bundle finding (`SEC-E`)** —
i documenti del lifecycle store erano già cifrabili, ma gli immutabili bundle JSON
`core.Finding`/`core.Asset` prodotti dagli scanner restavano in chiaro su disco →
policy di chiave single-source in `olympus/findings/encryption.py` (condivisa con
il lifecycle store), cifratura/decifratura via `olympus vulcan encrypt-bundle`/
`decrypt-bundle` con la **stessa** chiave `OLYMPUS_FINDINGS_ENCRYPTION_KEY` e
**decifratura trasparente** nel choke point unico di load (`vulcan.aggregate`), così
CLI e Web UI leggono bundle cifrati e in chiaro in modo identico; fail-closed su
chiave assente/errata o ciphertext alterato, compatibilità legacy — vedi `SEC-E`.

## Legenda

- `[x]` già presente e verificabile nel repository;
- `[~]` presente ma incompleto o non ancora validato in tutti gli scenari;
- `[ ]` da implementare;
- `[⏸]` differito perché richiede laboratorio, infrastruttura o credenziali esterne;
- **P0** blocca un utilizzo sicuro o una release affidabile;
- **P1** alto valore e alta priorità;
- **P2** miglioramento importante;
- **P3** evoluzione successiva.

### Come leggere e mantenere questa roadmap

- Ogni intervento ha un identificativo stabile (`SEC-*` cybersecurity, `DEV-*`
  sviluppo, `UX-*` design, `OPS-*` backlog operativo): fasi, priorità, issue, PR e
  commit devono citarlo, così lo stato resta tracciabile senza duplicare testo.
- `ROADMAP.md` è la fonte canonica per il lavoro **futuro**; `upgrade.md` resta il
  registro storico dei cicli di integrazione Argus/VAP e non va usato per
  pianificare nuove attività.
- Una casella passa a `[x]` solo rispettando la
  [Definition of Done trasversale](#definition-of-done-trasversale); un `[~]` deve
  sempre indicare, nella stessa voce, cosa manca.
- Un intervento `[⏸]` indica il prerequisito di sblocco nella tabella
  [Prerequisiti per le attività differite](#prerequisiti-per-le-attività-differite).

### Cruscotto di avanzamento

| Fase | Focus | Stato | Interventi principali |
| --- | --- | --- | --- |
| 0 | Baseline e coerenza documentale | `[~]` | `DEV-G` `[~]`, `DEV-H` `[~]`, `DEV-C` `[~]` (gate locali via `make check`; workflow CI rimosso in 58ba209 → nessun enforcement automatico) |
| 1 | Security hardening (**P0**) | `[~]` | `SEC-A`, `SEC-B`, `SEC-C`, `SEC-H`, `UX-B` |
| 2 | Architettura e qualità di release | `[~]` | `DEV-A`, `DEV-B`, `DEV-C`, `DEV-D`, `DEV-E`, `SEC-F` |
| 3 | UX operativa bilingue | `[ ]` | `UX-A`, `UX-C`, `UX-D`, `UX-E`, `UX-F`, `UX-G` |
| 4 | Capability Red/Blue/Purple | `[~]` | `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE`, `OPS-SCAN` |
| 5 | Production readiness scanner | `[ ]` | `D1`, `D2` |
| 6 | Distribuzione e osservabilità | `[~]` | `DEV-E`, `DEV-F`, `SEC-F` |
| 7 | Rename Themis + Web control plane | `[~]` | `DEV-I` ✓, `WEB-A` ✓, `WEB-B` ✓, `WEB-C` ✓, `WEB-D` ✓, `WEB-E` ✓, `WEB-F` ✓, `WEB-G`…`WEB-J` |

L'ordine di esecuzione concordato per la Fase 7 mette le **fondamenta dati prima
delle interfacce**: `DEV-I` (rename) → `WEB-B` (engagement entità di primo
livello) → **Finding strutturato** (`WEB-C`, campi CVE/CWE/EPSS/KEV tipizzati con
migrazione) → `WEB-A` (API/SSE + web skeleton sicuro) → `WEB-D` (tools) →
`WEB-E` (new assessment) ✓ → `WEB-C` (findings UI) → `WEB-J`/`WEB-I` (dati e
reporting) → `WEB-F` (smart scan) ✓ → `WEB-H` (persistenza) → ritiro runtime VAP
(`SEC-A`). `SEC-H` (parsing input ostile) va svolto in opportunità durante il
rename, perché non richiede un lab autorizzato.

Il cruscotto va aggiornato nella stessa PR che cambia lo stato di un intervento.

## 📌 Panoramica del Progetto

Il repository non è più costituito dal solo script `OLYMPUS.py`: quel file non è
presente sul branch `main`. Olympus è già un package Python 3.11+ installabile,
organizzato sotto `src/olympus/`, con una CLI Typer unificata, una TUI Textual,
modelli Pydantic condivisi e moduli dedicati a reconnaissance, vulnerability
assessment, web testing, detection engineering, DFIR, CTI, secret scanning,
reporting e orchestrazione.

La base corrente include già controlli importanti:

- [x] scope e autorizzazione esplicita per le operazioni network-active;
- [x] timeout, deadline, retry, rate limiting e cancellazione condivisi;
- [x] protezioni SSRF, pinning dell'indirizzo risolto e limiti sulle risposte;
- [x] redazione di segreti e parametri sensibili da log e audit;
- [x] sandbox dei processi scanner con drop dei privilegi e `rlimit` POSIX;
- [x] API AEGIS con identità, permessi per scope, revoca, limiti del body e rate limit;
- [~] generatori SBOM/hash lock e comandi audit presenti; enforcement CI assente (`DEV-C-01`, `SEC-F-01/02`);
- [~] packaging wheel disponibile; installazione locale registrata nelle verifiche, pipeline da ripristinare;
- [x] test offline e ledger di maturità per non sovrastimare gli adapter scanner.

La roadmap non deve quindi riproporre attività già concluse come “modularizzare lo
script” o “spostare le API key in variabili d'ambiente”. Deve portare la piattaforma
dallo stato attuale — ampio e tecnicamente promettente, ma con alcuni componenti
legacy e nessun adapter dichiarato `production-ready` — a un prodotto con confini
di sicurezza forti, release riproducibili e flussi operativi comprensibili.

### Evidenze e gap principali rilevati

| Area | Evidenza nel repository | Gap da chiudere |
| --- | --- | --- |
| Architettura | `src/olympus/` contiene moduli separati e un contratto dati comune | runtime `themis api/serve/migrate/workers` nativo e testato dalla wheel; resta la parità completa endpoint/dati legacy (`SEC-A`) |
| Sicurezza runtime | `core.execution`, `core.http`, `core.pinning`, `aegis.sandbox` | manca un egress allowlist per gli scanner; seccomp è predefinito, AppArmor richiede l'overlay esplicito su host compatibili |
| Credenziali | i segreti first-party sono letti dall'ambiente e redatti | manca un backend opzionale per secret manager e una policy uniforme di rotazione |
| Autorizzazione | scope file + conferma esplicita prima dell'esecuzione | manifest firmato/scadenza/revoca implementati; resta validazione live completa |
| Supply chain | SBOM, hash lock, audit dipendenze e secret scan | mancano attestazioni di build, firma immagini/release e SAST CodeQL bloccante |
| Qualità | Ruff/Mypy/test/schema/coverage/mutation sono comandi locali; matrice dichiarata 3.11–3.14 non rieseguita qui | CI qualità assente; container/live lab opt-in presenti ma non eseguiti nell'audit |
| Input ostili | report HTML Vulcan con `html.escape`; RichLog TUI con `markup=False` | Nmap usa defusedxml e test fuzz/corpus; resta revisione completa dei consumer e SEC-H-01/02 |
| Scanner | ledger in `integrations/maturity.py` con prove verificabili | 12 `live-tested`, 3 `offline-tested`, 0 `production-ready` |
| TUI | esecuzione senza shell e streaming dell'output | un solo campo libero per gli argomenti, UI solo inglese, poco supporto decisionale |
| Documentazione | README bilingue, threat model, ADR e guide operative | link interni corretti, ma manca un link checker in CI; alcuni conteggi non allineati |
| Governance | `ROADMAP.md` canonica, `upgrade.md` storico in sola aggiunta, `CONTRIBUTING.md` allineato alla CI, template issue/PR, label versionate e indice ADR | gli indicatori e la maturity table non sono ancora generati automaticamente |

## 🔎 Audit di stato verificato (ottobre 2026)

Verifica effettuata leggendo il codice su `main` (non la sola documentazione).
Legenda stato: ✅ implementata · 🟡 parziale · 🗓️ pianificata · ❌ assente ·
♻️ duplicata/sovrapposta a un modulo esistente.

### A. Capability (gap analysis) — funzione → stato → evidenza → decisione

| # | Funzione | Stato | Evidenza (file) | Decisione |
| --- | --- | --- | --- | --- |
| 1 | CLI e configurazione uniformi | ✅ | `cli.py` (Typer, 14 sub-app), `core/config.py`, `themis/config.py`, `core/output.py` (`OutputFormat`) | Estendere coerenza opzioni/errori (`UX-G`) |
| 2 | Schema comune asset/finding/IOC/eventi/evidenze | ✅ | `core/models.py` (`Asset`,`Finding`,`Event`,`Evidence`,`Alert`,`Observation`), `core/contracts.py`, `schemas/`; IOC in `metis/models.py`; `Finding` con CVE/CWE/EPSS/KEV/confidence tipizzati (`WEB-C`) | Mantenere; nessun nuovo modulo |
| 3 | Logging strutturato, timeout, retry, errori | ✅ | `core/observability.py` (OTel/Prometheus redatto), `core/execution.py` (`Deadline`, timeout, retry, cancellation), `core/errors.py`, `core/exit_codes.py` | Mantenere; nessun nuovo modulo |
| 4 | Dry-run e controlli perimetro autorizzato | 🟡 | scope gate `themis/scope.py`,`athena/scope.py`,`core/addresses.py`+`core/pinning.py` (SSRF); autorizzazione `core/execution.ExecutionPolicy`, `--i-am-authorized` | Scope ✅; **dry-run universale** → `SEC-G` |
| 5 | RBAC, segreti, audit log, rate limiting | 🟡 | `themis/identity.py` (hash delle credenziali, permessi/scadenza/limiti per identità), audit middleware `themis/api.py`, redaction `core/execution.py` | Base ✅; **RBAC/OIDC multiutente** → `WEB-H`; **SecretProvider** → `SEC-D` |
| 6 | Arresto immediato + approvazione invasive | 🟡 | cancellation `core/execution.py`, kill del process-group `themis/sandbox.py` | **Kill switch globale**, classi PASSIVE/ACTIVE/INTRUSIVE, preview → `SEC-G`,`UX-B` |
| 7 | Deduplicazione + ciclo di vita finding | ✅ | `vulcan/aggregate.py` (`dedupe_findings` per ID + `merge_duplicate_findings` cross-scanner lossless), `FindingStatus` (7 stati), macchina a stati + audit trail + suppression `core/finding_lifecycle.py`/`findings/store.py` (`WEB-C`) | Transizioni, dedup, audit trail, suppression, tagging/ricerca tutti ✅; filtri `FindingFilter` ora in parità CLI (`olympus vulcan rank …`) e Web; transizioni di stato ora anche da CLI (`olympus vulcan transition`, parità con API/Web) con id allocato dal ledger (`next_transition_id`, collision-free cross-processo) |
| 8 | Severità, confidence, risk scoring contestuale | ✅ | `Severity`, `Finding.confidence` (`WEB-C`), `Finding.risk_score()` 0–100 (`WEB-C`), `vulcan/enrichment.prioritize` (KEV>EPSS>CVSS>severità) | Confidence + risk score numerico ✅; mantenere |
| 9 | Mapping CVE/CWE/CVSS/MITRE ATT&CK | ✅ | `Finding.cvss` + campi `cve`/`cwe`/`epss`/`kev` strutturati (`WEB-C`); link NVD/MITRE in `vulcan/pdf.py`; EPSS/KEV `vulcan/enrichment.py`; ATT&CK detection `apollo/attack.py`, `Alert.mitre_attack`; **ATT&CK offensivo sui finding** `vulcan/attack.py` (`OPS-RED`) | Campi strutturati ✅; overlay ATT&CK offensivo ✅ (auto vs reviewed, mapping versionato) |
| 10 | Inventario centralizzato asset | 🟡 | `core.Asset`, `argus/assets.py`, persistenza per-assessment in Athena; `Asset.engagement_id` opzionale e stamping dal coordinator Athena per id canonici (`WEB-B` slice 2); engagement esposti via API/Web sullo stesso store con scope enforcement (`WEB-B` slice 3) | Engagement leggibili/operabili dai quattro canali ✅; **viste di aggregazione asset cross-engagement** (widget top-asset-per-esposizione sulla dashboard, `WEB-G`) ✅ |
| 11 | Scheduler, code, worker isolati, ripresa job | 🟡 | job store SQLite `themis/jobs.py` (stati+`recover`), `olympus themis jobs recover`, sandbox e worker continuo nativo (`SEC-A`) | Queue+recover+sandbox ✅; **scheduler nativo** ❌ → `D13`; runtime Celery ritirato ✅; parità dati/route legacy → `SEC-A` |
| 12 | Scansioni incrementali + confronto risultati | 🟡 | `argus/diff.py` (diff recon); **finding/scan diff cross-run** `vulcan/compare.py` + `olympus vulcan diff` + Web `/findings/diff` (`WEB-I` slice 2); **trend severità** `vulcan/trend.py` + `olympus vulcan trend` (`WEB-I` slice 3a) | Finding/scan diff ✅, trend finding ✅; **attack-surface evolution** → `WEB-I` |
| 13 | Dashboard, notifiche, report JSON/CSV/HTML/PDF/SARIF | 🟡 | report JSON/MD/HTML/PDF/CSV `vulcan/` (`render_report_csv`, spreadsheet-safe), SARIF `hermes/sarif.py`, OCSF/ECS/NDJSON `apollo/` | **CSV** ✅ (`olympus vulcan report --csv`, Web `GET /findings/report?format=csv`); **dashboard** ✅; **notifiche** → `WEB-I` |
| 14 | API, webhook, CI/CD, ticketing, SIEM, CTI | 🟡 | API tipizzata `themis/api.py`; CTI nativo Metis (`metis/misp.py`,`stix.py`) | API+CTI ✅; **webhook/ticketing/CI** → `WEB-J`; **SIEM** → `OPS-BLUE` |
| 15 | Test unit/integration/e2e + demo sicuro | ✅ | ~132 file di test (unit/contract/integration/container/live_lab), demo `labs/mars/`; web-security + job-lifecycle della Web UI nativa, tools page dal capability inventory, wizard New Assessment guidato con anteprima di rischio e findings review/triage nel browser con audit (`tests/unit/test_themis_web.py`, `tests/unit/test_scanner_activity.py`, `WEB-A`/`WEB-C`/`WEB-D`/`WEB-E`) | Estendere e2e Web sulle slice successive (`WEB-F`/`WEB-G`) |

### B. Moduli proposti (FASE 3) — valutazione

| Modulo proposto | Problema | Equivalente esistente | Decisione |
| --- | --- | --- | --- |
| **Hermes** (inventario asset) | asset inventory | ♻️ **conflitto di nome**: Hermes è già il **secret scanning** (`src/olympus/hermes/`) | **Scartare il nome**; inventario in `core.Asset`+`argus/assets.py`, centralizzato da `WEB-B` |
| **Aegis** (vuln management) | vulnerability management | ♻️ è **Themis** (ex-AEGIS: `src/olympus/themis/`) | **Scartare**: già Themis; lifecycle vuln → `WEB-C` |
| **Prometheus** (monitoraggio) | monitoring continuo | ♻️ **doppio conflitto**: il noto sistema Prometheus e il backend `observability` già chiamato `prometheus` (`core/observability.py`) | **Scartare il nome**; monitoring → estende `core/observability.py` + scheduler (`D13`) |
| **Hestia** (secret detection) | secret detection | ♻️ è **Hermes** (nativo: regex+entropia+git history, `hermes/scanner.py`) | **Scartare**: già Hermes |
| **Hephaestus** (supply-chain) | supply-chain security | 🟡 SBOM `core/sbom.py`, lockfile, pip-audit/gitleaks in CI; nome già **riservato** per hardening/CIS (`OPS-BLUE`) | **Integrare** in `SEC-F` (provenance/SLSA/Cosign) + candidati Trivy/OSV (`OPS-SCAN`); non un modulo nuovo |
| **Iris** (notifiche) | notifiche | 🟡 porta `core/notifications.py` (webhook SSRF-safe + e-mail, redatta, off-by-default) | `WEB-I`: resta l'emissione automatica sul loop job Themis |
| **Chronos** (scheduler) | scheduling | ❌ assente (job store c'è) | **Integrare** come servizio di scheduling su `themis/jobs.py` (`D13`); nome solo se diventa sub-app CLI |
| **Oracle** (risk scoring) | risk scoring | ♻️ **conflitto di nome** (Oracle DB); parziale in `vulcan/enrichment.prioritize` | **Scartare il nome**; estendere `vulcan` con risk score + confidence |

**Conclusione FASE 3:** nessun nuovo modulo di dominio è necessario. Ogni proposta
si integra in moduli esistenti (Themis, Vulcan, Argus, Metis, `core`, Web),
evitando i conflitti di nome con prodotti noti (Prometheus, Oracle) e con i
moduli Olympus già presenti (Hermes, Hephaestus).

### C. Integrazioni (FASE 4) — stato e priorità

| Tool | Utilità | Modulo responsabile | Stato | Priorità |
| --- | --- | --- | --- | --- |
| Nmap | discovery porte/servizi | Themis adapter | ✅ live-tested (`themis/adapters/nmap.py`) | — |
| Nuclei | vuln templating | Themis adapter | ✅ live-tested (`themis/adapters/nuclei.py`) | — |
| OWASP ZAP | web app scanning | Themis adapter | 🟡 a catalogo, adapter ❌ (`integrations/scanners.py`) | P2 |
| Semgrep | SAST del codice | Themis/`SEC-F` | ❌ | P2 |
| Trivy | container/IaC/dep + SBOM-vuln | Themis adapter | ❌ | P2 |
| Gitleaks | secret scanning | ♻️ Hermes (nativo) + CI secret-scan | ✅ coperto | basso |
| Checkov | IaC misconfig | Themis adapter | ❌ | P3 |
| Syft | SBOM | `core/sbom.py` (SBOM nativo) | 🟡 opzionale | P3 |
| Grype | vuln da SBOM | con Syft/Trivy | ❌ | P3 |
| YARA | pattern su file/malware | Metis/Apollo | ❌ | P3 |
| Sigma | regole detection | Apollo | ✅ import nativo (`apollo/sigma.py`) | — |
| MISP | CTI | Metis | ✅ nativo (`metis/misp.py`) | — |
| OpenCTI | CTI | Metis | 🟡 STIX/TAXII presenti; client OpenCTI ❌ → `D10` | P2 |

Regola invariata: uno scanner si aggiunge solo se colma una capability mancante e
non duplica un adapter presente; esecuzione sempre scope-gated e sandboxata.

### D. Milestone progressive (FASE 5) — mappate agli ID stabili

Gli interventi restano quelli già in roadmap (nessun ID nuovo inventato); qui sono
riorganizzati nelle 7 milestone richieste con criteri di accettazione misurabili.

| Milestone | Obiettivo | Stato verificato | Attività (ID) | Criterio di accettazione |
| --- | --- | --- | --- | --- |
| M1 Fondamenta | base stabile e coerente | 🟡 `DEV-I` ✅, `SEC-A` ✅, suite/coverage ✅ (gate locali via `make check`; workflow CI rimosso in 58ba209 → nessun enforcement automatico) | `DEV-G`,`DEV-H`,`DEV-C` | **ripristinare un workflow CI** (link checker/gate verdi su push/PR); 0 import runtime da `vendor/` |
| M2 Sicurezza operativa | guardrail attivi | 🟡 scope/sandbox ✅ | `SEC-B`,`SEC-C`,`SEC-G`,`SEC-H`,`UX-B` | dry-run+kill switch end-to-end; parser fuzzing in CI |
| M3 Modello dati & Finding Engine | finding ricchi e tracciabili | 🟡 stati+dedup ✅ | `WEB-C` (+`Finding.confidence`/risk score, CVE/CWE/EPSS/KEV strutturati) | lifecycle completo con audit; dedup senza perdita evidenza |
| M4 Asset & Vulnerability management | engagement centrale | 🟡 Themis ✅, asset parziale | `WEB-B`,`WEB-D` | stesso engagement/asset da CLI/TUI/API/Web |
| M5 Integrazioni | capability mancanti mirate | 🟡 Nmap/Nuclei/Sigma/MISP ✅ | `OPS-SCAN` (ZAP/Semgrep/Trivy), `OPS-BLUE` (SIEM/OpenCTI), `WEB-J` (webhook/CI/ticketing) | ogni integrazione scope-gated con fixture reale |
| M6 Dashboard & Reporting | output multi-formato e UI | 🟡 JSON/MD/HTML/PDF/SARIF ✅ | `WEB-A`,`WEB-E`,`WEB-G`,`WEB-I` (+CSV, scan diff, trend) | report CSV + diff tra run; dashboard con widget operativi |
| M7 Scalabilità & monitoraggio continuo | scheduling e osservabilità | 🟡 observability ✅, scheduler ❌ | `WEB-H` (Postgres), `D13` (scheduler), `DEV-E`/`SEC-F` | scheduler ricorrente scope-aware; stesso codice SQLite/Postgres |

Elementi **esclusi**: nuovi moduli `Prometheus`/`Oracle`/`Hestia`/`Aegis`
separati (conflitti/duplicazioni); wrapper scanner che duplicano capability
esistenti (Gitleaks↔Hermes). Ordine di implementazione: M1→M2→M3→M4→M5→M6→M7,
coerente con la Fase 7 del cruscotto.

## 🛡️ Prospettiva Cybersecurity (Analisi e Rinforzo)

Le note datate delle implementazioni sotto conservano la storia del progetto.
Le menzioni di job CI nelle note precedenti alla rimozione workflow non sono
stato corrente: vedere DEV-C-01 e verification-status. I criteri di accettazione
restano requisiti, non prove di esecuzione.


### Stato di sicurezza attuale

Non è stato rilevato hardcoding di API key o password nel codice first-party
analizzato. `src/olympus/core/config.py` carica impostazioni da TOML e variabili
d'ambiente; i moduli che richiedono token usano variabili dedicate. Il comando locale Gitleaks è disponibile quando il binario è installato.
Il workflow qualità è assente: scansione working tree/history e canary non sono
attualmente imposti in CI (`DEV-C-01`).

La parità VAP è stata classificata, lo storico terminale dispone di una migrazione
fail-closed e il sorgente vendorizzato è stato rimosso. Restano l'isolamento di
rete dei processi scanner e la forza probatoria dello scope e delle evidenze.
Il runtime mantenuto è interamente nativo.

### Intervento A · `SEC-A` — Ritirare la superficie VAP vendorizzata (**P0**)

- [x] Reimplementare nativamente le funzioni ancora delegate da
  `src/olympus/integrations/cli.py` a `vendor/vulnerability-assessment-platform`:
  API/web app, migrazioni e worker. `serve`/`web` condividono la Web UI nativa,
  `migrate` aggiorna soltanto il database job nativo e `workers` consuma la coda
  SQLite con cancellazione SIGINT/SIGTERM, senza Redis/Celery/Alembic o import
  VAP. Immagini native dalla wheel, smoke API/Web HTTPS/worker, test di lifecycle
  e CI container; guida IT/EN e rollback in
  [`docs/themis-runtime.md`](docs/themis-runtime.md). Il sorgente legacy resta
  archiviato; la matrice route/dati è in `docs/parity/themis-vap-runtime.json`.
  L'import revisionato dei record terminali, le decisioni route/dati e il ritiro
  fisico del sorgente sono completati e verificati. `themis legacy-snapshot` ora apre `vap.db` in
  sola lettura, crea un backup SQLite consistente e un inventario versionato con
  digest, conteggi, chiavi deterministiche, mapping esplicito degli stati e
  rollback; non crea job eseguibili e non importa consent/audit/analytics.
- [x] Definire una matrice di parità per endpoint, job state, persistenza, audit,
  report e cancellazione prima di rimuovere il codice legacy.
- [x] Rendere il control plane nativo fail-closed: autenticazione obbligatoria,
  autorizzazioni minime per rotta, scope registrati, limiti di concorrenza e live
  scan disabilitate di default. La chiave condivisa legacy ora concede per
  default solo `capabilities:read`; ulteriori scope richiedono un opt-in esplicito
  (`--api-key-scopes`), mentre sono preferibili identità nominate. API e Web ora applicano un limite di richieste
  simultanee aggregate fra processi che condividono il job database (default 64,
  configurabile 1–4096); l'overflow è respinto con 503 e Retry-After, ed è
  auditato. Autenticazione obbligatoria,
  scope per rotta e live scan disabilitate per default erano già presenti.
- [x] Eseguire la threat-model review per la milestone di controllo API/Web del
  2026-10-19; ripeterla prima di ogni successiva milestone di migrazione. Esito e
  rischi residui in [`docs/threat-model.md`](docs/threat-model.md).

**Criterio di completamento:** wheel e container eseguono API, worker e migrazioni
senza importare `vendor/`; i test di parità e regressione sono verdi; la directory
vendorizzata può essere rimossa senza perdita di funzionalità dichiarata.

**Avanzamento verificato (2026-10-19):** il control plane nativo rifiuta in modo
non bloccante le richieste oltre il limite concorrente di ciascun processo API o
Web. La risposta `503` è registrata nell'audit redatto e conserva gli header di
sicurezza. Il limite non coordina più processi o repliche; autenticazione
multiutente minima, privilegi di default ora ridotti per la chiave condivisa, e
limiti di concorrenza worker/distribuiti restano da verificare prima di
completare `SEC-A`.

**Avanzamento verificato (2026-10-19, smoke runtime):** il test della wheel e
dell'immagine container assegna esplicitamente alla chiave sintetica i permessi
minimi necessari al submit/lettura job (`capabilities:read`, `jobs:read`,
`jobs:write`). Il default read-only resta invariato; il test non dipende da
privilegi impliciti della chiave.

**Avanzamento verificato (2026-10-22, snapshot dati legacy):** il comando
`themis legacy-snapshot` produce un backup SQLite create-only e il contratto
`olympus.legacy-vap-snapshot` 1.0.0 senza modificare il database sorgente.
Registra digest di sorgente/backup, conteggi e chiavi di migrazione
deterministiche; esclude target e query secret, mantiene consent/audit/analytics
solo nel backup e marca le righe `queued`/`running` come non convertibili. La
conversione revisionata nei contratti nativi, la parità delle route residue e il
ritiro fisico del vendor restano aperti: `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-22, gate di integrità legacy):** il comando
read-only `themis legacy-verify` richiede sorgente, backup e manifest insieme;
verifica i digest e la dimensione sorgente, lo schema esatto del contratto,
`PRAGMA integrity_check` e l'inventario ricostruito dal backup, rifiutando anche
modifiche concorrenti. Non ripara, non importa e non crea job. La conversione
revisionata, le route residue e il ritiro fisico restano aperti: `SEC-A` resta
`[~]`.

**Avanzamento verificato (2026-10-23, piano di conversione revisionabile):**
`themis legacy-plan` rivalida sorgente, backup e manifest e pubblica il contratto
`olympus.legacy-vap-conversion-plan` 1.0.0 create-only. Il piano contiene solo
digest, mapping di stato/scanner e disposizioni fail-closed; record attivi,
eliminati, ambigui o privi di adapter restano nel backup. Non eredita consenso o
autorizzazione e crea esplicitamente zero job. L'importazione con engagement
manifest corrente, la parità delle route residue e il ritiro fisico del vendor
restano aperti: `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-23, approvazione firmata dell'import):**
`themis legacy-approve` rivalida snapshot e piano e accetta soltanto migration key
terminali selezionate esplicitamente. Firma Ed25519, revoche opzionali, finestra,
scope, tecnica e limite dei target sono verificati contro un engagement manifest
corrente. Il contratto `olympus.legacy-vap-import-approval` 1.0.0 espone solo
digest, non attribuisce retroattivamente autorizzazione alle esecuzioni storiche
e crea zero job. L'importatore storico, la parità delle route residue e il ritiro
fisico del vendor restano aperti: `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-23, import storico terminale):**
`themis legacy-import` rivalida snapshot, piano, approval, firma Ed25519,
revoche, finestra e scope prima di una transazione idempotente nel job store
nativo. Importa esclusivamente record approvati già terminali con
`authorized=false` e senza manifest di esecuzione; nessun worker può reclamarli.
Un legacy `completed` diventa `partial`, mai `succeeded`, perché i corpi finding
non affidabili restano nel backup e sono preservati soltanto tramite digest;
`failed` e `canceled` restano distinti. Query secret sono redatti prima della
persistenza e il contratto `olympus.legacy-vap-import-receipt` 1.0.0 espone solo
provenienza minimizzata. Parità delle route/dati esclusi, controllo distribuito
della concorrenza e ritiro fisico del vendor restano aperti: `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-23, decisione di ritiro route/dati):** la
review multidisciplinare ha classificato ogni route e confine dati VAP in
`native_replacement`, `intentional_exclusion` o `future_native_capability` nel
manifest verificabile
[`docs/parity/themis-vap-retirement.json`](docs/parity/themis-vap-retirement.json).
Il test contrattuale impone copertura esatta e non duplicata di tutte le route e
dei cinque confini dati; nessuna decisione richiede di conservare il sorgente
eseguibile. Le capability future rimangono legate agli ID roadmap esistenti e
non ereditano route, identità o contratti VAP. Controllo distribuito della
concorrenza e ritiro fisico del vendor restano aperti: `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-23, concorrenza control plane condivisa):**
API e Web coordinano lo stesso limite di richieste tra processi mediante un
sidecar SQLite con acquisizione atomica, lease rinnovabili e recupero dopo crash.
Overflow, lock contention e indisponibilità del coordinatore falliscono chiusi
con `503`, senza accodamento; il sidecar non persiste payload o identità. Le
repliche devono condividere il job database/volume e la stessa configurazione;
un deployment multi-host senza storage condiviso richiede ancora un limite a
monte. Il criterio fail-closed del control plane è completo; il limite worker e
il ritiro fisico del vendor sono i due residui successivi, quindi `SEC-A` resta `[~]`.

**Avanzamento verificato (2026-10-24, concorrenza worker condivisa):** ogni
worker esegue un job alla volta e `--max-concurrent-jobs` (default 1, 1–4096)
limita atomicamente il totale dei job `running` fra tutti i processi che
condividono il database. Il conteggio e il claim avvengono nella stessa
transazione SQLite; le lease scadute sono recuperate prima del conteggio e non
consumano capacità. Configurazioni discordanti tra repliche restano un errore
operativo documentato. Il limite worker è completo; rimane soltanto la rimozione
fisica del sorgente VAP archiviato.

**Completamento verificato (2026-10-24, ritiro fisico):** la directory
`vendor/vulnerability-assessment-platform`, l'helper di caricamento e lo script
di setup legacy sono stati rimossi. I manifest conservano revisione, digest,
inventario delle 39 route e decisioni sui cinque confini dati senza trattenere
codice eseguibile. I test impongono l'assenza del tree e verificano catalogo,
compatibilità CLI, runtime nativo e inventari. Wheel, container e migrazione
dello storico restano indipendenti dal vendor. **SEC-A è completato `[x]`.**

### Intervento B · `SEC-B` — Isolamento forte degli scanner (**P0**)

`src/olympus/themis/sandbox.py` applica già drop dei privilegi, limiti CPU/memoria/
processi/file descriptor, directory temporanea privata e terminazione del process
group. Il file dichiara correttamente ciò che manca.

- [x] Eseguire ogni scanner in un namespace/container con filesystem root
  read-only, capability Linux azzerate, `no-new-privileges` e profilo seccomp.
- [x] Applicare AppArmor o SELinux dove disponibile e pubblicare un profilo
  versionato nel repository.
- [~] Separare control plane e scan plane; consentire egress solo verso IP e porte
  derivati dallo scope già validato.
- [ ] Bloccare metadata endpoint cloud, loopback, link-local, reti private non
  dichiarate e redirect fuori scope anche dal network namespace dello scanner.
- [~] Aggiungere test di fuga: scrittura fuori scratch, fork bomb, accesso a file
  sensibili, connessione a target fuori scope e timeout non cooperativo.

**Avanzamento verificato (2026-10-24):** il worker Compose non-root applica ora
un profilo seccomp versionato, default-deny e compatibile x86-64/AArch64, oltre a
root filesystem read-only, capability azzerate e `no-new-privileges`. Il profilo
nega namespace aggiuntivi e syscall kernel ad alto rischio; il job CI
`native-container` avvia il runtime con quel profilo e verifica un rifiuto
`EPERM`. Il runtime locale non dispone di Docker/Podman e non consente `ptrace`,
quindi la prova kernel container resta demandata alla CI. SEC-B rimane `[~]`:
la CLI host non è ancora containerizzata obbligatoriamente e l'egress allowlist
scan-plane non è implementata; il profilo AppArmor opzionale
è descritto nell'avanzamento successivo.

**Avanzamento verificato (2026-10-24, escape test):** la suite container esegue
ora probe offline e limitati per root filesystem read-only, assenza di file host,
accesso a `/proc/kcore`, capability azzerate, `no-new-privileges`, seccomp e
creazione di user namespace. Una fork bomb simulata è limitata a 32 PID, ha un
massimo di 128 tentativi e termina sempre i processi creati. Il test non contatta
target. Restano aperte la prova di egress verso un target fuori scope e la
containerizzazione obbligatoria delle esecuzioni CLI dirette; il criterio resta
pertanto `[~]`.

**Avanzamento verificato (2026-10-24, LSM):** è pubblicato il profilo AppArmor
versionato `olympus-themis-scanner` con deny espliciti per mount/pivot-root,
ptrace, kernel memory, securityfs, firmware e percorsi host-sensitive. L'overlay
Compose è opt-in perché il profilo deve essere caricato dall'amministratore
dell'host. Su runner Linux compatibili la CI carica il profilo in enforce mode,
lo associa ai container e prova sia `/proc/self/attr/current` sia il rifiuto di
un canary sintetico bind-mounted. Il provisioner fail-closed
`scripts/manage_scanner_apparmor.py` valida identità, versione, file regolare e
digest, usa un argv fisso senza shell, richiede AppArmor attivo e privilegi root
e carica idempotentemente la policy; la CI usa lo stesso percorso prima della
prova container. Il criterio è quindi `[x]`: AppArmor soddisfa l'alternativa LSM
richiesta, mentre SELinux resta un'estensione portabile futura e non una
condizione di questo bullet.

**Avanzamento verificato (2026-10-24, container obbligatorio):** il servizio
applicativo rifiuta ora ogni esecuzione live se il processo non prova un marker
OCI root-owned, l'attestazione immagine con digest fissato, root filesystem in
sola lettura, capability effettive azzerate, `no-new-privileges` e almeno un
filtro seccomp. Il gate precede la risoluzione dello scope e la costruzione
dell'adapter; `themis run`, `workers` e `jobs work` non possono abilitarlo con
una variabile o un flag host. Simulazione e modalità live disabilitata restano
portabili e senza traffico. La CI esercita il gate nel container hardened; il
primo criterio è quindi `[x]`. Separazione scan/control plane ed egress
scope-derived erano i successivi residui SEC-B; l'avanzamento seguente completa
la separazione topologica mantenendo aperta la policy egress per job.

**Avanzamento verificato (2026-10-25, separazione reti):** il Compose nativo
collega API e Web esclusivamente alla rete `control`, dichiarata `internal`, e
worker più motori opzionali esclusivamente alla rete `scan-egress`; la migrazione
resta senza rete. Nessun servizio è dual-homed. Il volume SQLite condiviso
trasporta i job tra i due piani senza creare un percorso di rete dal piano di
scansione a quello di controllo. Un contract test analizza il Compose e rende
queste proprietà un gate di regressione. Il criterio congiunto resta `[~]`:
`scan-egress` consente ancora egress generale e deve essere ristretto, per ogni
job, agli IP e alle porte derivati dallo scope validato prima di poterlo chiudere.

**Avanzamento verificato (2026-10-25, timeout non cooperativo):** il probe
offline eseguito nel container hardened avvia ora un processo reale che ignora
`SIGTERM` tramite il runner di produzione. Impone timeout e grace period di 0,5
secondi, richiede il segnale all'intero process group, l'escalation `SIGKILL`, la
causa e il limite nel report strutturato e un deadline esterno di 10 secondi. La
prova non usa shell né rete e il job container mantiene `--network none`. Il
componente “timeout non cooperativo” del test di fuga è quindi verificato; il
bullet resta `[~]` perché la connessione fuori scope e la relativa policy egress
per job non sono ancora implementate.

**Criterio di completamento:** un adapter compromesso non può leggere il filesystem
host, elevare privilegi o raggiungere un indirizzo non autorizzato; le prove sono
automatizzate e allegate come evidenza di release.

### Intervento C · `SEC-C` — Engagement manifest firmato (**P1**)

`core.execution.ExecutionPolicy` richiede oggi `authorized=True` e può registrare
un `approval_reference`, ma una conferma booleana non prova chi abbia autorizzato
cosa e per quanto tempo.

- [x] Introdurre `EngagementManifest` versionato con cliente/owner, approvatore,
  target inclusi ed esclusi, finestre temporali, tecniche consentite, limiti,
  identificativo del contratto e data di scadenza.
- [x] Firmare il manifest con Ed25519 riusando `olympus.core.signing`; il
  verificatore a chiave pubblica fissata controlla digest, target, tecnica e
  finestra in ogni percorso che può produrre traffico live.
- [x] Legare ogni job live all'hash del manifest e registrarlo in audit, report ed
  evidenze; impedire il riuso dopo revoca o scadenza. La scadenza è già imposta
  dalla finestra temporale di `authorizes`; la **revoca** è ora applicata da
  `SignedEngagementManifest.authorize(..., revoked=...)`, che rifiuta con
  `ManifestRevocationError` (sottoclasse di `ManifestAuthorizationError`) un
  manifest il cui digest, `manifest_id` o `engagement_id` compaia nella lista di
  revoca — controllata **dopo** la verifica di firma/digest, così non maschera
  mai un manifest manomesso. L'argomento `revoked` rifiuta inoltre fail-closed
  input scalari, collezioni non-stringa o identificatori vuoti, così un singolo
  ID passato per errore come stringa non viene interpretato come lista di
  caratteri. Il database SQLite engagements ora persiste digest e `manifest_id`
  solo dopo la verifica della firma e offre `authorize_manifest`, che carica il
  registro prima di delegare i controlli. Restano il legame di ogni job all'hash
  del manifest e la registrazione in audit/report/evidenze (wiring nei percorsi
  attivi).
- [x] Prevedere un profilo lab separato, esplicito e limitato a reti dichiarate,
  senza scorciatoie globali come “allow all”.

**Avanzamento verificato (2026-10-19):** aggiunti i contratti versionati
`olympus.engagement-manifest` e `olympus.signed-engagement-manifest`, con firma
Ed25519 sul JSON canonico e verifica che richiede la chiave pubblica fidata del
verificatore. La funzione di autorizzazione controlla l'intervallo temporale,
scope incluso/escluso e tecnica richiesta. Al 2026-10-19 il controllo non era
integrato nei percorsi attivi, mancava un registro di revoca e i job non
persistevano l'hash del manifest; SEC-C non era completato e il manifest da solo
non abilitava una scansione.

**Avanzamento verificato (2026-10-20, registro revoche):** lo store SQLite
engagement registra digest e `manifest_id` di un manifest solo dopo aver
verificato digest e firma con la chiave pubblica fidata. Il metodo
`authorize_manifest` rilegge le revoche persistenti e rifiuta il riuso; test
offline coprono firma non attendibile, riapertura del database e rifiuto. Il
registro locale non è tamper-evident o distribuito e non è ancora collegato ai
percorsi attivi di submit job: `SEC-C` resta incompleto.

**Avanzamento verificato (2026-10-21, binding persistente):** il contratto job
Themis 3.0.0 e lo schema SQLite v3 possono conservare `manifest_sha256`; il
digest è validato, esposto al worker e parte dell'identità della richiesta
idempotente. La migrazione v2→v3 mantiene i job esistenti senza inventare una
provenienza di autorizzazione. API, Web e CLI non impongono ancora il manifest
firmato in ogni submit e SEC-C resta quindi `[~]`.

**Avanzamento verificato (2026-10-21, gate API):** quando il server configura
la chiave pubblica Ed25519 fidata, `POST /api/v1/jobs` richiede un manifest
firmato, verifica firma/digest, revoche persistenti, finestra, engagement,
target e scanner, quindi lega il digest al job. Un manifest inviato senza una
chiave fidata server-side viene rifiutato. Web e CLI non applicano ancora lo
stesso gate: SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-21, gate worker):** l'API conserva nel database
engagement il documento firmato già verificato. Un worker configurato con lo
stesso archivio e la chiave pubblica fissata ricarica il manifest legato al job
e ricontrolla firma, digest, revoca, finestra, target e scanner immediatamente
prima dell'esecuzione. Un digest non recuperabile o un worker senza verificatore
terminano il job come `policy_denied`, senza avviare lo scanner. Web e CLI non
impongono ancora il manifest firmato in ogni submit; SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-21, gate CLI):** `themis jobs submit` non
accetta più la sola conferma booleana: richiede il documento firmato, la chiave
pubblica Ed25519 fissata e l'archivio engagement. Prima di accodare verifica
firma, digest, revoca, finestra, target e scanner, conserva il documento e lega
il digest al job. Letture limitate di file regolari non-symlink e test di
regressione coprono manifest assente, scaduto e fuori scope/tecnica. Il Web non
impone ancora lo stesso gate e audit/report/evidenze non espongono ancora tutta
la provenienza, quindi SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-22, gate Web):** `themis web`/`serve` accetta
ora `--manifest-public-key` con lettura limitata di file regolari non-symlink e,
quando la chiave è configurata insieme all'archivio engagement, il wizard
richiede il documento firmato. Anteprima e submit verificano firma, digest,
revoca, finestra, engagement, target e scanner; il submit conserva il documento
e lega il digest al job. Test Web coprono assenza, manomissione, scadenza,
revoca, tecnica errata e chiave fidata assente. La modalità API/Web senza chiave
resta compatibile ma non è il profilo protetto; audit/report/evidenze non
espongono ancora tutta la provenienza, quindi SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-22, provenienza audit worker):** prima di
eseguire un job legato a un manifest, il worker registra un evento redatto
`themis.manifest-authorization` con esito `authorized` o `refused`, job ID,
digest e scanner; anche l'evento successivo `themis.native-scan` porta lo stesso
job ID e digest. Un rifiuto per revoca, scadenza, documento mancante o
verificatore assente è quindi dimostrabile senza salvare nel log il documento
firmato o eventuali segreti nella URL. Report ed evidenze non incorporano ancora
questa provenienza e la modalità compatibile senza chiave resta disponibile:
SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-22, provenienza evidenza job):** il contratto
`olympus.themis-result` 1.2.0 include ora `job_id` e `manifest_sha256` opzionali
ma accoppiati; il worker li persiste nel risultato dopo la rivalidazione, oltre
che negli eventi audit. Un risultato può quindi essere correlato alla decisione
di autorizzazione senza copiare manifest, approvatore o target non redatto.
L'inclusione della provenienza nei report consolidati e la rimozione della
modalità compatibile senza chiave restano aperte: SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-22, provenienza report verificata):** Vulcan
accetta risultati Themis 1.2.0, manifest firmati e chiave pubblica Ed25519
fissata come insieme fail-closed. Il report `olympus.security-report` 1.1.0
verifica firma/digest e che target e scanner del risultato siano coperti da
scope e tecniche firmati, quindi esporta in JSON/Markdown/HTML/PDF una proiezione
minimizzata con job, digest, identificativi, finestra e limiti, senza documento
firmato, target puntuale o dati di approvatore/cliente. Non inventa una verifica
retrospettiva di revoca o finestra temporale: quella decisione resta provata
dall'audit worker correlato. Il profilo lab separato e la modalità compatibile
senza chiave restano aperti: SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-25, gate esecuzione diretta):**
`olympus themis run` non può più avviare una scansione live con la sola conferma
booleana. Quando il live è abilitato richiede documento firmato, chiave pubblica
Ed25519 fissata e archivio engagement; verifica firma, digest, revoca, finestra,
target e scanner prima di costruire il servizio applicativo. Il documento viene
conservato e il risultato/audit ricevono job ID e digest correlabili; anche i
rifiuti sono auditati senza copiare il manifest. Simulazione e stato live-off
restano portabili e non creano provenienza fittizia. API/Web senza chiave e il
profilo lab separato restano aperti, quindi SEC-C resta `[~]`.

**Avanzamento verificato (2026-10-25, gate worker autorevole):** un worker con
live abilitato rifiuta ora come `policy_denied` qualsiasi job privo di digest del
manifest, prima di heartbeat, scope resolution o applicazione scanner. Il
rifiuto è auditato e redatto anche quando non esiste un digest; un manifest
legato continua a richiedere documento persistito, chiave fissata e
rivalidazione. La CLI non avvia inoltre un worker live senza archivio engagement
e chiave pubblica. La modalità API/Web senza chiave può ancora accodare lavoro
offline per compatibilità, ma non può più trasformarlo in traffico live tramite
un worker. Firma e binding sono quindi completi per le esecuzioni live; resta
aperto soltanto il profilo lab separato, perciò SEC-C rimane `[~]`.

**Completamento verificato (2026-10-25, profilo lab separato):** l'esecuzione
diretta può usare `--lab-policy` soltanto con un file nominato esplicitamente,
`[lab].enabled`, engagement non vuoto, identità e data di attivazione, CIDR
ammissibili e record di attivazione HMAC-SHA256 firmato tramite
`OLYMPUS_POLICY_LAB_KEY`. Il profilo è alternativo, mai cumulabile, al manifest
Ed25519. Ogni indirizzo risolto deve appartenere sia allo scope Themis sia a uno
dei CIDR lab; pubblico, loopback, link-local, metadata e qualunque rete non
dichiarata falliscono chiusi. Digest policy e firma di attivazione sono registrati
nell'audit nativo. Worker, API e Web non accettano questa eccezione e continuano
a richiedere manifest firmati prima di produrre traffico live. Test offline
coprono profilo assente/non firmato, range globale, provenienza malformata,
mix con manifest e target risolto fuori CIDR. **SEC-C è completato `[x]`.**

**Criterio di completamento:** nessuna live scan può partire con un semplice flag;
il report consente di dimostrare manifest, firma, scope e policy effettivi usati.

### Intervento D · `SEC-D` — Gestione credenziali e identità (**P1**)

- [x] Conservare le variabili d'ambiente come fallback locale, senza introdurre
  `.env` caricati automaticamente in produzione. `core/secrets.EnvSecretProvider`
  legge l'ambiente **vivo** del processo (valore vuoto o di soli spazi = non
  impostato) e non carica mai un file `.env`; è il `default_secret_provider()`.
- [x] Definire un'interfaccia `SecretProvider` con implementazioni opzionali per
  keyring OS e secret manager esterni; i valori devono restare `SecretStr` o byte
  buffer il più a lungo possibile. Porta `core/secrets.SecretProvider` (Protocol)
  con `EnvSecretProvider`, `KeyringSecretProvider` (import `keyring` isolato →
  `SecretProviderUnavailable` se assente, nessuna dipendenza hard nel core) e
  `ChainSecretProvider`; `resolve_secret(name, *, provider=None)` è l'unico punto
  di lookup. Il valore risolto è un `SecretStr` (mascherato in repr/log/traceback,
  estratto con `.get_secret_value()` solo all'uso). Adottato dai client OSINT di
  Argus (`NumverifyClient`/`RapidApiMessagingClient.from_env(..., secrets=…)`).
  Test `tests/unit/test_core_secrets.py` (+ provider iniettato in
  `tests/unit/test_argus_enrichment.py`); doc
  [`docs/configuration.md`](docs/configuration.md). **Resta aperto:** OIDC/mTLS
  (bullet successivo) e rotazione uniforme.
- [x] Per Themis API, affiancare alle API key hashate un'opzione OIDC per
  deployment multiutente; mantenere permessi per azione e revoca immediata.
  L'issuer HTTPS, l'audience e un JWKS locale sono fissati esplicitamente: non
  sono consentiti discovery o fetch di chiavi a runtime. Il `sub` verificato è
  mappato al registro locale, che resta autorevole per scope per azione, expiry,
  rate limit e revoca immediata. Algoritmi ammessi: RS256, ES256 ed EdDSA;
  token e durata sono limitati. CLI API/Web: `--oidc-issuer`,
  `--oidc-audience`, `--oidc-jwks`. Test sintetici coprono firma/claim errati,
  lifetime, doppia credenziale, revoca senza restart e audit privo del bearer.
  mTLS resta un'alternativa futura; la rotazione uniforme è applicata dal punto
  successivo.
- [x] Rendere uniforme la rotazione: le credenziali nominate nuove e ruotate
  scadono obbligatoriamente (90 giorni predefiniti, 1–3650 consentiti), l'overlap
  è limitato a un'ora e ogni `add`/`rotate`/`revoke` registra identità, azione,
  scadenza e overlap senza secret né digest. I register legacy senza scadenza
  restano leggibili e acquisiscono la policy alla rotazione. Test unitari,
  property-based, CLI e mutation coprono limiti, continuità e canary anti-leak.
- [x] Aggiungere property-based test alla redazione in `core.execution` per query
  URL, header, mapping annidati, output scanner, Unicode e chiavi inattese
  (`tests/unit/test_property_security.py`); i casi generati verificano la rimozione
  del token, la conservazione dei campi diagnostici non sensibili e il trattamento
  di URL embedded in output scanner Unicode.

**Criterio di completamento:** nessun segreto compare in log, eccezioni, report,
telemetria o file temporanei nei test canary; tutte le credenziali di servizio sono
ruotabili senza downtime. **SEC-D resta `[~]`: la gestione identità è implementata, ma SEC-D-01 (redazione TUI) è aperto.**

### Intervento E · `SEC-E` — Evidenze e chain of custody verificabili (**P1**)

- [x] Integrare la firma Ed25519 direttamente nell'append path del ledger Minerva,
  non solo come firma detached successiva del file. Nuova variante ledger **2.2.0**
  (`_CustodyLedgerV2Ed25519Signed` + `CustodyEd25519Signature`): `append_entry`
  firma la testa della catena (`entry_count`+`head_hash`) con **Ed25519** quando è
  presente `OLYMPUS_CUSTODY_ED25519_PRIVATE_KEY` (seed 32 byte hex, risolto via il
  `SecretProvider` di `SEC-D`), altrimenti HMAC 2.1.0, altrimenti 2.0.0.
  `verify_ed25519_signature`/`inspect_ledger` verificano con la **sola chiave
  pubblica** (`OLYMPUS_CUSTODY_ED25519_PUBLIC_KEY`) — **verifica da parte di un
  soggetto terzo**, che l'HMAC simmetrico non consente — e vincolano la chiave
  pubblica incorporata al trust anchor dell'operatore (un attaccante non può
  rifirmare un ledger riscritto con una propria chiave). Troncamento, riordino,
  manomissione e sostituzione di chiave sono rilevati; l'append su ledger firmato
  senza chiave è rifiutato (`CustodyKeyError`). CLI `olympus minerva record`/`verify`
  caricano le chiavi dall'ambiente. Test `tests/unit/test_minerva_custody.py`
  (append 2.2.0, verifica terza parte, chiave errata, manomissione, append senza
  chiave, loader, round-trip CLI); doc [`docs/minerva.md`](docs/minerva.md).
- [ ] Aggiungere timestamp attendibile RFC 3161 o servizio equivalente per
  attestare anche il momento di acquisizione.
- [x] Memorizzare hash, tool/versione, policy, scope, command template, stato di
  coverage e motivo di ogni risultato parziale. La famiglia custody 3.x richiede
  un documento di acquisizione stretto sulla prima voce `collected`; provenienza,
  digest dell'evidenza e stato entrano nell'hash e nella firma del ledger. Gli
  stati `partial`/`failed`/`cancelled` richiedono un motivo redatto. I ledger 2.x
  restano verificabili senza attribuzione retroattiva; test unitari, property e
  mutation coprono manomissione, segreti e compatibilità.
- [~] Cifrare a riposo findings ed evidenze sensibili con chiavi separabili dai
  dati e definire cancellazione verificabile secondo retention policy. Le
  evidenze Minerva dispongono ora di pacchetti cifrati autenticati, chiave runtime
  separata tramite `SecretProvider`, ripristino fail-closed e cancellazione della
  sorgente solo dopo verifica round-trip con ricevuta minimizzata. Anche i
  documenti del lifecycle store dei finding supportano ora cifratura autenticata
  per record con chiave distinta `OLYMPUS_FINDINGS_ENCRYPTION_KEY`, compatibilità
  di lettura legacy e rifiuto fail-closed di chiavi mancanti/errate o ciphertext
  alterato. **Bundle finding cifrati a riposo fatto (2026-10-28):** la policy di
  chiave è ora single-source in `olympus/findings/encryption.py` (nome env,
  lunghezza minima, risoluzione via `SecretProvider`), condivisa dal lifecycle
  store e dalla nuova via bundle; gli immutabili bundle JSON `core.Finding`/
  `core.Asset` prodotti da scanner e Athena possono essere cifrati con la **stessa**
  chiave (`olympus vulcan encrypt-bundle`/`decrypt-bundle`) e vengono **decifrati
  in modo trasparente dal choke point unico di caricamento** `vulcan.aggregate.
  load_findings`/`load_assets`, così CLI e Web UI leggono bundle cifrati e in chiaro
  in modo identico; lettura fail-closed (chiave assente/errata o ciphertext alterato
  → rifiuto, mai risultati vuoti/parziali) e compatibilità legacy in chiaro. Resta
  aperta solo l'applicazione schedulata e uniforme della retention su backup,
  snapshot e repliche (richiede infrastruttura di deployment); per questo la voce
  resta parziale.

**Criterio di completamento:** modifica, riordino, troncamento o sostituzione di una
evidenza vengono rilevati e la verifica è possibile da un soggetto terzo.

### Intervento F · `SEC-F` — Supply-chain security e release signing (**P1**)

- [ ] Aggiungere CodeQL/SAST come gate bloccante per il codice first-party.
- [ ] Generare provenance SLSA e attestazioni firmate per wheel, sdist, container,
  SBOM e lockfile.
- [ ] Firmare immagini container con Cosign e usare esclusivamente base image
  pinned per digest, già richieste dalle verifiche correnti.
- [ ] Separare SBOM core, extra AEGIS e tool esterni; associare a ogni adapter la
  versione supportata e l'esito della vulnerability scan.
- [ ] Abilitare regole di branch protection: review obbligatoria, status check,
  commit/release firmati e divieto di force-push su `main`.

**Criterio di completamento:** ogni release pubblica è riproducibile, firmata,
corredata da SBOM e attestazione; la verifica fallisce su artifact alterati.

### Intervento G · `SEC-G` — Guardrail per capacità offensive (**P1**)

- [~] Classificare ogni comando come `passive`, `active`, `intrusive` o
  `destructive-prohibited` e mostrare la classe prima dell'esecuzione.
  **Fatto:** la tassonomia `RiskClass` (`passive`/`active`/`intrusive`) con mappa
  per-scanner rivista (`integrations/activity.py`; non mappato → `active`, mai
  `passive`) è mostrata **prima dell'esecuzione** nell'anteprima di sicurezza
  (Web guided flow, TUI, CLI `olympus themis preview`) e ora anche nel **catalogo
  scanner** `olympus themis scanners --check` (campo `risk` per ogni voce). Test
  `tests/integration/test_vendored_integration.py`. **Resta:** la classe esplicita
  `destructive-prohibited` come confine di prodotto dichiarato (DoS/persistenza/
  credential-harvesting/evasione fuori scope) e una colonna rischio nel
  `docs/scanner-matrix.md` generato.
- [ ] Consentire le operazioni intrusive solo se esplicitamente abilitate nel
  manifest firmato; mantenere DoS, persistenza, credential harvesting reale ed
  evasione fuori dallo scope di prodotto.
- [~] Implementare dry-run con visualizzazione dell'argv redatto, destinazioni,
  rate/deadline e file che verranno creati. **Fatto:** `olympus themis preview`
  (motore puro e offline `themis/preview.preview_run`, nessun processo lanciato,
  nessuna risoluzione DNS) mostra ora il **comando pianificato redatto**
  (`SafetyPreview.planned_command`: ogni token passa da `redact_url` + `safe_terminal_text`,
  così userinfo/segreti di query non trapelano e un target ostile non forgia
  output), oltre a destinazione normalizzata, budget timeout/deadline/output/findings
  e i path di output/audit che verrebbero creati; assente onestamente per scanner
  senza adapter nativo o per target bloccati. Il campo è sul modello condiviso
  `SafetyPreview` (serializzato in `to_dict()`); la stessa logica è esposta come
  helper pubblico `preview.planned_command(scanner, target, target_kind, scope)` e
  resa anche nell'**anteprima guidata Web** (`POST /assessments/preview`, riga
  "Planned command" prima della conferma). Test `tests/unit/test_themis_preview.py`
  e `tests/unit/test_themis_web.py`. **Resta:** il comando pianificato
  nell'anteprima TUI e un flag `--dry-run` esplicito sui percorsi di esecuzione
  reale (oggi il dry-run è il comando `preview` dedicato).
- [ ] Applicare un kill switch coerente a CLI, TUI, API e worker, con cancellazione
  del process group e stato finale non ambiguo.

**Criterio di completamento:** lo stesso comando non può ottenere privilegi o
capacità maggiori passando da un'interfaccia diversa.

### Intervento H · `SEC-H` — Dati ostili restituiti dai target (**P1**)

Uno strumento di sicurezza elabora per definizione dati prodotti da sistemi non
fidati: banner, header, titoli di pagina, hostname, output di script NSE e report
degli scanner sono controllati dal target e possono colpire l'operatore
(“attacco al pentester”). Oggi Vulcan esegue `html.escape` e la TUI disabilita il
markup Rich, ma la difesa non è sistematica.

- [~] Trattare ogni output scanner come input non fidato: il parser Nmap usa
  `defusedxml`, disabilita entità e riferimenti esterni, e applica limiti di
  dimensione, profondità e numero di elementi durante il parsing. Tutti i parser
  JSON/JSONL (nuclei, katana, httpx, wapiti, dalfox, wafw00f, testssl)
  condividono ora `olympus.themis.base.check_json_depth`, che rifiuta l'annidamento
  eccessivo prima di invocare il decoder ricorsivo di Python. Restano da coprire
  eventuali ulteriori confini di parsing non-JSON e il fuzzing sistematico.
- [x] Aggiungere fuzzing (Hypothesis o Atheris) per tutti i parser in
  `themis/adapters/`, `apollo` e `metis`, con corpus iniziale dalle fixture reali:
  nessun input deve causare crash non gestiti, consumo illimitato o finding
  inventati. Tutti i 15 parser degli adapter `themis` sono ora coperti da una
  suite property-based che genera output ostile JSON/JSONL/testo e verifica
  l'invariante «lista di `Finding` oppure `ParseError`/`ValueError` gestito, mai
  eccezione non gestita». I parser di ingest `apollo` (access-log, Sigma) e `metis`
  (bundle STIX, evento MISP) sono ora coperti da una suite analoga con l'invariante
  «risultato valido oppure `ValueError` gestito» (`StixError`, `MispError`,
  `SigmaImportError` sono sottoclassi di `ValueError`). Il corpus iniziale dalle
  fixture reali è ora usato: una suite di mutation fuzzing parte dall'output reale
  catturato in `tests/fixtures/themis/live/` (nmap, wafw00f, testssl, wapiti,
  whatweb) e vi applica mutazioni byte-level, verificando lo stesso invariante.
  Anche i normalizzatori ECS/OCSF di Apollo sono ora sotto fuzzing: alert con testo
  ostile producono mapping JSON-serializzabili e NDJSON valido senza byte di
  controllo grezzi. Infine i parser di file non fidati residui — `metis`
  `load_case_document` (caso portatile) e `apollo` `load_rule` (regola di
  detection) — sono coperti con l'invariante «modello valido oppure `ValueError`
  / `ValidationError` gestito». La copertura di fuzzing dei parser è ora completa.
- [~] Neutralizzare sequenze di escape ANSI/OSC e caratteri di controllo prima di
  mostrarle in CLI, TUI e log (terminal injection, falsificazione di righe di log).
  I diagnostici di evento malformato stampati da `apollo run` passano ora da
  `safe_terminal_text`, perché i nomi delle chiavi JSON non supportate possono
  essere controllati dall'input importato. Il test offline verifica la rimozione
  di ANSI e la prevenzione di righe CLI falsificate; anche il dettaglio di errore
  restituito dal server remoto nel client `olympus themis scan` è sanitizzato e
  coperto da test HTTP mockato offline. Inoltre i warning dinamici dei comandi
  Argus (provider OSINT, risultati parziali e pivot) vengono sanitizzati; un test
  CLI offline inietta ANSI e newline nel warning del provider. Altri output CLI
  dinamici restano da rivedere.
- [~] Garantire escaping contestuale in tutti gli export: HTML con Content Security
  Policy restrittiva e nessuno script inline, Markdown, SARIF e CSV/XLSX con
  protezione da formula injection (`=`, `+`, `-`, `@` in testa alla cella).
  **HTML fatto** (CSP `default-src 'none'`, nessuno script inline, `html.escape`
  dopo `safe_terminal_text`). **Markdown fatto** per i metacaratteri e per i link
  letterali `http(s)://` del target, defangati per evitare autolink cliccabili.
  **SARIF export fatto:** in `vulcan/sarif.findings_to_sarif` i campi *renderizzati*
  dai consumer — il `message.text` del result e l'`uri` della location — passano
  ora da `safe_terminal_text` (strip ANSI/OSC e C0/C1, collasso dei newline), così
  un titolo/descrizione controllato dal target non può iniettare sequenze di
  controllo o righe forgiate in un viewer SARIF o in un terminale; titolo e
  descrizione sono sanitizzati **separatamente** e riuniti con `\n`, così lo split
  sopravvive al re-import (round-trip invariato). Test
  `tests/unit/test_vulcan_sarif.py::test_export_neutralizes_hostile_finding_text`.
  **SARIF export di Hermes fatto:** in `hermes/sarif.to_sarif` il `message.text`
  del result incorpora `finding.masked`, derivato dal contenuto del file
  scansionato (controllato dalla sorgente), e passa ora da `safe_terminal_text`;
  l'`uri` della location era già percent-encoded da `_artifact_uri`. Così un
  finding (anche costruito a mano o importato da terzi) con sequenze ANSI/OSC o
  newline nel valore mascherato non può iniettare controlli o righe forgiate in
  un viewer SARIF o in un terminale. Test
  `tests/unit/test_hermes.py::test_sarif_neutralizes_control_sequences_in_message_text`.
  **CSV export fatto:** `vulcan/report.render_report_csv` emette una riga per
  finding (ordinamento per rischio) con ogni cella sanitizzata da
  `safe_terminal_text` e protetta da **formula injection** (`_csv_cell`: prefisso
  apostrofo quando la cella inizia con `=`, `+`, `-`, `@` o tab/CR), così un
  campo controllato dal target come `=HYPERLINK(...)` resta testo letterale e non
  viene eseguito all'apertura in un foglio di calcolo; disponibile da CLI
  (`olympus vulcan report --csv`) e dal browser (`GET /findings/report?format=csv`,
  `text/csv`). Test `tests/unit/test_vulcan.py::test_render_report_csv_is_spreadsheet_safe`.
  Resta: export XLSX (non previsto al momento; il CSV copre il caso tabellare).
- [x] Vietare che valori provenienti dal target diventino path, argv, URL di
  follow-up o nomi file senza passare per validazione e scope gate (path traversal,
  SSRF di secondo ordine, argument injection). Argument injection e path traversal
  sono ora bloccati e verificati: `host_of`/`_normalize_host` rifiutano host
  flag-like (label con `-` iniziale), metacaratteri URL/shell e spazi e accettano
  solo URL http/https validi; ogni adapter costruisce un argv `list[str]` (mai una
  stringa shell), quindi un token derivato dal target non può essere interpretato
  come flag; `output_path`/`state_file_path`/`audit_log_path` rifiutano i nomi file
  con traversal/separatori. **SSRF di secondo ordine verificata formalmente:** nel
  motore di investigazione Argus (`argus/transforms.py`, `argus/application.py`) il
  gate di scope dell'engagement (`_InvestigationScopeGate.allows`) è applicato a
  **ogni entità scoperta** prima di qualunque pivot di rete, non solo al seed, così
  un valore controllato dal target (un sottodominio restituito da Certificate
  Transparency, un IP risolto via DNS, un handle) non diventa un lookup di
  follow-up se cade fuori perimetro: l'entità resta nel grafo per tracciabilità ma
  non viene mai risolta/interrogata, e lo skip è auditato. Regressione pinnata da
  `tests/unit/test_argus_application.py::test_investigation_does_not_resolve_out_of_scope_discovered_subdomain`
  (un sottodominio CT fuori scope non è mai passato al resolver) oltre allo skip
  già coperto per username/IP.
- [x] Creare fixture “malevole” versionate (XML bomb, banner con escape ANSI,
  payload XSS nel titolo, nomi file con `../`) eseguite a ogni run di CI. Il corpus
  vive in `tests/fixtures/malicious/` (con README) ed è esercitato dalla suite
  unitaria `tests/unit/test_malicious_fixtures.py`, parte della CI: ogni voce
  verifica la difesa corrispondente (rifiuto entità/profondità XML e JSON,
  neutralizzazione ANSI/OSC negli export, escaping XSS + CSP, rifiuto dei nomi file
  con traversal da parte di `output_path`).

**Criterio di completamento:** un target controllato dall'attaccante non può
eseguire codice, alterare la visualizzazione, iniettare contenuto nei report o
esaurire le risorse dell'host che esegue Olympus; ogni regressione fa fallire la CI.

**Avanzamento verificato (2026-10-18):** il parser Nmap ora usa `defusedxml`,
rifiuta espansione di entità e riferimenti esterni preservando il `DOCTYPE`
innocuo emesso da Nmap, limita l'input a 4 MiB e la profondità a 64 livelli.
Test offline coprono entity declaration, input sovradimensionato e nesting
eccessivo. `SEC-H` resta `[~]`: fuzzing degli altri parser, neutralizzazione
ANSI/OSC e escaping contestuale degli export non sono ancora completati.

**Avanzamento verificato (2026-10-18, presentazione):** la sanitizzazione
condivisa rimuove controlli C0/C1 (inclusi ANSI/OSC), redige URL e porta il
testo su una sola riga nelle viste Web e Vulcan CLI/TUI; i valori canonici e le
evidenze grezze restano invariati. Restano da coprire altri output/log e gli
escaping degli export indicati sopra.

**Avanzamento verificato (2026-10-19, parsing Nmap):** il parser ora rifiuta
esplicitamente attributi `portid` mancanti, non numerici o fuori dall'intervallo
valido 1–65535, producendo `ParseError` invece di propagare `ValueError` o
creare finding su porte impossibili. Test offline di regressione coprono i
formati malformati e i limiti numerici; un test Hypothesis classifica inoltre
input arbitrari per l'attributo. La revisione non esegue scansioni. Il fuzzing
degli altri parser, l'escaping completo degli export e le restanti voci SEC-H
restano aperti.

**Avanzamento verificato (2026-10-19, JSONL Nuclei):** il parser ora richiede
record JSONL oggetto con `template-id` non vuoto e `info` oggetto; record JSON
validi ma estranei allo schema non vengono più trasformati in finding sintetici.
Un test Hypothesis genera valori JSON arbitrari e verifica che siano rifiutati
con `ParseError` oppure producano un solo finding correttamente attribuito.
Il parser inoltre limita ciascuna riga JSONL a 1 MiB e la profondità JSON a 64
livelli prima del decoding ricorsivo; `RecursionError` è normalizzato in
`ParseError`. Test offline coprono record sovradimensionati, nesting oltre il
limite e delimitatori tra virgolette. Restano aperti fuzzing degli altri parser,
escaping degli export e gli altri criteri SEC-H.

**Avanzamento verificato (2026-10-19, CSP export HTML):** il report HTML
autoconsistente di Vulcan (`render_report_html`) incorpora ora una
Content-Security-Policy restrittiva via `<meta http-equiv>`: `default-src
'none'` vieta script, oggetti e frame, `style-src 'unsafe-inline'` ammette solo
lo stile inline emesso dal renderer, e `base-uri`/`form-action`/`frame-ancestors`
sono azzerati. Anche se un valore controllato dal target eludesse l'escaping
`html.escape`, il browser rifiuterebbe comunque l'esecuzione di script iniettati.
L'attributo è a doppi apici perché le direttive CSP usano apici singoli, così il
valore non viene troncato alla prima parola chiave. Un test unitario offline
verifica la presenza, la restrittività e la chiusura corretta della policy, e che
nessun tag `<script>` venga mai emesso. La sotto-voce dell'escaping contestuale
degli export resta `[ ]`: mancano ancora la protezione da formula injection per
eventuali export tabellari (CSV/XLSX, non ancora presenti) e la revisione
sistematica di Markdown e SARIF.

**Avanzamento verificato (2026-10-19, limite di profondità JSON condiviso):** il
limite di annidamento, finora presente solo nel parser Nuclei, è stato estratto
in `olympus.themis.base.check_json_depth` (`MAX_JSON_DEPTH = 64`, conteggio dei
soli delimitatori fuori dalle stringhe) e applicato prima di `json.loads` in tutti
gli adapter che decodificano JSON/JSONL: `katana`, `httpx`, `wapiti`, `dalfox`,
`wafw00f`, `testssl`, con Nuclei refattorizzato per riusare lo stesso helper senza
duplicazione. Questo impedisce che output di scanner ostile con migliaia di
container annidati esaurisca lo stack dell'interprete (`RecursionError`) o la CPU
prima di produrre un finding. Nuovi test offline (`tests/unit/test_themis_json_depth.py`)
verificano l'helper (inclusa l'immunità ai delimitatori nelle stringhe e un test
Hypothesis) e che ciascuno dei sette adapter rifiuti l'annidamento eccessivo con
`ParseError`. Nessuna scansione eseguita. Restano aperti il fuzzing sistematico di
tutti i parser, l'escaping degli export (Markdown/SARIF) e le restanti voci SEC-H.

**Avanzamento verificato (2026-10-19, neutralizzazione controlli negli export):**
i renderer di report HTML e Markdown di Vulcan (`render_report_html`,
`render_report_markdown`) instradano ora ogni testo controllabile dal target
attraverso `olympus.core.execution.safe_terminal_text` prima dell'escaping
HTML/Markdown. Finora l'escaping (`html.escape`, metacaratteri Markdown)
lasciava intatti ESC, BEL e gli altri controlli C0/C1 (incluse le sequenze
ANSI/OSC): un titolo o una descrizione di finding provenienti da banner o output
scanner potevano quindi iniettare sequenze terminale quando un operatore apriva o
eseguiva `cat` del report esportato (terminal injection, falsificazione di righe
di log). La stessa sanitizzazione condivisa era già applicata alle viste Web e
Vulcan CLI/TUI; ora copre anche gli export testuali. L'export JSON canonico resta
invariato perché `json.dumps` già neutralizza i controlli come sequenze `\uXXXX`
inerti. Un test offline verifica che né l'HTML né il Markdown contengano più
ESC/BEL/DEL/BS pur conservando il testo stampabile. Restano aperti l'export SARIF,
la protezione da formula injection per eventuali export tabellari, il fuzzing dei
parser e le restanti voci SEC-H.

**Avanzamento verificato (2026-10-19, fuzzing dei parser adapter):** aggiunta la
suite property-based `tests/unit/test_themis_parser_fuzz.py` che, enumerando gli
adapter dal registry (`olympus.themis.registry.implemented`, 15 scanner), genera
con Hypothesis output ostile nelle tre forme realmente prodotte dai tool — JSON,
JSONL e testo libero con controlli C0/C1 e unicode — e verifica per ciascun parser
l'invariante: `parse()` restituisce una lista di `Finding` oppure solleva
`ParseError`/`ValueError` (che `ScannerAdapter.run` converte in stato FAILED
pulito), mai un'eccezione non gestita che farebbe crashare il job. Un test di
guardia impedisce che la parametrizzazione collassi a vuoto. Nessuno scanner è
eseguito.

**Avanzamento verificato (2026-10-19, fuzzing parser Apollo/Metis):** aggiunta
`tests/unit/test_cti_parser_fuzz.py` che sottopone a fuzzing Hypothesis i parser
di input non fidato di Apollo e Metis — `bundle_to_indicators` (STIX),
`event_to_indicators` (MISP), `parse_sigma_yaml` e `parse_access_log` — con feed
ostili JSON/JSONL/testo (controlli C0/C1 e unicode). L'invariante verificato: ogni
parser restituisce un risultato valido oppure solleva un `ValueError` gestito
(`StixError`/`MispError`/`SigmaImportError` ne sono sottoclassi), mai un'eccezione
non gestita; `parse_access_log` non solleva mai sui contenuti (le righe non
interpretabili finiscono in `skipped`). Analisi preliminare: 0 crash non gestiti su
migliaia di esempi generati. Restano da seedare il corpus dalle fixture reali e da
coprire i normalizzatori ECS/OCSF prima di spuntare la voce.

**Avanzamento verificato (2026-10-19, corpus di fixture malevole in CI):** creato
il corpus versionato `tests/fixtures/malicious/` (con README) e la suite unitaria
`tests/unit/test_malicious_fixtures.py`, eseguita a ogni run di CI, che mette ogni
fixture di fronte alla difesa reale: bomba di entità XML (rifiutata da
`defusedxml`), XML e JSONL oltre il limite di profondità (`ParseError`), banner
ANSI/OSC (controlli rimossi dagli export HTML/Markdown), payload XSS in un titolo
di finding (escaping + CSP restrittiva nell'export HTML) e nomi file con `../`,
assoluti o con separatori (rifiutati da `output_path`). Un test di guardia impedisce
che il corpus sparisca lasciando passare la suite in silenzio. La sotto-voce è ora
`[x]`; `SEC-H` resta `[~]` per le voci ancora aperte (escaping SARIF, formula
injection per export tabellari, seeding del corpus di fuzzing, normalizzatori
ECS/OCSF).

**Avanzamento verificato (2026-10-19, tabelle CLI):** il renderer condiviso
`core.output.render_table` neutralizza ora controlli C0/C1, righe e query URL
sensibili, e passa celle e titolo a Rich come `Text` anziché come markup. I
valori non fidati non possono quindi attivare markup Rich né iniettare sequenze
ANSI o righe contraffatte nelle tabelle. Il JSON macchina resta invariato. La
voce di neutralizzazione resta parziale: mancano ancora la revisione delle
stampe testuali dirette e degli eventuali log fuori dal renderer condiviso.

**Avanzamento verificato (2026-10-19, URI SARIF Hermes):** i percorsi degli
artifact vengono serializzati come URI reference: i separatori diventano `/`,
mentre caratteri di controllo, delimitatori URI, backslash e `%` sono
percent-encoded. Questo impedisce che un nome file ostile introduca uno schema
URI esterno o alteri la location nei consumer SARIF. Un test offline copre
schema `file:`, backslash, UNC, percorsi Windows assoluti e sequenze CR/LF
codificate. SEC-H resta `[~]`: ciò non completa la revisione di ogni consumer
SARIF né gli altri escaping degli export o la protezione da formula injection.

**Avanzamento verificato (2026-10-19, output Hermes):** il CLI Hermes usa ora
`safe_terminal_text` per ogni messaggio umano, compresi finding, percorsi,
errori e scansioni parziali. Il test
`test_pre_commit_terminal_sanitizes_untrusted_finding_text` inietta path e testo
mascherato con newline, ANSI e OSC tramite il confine applicativo, verificando
che il terminale riceva soltanto output monoriga privo di sequenze di controllo.
La neutralizzazione globale resta `[~]`: gli altri comandi e logger devono
ancora essere auditati.

**Intervento implementato (2026-10-20, import CTI Metis):** gli avvisi per
attributi MISP e pattern STIX deliberatamente saltati passano ora da
`safe_terminal_text` prima di essere scritti nel terminale. Valori provenienti
da feed ostili non possono quindi aggiungere sequenze ANSI/OSC né falsificare
righe negli avvisi CLI. È stato aggiunto un test di regressione offline del
comando `misp-import` con un valore ostile contenente ANSI e newline; il test
verifica anche che JSON di riepilogo e dati canonici restino invariati. Il test
non è eseguibile nell'ambiente locale attuale perché manca `pytest`; l'esito CI
va verificato dopo la pubblicazione. Questa è una correzione mirata: SEC-H resta
`[~]` perché l'audit degli altri output testuali diretti e dei logger non è
concluso.

**Avanzamento verificato (2026-10-20, errori CLI Metis):** il gestore comune
`metis._fail` passa ora ogni eccezione operativa/di validazione da
`safe_terminal_text` prima di scriverla su stderr. Questo copre i percorsi e i
messaggi derivati da database, artefatti e bundle CTI, neutralizzando controlli
ANSI/OSC, righe contraffatte e query URL sensibili senza alterare il codice di
uscita `USAGE`. Un test offline sostituisce lo store SQLite con un errore
sintetico contenente ESC e newline e verifica l'output CLI monoriga. Nessun input
è stato inviato a sistemi remoti. SEC-H resta `[~]`: altri output testuali
dinamici e logger devono ancora essere auditati.

**Intervento implementato (2026-10-20, errori di trasporto Artemis):** i
campioni di errore mostrati dal CLI attraverso il report di coverage passano ora
da `safe_terminal_text`. Il messaggio ricevuto da un trasporto ostile non può
più iniettare controlli ANSI/OSC o righe aggiuntive nella diagnostica. È stato
aggiunto un test CLI offline con trasporto fittizio che restituisce un errore
contenente ESC e newline; l'esito pytest locale è indisponibile in questo runner
perché manca `pytest`, quindi resta da confermare in CI. La correzione copre
questo percorso, non l'audit completo degli altri messaggi dinamici e logger.

**Avanzamento verificato (2026-10-20, diagnostica Artemis):** le uscite CLI che
interpolano URL approvati/bloccati, errori di scope o di policy, percorsi
wordlist e nomi di tecnologie rilevate passano ora da
`safe_terminal_text`. Questo neutralizza ANSI/OSC e controlli C0/C1, collassa
newline contraffatte e applica la redazione degli URL prima della visualizzazione;
il JSON dei finding resta invariato. Un test offline usa un percorso scope
inesistente con ESC e newline e verifica che non possa falsificare una riga CLI.
Sono stati eseguiti solo test con fixture/mock, nessuna richiesta live. La voce
di neutralizzazione resta `[~]`: gli altri output CLI diretti e log devono ancora
essere revisionati sistematicamente.

**Intervento implementato (2026-10-20, errori diretti Artemis):** i comandi
`fetch` e `fingerprint` neutralizzano ora con `safe_terminal_text` anche il
messaggio diretto dell'eccezione di trasporto. In precedenza questi due rami
stampavano `HttpClientError` senza sanitizer, prima della classificazione della
coverage. Test CLI offline iniettano ESC e newline contraffatte e verificano che
il testo venga reso innocuo mantenendo exit code `FAILED` (6). È una copertura
mirata: SEC-H resta `[~]` finché non termina la revisione degli altri output
testuali e logger.

**Avanzamento verificato (2026-10-20, diagnostica Minerva):** i messaggi CLI di
errore e i percorsi/identificativi stampati da Minerva sono ora passati da
`safe_terminal_text`, neutralizzando controlli terminale, sequenze ANSI/OSC,
newline contraffatte e parametri URL sensibili senza alterare i contratti JSON o
gli exit code. Un test CLI offline inietta un errore sintetico con ANSI e una
riga contraffatta e verifica che resti un singolo messaggio con exit code 2.
SEC-H resta `[~]`: la revisione delle altre superfici CLI/log e dei formati
strutturati non è completata.

**Avanzamento verificato (2026-10-20, output CLI Apollo):** le stampe testuali
dirette di Apollo ora passano da un helper che applica `safe_terminal_text` a
errori, diagnostica, riepiloghi e percorsi; l'output JSON macchina resta
inalterato. Un test CLI offline usa un percorso mancante con ANSI e newline
contraffatta e verifica che l'errore resti su una sola riga con exit code `2`.
SEC-H resta `[~]`: le altre superfici e l'escaping completo degli export non sono
stati verificati.

**Avanzamento verificato (2026-10-19, anti argument-injection):** aggiunta la
suite `tests/unit/test_argument_injection_guards.py` che blinda l'invariante «un
valore dal target non diventa un flag dello scanner né un argomento shell».
`host_of`/`_normalize_host` rifiutano host flag-like (label con `-` iniziale),
metacaratteri URL/shell e spazi, e accettano solo URL `http`/`https` con host
valido; ogni adapter del registry costruisce un argv `list[str]` (mai una stringa
shell) in cui il token derivato dal target non è mai option-like, verificato per
target host e URL su tutti e 15 gli adapter. Insieme al rifiuto dei nomi file con
traversal da parte di `output_path`/`state_file_path`/`audit_log_path` (già
coperto), la voce passa a `[~]`; resta da auditare la SSRF di secondo ordine sugli
URL di follow-up costruiti da output dello scanner nei flussi di ricognizione.

**Avanzamento verificato (2026-10-19, fuzzing seedato dal corpus reale):** aggiunta
`tests/unit/test_themis_parser_corpus_fuzz.py`, mutation fuzzing che parte
dall'output reale catturato in `tests/fixtures/themis/live/` (nmap, wafw00f,
testssl, wapiti, whatweb) e applica mutazioni byte-level (troncamento, iniezione di
controlli/ANSI, cancellazione di slice, duplicazione di righe, sostituzione di un
carattere), verificando lo stesso invariante «lista di `Finding` oppure
`ParseError`/`ValueError` gestito, mai eccezione non gestita». Partire da output
valido spinge le mutazioni nei percorsi reali del parser; un'ancora senza mutazioni
verifica che il seed stesso sia robusto. 0 crash non gestiti su centinaia di
esempi. Questo soddisfa la clausola «corpus iniziale dalle fixture reali» della
voce fuzzing (che resta `[~]` per i normalizzatori ECS/OCSF).

**Avanzamento verificato (2026-10-19, fuzzing normalizzatori ECS/OCSF):** aggiunta
`tests/unit/test_apollo_normalizer_fuzz.py` che sottopone a fuzzing gli esportatori
`alert_to_ecs`/`alert_to_ocsf` e `alerts_to_ndjson` di Apollo con alert dal testo
ostile (titolo/event_id con controlli C0/C1, ANSI/OSC e unicode). Invariante
verificato: ogni normalizzatore produce un mapping JSON-serializzabile e l'NDJSON ha
ogni riga come documento JSON valido senza byte di controllo grezzi (`json.dumps`
li codifica come `\uXXXX`), così l'output non può iniettare sequenze terminale né
righe contraffatte in un SIEM a valle. Resta fuori solo qualche parser secondario
(`metis` cases/labs, `apollo` rules/attack layer); la voce fuzzing resta `[~]`.

**Avanzamento verificato (2026-10-19, fuzzing parser di file residui):** aggiunta
`tests/unit/test_secondary_parser_fuzz.py` che sottopone a fuzzing gli ultimi
parser di file non fidati — `olympus.metis.models.load_case_document` (caso
portatile importato) con oggetti JSON arbitrari, e `olympus.apollo.rules.load_rule`
(regola di detection) con testo arbitrario scritto su file temporaneo. Invariante:
ogni parser restituisce il modello validato (`IntelCaseDocument` / `DetectionRule`)
oppure solleva un errore gestito (`ValueError` — di cui `SigmaImportError` e gli
errori di contratto/migrazione sono sottoclassi — o `pydantic.ValidationError`),
mai un'eccezione non gestita. 0 crash su centinaia di esempi. Con questo la
copertura di fuzzing dei parser di `themis/adapters`, `apollo` e `metis` è completa
e la voce passa a `[x]`.

**Avanzamento verificato (2026-10-19, encoding XML ostile):** la suite di
mutation fuzzing ha riprodotto un'eccezione `LookupError` non gestita quando un
input Nmap dichiarava un encoding inesistente. `NmapAdapter` converte ora gli
errori di encoding del decoder in `ParseError`, mantenendo il fallimento confinato
al parser; `test_nmap_normalizes_unknown_declared_encoding` copre la regressione
offline. Nessuno scanner è stato eseguito; `SEC-H` resta aperto per i controlli
residui su escaping degli export e URL di follow-up.

**Avanzamento verificato (2026-10-20, link Markdown):** Vulcan defanga ora gli
schemi letterali `http(s)://` inclusi nei campi testuali del report Markdown, così
un viewer CommonMark/GFM non trasforma testo controllato dal target in un link
cliccabile. `safe_terminal_text` continua a redigere i parametri URL sensibili
prima della serializzazione. Un test offline verifica URL non attivo e redazione
del token. SEC-H resta `[~]`: revisione SARIF, spreadsheet/export futuri e altre
superfici di output rimangono da completare.

**Avanzamento verificato (2026-10-20, diagnostica Vulcan):** i rami CLI Vulcan
che mostrano eccezioni applicative o identificativi/path non trovati passano ora
da `safe_terminal_text`, neutralizzando ANSI/OSC e newline contraffatte. Un test
offline verifica sia un percorso inesistente ostile sia un ID di finding ostile;
gli exit code di errore restano invariati. È una correzione circoscritta: SEC-H
resta `[~]` finché non termina l'audit degli altri output CLI e logger.

### Intervento I · `SEC-I` — Security operations del progetto (**P2**)

- [x] Definire in `SECURITY.md` tempi di presa in carico e di risoluzione per
  severità (es. critica: triage 48 h, fix 7 giorni) e un canale di segnalazione
  privato (GitHub Private Vulnerability Reporting). `SECURITY.md` ha ora una sezione
  «Response targets»/«Tempi di risposta» con tabella SLA per severità (presa in
  carico, decisione di triage, obiettivo di fix) e il canale privato esplicito
  (Security → Advisories → Report a vulnerability), in parità IT/EN; corrette anche
  due sezioni italiane rimaste in inglese (Ambito, Requisiti di sicurezza).
- [x] Collegare Dependabot a una SLA di aggiornamento per le dipendenze con CVE
  note e registrare le eccezioni motivate con scadenza, mai allowlist permanenti.
  Dependabot (pip + github-actions, settimanale) è già attivo; `SECURITY.md`
  (IT/EN) collega ora le vulnerabilità segnalate dal gate bloccante `pip-audit`
  ai **Tempi di risposta** per severità. Le deroghe passano solo per il registro
  a scadenza [`.github/audit-exceptions.toml`](.github/audit-exceptions.toml)
  (motivazione, owner, data, scadenza); `scripts/check_audit_exceptions.py`
  valida il registro in CI e fa fallire la build su deroghe scadute o malformate,
  mentre il job `pip-audit` deriva gli `--ignore-vuln` solo dalle voci attive
  (registro vuoto di default ⇒ audit non filtrato). Coperto da
  `tests/unit/test_audit_exceptions.py`.
- [x] Redigere un runbook di incident response per compromissione di chiavi di
  firma, token CI o API key AEGIS: revoca, rotazione, re-firma e comunicazione.
  Aggiunto [`docs/incident-response.md`](docs/incident-response.md) (bilingue IT/EN)
  con tre playbook — chiave di firma Ed25519 (`olympus core keygen`/`sign`/`verify`),
  token CI / secret GitHub Actions, e API key AEGIS/Themis
  (`olympus themis identities revoke`/`rotate`) — ciascuno con contenimento, revoca,
  rotazione, re-firma/ricostruzione, verifica e comunicazione, più passi
  post-incidente. Collegato da `SECURITY.md` in entrambe le lingue.
- [ ] Pianificare una review di sicurezza esterna o un bug bounty privato prima
  della prima release dichiarata `production-ready`.

**Criterio di completamento:** una vulnerabilità segnalata segue un percorso
documentato e misurabile, dalla ricezione all'advisory pubblicato.

## 💻 Prospettiva Sviluppatore (Code Quality e Architettura)

### Stato del codice attuale

Il progetto usa già layout `src`, Hatchling, type hints, Pydantic, Typer, Ruff,
Mypy, Pytest, Hypothesis e pre-commit. La CI costruisce wheel/sdist e installa la
wheel in un virtual environment pulito: la distribuibilità di base è quindi già
presente. I principali rischi sono il doppio stack nativo/vendorizzato, la
registrazione statica degli adapter, una matrice di compatibilità troppo stretta e
la mancanza di metriche di coverage bloccanti.

### Intervento A · `DEV-A` — Confini architetturali e rimozione del doppio stack (**P0**)

- [ ] Stabilire una sola source of truth per API, job model, audit, persistence e
  report; il codice in `vendor/` non deve evolvere parallelamente al core nativo.
- [ ] Formalizzare i confini `domain` → `application` → `ports` → `adapters` già
  usati da Athena e portarli nei moduli che mescolano CLI e orchestrazione.
- [ ] Spezzare `src/olympus/cli.py` in registrazione comandi, presentazione e use
  case, mantenendo l'entry point pubblico `olympus.cli:main`.
- [x] Aggiungere test di architettura che vietino import inversi e accessi diretti
  al network dal dominio. **Fatto:** `tests/unit/test_architecture_boundaries.py`
  analizza il grafo di import reale con `ast` e fallisce la CI se (a) un modulo
  del layer `domain` (scoperti genericamente, oggi `athena/domain`) importa un
  framework web/CLI/TUI/DB (`fastapi`, `typer`, `click`, `textual`, `rich`,
  `sqlalchemy`, `celery`, `redis`, `httpx`/`requests`…), un modulo stdlib di
  rete/processo/DB (`socket`, `subprocess`, `sqlite3`, `asyncio`,
  `urllib.request`…) o il client di rete `olympus.core.http`; (b) un modulo del
  dominio importa *verso l'alto* un layer `application`/`adapters`/`cli`/`api`/
  `web`/`tui` (dipendenza invertita). Il kernel dei contratti condivisi
  (`core/models|contracts|enums|ids|errors|exit_codes|coverage`) è vincolato a
  restare framework-free dalla stessa suite (Pydantic ammesso: è la libreria di
  validazione dei contratti, non I/O). Un test con violazione piantata prova che
  il guard rileva davvero (nessun pass vacuo). I confini restano documentati in
  [`docs/architecture/adr-002-athena-target-architecture.md`](docs/architecture/adr-002-athena-target-architecture.md).
  Restano gli altri bullet `DEV-A` (source-of-truth unica vs `vendor/`,
  formalizzazione dei confini nei moduli che mescolano CLI/orchestrazione, split
  di `cli.py`).

**Criterio di completamento:** dipendenze tra layer documentate e verificate in
CI; nessuna logica di dominio dipende da Typer, Textual, FastAPI o SQLite.

### Intervento B · `DEV-B` — SDK per adapter e plugin registry (**P1**)

- [ ] Estrarre un protocollo pubblico stabile per adapter: metadata, capability,
  input, argv, parser, health check, maturity ed evidence manifest.
- [~] Scoprire adapter opzionali tramite entry point Python, mantenendo una
  allowlist di plugin firmati/approvati per le installazioni professionali.
  **Discovery + allowlist approvata fatta:** `olympus/themis/plugins.py` scopre
  gli adapter esposti nel gruppo entry point `olympus.scanner_adapters` in modo
  **default-deny** — carica solo i nomi nell'allowlist dell'operatore
  (`OLYMPUS_SCANNER_PLUGIN_ALLOWLIST`), riporta i presenti-non-approvati come
  `skipped` (mai caricati) e gli approvati-non-validi come `rejected` con
  motivazione (un import fallito non interrompe la scoperta); ogni plugin deve
  essere una sottoclasse **concreta** di `ScannerAdapter`. `available_adapters()`
  unisce ai nativi dando **precedenza di prima parte** (un plugin non può
  oscurare un adapter integrato come `nmap`); accessor `registry.adapter_classes`.
  Test `tests/unit/test_themis_plugins.py`; doc
  [`docs/scanner-maturity.md`](docs/scanner-maturity.md). **Resta da fare:** la
  verifica della **firma crittografica** dei plugin (oltre all'allowlist per
  nome), che poggia sul release-signing di `SEC-F`.
- [ ] Validare output scanner con schema versionato e quarantena dei record non
  conformi; mai “best effort” silenzioso.
- [x] Fornire un template e contract test riutilizzabile per nuovi adapter.
  **Fatto:** `tests/contract/test_adapter_contract.py` è parametrizzato su
  **ogni adapter registrato** (`themis.registry.implemented`, oggi 15) e verifica
  offline — senza eseguire alcun binario né contattare un target — il contratto
  condiviso che ogni adapter deve rispettare: identità coerente con il registry e
  con il catalogo (`integrations.scanners`), `build_argv` che restituisce un
  vettore `list[str]` non vuoto (mai una stringa shell) con l'host trasportato
  come token atomico, `parse` che su output ostile (JSON malformato, byte di
  controllo, annidamento profondo, path traversal) restituisce `list[Finding]`
  oppure solleva `ParseError`/`ValueError` gestito (mai un'eccezione non gestita o
  un finding inventato), `run` che rifiuta uno scanner non corrispondente e
  `simulate` che etichetta sempre i finding come `SIMULATION`. Poiché la suite è
  guidata dal registry, un nuovo adapter aggiunto al registry è
  **contract-tested automaticamente** senza modificare il core — l'obiettivo
  `DEV-B`. Restano gli altri bullet `DEV-B` (protocollo pubblico stabile estratto,
  discovery via entry point + allowlist firmata, quarantena schema-validata degli
  output non conformi).

**Criterio di completamento:** un adapter esterno può essere sviluppato e testato
senza modificare il core, ma non può bypassare scope, policy, audit o sandbox.

### Intervento C · `DEV-C` — Compatibilità e qualità misurabile (**P1**)

- [~] Rendere Mypy un gate CI bloccante sul codice first-party e aggiungere
  `ruff format --check`: lint, format-check, type checking strict, coverage e il
  gate offline del registro deroghe (`audit-exceptions`) sono concatenati in
  `make check` ed eseguiti localmente (repository normalizzato dal formatter).
  **Regressione (commit 58ba209):** il workflow GitHub Actions che rispecchiava
  questi gate è stato rimosso dal repository, quindi **oggi non c'è enforcement
  automatico su push/PR**: i gate restano eseguibili via `make check` /
  `make audit` / `make secrets-scan` finché un workflow CI non viene ripristinato.
- [x] Estendere la CI a Python 3.11, 3.12, 3.13 e 3.14 su Ubuntu e aggiungere
  build della wheel e smoke test CLI portabili su macOS e Windows.
- [x] Isolare i test real-kernel della sandbox in `tests/platform/posix/`,
  registrarli con marker strict `posix_only`/`linux_only`/`root_only` ed eseguirli
  in un job Ubuntu dedicato, separato dalla matrice portabile Python 3.11–3.14.
- [x] Misurare la branch coverage del codice first-party e imporre un floor
  iniziale del 75% con report JSON, checker dedicato e job CI Python 3.11;
  aumentare la soglia progressivamente quando la baseline cresce.
- [x] Separare unit, contract e integration con directory, marker e job CI
  indipendenti; container e live-lab hanno selezione esplicita e opt-in, e una
  suite vuota fallisce come “no tests collected”. La suite container SEC-A ha
  un caso eseguibile in CI; la suite live-lab resta senza casi e non attesta
  scanner live o isolamento egress.
- [x] Aggiungere mutation test mirati a scope gate, redaction, parser, exit code e
  state machine dei job: la suite dedicata e un gate CI Linux selezionano le
  funzioni critiche; il checker richiede almeno il 35% di mutazioni uccise per
  ciascuna funzione, blocca gli esiti non verificati e segnala i mutanti superstiti.

**Fix verificato (2026-10-19, job CI mutation):** il job `security-boundary
mutation tests` falliva stabilmente con «failed to collect stats. runner
returned 2» perché installava solo l'extra `.[dev]`, mentre il gate muta
`olympus.themis.api` e `tests/mutation/test_guardrails.py` lo importa (quindi
importa FastAPI): senza l'extra `api`, la raccolta pytest della baseline mutmut
usciva con codice 2. Il job ora installa `.[dev,api]` come gli altri job di test.
Riproduzione: in un venv con solo `.[dev]`, `pytest tests/mutation/` esce 2 con
`ModuleNotFoundError: fastapi`; con `.[dev,api]` la raccolta passa (25 test) e la
fase di stats di mutmut termina con successo. Il gate completo resta verde
(273/485 mutanti uccisi, 56,3%).

**Criterio di completamento:** matrice supportata dichiarata uguale a quella
effettivamente testata; regressioni dei guardrail provocano sempre un fallimento.

### Intervento D · `DEV-D` — Contratti, migrazioni e backward compatibility (**P1**)

- [x] Pubblicare JSON Schema versionati per input/output e applicare SemVer ai
  contratti oltre che al package: il catalogo committato include direzione,
  `$id`, versione, percorso e SHA-256; contract test e `make schemas-check`
  impediscono drift tra modelli e artifact pubblicati.
- [x] Aggiungere golden contract test per CLI JSON/NDJSON, API OpenAPI, SQLite e
  report; le sei fixture deterministiche sono bloccanti nella suite contract e
  la policy documenta classificazione delle modifiche, deprecazioni e finestra
  minima di compatibilità.
- [x] Introdurre migrazioni esplicite per scope, assessment plan, job, evidence e
  case CTI: un registro centrale applica solo trasformazioni deterministiche,
  espone il manifest via CLI e rifiuta versioni future, header parziali o dati di
  provenienza non ricostruibili.
- [x] Centralizzare exit code e stati (`clean`, `findings`, `partial`, `failed`,
  `cancelled`) in tutti i moduli: `RunStatus` e `ExitCode` definiscono il
  contratto 0–7, Apollo/Hermes distinguono i risultati parziali dagli errori di
  input, Athena e AEGIS riducono le proprie state machine nello stesso mapping e
  i contract test vietano exit code numerici locali o valori esterni non
  normalizzati.

**Criterio di completamento:** una release nuova legge gli artifact supportati
dalla precedente oppure restituisce un errore di migrazione esplicito e sicuro.

### Intervento E · `DEV-E` — Performance, resilienza e osservabilità (**P2**)

- [x] Creare benchmark offline ripetibili per ingest, normalizzazione,
  deduplicazione finding, rendering report e lifecycle della coda AEGIS; il
  profilo quick/standard registra wall time, CPU e memoria Python e dispone di
  budget espliciti applicabili con `--enforce` (`docs/performance.md`). I limiti
  non sono ancora gate CI perché i runner condivisi hanno prestazioni variabili.
- [x] Usare streaming e backpressure per file/log grandi: Apollo ingest legge e
  normalizza una riga alla volta, pubblica NDJSON con scrittura atomica
  incrementale e limita byte totali, byte per riga e diagnostica degli scarti;
  Apollo run valuta subito ogni evento e conserva per la deduplica solo ID e
  fingerprint, non l'intero dataset.
- [x] Aggiungere metriche OpenTelemetry/Prometheus con cardinalità limitata e
  redazione by design: backend opzionali `none|prometheus|otlp`, endpoint
  Prometheus AEGIS autenticato, textfile atomico per processi brevi e metriche
  prive di target/identità/ID. Le trace correlano assessment, job, evidence e
  report esclusivamente tramite identificativi Olympus opachi e validati
  (`docs/observability.md`).
- [x] Testare crash recovery, retry idempotenti, lock SQLite, migrazioni interrotte
  e cancellazione durante l'esecuzione di un tool esterno: la suite di fault
  injection riavvia lo store dopo una lease abbandonata, forza submit concorrenti
  con la stessa idempotency key, contende un writer lock reale, interrompe una
  migrazione DDL e cancella un processo già avviato. Le migrazioni AEGIS sono ora
  atomiche e acquisiscono il write lock solo quando la versione deve avanzare
  (`tests/integration/test_aegis_resilience.py`, suite POSIX).

**Criterio di completamento:** esistono SLO e performance budget misurati; un
riavvio non duplica scansioni né perde lo stato terminale di un job.

### Intervento F · `DEV-F` — Release PyPI professionale (**P2**)

- [ ] Automatizzare versione, changelog, build, test, firma e pubblicazione PyPI
  tramite Trusted Publishing/OIDC, senza token statici.
- [ ] Testare sia dipendenze minime sia extra (`api`, `themis`, `dev`) e dichiarare
  chiaramente cosa è incluso nella wheel e cosa richiede binari esterni.
- [ ] Pubblicare release candidate e procedura di rollback; evitare release se
  documentazione, schema o maturity ledger sono incoerenti.
- [x] Generare una CLI reference dalla command tree per eliminare duplicazioni.
  `olympus.cli_reference.render_document` introspeziona l'albero Typer reale
  (`olympus.cli:app`) e produce `docs/cli-reference.md` in modo **deterministico**
  (gruppi/comandi ordinati, 138 comandi), fonte unica derivata dal codice. Lo
  script `scripts/generate_cli_reference.py` rigenera il doc e, con `--check`, è
  un **gate anti-drift** (come `maturity --check`); il test
  `tests/unit/test_cli_reference.py` fallisce la build se il doc è stale. Nessun
  help scritto a mano accanto ai decoratori Typer: la duplicazione è eliminata.

**Criterio di completamento:** installazione con `pipx install olympus-security`
da artifact firmato e smoke test completo fuori dal checkout.

### Intervento G · `DEV-G` — Documentazione come codice (**P1**)

- [x] Correggere i link a `ROADMAP_HARDENING.md` e `ROADMAP_OPERATIVA.md`, file
  non più presenti: i rimandi in `README.md`, `CHANGELOG.md`,
  `docker-compose.yml`, `docs/scanner-maturity.md`, `docs/threat-model.md` e
  `docs/apollo.md` puntano ora a `ROADMAP.md` tramite gli ID degli interventi
  (`§3.0`, `§5.3`, `§5.4` sostituiti). Corretti anche i percorsi relativi di
  `docs/reference.md` verso `LICENSE` e `labs/mars/README.md`. Verifica eseguita
  su tutti i Markdown first-party (esclusa `vendor/`): 0 link relativi rotti.
- [x] Allineare README e `integrations/maturity.py`: il
  ledger attuale dichiara 12 adapter `live-tested`, 3 `offline-tested` incluso
  Wapiti e nessun `production-ready`. `README.md` e `docs/scanner-maturity.md`
  riportavano ancora `catalog-only 10` e `offline-tested 2` (senza Wapiti):
  corretti a `9`/`3` (`testssl, whatweb, wapiti`) in linea con
  `maturity.summary()` (9/0/3/12/0 sul catalogo di 24). `tests/unit/test_maturity_docs.py`
  estrae i conteggi dai due documenti e li confronta con il ledger vivo, così la
  tabella non può più divergere.
- [x] Aggiungere un link checker, esempi eseguibili e test che rigenerino tabelle
  di capacità/maturità dal registry invece di mantenerle a mano. Link checker
  implementato: `scripts/check_doc_links.py` verifica tutti i Markdown first-party
  (esclusa `vendor/`), validando l'esistenza dei file linkati e gli anchor
  (slug stile GitHub, ignorando le heading dentro i fence di codice); è eseguito a
  ogni run CI tramite `tests/unit/test_doc_links.py`, che fallisce su qualunque
  link interno rotto (64 file, 0 rotti alla verifica). **Rigenerazione automatica
  delle tabelle fatta:** la tabella capacità/licenze di `docs/scanner-matrix.md`
  è generata da `olympus themis matrix` (gate `tests/unit/test_scanner_matrix.py`)
  e il blocco "Lo stato oggi" di `docs/scanner-maturity.md` (conteggi **e** nomi
  per stadio) è ora generato dal ledger via `olympus themis maturity`
  (`olympus.integrations.maturity.render_status_section`, marker
  `GENERATED:maturity-status`): non più mantenuto a mano ma rigenerato e sottoposto
  a drift gate da `tests/unit/test_scanner_maturity.py` (`--check` esce `2` se il
  blocco committato diverge dal registry), oltre alla validazione dei conteggi già
  presente in `tests/unit/test_maturity_docs.py`. **Esempi eseguibili fatti:** i
  comandi documentati in `examples/README.md` (IT/EN) sul dataset sintetico
  `examples/` — `apollo test`/`rules`, catena DFIR `minerva triage`+`verify`,
  `hermes scan`, `core export-schemas` — sono **offline** (nessuna rete né
  bersaglio) ed **eseguiti in CI** da `tests/integration/test_examples_offline.py`,
  che asserisce il codice di uscita canonico e un risultato contract-valid, così i
  comandi documentati non possono invecchiare in silenzio.
- [x] Consolidare il backlog tecnico e strategico in questo unico `ROADMAP.md`,
  eliminando roadmap parallele che potrebbero divergere.

**Criterio di completamento:** nessun link interno rotto e nessun numero di
capability scritto manualmente può divergere dal codice senza fallire la CI.

### Intervento H · `DEV-H` — Governance del backlog (**P1**)

- [x] Riconciliare i principi di `upgrade.md` (“nessun gate obbligatorio”) con la
  CI bloccante e con la Definition of Done di questa roadmap; dichiarare
  `upgrade.md` registro storico in sola aggiunta. `upgrade.md` ha ora un avviso
  iniziale; `CONTRIBUTING.md` e `Makefile` descrivono i controlli CI realmente
  bloccanti (prima dichiaravano `continue-on-error` e secret scan “advisory”,
  entrambi falsi) e quelli pianificati ma non ancora attivi.
- [x] Creare issue template e label coerenti con gli ID (`SEC-*`, `DEV-*`, `UX-*`,
  `OPS-*`) e con le priorità P0–P3, così che ogni issue sia riconducibile a un
  intervento. I moduli `.github/ISSUE_TEMPLATE/` coprono roadmap item, bug report
  e segnalazione vulnerabilità privata, con issue vuote disabilitate. Le label
  `roadmap`, `bug`, `area:*` e `P0`–`P3` sono dichiarate in
  `.github/labels.json` e sincronizzate in modo non distruttivo dal workflow
  `.github/workflows/labels.yml`; validazione e piano di modifica sono coperti da
  `tests/unit/test_label_sync.py`.
- [x] Aggiungere un template di PR con checklist della Definition of Done e
  richiamo all'ID dell'intervento (`.github/pull_request_template.md`).
- [x] Registrare ogni decisione strutturale come ADR numerato proseguendo la
  sequenza esistente: indice, regole di numerazione/immutabilità e template in
  `docs/architecture/README.md` e `docs/architecture/adr-template.md`, con
  `adr-003`–`adr-005` riservati per `SEC-A`, `DEV-B` e `SEC-C`.

**Criterio di completamento:** ogni modifica è tracciabile da ID → issue → PR →
commit → evidenza, e non esistono documenti di pianificazione in conflitto.

### Intervento I · `DEV-I` — Rinominare AEGIS in Themis (**P1**)

Il sottosistema `src/olympus/aegis/` (control plane degli scanner specialistici:
registry, adapter, job, scope, autorizzazione, sandbox, execution, API,
identity) assume il nome **Themis** — la Titanide della legge e dell'ordine, che
riflette il suo ruolo di gate di governance sull'esecuzione degli strumenti. Il
rename è un'evoluzione di naming, non una riscrittura: una sola implementazione.
Precedente collaudato: `docs/vap-to-aegis-rename.md` (VAP → AEGIS).

- [x] **Milestone 1 (fatto).** Migrati gli identificatori tecnici: package/dir
  `aegis/` → `themis/`, `athena/adapters/aegis_scan.py` → `themis_scan.py`,
  classi `Aegis*` → `Themis*`, comando CLI `aegis` → `themis`, tag/endpoint
  FastAPI, doc `docs/aegis-*.md` → `docs/themis-*.md`, servizi docker
  `aegis-*` → `themis-*`, file/fixture di test, stringhe e messaggi CLI.
- [x] **Milestone 1 (fatto).** `olympus aegis` resta **alias deprecato** (warning
  che indica `olympus themis`) che inoltra a `themis` senza duplicare
  l'implementazione; un CLI backward-compatibility test lo verifica.
- [x] **Milestone 1 (fatto).** Riferimenti **storici** preservati (`upgrade.md`,
  `docs/vap-to-aegis-rename.md`, `CHANGELOG`, `adr-006`).
- [x] **Milestone 1b (fatto).** Schema name versionati rinominati in
  `olympus.themis-*` e valore provenance `Source` portato a `"themis"`: un
  canonicalizzatore (`core.contracts.canonicalize_schema_name`, applicato in
  `migrate_document`, `validate_contract_header` e nel load delle identità)
  riscrive i documenti persistiti sotto i vecchi nomi `olympus.aegis-*`, e il
  membro deprecato `Source.AEGIS = "aegis"` mantiene validi i record storici.
  Schema catalog e golden rigenerati; test di migrazione e di provenance.
- [x] **Milestone 1c (fatto).** Variabili d'ambiente canoniche `THEMIS_*` con
  **fallback automatico** `THEMIS_*` → `AEGIS_*` → `VAP_*` centralizzato in
  `olympus.themis.config` (resolver bidirezionale, ambiguità rifiutata); call
  site aggiornati (sandbox, nuclei, capabilities, scanner-doctor, API key CLI),
  docker-compose e docs allineati; test del fallback. Le `AEGIS_*`/`VAP_*`
  esistenti continuano a funzionare senza modifiche.

**Criterio di completamento (soddisfatto):** nessun identificatore tecnico
`AEGIS`/`aegis` residuo salvo l'alias CLI deprecato, i nomi env legaci di
fallback e i riferimenti storici; migrazione schema e fallback env testati;
`olympus aegis` emette il warning e funziona; Ruff, Mypy, Pytest, schema-check e
golden contract verdi; documentazione allineata. **`DEV-I` completo.**

## 🌐 Prospettiva Web Control Plane (interfaccia sullo stesso core)

> CLI, TUI, API e Web sono interfacce diverse sullo **stesso** core e sugli stessi
> use case: nessuna logica di cybersecurity nel frontend, nessun bypass di scope,
> autorizzazione, execution policy, sandbox, audit, retention o redaction. Il
> control plane nativo è `olympus.themis.api` (FastAPI tipizzata); la Web UI vi si
> appoggia, non la sostituisce.

### Stato attuale

Esiste già un'API FastAPI tipizzata (`themis/api.py`, ex `aegis/api.py`) con
autenticazione per-scope, middleware di accountability e limiti sul body,
`/health`, `/ready`, `/metrics`, `/api/v1/capabilities` e `/api/v1/jobs`
(submit/list/get/cancel). **Esiste ora una Web UI nativa** (`themis/web.py`,
`olympus themis web`, `WEB-A` ✓) costruita **sopra** questa API e sullo stesso
store, non come piattaforma parallela; la VAP vendorizzata resta in quarantena
(solo loopback), destinata al ritiro (`SEC-A`). Le prossime slice web
(`WEB-G`, `WEB-I`…) estendono questa UI, non la sostituiscono.

### Intervento A · `WEB-A` — Web control plane nativo (**P0/P1**)

- [x] Servire una Web UI nativa sopra l'API tipizzata esistente; nessun endpoint
  tipo `POST /run-command` e nessuna shell arbitraria — solo richieste tipizzate
  (`scanner`, `target`, `target_kind`, `scope_id`) che il server traduce
  nell'esecuzione scope/policy-gated. **Fatto:** `olympus.themis.web.create_web_app`
  (FastAPI + Jinja2 + server-sent events, con enhancement progressivo via un
  unico script same-origin invece di HTMX, per rispettare la CSP senza
  `'unsafe-inline'`), servita da `olympus themis web`. Il submit riusa lo stesso
  contratto `JobSubmission` dell'API. Doc: [`docs/web.md`](docs/web.md).
- [x] Applicare gli stessi controlli della CLI: scope, autorizzazione, execution
  policy, rate limit, deadline, sandbox, audit, retention, redaction; la GUI non
  può ridurli (**P0**). **Fatto:** la rotta di submit chiama lo **stesso**
  `ThemisJobStore.submit` con la **stessa** risoluzione dello scope registrato
  (`_registered_scope`) e lo stesso gate `authorized`; un job del browser è
  verificabilmente identico via API (stesso store), e l'audit redatto è emesso
  dallo stesso middleware di accountability.
- [x] Aggiungere security headers, CSP restrittiva, cookie `Secure`/`SameSite`,
  CSRF dove necessario, validazione input, rate limiting, autenticazione e audit
  trail (**P0**). **Fatto:** sessione via cookie firmato HMAC
  `HttpOnly`/`Secure`/`SameSite=Strict` emesso solo da una credenziale valida;
  token CSRF sincronizzatore legato al nonce di sessione e confrontato in tempo
  costante su ogni form che cambia stato; CSP `default-src 'none'` senza
  script/stile inline più `nosniff`/`DENY`/`no-referrer`/`no-store` e body
  limitato a 64 KiB; scope enforcement per rotta; rate limit per identità.
- [x] Streaming job via SSE con gli stati reali dello store (`queued`, `running`,
  `succeeded`, `partial`, `failed`, `timed_out`, `cancelled`, `policy_denied`),
  output redatto e pulsante **Cancel** collegato alla cancellazione reale di
  Olympus. **Fatto:** `GET /jobs/{id}/events` (`text/event-stream`) emette ogni
  transizione fino allo stato terminale; le sotto-fasi non registrate dal worker
  (parsing/normalizing) non sono inventate (onestà dello stato). Cancel via
  `POST /jobs/{id}/cancel` protetto da CSRF che invoca `ThemisJobStore.cancel`.

**Criterio di completamento (soddisfatto):** un job avviato dal browser è
indistinguibile, per policy e audit, da uno avviato in CLI; i test di
web-security (headers, CSP, CSRF, authz, sessione, body limit) e di
job-lifecycle/cancellation/SSE passano (`tests/unit/test_themis_web.py`).
**`WEB-A` completo.**

### Intervento B · `WEB-B` — Engagement come entità di primo livello (**P1**)

- [x] **Slice 1 (fatto).** Contratto condiviso versionato `olympus.engagement`
  (`core/models.py`: `Engagement` + `EngagementScope` con scope incluso/escluso e
  `covers()`), store SQLite owner-only (`engagements/store.py`) e comandi CLI
  `olympus engagement create|list|show` (`engagements/cli.py`), sullo **stesso**
  modello e database per tutti i canali. Schema catalog + golden, test unit e
  integration, `docs/engagements.md`.
- [x] **Slice 2 (fatto).** Campo opzionale `engagement_id` sui contratti scoped
  (`Asset`, `Finding`, `Event`, `Evidence`, `Alert`, `Incident`, `Observation`)
  via base `EngagementScopedModel` (additivo, schema `1.0.0`, validazione
  `ENG-YYYY-NNNNN`); primitive `Engagement.stamp()`/`stamp_all()`/`covers()` e
  `SqliteEngagementStore.require()`. **Wiring Athena/Themis fatto:** il coordinator
  marca gli oggetti prodotti (asset+finding, path Themis incluso) con
  l'`engagement_id` del piano **solo se canonico** (`is_canonical_engagement_id`);
  le label libere dei piani (`ENG-DEMO-2026`, `ENG-1`) non vengono marcate, così
  nessuna fixture si rompe. I due namespace restano distinti per disegno: l'id di
  piano Athena è un'etichetta locale, l'`engagement_id` core referenzia un record
  `olympus.engagement`.
- [x] **Slice 3 (fatto).** Engagement esposti via API e Web UI sullo **stesso**
  store (`engagements/resolve.py`, fonte unica per entrambe le interfacce). API:
  `GET /api/v1/engagements` (contratto `olympus.themis-engagement-list`) e
  `GET /api/v1/engagements/{id}` (contratto `olympus.engagement`), protetti da un
  nuovo scope di identità `engagements:read`; store non configurato → `503`
  onesto (mai una lista vuota che fingerebbe l'assenza di engagement). Web:
  pagine `GET /engagements` e `GET /engagements/{id}` con lo stesso gate di scope
  e la stessa redazione (`SEC-H`). **Scope enforcement derivato dall'engagement:**
  `JobSubmission.engagement_id` opzionale (canonico `ENG-YYYY-NNNNN`); quando
  presente, API e Web risolvono l'engagement dallo stesso store e rifiutano — con
  la stessa logica `Engagement.covers()`, l'host dedotto dal target tipizzato
  (host/domain verbatim, url per hostname) — ogni target fuori perimetro **prima**
  di accodare il job (`422`), id sconosciuto `404`, store non configurato `400`.
  Il form "New assessment" offre gli engagement come selezione opzionale. CLI
  `olympus themis api|web --engagement-storage` abilita le rotte sullo stesso
  database `engagements.db` usato da `olympus engagement`. OpenAPI golden
  rigenerato; test web/API e di scope enforcement. Doc:
  [`docs/web.md`](docs/web.md), [`docs/engagements.md`](docs/engagements.md).

**Criterio di completamento (soddisfatto):** lo stesso engagement è leggibile e
operabile identicamente dai quattro canali (CLI, TUI via core, API, Web), con lo
stesso store, lo stesso modello e lo stesso scope enforcement. **`WEB-B` completo.**

- [x] **Hardening (2026-10-28, P0 data-loss).** La creazione engagement si
  appoggiava a `new_id()`, che riparte da `…00001` in ogni processo: due
  `olympus engagement create` separati coniavano lo stesso `ENG-<anno>-00001` e
  `save()` (`INSERT OR REPLACE`) sovrascriveva silenziosamente il primo record —
  perdita del perimetro autorizzato di un engagement reale. Corretto con
  `SqliteEngagementStore.next_engagement_id(year)` (deriva il prossimo progressivo
  dagli id canonici già persistiti, unico a prescindere dalla vita del processo) e
  `SqliteEngagementStore.create()` insert-only **fail-closed** (su id già presente
  solleva `EngagementStoreError` invece di sovrascrivere); la CLI `create` alloca
  l'id dallo store e usa `create()`, mentre `import` conserva `save()` per
  preservare gli id importati. Regressione coperta in unit e integration
  (`test_store_create_refuses_to_overwrite_an_existing_id`,
  `test_store_next_engagement_id_is_collision_free`,
  `test_engagement_create_twice_does_not_lose_the_first`).

### Intervento C · `WEB-C` — Finding management e lifecycle (**P1**)

- [x] Vista finding con Title, Severity, Status, Asset, Source, Scanner, CVE,
  CWE, CVSS, EPSS, CISA KEV (quando disponibili), Evidence, First/Last seen,
  Remediation, References, senza assumere che ogni dato sia sempre presente.
  **Fatto:** proiezione interface-agnostica `vulcan/view.FindingView`
  (`row`/`display_items`/`detail`, più `rank_by_risk`) — unica fonte di
  presentazione riusata da CLI/TUI/Web, come `vulcan/search.py` lo è per i
  filtri. Un dato assente resta `None` in `detail()` e si rende come `—`
  (`view.ABSENT`) nelle viste umane, così "assente" non si confonde con "vuoto"
  o con uno zero inventato; `source` è la provenienza/engine (non esiste un
  campo *scanner* separato sul contratto). CLI `olympus vulcan findings
  list|show` (tabella/JSON) con tutti i criteri di `FindingFilter` come flag,
  ordinata per risk score decrescente. Doc: [`docs/findings.md`](docs/findings.md).
- [x] Stati e ciclo di vita. **Fatto:** macchina a stati delle transizioni in
  `core/finding_lifecycle.py` sui 7 stati `FindingStatus` (triage, confirmed,
  false-positive, accepted-risk, in-remediation, closed, riapertura su
  recurrence/retest), con `can_transition`/`allowed_transitions`/`transition`
  (ritorna una copia aggiornata, rifiuta mosse illegali e no-op); nessun cambio
  di contratto. Doc: [`docs/findings.md`](docs/findings.md).
  **Deduplica cross-scanner fatta:** `vulcan/aggregate.merge_duplicate_findings`
  fonde i duplicati logici (stesso asset + stessa vuln via CVE o titolo) in un
  unico finding senza perdere evidenze (union di evidence/reference/CVE/CWE,
  segnale più urgente per gli scalari), nel pipeline Vulcan dopo il dedup per ID.
  **Tagging/ricerca/filtri fatti:** campo `Finding.tags` (additivo, normalizzato)
  e `vulcan/search.FindingFilter`/`search_findings` — criteri componibili (stato,
  severità minima, source, engagement, KEV, has-CVE, tag case-insensitive, testo
  libero, risk score minimo) con semantica AND, fonte unica per CLI/TUI/Web.
  **Audit trail fatto:** contratto `olympus.finding-transition` (chi/quando/da→a/
  motivo, scoped all'engagement), `core/finding_lifecycle.record_transition`
  (applica + produce il record) e store SQLite append-only owner-only
  (`findings/store.SqliteFindingTransitionStore`, `append`/`history`, rifiuta id
  duplicati). **Suppression fatta:** `finding_lifecycle.suppress`/`unsuppress`/
  `is_suppressed` (accepted-risk o false-positive) — `suppress` esige una
  motivazione non vuota e uno stato di suppression, passa per la macchina a stati
  e produce il record d'audit; `unsuppress` riapre a `confirmed`. Ciclo di vita
  finding **completo**.
- [x] **Evidence browser**: navigare le evidenze collegate a un finding
  (comando/argv redatto, output, digest, firma della chain-of-custody) riusando
  Minerva e la chain-of-custody, senza esporre dati redatti o segreti.
  **Fatto:** proiezione interface-agnostica `vulcan/evidence_view.FindingEvidenceView`
  (`build_finding_evidence_view`, `rows`/`detail`/`custody_signature`) — unica
  fonte di navigazione riusata da CLI/TUI/Web, come `vulcan/view.py` lo è per le
  colonne. Classifica ogni riferimento in **strutturato** (`EVD-YYYY-NNNNN`) o
  **inline** (snippet dell'adapter): i riferimenti strutturati sono risolti
  contro la custody chain Minerva verificata (eventi collected/transferred/
  analyzed/archived, digest SHA-256, confronto digest record↔ledger) e lo stato
  firma del ledger (`HMAC-SHA256` verificato / SIGNED non verificato / unsigned /
  legacy); gli snippet inline sono resi con `redact_text` e privati delle
  sequenze di controllo del terminale (`SEC-H`). Il contenuto grezzo dell'evidenza
  non viene mai letto né stampato (solo digest e metadati di custody) e l'assenza
  è onesta (`no-custody`, `digest-mismatch`). CLI `olympus vulcan findings
  evidence FND-… --findings … [--ledger …] [--evidence …]` (tabella/JSON);
  `--ledger`/`--evidence` opzionali. Timeline custody firmabile Ed25519 via
  `olympus minerva timeline --export --sign-key`. Doc:
  [`docs/findings.md`](docs/findings.md).
- [x] **Finding strutturato (fondamenta).** CVE, CWE, EPSS, KEV e `confidence`
  promossi da testo-regex a **campi opzionali tipizzati** sul contratto
  `Finding` (`core/models.py`), additivi e retro-compatibili (schema resta
  `1.0.0`: i finding pre-`WEB-C` validano ancora, i campi default a vuoto). Helper
  `cves()`/`cwes()` preferiscono il campo strutturato e ricadono sul free-text;
  `vulcan/enrichment.extract_cves` e `vulcan/pdf.py` (tabella CVE + metadati
  finding) usano i campi tipizzati e mostrano EPSS/KEV/confidence anche **senza**
  overlay di enrichment live. Doc: [`docs/findings.md`](docs/findings.md).
- [x] **Risk score numerico contestuale** su `Finding`: metodo calcolato
  `Finding.risk_score()` (0–100) che combina severity+CVSS+EPSS+KEV+confidence
  nell'ordine di priorità di `vulcan/enrichment.prioritize` (KEV>EPSS>CVSS>
  severità); calcolato on-demand (nessun campo stored, mai stale), esposto nei
  metadati del finding nel report PDF. Doc: [`docs/findings.md`](docs/findings.md).
- [x] **Findings nel browser (wiring Web UI).** Le fondamenta interface-agnostic
  sopra (view, search/filtri, lifecycle, evidence browser, transition store)
  sono ora collegate alla Web UI, così la fase di analisi/verifica del ciclo non
  richiede più il terminale. Rotte `GET /findings` (lista filtrata e ordinata per
  rischio riusando `FindingFilter`/`search_findings`/`rank_by_risk`, scope
  `findings:read`), `GET /findings/{id}` (dettaglio via `FindingView.display_items`,
  evidence browser via `build_finding_evidence_view` con custody onesta
  `no-custody` quando nessun ledger è collegato, storico transizioni) e
  `POST /findings/{id}/transition` (scope `findings:write`, CSRF, rate limit) che
  registra la transizione nello store append-only `olympus.finding-transition`
  via la **stessa** macchina a stati (`record_transition`); lo stato *effettivo*
  del finding è ricavato ripiegando lo storico sulla base del bundle, senza mai
  riscrivere l'artefatto immutabile del produttore. I bundle sono letti con lo
  stesso `load_findings` strict/bounded della CLI; fonti non configurate degradano
  onestamente (`--findings-directory`/`--findings-storage`). Nuovi scope identità
  `findings:read`/`findings:write`. Template `web_templates/findings.html` +
  `finding_detail.html`, stili same-origin (CSP senza inline), test in
  `tests/unit/test_themis_web.py`. Doc: [`docs/web.md`](docs/web.md).
- [x] **Parità CLI del ciclo di vita (audit 2026-10-28).** La transizione di
  stato, finora solo in API/Web, è ora disponibile da CLI con
  `olympus vulcan transition --finding-id … --to-status … --findings … --database …
  [--reason … --actor …]`: stessa macchina a stati (`record_transition`), stesso
  store append-only, stato *effettivo* ripiegato dallo storico sulla base del
  bundle, suppressioni (`accepted`/`false_positive`) che richiedono `--reason`.
  **Fix di unicità id:** poiché `core.ids.new_id` riparte da `…00001` per processo,
  un chiamante a vita breve rigenererebbe id già presenti nel ledger; il nuovo
  `SqliteFindingTransitionStore.next_transition_id(year)` alloca l'id dallo stato
  persistito (collision-free cross-processo), usato dalla CLI. Test
  `tests/unit/test_vulcan.py` e `tests/unit/test_finding_transitions.py`; doc
  [`docs/cli-reference.md`](docs/cli-reference.md). **Follow-up completato
  (2026-10-28):** anche il gestore transizioni Web (`POST /findings/{id}/transition`)
  alloca ora l'id con `next_transition_id`, quindi un worker riavviato non collide
  più con il ledger esistente (prima mascherato dal processo long-lived). Test
  `tests/unit/test_themis_web.py::test_a_transition_does_not_collide_with_pre_existing_ledger_ids`.

**Criterio di completamento (soddisfatto):** un finding attraversa tutto il ciclo
di vita con audit; la deduplica non perde evidenza né remediation; ogni finding è
navigabile fino alla sua evidenza verificabile — ora anche da browser, con lo
stesso workflow, le stesse viste e lo stesso scope enforcement della CLI.
**`WEB-C` completo.**

### Intervento D · `WEB-D` — Pagina Tools dal registry reale (**P1**)

- [x] Card per ogni strumento con nome, categoria, descrizione non eccessivamente
  tecnica, stato, maturity Olympus, capability (classe di deployment e licenza),
  requisiti e i fatti separati installato/configurato/ready — **derivati dal
  registry/capability system reale**, mai da un elenco hardcoded nella GUI.
  **Fatto:** rotta `GET /tools` (`themis/web.py`, scope `capabilities:read`) che
  proietta `olympus.integrations.capabilities.inventory()` — la **stessa** fonte
  usata da `olympus themis capabilities` (CLI) e da `GET /api/v1/capabilities`
  (API). Lo stato di prontezza (`Ready`, `No Olympus adapter`, `Engine not
  installed`, `Not configured`) è calcolato dal capability system, non dalla GUI:
  un motore catalogato ma **non adattato** mostra lo stato onesto e non appare
  mai eseguibile (il flag "runnable here: yes" marca solo i motori `ready`, cioè
  adattati **e** disponibili). La versione installata del motore non è catalogata
  (richiederebbe l'esecuzione del tool, che l'inventario rifiuta per disegno) e
  quindi non viene inventata. Template `web_templates/tools.html`, stili
  same-origin (CSP senza inline), test `tests/unit/test_themis_web.py`
  (`test_tools_page_reflects_the_real_capability_inventory`,
  `test_tools_page_requires_the_capabilities_scope`). Doc:
  [`docs/web.md`](docs/web.md).

**Criterio di completamento (soddisfatto):** la pagina riflette esattamente il
registry/capability inventory; uno scanner non adattato non appare eseguibile.
**`WEB-D` completo.**

### Intervento E · `WEB-E` — New Assessment guidato (**P1**)

- [x] Flusso: scegli engagement → target → controllo scope → tipo attività
  (Recon / Network / Web / Vulnerability Assessment / Secret Scan / Detection /
  Full) → tool o modalità automatica → **anteprima "Olympus sta per eseguire"**
  con livello `PASSIVE/ACTIVE/INTRUSIVE` → autorizzazione quando necessaria →
  avvio → progress → risultati. **Fatto:** wizard activity-first `GET
  /assessments/new` → `POST /assessments/preview` (anteprima che non accoda
  nulla e ri-valida scope ed engagement) → `POST /jobs` (launch) → `GET
  /jobs/{id}` con SSE di stato reale e Cancel (già `WEB-A`). Le quattro attività
  Themis (recon/network/web/vulnerability) accodano un job scanner; Secret
  Scan / Detection / Full sono dichiarate oneste come gestite da altri moduli
  (hint CLI `olympus hermes`/`apollo`/`athena`), mai simulate. La modalità
  **Automatic** sceglie un tool `ready` per l'attività e **rifiuta** onestamente
  se nessuno è disponibile sull'host. Evidenze/finding/report restano navigabili
  da Vulcan (`WEB-C`) e dal reporting (`WEB-I`).
- [x] Spiegazioni brevi non tecniche per ogni strumento e una modalità
  **Advanced** per utenti esperti; onboarding guidato. **Fatto:** classificazione
  interface-agnostica `olympus.integrations.activity` (attività derivata dalla
  categoria del registry, classe di rischio da una mappa unica revisionata con
  default sicuro `ACTIVE`, riassunti in linguaggio semplice) riusabile da ogni
  interfaccia; sezione `<details>` **Advanced** per `max_attempts`/idempotency
  key; enhancement progressivo (`assessment.js`) senza violare la CSP. Test
  `tests/unit/test_scanner_activity.py` e flusso web in
  `tests/unit/test_themis_web.py`. Doc: [`docs/web.md`](docs/web.md).

**Criterio di completamento (soddisfatto):** un utente che non ricorda i flag CLI
completa un assessment passivo end-to-end; nessuna operazione attiva parte senza
preview e autorizzazione (la GUI non indebolisce mai il gate di autorizzazione
della CLI). **`WEB-E` completo.**

### Intervento F · `WEB-F` — Smart Scan (pipeline proposta) (**P2**)

- [x] Da target + engagement + obiettivo, Olympus **propone** una pipeline
  deterministica, spiegabile, scope-aware, policy-aware, limitata, configurabile e
  **visualizzabile prima dell'esecuzione**; mai esecuzione automatica di qualunque
  scanner. L'utente approva il piano. **Fatto:** motore puro e offline
  `olympus.integrations.smartscan.propose_pipeline` (sibling di
  `integrations/activity.py`, fonte unica interface-agnostica riusata da CLI e
  Web, come `activity.py` lo è per il flusso a singolo scanner di `WEB-E`).
  L'obiettivo (`recon`/`web-app`/`network`/`full`) espande a una lista ordinata
  e revisionata di attività **native** (recon sempre per prima, così gli stadi
  più rumorosi agiscono su una superficie già mappata); ogni stadio sceglie lo
  scanner **ready** dell'attività via `recommended_scanner`, con una `rationale`
  in linguaggio semplice. **Riproducibilità:** il piano espone un `digest`
  SHA-256 stabile sui suoi input e stadi ordinati (stessi input → stesso piano,
  verificato). **Scope-aware:** con un engagement, un target fuori perimetro
  produce `in_scope=False` e **zero stadi** (nessun ramo pianificato fuori
  scope). **Policy-aware:** un soffitto di rischio (default `active`) scarta con
  motivazione esplicita ogni scanner più rumoroso del soffitto — le tecniche
  `intrusive` sono proposte solo con opt-in `--max-risk intrusive`. **Limitata:**
  cap configurabile sugli stadi (`MAX_PIPELINE_STAGES`). **Mai esecuzione
  automatica:** il motore non lancia nulla e non contatta alcun target; ogni
  stadio rimanda al flusso audited esistente (`/assessments/preview` → `/jobs`,
  o `olympus themis jobs`) che applica scope, autorizzazione e preview. CLI
  `olympus themis smart-scan --objective … --target … [--max-risk …]
  [--engagement-storage … --engagement …] [--format table|json]` (tabella
  terminal-safe via `safe_terminal_text`, JSON machine-readable; `OUT_OF_SCOPE`
  quando il target è fuori dall'engagement). Web: `GET /assessments/smart` +
  `POST /assessments/smart/plan` (scope `jobs:write`, CSRF, degrado onesto),
  template `web_templates/smart_scan.html` con enhancement progressivo
  same-origin (`smart_scan.js`, CSP senza inline); ogni stadio è un form verso
  `/assessments/preview`, così l'approvazione resta esplicita e sul gate reale.
  Test `tests/unit/test_smartscan.py` (motore), `tests/unit/test_smartscan_cli.py`
  (CLI) e flusso web in `tests/unit/test_themis_web.py`. Doc:
  [`docs/web.md`](docs/web.md).

**Criterio di completamento (soddisfatto):** la pipeline proposta è riproducibile
(digest stabile) e approvata esplicitamente (ogni stadio passa per il preview e
l'autorizzazione reali); nessun ramo parte fuori scope (target fuori engagement →
nessuno stadio) o senza autorizzazione (il motore non esegue mai nulla).
**`WEB-F` completo.**

### Intervento G · `WEB-G` — Dashboard, accessibilità, i18n (**P2**)

- [x] Dashboard con widget che rispondono a domande operative reali (asset, job
  in corso, scansioni completate, finding per severità/scanner, incident aperti,
  attività recente, scanner readiness, avanzamento assessment); nessun widget
  decorativo. **Fatto finora:** totali e istogramma stati job + job recenti; e il
  widget **finding per severità/scanner** sulla dashboard (`GET /`), scope-gated
  a `findings:read` e attivo solo con `--findings-directory`, che riusa
  `vulcan.aggregate.severity_breakdown` e `source_breakdown` (quest'ultimo elenca
  solo le sorgenti che hanno prodotto finding, ordinate per conteggio) e
  `asset_breakdown` (aggregazione asset cross-engagement: top asset per
  esposizione, severità peggiore prima, poi conteggio), linkando alla vista
  findings filtrata per severità, per sorgente e per asset (filtro testo che già
  matcha l'`asset_id`); degrada onestamente (assente) se non configurato o non
  leggibile; e
  il widget **scanner readiness** (`GET /`), scope-gated a `capabilities:read`,
  che proietta fedelmente l'inventario capability (`integrations.capabilities.inventory`
  — stessa fonte di `olympus themis capabilities` e della pagina Tools) in
  conteggi ready/installati/adattati/catalogati e linka alla pagina Tools,
  rispondendo a «quali scanner adattati posso eseguire ora su questo host?»; e
  il widget **avanzamento assessment** (`GET /`), calcolato dai job già caricati
  (nessuna query extra) sulla partizione autorevole `TERMINAL_STATES`: percentuale
  completata, job in corso / terminati / completati con successo pulito, presente
  solo quando esistono job, rispondendo a «quanto lavoro è ancora in volo e quanto
  è finito bene?»; e il widget **incident per stato** (`GET /`), scope-gated a
  `incidents:read` e attivo solo con `--incidents-directory`, che riusa
  `minerva.triage.load_incidents` + `incident_status_breakdown` sui documenti
  `core.Incident` prodotti da `olympus minerva triage` (artefatti read-only, mai
  uno store), mostrando il totale e il conteggio per ogni stato del ciclo di vita
  (open→closed) con etichette testuali oltre al colore; degrada onestamente
  (assente) se non configurato o non leggibile. Test
  `tests/unit/test_themis_web.py` e `tests/unit/test_minerva_triage.py`; doc
  [`docs/web.md`](docs/web.md), [`docs/cli-reference.md`](docs/cli-reference.md).
  **Tutti i widget operativi previsti sono implementati** (asset, job in corso,
  scansioni completate, finding per severità/scanner, incident per stato,
  attività recente, scanner readiness, avanzamento assessment).
- [ ] Responsive, accessibile (lega a `UX-E`), bilingue IT/EN, con onboarding e
  modalità Advanced.

**Criterio di completamento:** ogni widget è tracciabile a una domanda
operativa; i flussi primari sono usabili da tastiera, in IT ed EN.

### Intervento H · `WEB-H` — Astrazione persistenza (SQLite / Postgres) (**P2**)

- [ ] Introdurre un repository/port di persistenza che mantiene **SQLite come
  default locale** e consente **PostgreSQL opzionale** per deployment
  server/multiutente; Postgres non è mai un requisito per l'uso locale.
- [ ] RBAC, OIDC e API token multiutente estendono l'identità già presente
  (`SEC-D`), con audit trail multiutente.

**Criterio di completamento:** lo stesso codice gira su SQLite e Postgres dietro
lo stesso port; l'utente locale non deve installare Postgres.

### Intervento I · `WEB-I` — Reporting, trend e notifiche (**P2**)

- [x] **Report builder (slice 1 — export dal browser).** Dalla vista findings
  (`WEB-C`) l'operatore scarica un report Vulcan della selezione corrente in
  `md`/`html`/`json`/`sarif` via `GET /findings/report` (scope `findings:read`), con lo
  **stesso** filtro della tabella (`_finding_filter_from_params` →
  `FindingFilter`) e i renderer esistenti (`build_report_model` +
  `render_report_markdown`/`render_report_html`/JSON dump): nessuna logica di
  rendering duplicata, quindi il report dal browser è identico a quello della
  CLI per lo stesso set. Servito come download (`Content-Disposition: attachment`);
  etichetta engagement sanitizzata (`SEC-H`) e slug per il filename.
  **Sezioni executive/tecnico selezionabili fatte:** `report.ReportSection`
  (`full`/`executive`) sui renderer Markdown/HTML — `executive` rende sintesi,
  tabella severità e un elenco finding compatto (una riga per severità/titolo/
  asset/rischio), omettendo dettaglio tecnico, inventario asset, alert e appendice
  di provenienza. Esposta da CLI `olympus vulcan report --section executive|full`
  e da Web `GET /findings/report?report_section=executive` (i formati macchina
  json/csv/sarif restano sempre completi); default `full`, retrocompatibile.
  Test `tests/unit/test_vulcan.py`, `tests/unit/test_themis_web.py`; doc
  [`docs/web.md`](docs/web.md), [`docs/cli-reference.md`](docs/cli-reference.md).
  **PDF dal browser fatto:** `GET /findings/report?format=pdf` riusa
  `vulcan.pdf.render_report_pdf` (extra `report`/reportlab) e serve
  `application/pdf` come download; se l'extra manca degrada onestamente con
  `503` (`PdfUnavailableError` sanitizzato), senza fingere un PDF. Pulsante PDF
  nella barra export dei findings. Test `tests/unit/test_themis_web.py`.
- [x] **Report comparison / scan diff (slice 2).** Motore puro e offline
  `vulcan/compare.diff_findings` → `ScanDiff` che classifica ogni finding logico
  come **new** (regressione o nuova scoperta), **resolved** (prova che una
  remediation ha funzionato) o **persistent** (ancora aperto, con cambio di
  severità/rischio evidenziato), abbinando per identità logica
  (`vulcan.aggregate.finding_fingerprint`: stesso asset + stessa vuln, mai il
  `finding_id` per-run); fonte unica per CLI e Web. CLI `olympus vulcan diff
  --baseline … --current …` (tabella/JSON, exit code `1` se ci sono finding nuovi,
  `0` altrimenti). Web `GET /findings/diff` (scope `findings:read`) confronta il
  `--baseline-directory` con il `--findings-directory` corrente riusando lo stesso
  motore e `FindingView`; degrado onesto se non configurato. Nessun artefatto
  produttore viene riscritto. Test `tests/unit/test_vulcan_compare.py` e
  `tests/unit/test_themis_web.py`; doc [`docs/findings.md`](docs/findings.md),
  [`docs/web.md`](docs/web.md).
- [x] **Trend storici dei finding (slice 3a).** Motore puro e offline
  `vulcan/trend.build_finding_trend`: da una serie ordinata di snapshot (dal più
  vecchio) produce, per ogni run, il totale logico e il breakdown per severità e,
  tra run consecutivi, i conteggi new/resolved/persistent (riusando
  `diff_findings` e `severity_breakdown`, fonte unica condivisa). CLI `olympus
  vulcan trend --snapshot … --snapshot …` (tabella/JSON, exit code `1` se l'ultimo
  run introduce finding nuovi, `0` altrimenti; min 2 snapshot). Deterministico.
  Test `tests/unit/test_vulcan_compare.py`; doc [`docs/findings.md`](docs/findings.md).
- [x] **Attack-surface evolution (slice 3b — superficie asset).** Esteso il diff
  già presente in Argus (`argus/diff.py`, `olympus argus diff`) dalla sola lista
  di hostname all'intera superficie modellata dall'`Asset`: hostname/subdomain
  **e** indirizzi IP aggiunti/rimossi/invariati. Nuovo motore puro e offline
  `diff_assets(before, after) -> AssetDiff` (DI-friendly, deterministico,
  normalizza gli hostname); `diff_snapshots` lo riusa via un loader condiviso
  mantenendo il contratto storico (`added`/`removed`/`unchanged` = hostname).
  Porte/servizi **non** sono campi di primo livello su `core.Asset` e non vengono
  inventati (onestà della superficie). Test `tests/unit/test_argus_assets_diff.py`;
  doc [`docs/reference.md`](docs/reference.md).
- [ ] **Resta aperto**: porte/servizi come superficie di primo livello (richiede
  un'estensione del contratto `Asset`) e la vista trend multi-snapshot nel browser
  (richiede uno storico persistente degli snapshot).
- [~] **Notifiche (porta di output sul core).** `core/notifications.py` è la porta
  "Iris" (non un nuovo modulo dominio): trasforma un `core.Finding` o un
  `core.ScanJob` in un payload `Notification` **versionato** (`olympus.notification`
  `1.0.0`, pubblicato nel catalogo schemi) e **redatto** (ogni testo via
  `safe_terminal_text`, ogni label via `redact_mapping`: nessun segreto), e lo
  recapita solo quando configurato. **Disattivate di default**: un
  `NotificationDispatcher` senza canali è un no-op e senza `--webhook` la CLI
  mostra solo l'anteprima, senza alcuna chiamata di rete. Canale **webhook**
  `WebhookChannel` con trasporto `PinnedWebhookPoster` **SSRF-safe** (ogni hop
  vincolato alla `global_address_policy` solo-pubblica; solo schemi `http(s)`);
  una consegna non-2xx o fallita è riportata, mai sollevata. Canale **e-mail**
  `EmailChannel` sulla stessa porta: messaggio di testo redatto via `smtplib`
  (`SmtpEmailTransport`), indirizzi validati contro header-injection, errori SMTP
  riportati non sollevati. CLI `olympus vulcan notify --findings …
  [--min-severity …] [--webhook …] [--email-to … --email-from … --smtp-host …]`
  (anteprima redatta o consegna su uno/entrambi i canali; exit `5` se una consegna
  fallisce). Test `tests/unit/test_core_notifications.py` (motore + CLI con doppi
  in memoria, zero rete); doc [`docs/findings.md`](docs/findings.md).
  **Resta da fare:** emissione automatica sugli eventi di job/finding del loop
  Themis (motore e builder per job e finding già pronti; il wiring tocca codice
  Themis).

**Criterio di completamento:** un operatore confronta due assessment e riceve una
notifica redatta alla chiusura di un job, senza logica di report duplicata.

### Intervento J · `WEB-J` — Operabilità dei dati (**P2**)

- [ ] **Backup / restore** verificabile di engagement, job, finding, evidence e
  identità, con integrità controllabile; **data retention** applicata in modo
  uniforme (riusa `core.retention`).
- [x] **Import / export di engagement (slice 1 — portabilità engagement).**
  Formato portabile **NDJSON versionato** (un engagement per riga, documento
  deterministico `olympus.engagement` via `canonical_json`): motore puro e offline
  `engagements/portable.py` (`export_engagements` ordinato per id →
  diffabile/round-trip verificabile; `import_engagements` strict, bounded,
  validato sul contratto, **all-or-nothing**). CLI `olympus engagement
  export --storage … -o file.ndjson [--id …]` e `olympus engagement import
  --storage … -i file.ndjson` (upsert per id; file malformato → exit `2`, nulla
  scritto). Round-trip senza perdita verificato A→export→import→B (digest uguali).
  Test `tests/unit/test_engagements_portable.py`; doc
  [`docs/engagements.md`](docs/engagements.md).
- [x] **Import / export di finding e asset (slice 2 — NDJSON portabile).**
  `vulcan/portable.py` (sibling di `engagements/portable.py`): export deterministico
  ordinato per id e import strict/bounded/**all-or-nothing** per `Finding` e
  `Asset`, validati sui contratti `olympus.finding`/`olympus.asset`; round-trip
  lossless con i bundle JSON che i loader già consumano. CLI `olympus vulcan
  export --kind findings|assets -i bundle.json -o out.ndjson` e `olympus vulcan
  import --kind … -i out.ndjson -o bundle.json` (file malformato → exit `2`, nulla
  scritto). Test `tests/unit/test_vulcan_portable.py`; doc
  [`docs/findings.md`](docs/findings.md), [`docs/reference.md`](docs/reference.md).
- [x] **Import SARIF (slice 3 — interoperabilità).** `vulcan/sarif.py`
  `sarif_to_findings(document, *, asset_id, source)`: importa un report **SARIF
  2.1.0** di terze parti come `core.Finding` (mapping `level`→severità con default
  sicuro `medium`, `ruleId`/`helpUri`→references, location→evidence), trattando il
  documento come **input ostile** (validazione 2.1.0 stretta, campi type-checked,
  dimensioni limitate; documento malformato non importa nulla). Chiude il formato
  SARIF citato nel bullet import/export (l'export SARIF dei finding era già in
  Hermes). CLI `olympus vulcan sarif-import -i report.sarif.json -o findings.json
  --asset-id … [--source …]` (bundle JSON caricabile dai loader; malformato → exit
  `2`, nulla scritto). **Export simmetrico** `findings_to_sarif` +
  `olympus vulcan sarif-export -i findings.json -o report.sarif.json`
  (deterministico, ordinato per id; severità→`level` con severità/provenienza/
  stato/rischio/CVE-CWE-KEV conservati nel `properties` bag, così il dettaglio non
  si perde oltre il collasso a 4 livelli). Test `tests/unit/test_vulcan_sarif.py`;
  doc [`docs/findings.md`](docs/findings.md), [`docs/reference.md`](docs/reference.md).
- [x] **OpenAPI pubblicata e documentata**: lo schema OpenAPI del control plane
  (`themis.api`) è generato (`scripts/update_contract_goldens.py`) e **versionato
  e verificato in CI** come golden (`tests/fixtures/contracts/openapi.json`,
  gate `tests/contract/test_golden_interfaces.py`), documentato in
  [`docs/contracts.md`](docs/contracts.md). **Resta aperto:** esempi d'uso
  per gli integratori e un comando dedicato per emetterlo on-demand.

**Criterio di completamento:** un engagement esportato da un'installazione è
reimportabile in un'altra senza perdita di dati né violazione di contratto; lo
schema OpenAPI è versionato e verificato in CI.

## 🎨 Prospettiva Designer (UI/UX)

### Stato dell'interfaccia attuale

La TUI in `src/olympus/tui/app.py` è keyboard-first, elenca moduli e comandi,
mostra l'usage reale della command tree, esegue il processo tramite
`asyncio.create_subprocess_exec` senza shell, streamma l'output e supporta la
cancellazione. È una base sicura, ma la schermata di esecuzione espone un solo
campo `Arguments` interpretato con `shlex.split`: l'utente deve già conoscere
flag, formati dei file e relazioni tra scope, autorizzazione e output.

### Principi di design

1. **Sicurezza visibile, non nascosta:** scope, autorizzazione e classe di rischio
   sono sempre sullo schermo prima e durante un'operazione attiva.
2. **Onestà dello stato:** “nessun finding” non deve mai essere confuso con
   “scansione parziale”, “simulazione” o “tool non disponibile”.
3. **Attrito proporzionato:** nessuna conferma per operazioni passive, conferma
   esplicita e specifica per quelle attive o intrusive.
4. **Stesso modello, più interfacce:** CLI, TUI ed eventuale web UI condividono
   schema, validazione e messaggi; nessuna logica duplicata.
5. **Esperti e principianti:** percorsi guidati per chi inizia, modalità raw e
   scorciatoie da tastiera per chi conosce già gli strumenti.

### Intervento A · `UX-A` — Form dinamici derivati dalla CLI (**P1**)

- [x] Generare controlli TUI dalla metadata Click/Typer: text field, select,
  checkbox, path picker e repeatable option, invece di un'unica stringa libera.
  **Schema fatto:** `olympus/cli_forms.py` deriva dall'albero Typer reale un
  `CommandForm` con `FormField` tipizzati — `kind` ∈ {text, integer, number,
  boolean, choice, path}, più `required`, `default` stabile, `choices` (dagli
  enum), `minimum`/`maximum` (dai range Click) e flag `multiple` (repeatable).
  **Rendering fatto (2026-10-29):** `tui.app.CommandScreen` disegna un widget per
  campo dal `CommandForm` — `Checkbox` per i boolean, `Select` per le choice
  (enum), `Input` tipizzato per text/integer/number/path (placeholder con
  range/default; path come input testuale validato, non un file-browser modale) —
  in un pannello scrollabile `#fields`, al posto dell'unica stringa libera. L'argv
  è costruito in modo sicuro come `list[str]` (`--flag valore`, un boolean solo se
  attivo, posizionali come valore nudo nell'ordine di dichiarazione), **mai** una
  stringa shell. Repeatable → un `--flag valore` per voce (input separato da spazi).
- [x] Mostrare required/default/range/example e validare localmente prima del run.
  Lo schema espone required/default/choices/range per ogni campo e
  `cli_forms.validate_values(form, values)` **valida localmente** prima di
  qualunque run (required mancanti, choice non valide, input non numerico, numeri
  fuori range → errori leggibili). **Visualizzazione fatta (2026-10-29):** ogni
  campo mostra flag, marcatore `*` per i required e help; i vincoli (range/default)
  sono nel placeholder; un valore non valido blocca il run con gli errori di
  `validate_values` e nessun processo viene avviato.
- [x] Conservare una modalità “raw arguments” per utenti esperti, separata e
  chiaramente indicata. Una checkbox **Raw arguments mode (expert)** affianca il
  form guidato: quando attiva, i campi tipizzati sono ignorati e la stringa libera
  è divisa con `shlex.split` (nessuna shell), preservando il percorso esperto
  originale; una command senza opzioni mostra solo il campo raw.
- [x] Riutilizzare lo stesso schema per eventuale web UI, evitando logiche diverse
  tra CLI e TUI. Lo schema di `cli_forms` è **interface-agnostic** (`form_for`,
  `forms_for_app`, `validate_values`, con `to_dict()` serializzabile): TUI e web
  consumano la stessa fonte derivata dalla command tree, nessuna logica duplicata.
  Test `tests/unit/test_cli_forms.py`; doc [`docs/tui.md`](docs/tui.md).
- [x] Launcher `olympus ui` ripristinato: la guardia in `cli.py` usava
  `isinstance(root, click.Group)` contro il `TyperGroup` vendorizzato da Typer
  (che **non** eredita dallo `click.Group` di stdlib), quindi l'entry point
  sollevava sempre `RuntimeError` e la TUI era irraggiungibile dalla CLI. Ora il
  gruppo è rilevato strutturalmente via `.commands`; regressione coperta da
  `tests/unit/test_cli.py::test_ui_command_launches_the_tui_group`.

**Criterio di completamento (soddisfatto):** un nuovo utente può configurare una
scansione senza consultare `--help` — i campi tipizzati con flag, required e
vincoli sono sullo schermo — e l'argv prodotto è visibile (stampato prima del run),
costruito come `list[str]` senza shell e riproducibile. **`UX-A` completo.**
(La safety preview in-flow e il kill switch sempre visibile restano in `UX-B`.)

### Intervento B · `UX-B` — Safety preview e conferme proporzionate (**P0/P1**)

- [~] Prima del run mostrare target normalizzato, scope match, classe di rischio,
  manifest/approvazione, timeout, rate, concorrenza, output e tool esterno.
  **Fonte dati fatta:** `olympus/themis/preview.py` compone un `SafetyPreview`
  interface-agnostic (`to_dict()` serializzabile) da un `ThemisRunRequest`
  pianificato: target normalizzato, esito **statico** di scope
  (`ensure_allowed`, **nessun DNS**: `in_scope`/`resolution_required`/
  `out_of_scope`/`blocked`/`invalid`), classe di rischio e spiegazione (riuso di
  `integrations.activity`), stato autorizzazione (manifest firmato / lab /
  simulazione), budget (timeout/deadline/output-bytes/findings), percorsi di
  output e audit, e tool esterno. Esposto come `olympus themis preview`
  (read-only, offline, `--format table|json`, codice `3` se lo scope bloccherebbe
  il lancio). Doc [`docs/safety-preview.md`](docs/safety-preview.md). **Innesto
  in-flow iniziale fatto (2026-10-29):** prima di un'operazione attiva la TUI mostra
  l'invocazione esatta e il target nella `ConfirmRunScreen` (vedi il punto
  conferme). **Resta da fare:** il rendering del `SafetyPreview` completo
  (decisione di scope, manifest/approvazione, budget, tool esterno) in un widget
  dedicato del percorso di esecuzione Themis.
- [x] Per comandi `active` o `intrusive`, richiedere una conferma esplicita che
  riporti il target; nessuna conferma aggiuntiva per operazioni passive e locali.
  Il preview Themis espone già il predicato `requires_confirmation` (true per run
  `active`/`intrusive` non simulati, false per passivi e simulazioni; uno scanner
  ignoto non è mai sottostimato). **Prompt interattivo fatto (2026-10-29):** la TUI
  (`tui.app.CommandScreen`) innesta il predicato nel percorso di esecuzione — prima
  di lanciare, se l'argv costruito contiene `--i-am-authorized` (il gate universale
  di operazione attiva autorizzata del prodotto, in modalità guidata **o** raw)
  apre una `ConfirmRunScreen` modale che riporta l'invocazione esatta e il target,
  e il processo parte **solo** dopo conferma esplicita; i comandi passivi/locali
  (senza il gate) partono senza attrito aggiuntivo. Coperto da
  `tests/unit/test_tui.py` (conferma richiesta, annulla→nessun run, conferma→run
  con l'argv autorizzato, passivo→nessun modale). Il predicato Themis
  `requires_confirmation` resta la fonte per il percorso di esecuzione Themis
  dedicato.
- [~] Evidenziare `simulation`, `unavailable`, `partial` e `failed` come stati
  distinti: un risultato parziale non deve sembrare “nessuna vulnerabilità”.
  **Fonte dati fatta:** `olympus/themis/outcome.py` compone un `OutcomeSummary`
  interface-agnostic da un run concluso, con stati distinti (`clean`, `findings`,
  `partial`, `cancelled`, `failed`, `unavailable`, `disabled`, `simulation`) e
  un solo predicato di sicurezza — `trustworthy_empty` è vero **solo** per
  `clean` (run live a termine, zero finding); ogni altro stato è
  `conclusive=False`, quindi l'assenza di finding non significa "nessuna
  vulnerabilità". Fail-safe: uno stato persistito ignoto è trattato come
  `failed`. Esposto in `olympus themis jobs status --format table` (il default
  `json` resta invariato). Doc [`docs/safety-preview.md`](docs/safety-preview.md).
  **Stati distinti nella TUI fatto (2026-10-29):** al termine di un run la TUI
  mappa il codice di uscita canonico (`core.exit_codes.ExitCode` 0–7, condiviso da
  **ogni** comando) in uno stato etichettato e colorato distinto
  (`describe_completion`): success, findings, usage, blocked (out-of-scope),
  refused, **partial — NOT exhaustive**, failed, cancelled; un codice esterno
  ignoto è normalizzato a *failed*, mai mostrato come successo. Così un run parziale
  (uscita 5) o fallito (6) non appare mai come "nessuna vulnerabilità". **Resta da
  fare:** il rendering degli stati Themis-specifici `simulation`/`unavailable`
  (non derivabili dal solo codice di uscita) nel percorso Themis dedicato e nella
  Web UI.
- [x] Integrare un kill switch sempre visibile con feedback su processo terminato,
  cleanup ed evidenze conservate. **Fatto (2026-10-29):** la TUI espone sempre il
  pulsante CANCEL e il binding `Ctrl+C`; `action_cancel_command` segna il run come
  annullato, invia `terminate()` e, dopo una grazia (`KILL_GRACE_SECONDS`),
  **escala a `kill()`** se il processo ignora il segnale (`_escalate_kill`). Il
  completamento riporta uno stato *Cancelled — the process was terminated*
  distinto (mai "success" per via del codice di segnale), e l'output catturato
  fino a quel punto resta nel log. Coperto da `tests/unit/test_tui.py`
  (`describe_completion` per ogni stato + cancellazione; kill switch segna annullato
  e termina il processo). *Nota di onestà:* il cleanup del process-group reale e la
  conservazione delle evidenze su disco sono proprietà del sottoprocesso
  (`themis/sandbox.py`, `core/retention.py`), non simulati dalla TUI.

**Criterio di completamento:** test di usabilità dimostrano che gli utenti non
confondono simulazione, successo senza finding e copertura incompleta.

### Intervento C · `UX-C` — Flusso guidato per assessment (**P1**)

- [ ] Aggiungere wizard: crea/importa engagement → valida scope → esegui doctor →
  seleziona capability → stima impatto → avvia → monitora → esporta report.
- [ ] Offrire preset `passive recon`, `web assessment`, `detection validation` e
  `incident triage`, tutti ispezionabili e senza target predefiniti.
- [ ] Mostrare dipendenze mancanti e maturity dello scanner prima della selezione;
  `catalog-only` non deve apparire eseguibile.
- [ ] Salvare preset senza segreti e permettere dry-run/clone dell'assessment.

**Criterio di completamento:** il percorso principale richiede decisioni chiare e
non espone opzioni non applicabili all'ambiente corrente.

### Intervento D · `UX-D` — Monitoraggio operativo e cronologia (**P1**)

- [ ] Aggiungere vista job con progresso, fase, tempo trascorso, deadline, retry,
  coverage, finding count e stato dello scanner.
- [ ] Collegare assessment → job → evidence → finding → report con navigazione
  coerente e filtri per severity, asset, modulo e stato.
- [ ] Rendere ricercabili audit e output senza mostrare dati redatti o segreti.
- [ ] Permettere ripresa di sessioni interrotte leggendo lo stato persistito,
  senza rilanciare automaticamente operazioni attive.

**Criterio di completamento:** l'utente può spiegare in ogni momento cosa è in
esecuzione, con quale autorizzazione e quanto è completa la copertura.

### Intervento E · `UX-E` — Accessibilità e internazionalizzazione (**P1**)

- [ ] Estrarre tutte le stringhe runtime da TUI e CLI e introdurre cataloghi
  `it`/`en`; oggi README e policy sono bilingui, l'interfaccia è solo inglese.
- [ ] Evitare significati affidati unicamente al colore; affiancare etichette,
  simboli e stati testuali coerenti.
- [ ] Aggiungere tema ad alto contrasto, gestione terminali piccoli, focus visibile,
  ordine di tabulazione e modalità plain-text/screen-reader friendly.
- [ ] Verificare contrasto, ridimensionamento, tastiera completa e messaggi di
  errore con test automatici e sessioni manuali documentate.

**Criterio di completamento:** tutti i flussi primari sono usabili da tastiera, in
italiano e inglese, senza dipendere dalla percezione cromatica.

### Intervento F · `UX-F` — Reporting a più livelli (**P2**)

- [ ] Separare vista executive, tecnica e raw evidence mantenendo la tracciabilità
  dello stesso finding.
- [ ] Esporre impatto, evidenza, confidence, remediation, asset, ATT&CK/CWE/CVE e
  coverage senza sovraccaricare la schermata iniziale.
- [ ] Fornire template HTML/PDF accessibili e export JSON, NDJSON e SARIF
  versionati; indicare sempre dati redatti e sezioni non coperte.
- [ ] Rendere visibile la provenienza degli enrichment KEV/EPSS e la loro data.

**Criterio di completamento:** lo stesso assessment produce un riepilogo leggibile
dal management e un allegato tecnico verificabile senza duplicare i dati.

### Intervento G · `UX-G` — Coerenza CLI, errori e onboarding (**P1**)

- [ ] Uniformare in tutti i moduli le opzioni trasversali (`--format
  table|json|ndjson`, `--output`, `--quiet`, `--verbose`) e rispettare la variabile
  `NO_COLOR` anche nell'output di Olympus, non solo nei processi scanner figli.
- [ ] Riscrivere i messaggi di errore secondo lo schema “cosa è successo → perché →
  cosa fare”, con codice errore stabile e link alla documentazione; mai stack
  trace o segreti all'utente finale.
- [ ] Offrire un primo avvio guidato basato su un `olympus doctor` globale (oggi il
  doctor esiste solo in Argus): dipendenze, binari scanner, maturity, permessi,
  configurazione e scope di esempio in un'unica diagnosi.
- [ ] Rendere scopribili i comandi con suggerimenti “forse intendevi…”, esempi
  copiabili in ogni `--help` e completion per bash/zsh/fish.

**Criterio di completamento:** un nuovo utente installa Olympus, esegue la diagnosi
e completa la prima operazione passiva senza consultare documentazione esterna;
gli script possono consumare ogni comando in JSON senza parsing di testo.

## 🧭 Backlog Operativo Consolidato

Questa sezione incorpora gli interventi ancora validi della precedente roadmap
operativa. È la lista delle capability concrete da sviluppare sopra i guardrail,
i contratti e i controlli di sicurezza descritti nelle sezioni precedenti.

### Funzionalità già consolidate

- [x] **Athena playbook end-to-end:** `recon → scan → enrich → report` in un solo
  flusso scope-safe, con enrichment KEV/EPSS da feed locali e sidecar JSON.
- [x] **AEGIS in Athena:** adapter di piano con doppio scope gate; simulazione
  esplicitamente etichettata quando le live scan sono disabilitate.
- [x] **Apollo access-log ingest:** normalizzazione bounded di log Apache/nginx e
  `http.server` in `core.Event` NDJSON, con catena ingest → regola → alert testata.
- [x] **Minerva timeline:** export firmabile Ed25519 e verificabile con
  `olympus core verify`.
- [x] **Metis IOC sweep:** confronto normalizzato type+value tra osservabili e IOC,
  senza matching per semplice substring.
- [~] **Wapiti:** adapter nativo e parser provato su report JSON reale; resta la
  validazione end-to-end attraverso lo scope gate per passare a `live-tested`.

### Red Team · `OPS-RED` — Copertura offensiva scope-safe

- [⏸] **P1 — Recon ProjectDiscovery/OSINT:** aggiungere adapter nativi per
  `subfinder`, `dnsx`, `naabu`, `amass` e `theHarvester`, ciascuno con argv senza
  shell, parser, fixture su output reale, scope gate e maturity evidence.
- [~] **P1 — Adapter web residui:** completare `nosqlmap` e `wpscan`; gestire il
  token WPScan esclusivamente tramite `SecretProvider`. Portare Wapiti a
  `live-tested` in un lab autorizzato.
- [⏸] **P2 — Exploitation orchestration controllata:** integrare eventualmente
  Metasploit tramite RPC solo dopo l'introduzione dell'engagement manifest
  firmato, con allowlist dei moduli, dry-run predefinito, audit completo, timeout
  e divieto esplicito di persistenza, DoS ed evasione.
- [x] **P2 — Mapping MITRE ATT&CK dei finding offensivi:** associare tecnica,
  tattica, confidence e motivazione ai finding Vulcan, conservando il mapping
  versionato e distinguendo associazioni automatiche da revisioni umane.
  **Fatto:** overlay puro e offline `vulcan/attack.py` (sibling di
  `vulcan/enrichment.py`: non muta il contratto `Finding`) con una tabella
  CWE→ATT&CK **versionata** (`ATTACK_MAP_VERSION`) e revisionata; `associate_attack`/
  `associate_all` derivano per ogni finding `AttackAssociation` (technique, name,
  tactic, `Confidence`, rationale) marcate `AttackSource.AUTOMATIC`, mentre un file
  di revisione umana opzionale aggiunge/sovrascrive associazioni marcate
  `REVIEWED` (precedenza sulle automatiche, nessun duplicato). CWE non mappata →
  nessuna associazione inventata (assenza onesta); output deterministico e
  ordinato. I conteggi tecnici alimentano lo **stesso** ATT&CK Navigator di Apollo
  (`apollo.attack.build_navigator_layer`), così finding offensivi e detection
  difensive popolano un'unica matrice. CLI `olympus vulcan attack --findings …
  [--reviews …] [--navigator …] [--format table|json]`. Test
  `tests/unit/test_vulcan_attack.py` (motore + CLI); doc
  [`docs/reference.md`](docs/reference.md). La tabella iniziale è volutamente
  conservativa ed estensibile (il bump di versione la rende una modifica
  tracciabile).
- [⏸] **P3 — Proteus simulated delivery:** evolvere la modellazione in campagne
  simulate esclusivamente in lab, con click e credential-harvest sintetici e
  nessun invio o dato riferito a utenti reali.

**Criterio di completamento Red Team:** ogni adapter eredita scope, autorizzazione,
policy, audit, sandbox e stati di coverage; nessuna funzione offensiva diventa
eseguibile solo perché il binario esterno è installato.

### Blue Team · `OPS-BLUE` — Detection, SIEM, CTI e DFIR

- [~] **P1 — Ingest Apollo:** aggiungere Sysmon/Windows Event e Zeek oltre al
  formato access-log già disponibile. Separare sempre acquisizione e parsing,
  usare fixture sanitizzate reali e non inventare campi mancanti. **Zeek fatto:**
  `apollo/ingest.py` `parse_zeek_json`/`iter_zeek_json` normalizza i log
  Zeek JSON-streaming (`_path` → kind) mappando `conn`/`dns`/`http`/`ssl` a
  `network.connection`/`dns.query`/`http.request`/`tls.session` con i soli campi
  Zeek documentati (chiavi `id.orig_h` piatte **o** forma annidata `{"id":{...}}`);
  acquisizione (CLI, I/O bounded) separata dal parsing puro; *skip, never guess*
  (JSON non valido, `_path` sconosciuto, nessun campo mappabile o nesting
  eccessivo → riga saltata con motivo, mai evento fabbricato); `ts` epoch ancorato
  a UTC. CLI `olympus apollo ingest --format zeek-json`. Fixture format-fedele
  sintetica `tests/fixtures/apollo/ingest/zeek.jsonl`; test
  `tests/integration/test_apollo_ingest_zeek.py` (parse per-kind, forma annidata,
  skip, backpressure, CLI ingest→run con rilevazione DNS C2). Doc
  [`docs/apollo.md`](docs/apollo.md). **Resta:** Sysmon/Windows Event (richiede
  telemetria Windows reale).
- [⏸] **P1 — Detection engineering loop:** eseguire regola Sigma → generazione di
  telemetria controllata → verifica → tuning → regression test, usando Atomic Red
  Team soltanto in un lab autorizzato.
- [⏸] **P2 — Connettori SIEM/EDR:** implementare Splunk HEC, Elastic e Microsoft
  Sentinel tramite porte iniettate, retry idempotenti, backpressure, checkpoint e
  test offline dei payload; le credenziali reali non entrano nelle fixture.
- [⏸] **P2 — CTI live:** aggiungere client TAXII 2.1, MISP server e OpenCTI a
  Metis, con allowlist delle sorgenti, caching, provenance, TTL e isolamento tra
  fetch e parse.
- [ ] **P3 — Hephaestus:** nuovo modulo per hardening e benchmark CIS su host e
  configurazioni, inizialmente in modalità read-only, con profilo del benchmark,
  evidenza, severità e remediation senza modifica automatica del sistema.

**Criterio di completamento Blue Team:** ogni evento mantiene provenienza e schema;
gli errori di ingest producono coverage parziale esplicita e non una pipeline
apparentemente pulita.

### Purple Team · `OPS-PURPLE` — Validazione e regressione operativa

- [ ] **P2 — `athena purple`:** orchestrare attacco simulato scope-safe → ingest
  Apollo → valutazione detection → report del gap di copertura, collegando tecnica
  ATT&CK, evidenza generata, regola attesa e risultato osservato.
- [ ] **P3 — Profilo lab ripetibile:** usare `labs/mars` come ambiente locale
  dichiarato, con seed, versioni, policy, output atteso ed evidenze committate per
  una regressione operativa riproducibile.
- [x] Aggiungere una matrice “tecnica ATT&CK → telemetria → regola → test” per
  mostrare copertura reale, copertura parziale e assenza di dati. **Fatto:**
  motore puro e offline `apollo/coverage.py` (`assess_coverage`) che correla ogni
  tecnica ATT&CK referenziata dalle regole con l'`event_type` di cui ciascuna
  regola ha bisogno e con i tipi di evento **realmente ingeriti**, classificando
  ogni tecnica come `covered` (tutte le regole hanno la telemetria), `partial`
  (solo alcune: restano punti ciechi) o `no-telemetry` (regola presente ma dato
  mai ingerito → tecnica non rilevabile). Riusa il modello `DetectionRule` e i
  tipi di evento dello stream Apollo; `event_types_from_ndjson` deriva la
  telemetria disponibile da un capture reale saltando le righe non-evento (stessa
  disciplina *skip, never guess*). Deterministico e ordinato; nessuna tecnica
  inventata senza regola (assenza onesta). CLI `olympus apollo coverage --rules
  … [--events …] [--telemetry …] [--format table|json] [--strict]` (`--strict`
  esce `1` sui punti ciechi senza telemetria). Test `tests/unit/test_apollo_coverage.py`
  (engine + CLI); doc [`docs/apollo.md`](docs/apollo.md). La dimensione
  "tecnica senza alcuna regola" richiederebbe un catalogo ATT&CK di riferimento ed
  è fuori scope: la matrice misura la copertura del set di detection contro la
  telemetria disponibile, esattamente il divario che rende una regola cieca.

**Criterio di completamento Purple Team:** la pipeline non misura soltanto se una
regola scatta, ma se la telemetria necessaria è stata prodotta, ingerita e
correlata senza perdita di coverage.

### Suite di scansione guidata · `OPS-SCAN` — Esperienza "pentest-tools.com" (**P1**)

Allineare l'esperienza operatore a quella di una suite commerciale tipo
[pentest-tools.com](https://pentest-tools.com/alltools): un toolkit integrato in
cui, scelto un target autorizzato e un profilo, parte una catena
`recon → scan → enrich → report` e si ottiene un report professionale
esportabile. Le fondamenta esistono già in Olympus — **Athena** orchestra la
catena su un piano firmabile e **Vulcan** produce report JSON/Markdown/HTML — per
cui questo intervento *potenzia* quei due moduli, non ne crea di paralleli.

- [x] **Report PDF formattato.** Renderer PDF minimal in Vulcan: copertina
  brandizzata, summary (overall risk, conteggi, barra severità), **tabella delle
  vulnerabilità note** (`CVE · CVSS · EPSS · percentile · KEV` con link al NIST
  NVD) e finding con Risk description/Recommendation/Evidence/References (link
  NVD e CWE). EPSS/KEV dall'overlay di enrichment (mai inventati); esposto da
  `vulcan report --pdf [--kev/--epss]` e da `athena run --report`, mantenendo
  JSON/Markdown/HTML. Testo dei target escapato (`SEC-H`).
- [ ] **Profili Light/Deep.** Introdurre profili di scansione nominati che
  generano il piano Athena, come il Light/Deep scan della suite: `light` passivo e
  veloce (recon + header + TLS, nessuna autenticazione), `deep` completo
  (aggiunge gli adapter attivi AEGIS). Ispezionabili e senza target predefiniti.
- [ ] **Catalogo capability allineato.** Mappare esplicitamente ogni capacità
  della suite (Website/Network/SSL/CMS scanner, Port Scanner, Subdomain/Domain
  Finder, Password Auditor) sui moduli Olympus esistenti o mancanti, così il
  `catalog` dichiara cosa c'è, cosa è simulato e cosa manca, senza sovrastimare.
- [ ] **Report template e sommario esecutivo riusabile.** Sezioni riusabili
  (scope, metodologia, disclaimer, executive summary) parametrizzate
  dall'engagement manifest (`SEC-C`), per report ripetibili tra ingaggi.
- [⏸] **Scansioni programmate e monitoraggio.** Esecuzione ricorrente di un
  profilo su uno scope con diff dei finding tra run; differito perché richiede uno
  scheduler persistente e un lab autorizzato (prerequisito D13).

#### Candidati scanner vagliati (solo se colmano una capability mancante)

Regola: nessuno scanner si aggiunge perché esiste; solo se colma una capability
reale e non duplica un adapter presente. Il valore resta orchestrazione +
normalizzazione + scope + evidence + report, non il numero di wrapper. La recon
attiva ProjectDiscovery/OSINT (`subfinder`, `dnsx`, `naabu`, `amass`,
`theHarvester`) è già pianificata in `OPS-RED`; il SAST first-party (CodeQL) in
`SEC-F`. Restano da valutare:

| Tool | Capability mancante | Sovrapposizione | Priorità |
| --- | --- | --- | --- |
| Semgrep / Bandit | SAST del codice dell'ingaggio (oltre a CodeQL in CI) | parziale con `SEC-F` | P2 |
| Trivy / OSV-Scanner | dependency/container/IaC e SBOM-vuln | nessuna oggi | P2 |
| sslscan | TLS rapido e leggero | parziale con `testssl` | P3 |
| ffuf | fuzzing web parametrico ampio | parziale con `dirsearch` | P3 |

Esplicitamente **non** pianificati (sovrapposti o fuori dallo scope di prodotto:
DoS-prone o post-exploitation/AD che eccede i guardrail): Masscan, RustScan,
Gobuster, Feroxbuster, kiterunner, kube-bench, kube-hunter,
BloodHound/SharpHound, NetExec, Impacket.

**Criterio di completamento OPS-SCAN:** un operatore configura un profilo su un
target autorizzato, avvia una scansione scope-safe e ottiene un report PDF
leggibile dal management, senza scrivere a mano il piano JSON e senza che una
capacità simulata appaia come reale.

### Prerequisiti per le attività differite

| ID | Intervento | Prerequisito verificabile di sblocco |
| --- | --- | --- |
| D1 | Adapter `live-tested` → `production-ready` | Run attraverso scope gate in lab autorizzato, evidence manifest, digest, SBOM, vulnerability scan e matrice versioni |
| D2 | `testssl`, `whatweb` e Wapiti → `live-tested` | Binari canonici/versioni supportate e target di lab autorizzato |
| D3 | Ritiro completo di `vendor/` | Control plane nativo con API, worker, migrazioni e test di parità |
| D4 | Adapter recon ProjectDiscovery/OSINT | Binari verificati, sorgenti raggiungibili e fixture reali sanitizzate |
| D5 | `nosqlmap` e `wpscan` | Target NoSQL/WordPress controllati e secret provider per il token WPScan |
| D6 | Metasploit RPC | Manifest firmato, allowlist moduli, `msfrpcd` isolato e lab autorizzato |
| D7 | Proteus simulated delivery | Lab chiuso con identità e tracking interamente sintetici |
| D8 | Detection loop con Atomic Red Team | Endpoint di test ripristinabile e raccolta telemetria controllata |
| D9 | Connettori SIEM/EDR | Endpoint di sviluppo, credenziali dedicate a minimo privilegio e dataset sanitizzati |
| D10 | TAXII/MISP/OpenCTI live | Istanze di test raggiungibili e policy di provenance/retention approvate |
| D11 | Firma e hardening container | Registry disponibile, profili seccomp/AppArmor e pipeline Cosign |
| D12 | Release multi-platform | Runner CI per matrice Python/OS e suite chiaramente separate |
| D13 | Scansioni programmate e monitoraggio (`OPS-SCAN`) | Scheduler persistente, storage dei run e lab autorizzato per i diff tra scansioni |

### Verifiche dal vivo (live) — da eseguire in un secondo momento

Checklist delle verifiche che richiedono **esecuzione reale** contro bersagli
veri e **non** possono essere eseguite (né simulate) offline. Si eseguono nel
**lab locale isolato e autorizzato** (`labs/mars/` + doppio opt-in +
`make test-live-lab`, vedi [`docs/verification-status.md`](docs/verification-status.md)),
scansionando solo host che l'operatore possiede. Ogni voce diventa `[x]` solo con
evidenza reale (evidence manifest, digest, SBOM), mai per dichiarazione.

- [ ] **(D1)** Promuovere gli adapter da `live-tested` a `production-ready`: run reale
  attraverso lo scope gate + evidence manifest/digest/SBOM/matrice versioni.
- [ ] **(D2)** Portare `testssl`, `whatweb` e Wapiti a `live-tested` contro i target di lab.
- [ ] **(D4)** Adapter recon ProjectDiscovery/OSINT verificati su sorgenti/fixture reali.
- [ ] **(D5)** `nosqlmap` e `wpscan` contro target NoSQL/WordPress controllati (token via SecretProvider).
- [ ] **(D6)** Exploitation orchestration (Metasploit RPC) con `msfrpcd` isolato e allowlist moduli.
- [ ] **(D7)** Proteus simulated delivery in lab chiuso con identità sintetiche.
- [ ] **(D8)** Detection loop con Atomic Red Team su endpoint di test ripristinabile.
- [ ] **(D9)** Connettori SIEM/EDR (Splunk HEC, Elastic, Microsoft) su endpoint dev dedicati.
- [ ] **(D10)** CTI live (TAXII 2.1, MISP, OpenCTI) contro istanze di test.
- [ ] **(D11)** Firma container **Cosign** contro un registry + hardening seccomp/AppArmor.
- [ ] **(D12)** Release multi-platform sulla matrice OS/Python dei runner CI.
- [ ] **(D13)** Scansioni programmate e monitoraggio (`OPS-SCAN`) con scheduler e storage dei run.
- [ ] **(SEC-F)** CodeQL/SAST come gate bloccante e provenance SLSA firmata (GitHub/CI).
- [ ] **(SEC-F)** Branch protection su `main` (impostazione del titolare del repository).

## 📅 Pianificazione Temporale

Le durate sono stime per un team piccolo e presuppongono decisioni architetturali
rapide. Le attività che richiedono scanner reali devono essere validate solo in un
lab autorizzato; in assenza del lab restano aperte e non cambiano maturità. Il
percorso legittimo per eseguirle — lab locale isolato `labs/mars/`, doppio opt-in
e `make test-live-lab` — e l'elenco delle verifiche offline già eseguibili sono
documentati in [`docs/verification-status.md`](docs/verification-status.md).

### Fase 0 — Baseline e coerenza documentale (1–2 settimane)

- [x] Rendere `ROADMAP.md` la fonte canonica e risolvere i link interni rotti
  (`DEV-G`).
- [x] Riconciliare `upgrade.md` con la roadmap e creare template issue/PR e label
  versionate (`DEV-H`).
- [x] Attivare Mypy e `ruff format --check` come gate CI (`DEV-C`).
- [ ] Generare automaticamente inventario e maturity table.
- [ ] Registrare baseline di test, coverage, package build e threat model.
- [ ] Aprire `adr-003` ritiro VAP, `adr-004` plugin SDK e `adr-005` engagement
  manifest firmato.

**Exit gate:** documentazione coerente con `main`, backlog senza duplicati e ADR
approvati per i tre cambiamenti strutturali.

### Fase 1 — Security hardening (**P0**, 3–6 settimane)

- [ ] Migrare o disabilitare in produzione le route legacy VAP non equivalenti.
- [ ] Implementare egress allowlist, container sandbox e profilo seccomp/AppArmor.
- [ ] Introdurre engagement manifest firmato e safety preview.
- [ ] Rafforzare redaction test, secret provider e kill switch end-to-end.
- [ ] Parsing sicuro, fuzzing e fixture malevole per i dati restituiti dai target
  (`SEC-H`).

**Exit gate:** nessuna operazione attiva può bypassare scope/autorizzazione, un
processo scanner compromesso resta confinato e un target ostile non può colpire
l'operatore tramite output, log o report.

### Fase 2 — Architettura e qualità di release (4–8 settimane)

- [~] Runtime Themis API/Web/migrazione/worker nativo e indipendente da `vendor/`
  (`SEC-A`, primo punto); restano parità completa endpoint/dati legacy e rimozione
  fisica del sorgente archiviato.
- [ ] Pubblicare SDK/contract test per adapter.
- [x] Attivare matrice Python, branch coverage gate e suite unit/contract/integration
  separate; POSIX resta in un job dedicato.
- [x] Aggiungere mutation test mirati e il gate minimo per funzione.
- [ ] Aggiungere CodeQL; la suite container nativa SEC-A è eseguibile in CI,
  mentre live-lab e isolamento egress degli scanner richiedono ancora prove.
- [ ] Stabilizzare schema, migrazioni, exit code e recovery dei job.
- [x] Registrare baseline di performance offline e budget iniziali per le
  operazioni critiche (`DEV-E`); il gate resta manuale fino alla raccolta di
  misure su runner stabili.
- [x] Rendere incrementali ingest e valutazione Apollo con backpressure, limiti
  per riga e output atomico, senza materializzare l'intero stream di eventi.

**Exit gate:** wheel indipendente dal checkout, contratti versionati e pipeline
verde su tutta la matrice dichiarata.

### Fase 3 — UX operativa bilingue (4–7 settimane)

- [ ] Sostituire l'input argomenti unico con form dinamici.
- [ ] Implementare wizard assessment, stato job, cronologia e navigazione delle
  evidenze.
- [ ] Completare localizzazione IT/EN e audit di accessibilità.
- [ ] Consolidare report executive/technical/raw.
- [ ] Uniformare opzioni CLI, messaggi di errore e `olympus doctor` globale
  (`UX-G`).

**Exit gate:** test con utenti rappresentativi completano i flussi primari senza
ricorrere alla documentazione e interpretano correttamente gli stati di coverage.

### Fase 4 — Capability Red/Blue/Purple (6–12 settimane, incrementale)

- [ ] Completare ingest Apollo per Zeek e Sysmon/Windows Event.
- [ ] Implementare mapping ATT&CK offensivo e il primo flusso `athena purple`.
- [ ] Aggiungere progressivamente adapter recon/web secondo i prerequisiti D4/D5.
- [ ] Sviluppare connettori SIEM/CTI partendo da porte e parser testabili offline.
- [ ] Avviare Hephaestus read-only su configurazioni e benchmark CIS selezionati.

**Exit gate:** ogni nuova capability dispone di schema, fixture reale sanitizzata,
coverage esplicita e almeno un flusso end-to-end ripetibile.

### Fase 5 — Production readiness degli scanner (continuativa, 1–2 adapter/sprint)

- [ ] Portare prima `nmap`, `httpx` e `nuclei` a `production-ready` con evidence
  manifest, digest, SBOM, vulnerability scan e matrice versioni.
- [ ] Validare live `testssl`, `whatweb` e `wapiti` tramite scope gate in lab.
- [ ] Proseguire sugli adapter restanti solo con fixture reali e prove ripetibili.
- [ ] Automatizzare il controllo della Definition of Done in CI.

**Exit gate per adapter:** nessuna dichiarazione di maturità senza evidenza
committata e verificabile secondo `docs/scanner-maturity.md`.

### Fase 6 — Distribuzione e osservabilità (2–4 settimane, poi continua)

- [ ] Trusted Publishing su PyPI, firma release/container e provenance SLSA.
- [~] Metriche e tracing redatti sono disponibili via Prometheus/OTLP (`DEV-E`);
  restano da definire dashboard operative e SLO misurati su ambienti stabili.
- [ ] Runbook di installazione, upgrade, backup, restore, revoca e incident response.
- [ ] Release candidate in lab, security review e rollback testato.
- [ ] SLA di vulnerability disclosure e runbook di compromissione chiavi
  (`SEC-I`).

**Exit gate:** release firmata, riproducibile, monitorabile e ripristinabile.

## Ordine di priorità raccomandato

| Ordine | Deliverable | Ruolo guida | Dipendenza |
| ---: | --- | --- | --- |
| 0 | Quick win: gate Mypy, link rotti, governance backlog (`DEV-C`, `DEV-G`, `DEV-H`) | Development | Nessuna |
| 1 | Ritiro/messa in sicurezza VAP legacy (`SEC-A`, `DEV-A`) | Cybersecurity + Development | ADR e test di parità |
| 2 | Egress allowlist e sandbox forte (`SEC-B`) | Cybersecurity | Runtime Linux/container |
| 3 | Engagement manifest firmato (`SEC-C`) | Cybersecurity + Development | Contratto schema + key management |
| 4 | Parsing sicuro e fuzzing dei dati dei target (`SEC-H`) | Cybersecurity + Development | Fixture reali esistenti |
| 5 | CI matrix, coverage, SAST e docs-as-code (`DEV-C`, `SEC-F`) | Development | Nessuna dipendenza esterna critica |
| 6 | Form TUI e safety preview (`UX-A`, `UX-B`) | UX + Development | Metadata CLI stabile |
| 7 | Primi adapter `production-ready` (`D1`) | Cybersecurity | Lab autorizzato + evidenze |
| 8 | Ingest Zeek/Sysmon e primo `athena purple` (`OPS-BLUE`, `OPS-PURPLE`) | Cybersecurity + Development | Fixture reali e lab ripetibile |
| 9 | Release firmata PyPI/container (`DEV-F`, `SEC-F`) | Development + Cybersecurity | Gate precedenti verdi |
| 10 | Wizard, reporting, CLI coerente e accessibilità IT/EN (`UX-C`…`UX-G`) | UX | Flussi e contratti stabilizzati |

## 📈 Indicatori di avanzamento

| Indicatore | Stato verificato (25/09/2026) | Obiettivo | Fonte verificabile |
| --- | --- | --- | --- |
| Adapter `production-ready` | 0 su 15 | ≥ 3 (`nmap`, `httpx`, `nuclei`) | `integrations/maturity.py` |
| Adapter almeno `live-tested` | 12 su 15 | 15 su 15 | `integrations/maturity.py` |
| Branch coverage first-party | gate CI ≥75% (checker su report JSON) | mantenere la soglia e alzarla solo dopo baseline verificabile | `.github/workflows/ci.yml` + `scripts/check_branch_coverage.py` |
| Versioni Python testate in CI | 4 (3.11–3.14) | mantenere tutte le versioni dichiarate | `.github/workflows/ci.yml` |
| Gate statici bloccanti | Ruff lint/format, Mypy, pytest, pip-audit, gitleaks | + CodeQL, link checker | `.github/workflows/ci.yml` |
| Parser coperti da fuzzing | 0 | 100% degli adapter dichiarati | suite `SEC-H` |
| Import runtime da `vendor/` | 0 nel runtime mantenuto (`SEC-A`, primo punto) | mantenere 0 | `tests/contract/test_themis_native_deployment.py` + smoke wheel/container |
| Link interni rotti | ≥ 6 file → 0 (verifica manuale del 24/09/2026) | 0, garantito dalla CI | link checker `DEV-G` |
| Lingue dell'interfaccia | 1 (EN) | 2 (IT/EN) | cataloghi `UX-E` |
| Formati di report Vulcan | 4 (JSON, Markdown, HTML, PDF con tabella NVD/EPSS) | mantenere e arricchire | `src/olympus/vulcan/` + test |

Gli indicatori si aggiornano solo dalla fonte indicata: un valore senza prova
verificabile resta al valore precedente.

## ⚠️ Registro dei rischi

| Rischio | Probabilità | Impatto | Mitigazione |
| --- | --- | --- | --- |
| La migrazione dal VAP perde funzionalità o regressa la sicurezza | Media | Alto | matrice di parità, threat-model review per milestone, feature flag e rollback (`SEC-A`) |
| Uso non autorizzato delle capacità offensive | Media | Critico | manifest firmato con scadenza, classi di rischio, dry-run e audit (`SEC-C`, `SEC-G`) |
| Target ostile colpisce l'operatore tramite output o report | Media | Alto | parsing sicuro, escaping contestuale, fuzzing (`SEC-H`) |
| Compromissione della supply chain o delle chiavi di firma | Bassa | Critico | provenance SLSA, Cosign, Trusted Publishing, runbook di rotazione (`SEC-F`, `SEC-I`) |
| Lab autorizzato non disponibile blocca la maturità degli scanner | Alta | Medio | lavoro offline su parser e contratti; nessuna promozione senza evidenza (`D1`–`D12`) |
| Dichiarazioni di maturità più ottimistiche delle prove | Media | Alto | tabelle generate dal ledger e verifica in CI (`DEV-G`) |
| Complessità UX che induce errori operativi | Media | Medio | safety preview, stati di coverage distinti, test con utenti (`UX-B`, `UX-D`) |

## Definition of Done trasversale

Un intervento può essere marcato `[x]` soltanto se:

1. il codice è implementato senza bypassare scope, autorizzazione, audit o limiti;
2. sono presenti unit test e, dove appropriato, contract/integration test;
3. Ruff, Mypy, Pytest, secret scan, dependency audit e SAST risultano verdi;
4. la documentazione IT/EN e il threat model sono aggiornati;
5. errori, coverage parziale e dipendenze mancanti sono esposti chiaramente;
6. non sono presenti segreti, target reali o dati personali negli artifact;
7. l'evidenza di validazione è ripetibile e collegata al commit;
8. per funzioni network-active, il test live è avvenuto esclusivamente in un lab
   controllato e autorizzato;
9. la modifica include piano di migrazione/rollback quando altera dati o contratti;
10. UX, accessibilità e localizzazione sono verificate per ogni nuovo flusso
    operatore-facing;
11. ogni dato proveniente da un target è trattato come non fidato (`SEC-H`) e
    l'intervento è citato tramite il suo ID in issue, PR e commit.

---

Questa roadmap va riesaminata a ogni release minor. Il ledger di maturità degli
scanner, il threat model e gli schemi versionati restano fonti tecniche
autorevoli; in caso di divergenza, la documentazione deve essere rigenerata dal
codice e nessuna capability deve essere presentata come più matura delle prove
disponibili.

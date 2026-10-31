Warning: truncated output (original token count: 62990)
Total output lines: 3530

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
`UX-A` form CLI derivati e consumati dalla TUI, criteri completati nella sezione dedicata; `OPS-PURPLE` matrice
presenza telemetria implementata, catena tecnica→regola→test non completata.
`UX-G` doctor globale già implementato; resta onboarding. `UX-F` report multilivello
presente in Vulcan/Web, resta validazione utenti. `SEC-A`/`DEV-A` runtime nativo
presente; `D3` non è più bloccato dall'assenza vendor, eventuale parità storica resta
nel manifest dedicato. `[x]` indica criteri testati nello scope indicato, non
production readiness. Il workflow CI (gate, SBOM/wheel, pip-audit, gitleaks) è
stato **ripristinato** il 2026-10-30 (`.github/workflows/ci.yml`); l'enforcement
effettivo resta subordinato all'esito verde dei run remoti e alle branch
protection rule: `DEV-C-01` `[~]`.

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
| `SEC-H-01` | Rifiuto directory symlink API | P1 | AppSec/Backend | S | M1 | [x] |
| `SEC-H-02` | Letture FIFO non bloccanti | P1 | AppSec/Backend | S | M1 | [x] |
| `SEC-D-01` | Redazione argomenti nel log TUI | P1 | AppSec/UX | S | M1 | [x] |
| `SEC-G-01` | Cancellazione TUI completa | P1 | Backend/QA | M | M2 | [~] |
| `DEV-E-01` | Transizioni Athena concorrenti e audit atomico | P1 | Data/Architect | L | M2 | [x] |
| `SEC-E-02` | Verifica digest risultati in lettura | P1 | Data/AppSec | S | M1 | [x] |
| `DEV-B-01` | Plugin concreti e realmente integrati | P1 | Scanner/Architect | L | M3 | [x] |
| `DEV-D-01` | Versionamento fisico degli store | P1 | Data | L | M3 | [x] |
| `WEB-J-01` | Backup e restore coordinato | P1 | Data/SRE/Privacy | L | M3 | [~] |
| `WEB-J-02` | Retention e privacy di sistema | P2 | Privacy/Data | L | M3 | [ ] |
| `DEV-C-01` | Ripristino enforcement qualità e release | P1 | QA/SRE | L | M1 | [~] |
| `SEC-F-01` | Build scanner riproducibile e licenze | P1 | SRE/Governance | L | M2 | [⏸] |
| `SEC-F-02` | Chiusura dipendenze SBOM conforme ai marker | P1 | Supply-chain/Backend | M | M1 | [x] |
| `DEV-G-01` | Riconciliazione dichiarazioni e inventario | P1 | Writer/QA/Product | M | M1 | [~] |
| `UX-A-01` | Parità TUI e consumer form | P1 | UX/Frontend/Product | L | M3 | [x] |
| `WEB-A-01` | Ripresa SSE visibile | P1 | Frontend/Backend | M | M3 | [x] |
| `WEB-B-01` | Store guasto distinto da vuoto | P1 | Frontend/UX | M | M3 | [~] |
| `WEB-G-01` | Conteggi dashboard corretti | P2 | Data/Frontend | S | M3 | [x] |
| `OPS-PURPLE-01` | Coverage telemetria distinta da detection | P1 | Detection/QA | M | M2 | [x] |
| `UX-E-01` | Accessibilità e parità IT/EN dimostrate | P1 | Accessibility/I18n/QA | L | M3 | [~] |
| `DEV-E-02` | Modello single-node e soglie scalabilità | P2 | Architect/SRE | L | M4 | [~] |
| `DEV-E-03` | Allocazione ID atomica engagement/finding | P2 | Data/Backend | M | M3 | [x] |
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
- Stato (verifica locale 2026-10-31, resta `[⏸]`): verificato in locale solo il
  layer di isolamento runtime del container (smoke SEC-A dell'immagine nativa, vedi
  D11) e corretto un difetto collegato — i Dockerfile facevano `COPY --chown=0:0`
  senza fissare il mode, così il trust-anchor `/etc/olympus/scanner-runtime.json`
  ereditava 0664 (group-writable) e `require_scanner_isolation()` lo rifiutava;
  aggiunto `RUN chmod 0444` in `docker/Dockerfile` e `docker/Dockerfile.scanners`.
  Il vincolo egress/DNS allo scope (il cuore di SEC-B-01) richiede ancora il test
  negativo con packet-capture in lab autorizzato; a livello applicativo l'enforcement
  dello scope è però dimostrato in locale (2026-10-31): `olympus artemis fingerprint`
  verso target fuori perimetro (`http://127.0.0.1:9999/`, `http://192.0.2.10/`) è
  **bloccato** con `out of scope` ed exit code 3.
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
- Stato (verifica locale 2026-10-31, `[x]`): il controllo esamina il percorso
  originale prima di `resolve()` per la directory scope e per le directory
  finding, baseline e incidenti. Otto casi parametrizzati provano il rifiuto
  di link validi e dangling; directory normali restano accettate
  dalla suite API. Link in componenti parent e sostituzioni concorrenti del
  filesystem restano fuori dal controllo e richiedono directory configurate
  fidate e non modificabili da utenti non attendibili. Il mutation gate
  configurato passa (1.237/2.009 mutanti selezionati uccisi, soglia per funzione
  rispettata).

### SEC-H-02 — Letture FIFO non bloccanti

- Componente/superfici: core.fileio / consumer.
- Problema/evidenza: Primitiva OS riprodotta: open FIFO blocca prima di fstat; fileio.py:65,110.
- Gravità/probabilità/impatto e motivo P1: DoS locale con input speciale; probabilità condizionata, impatto disponibilità alto.
- Soluzione: Aprire senza blocco e verificare descriptor; mantenere no-follow e limiti.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Entrambe le API rifiutano FIFO entro deadline; file normali e link testati.
- Test: subprocess locale con timeout e cleanup.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): `read_regular_bytes` e
  `iter_regular_utf8_lines` aprono con `O_NONBLOCK` dove disponibile, quindi
  `fstat` può rifiutare FIFO senza attendere un writer. Il flag non cambia il
  comportamento delle normali letture di file regolari; `O_NOFOLLOW`, i limiti
  di byte e la validazione del descriptor restano attivi. Due prove in subprocess
  con timeout verificano entrambi i reader; saltate solo sui sistemi senza
  `mkfifo`.

### SEC-D-01 — Redazione argomenti nel log TUI

- Componente/superfici: TUI / core.
- Problema/evidenza: Statica: tui/app.py stampa argv grezzo.
- Gravità/probabilità/impatto e motivo P1: Potenziale esposizione token/URL nel terminale; probabilità condizionata, impatto alto.
- Soluzione: Formatter condiviso redatto senza alterare argv eseguito.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Token sintetici assenti da log e errori; comando riceve argomenti originali.
- Test: pilot TUI e URL/userinfo/query fixtures.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): aggiunto il formatter condiviso
  `redact_arguments` in `core.execution`; maschera valori di opzioni secret,
  credenziali URL e query sensibili senza mutare l'argv passato al processo.
  Il TUI applica anche la sanitizzazione terminale/redazione URL alle righe
  mostrate e agli errori di avvio. Test core e pilot TUI usano token sintetici
  e verificano sia l'assenza nei log sia l'argv originale al subprocess.

### SEC-G-01 — Cancellazione TUI completa

- Componente/superfici: TUI / subprocess.
- Problema/evidenza: Statica: terminate solo figlio immediato, nessun gruppo/cleanup robusto.
- Gravità/probabilità/impatto e motivo P1: Rischio figli sopravvissuti, non riprodotto; impatto alto.
- Soluzione: Lifecycle gruppo processi e terminate/wait/kill bounded multipiattaforma.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Nessun figlio sintetico resta dopo cancel/errore/chiusura.
- Test: processi locali e test Windows/POSIX.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, `[x]` nel perimetro verificato): su POSIX il TUI avvia ogni
  comando in una nuova sessione e invia SIGTERM/SIGKILL all'intero process group;
  annullamento, chiusura schermata ed errore avviano cleanup bounded. Su Windows
  usa un nuovo process group, CTRL_BREAK e `taskkill /T /F` con timeout. Il test
  POSIX locale dimostra la terminazione di un processo e del suo figlio; un
  Testual Pilot chiude l'app durante un comando e verifica la terminazione di
  parent e child. Aggiunto al job Windows portable-smoke un test dedicato che
  usa taskkill `/T /F` e verifica il child; il run Windows portable-smoke
  `41225520765` è passato. Il run successivo ha rivelato che l'uscita dell'App
  non sempre attendeva l'unmount su POSIX: il primo cleanup `on_shutdown` non
  era un hook Textual. Il reap è stato spostato nell'`async on_unmount` di
  `CommandScreen`; CI `41226565373` passa unit e coverage Python 3.11, matrix
  pytest 3.11–3.14, mutation, POSIX e smoke Windows/macOS; il test Windows
  process-tree passa. La DoD SEC-G-01 è soddisfatta per il perimetro testato;
  non si inferisce prova su ogni shell o processo scanner esterno.

### DEV-E-01 — Transizioni Athena concorrenti e audit atomico

- Componente/superfici: Athena / SQLite.
- Problema/evidenza: Statica: transizioni senza CAS; stato e append audit in transazioni separate.
- Gravità/probabilità/impatto e motivo P1: Race o crash può lasciare stato senza audit; rischio dedotto alto.
- Soluzione: CAS sullo stato persistito e unità di lavoro stato+audit; outbox se necessaria.
- Dipendenze/blocchi: SEC-E-01.
- Accettazione misurabile: Due writer non applicano transizioni incompatibili; fault injection non perde audit di stato.
- Test: concorrenza e crash injection.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): transizioni job/assessment
  confrontano lo stato persistito (CAS) e rifiutano writer stantii; il sink
  SQLite scrive stato ed evento audit nella stessa transazione `BEGIN IMMEDIATE`.
  Il coordinator usa questo percorso per start, terminalità, cancel e recovery;
  sink non durevoli mantengono il fallback port-based. Test offline provano due
  writer sulla stessa job, rollback dello stato quando un trigger rifiuta l'audit
  e il flusso coordinator→store con sequenze persistenti. Nessuna race live o
  perdita pregressa viene inferita.

### SEC-E-02 — Verifica digest risultati in lettura

- Componente/superfici: Athena / result store.
- Problema/evidenza: Statica: load_result legge document senza sha256/length salvati.
- Gravità/probabilità/impatto e motivo P1: Corruzione JSON valida non rilevata; probabilità non misurata, impatto alto.
- Soluzione: Verificare digest/lunghezza e binding identity prima del consumo.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Alterazione sintatticamente valida rifiutata; risultato integro leggibile.
- Test: tamper e compatibilità.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): `load_result` confronta byte length,
  SHA-256, result ID derivato e assessment/job identity prima di restituire il
  documento normalizzato; applica anche il limite massimo in lettura. Un test
  altera in SQLite un documento ancora JSON valido e ne verifica il rifiuto.
  Il digest rileva alterazioni dei dati senza aggiornamento coerente dei metadati;
  non è una firma e non protegge da un writer DB che modifica insieme documento,
  digest e lunghezza.

### DEV-B-01 — Plugin concreti e realmente integrati

- Componente/superfici: Themis/Athena/preview/capabilities.
- Problema/evidenza: Dinamica: classe astratta accettata; statica: available_adapters non consumata dal runtime.
- Gravità/probabilità/impatto e motivo P1: Plugin dichiarato integrato non eseguibile; impatto funzionale alto.
- Soluzione: Rifiuto abstract/duplicati; resolver unico, metadata distribuzione/versione; no override native.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Plugin fixture percorre preview/run/capabilities; duplicati/abstract rifiutati prima import quando possibile.
- Test: contract plugin, fake offline; provenienza firmata resta SEC-F.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): resolver condiviso collega adapter
  approvati a preview e runtime; allowlist vuota/non approvata non importa il
  plugin. Duplicati, nomi nativi, classi astratte, identità incoerente, binary
  non semplice e override di `run`/`resolve` sono rifiutati. Fixture offline
  copre `preview_run`, `ThemisApplicationService.run` in simulazione e inventario
  capability. Il report versionato `1.2.0` espone distribuzione/versione e la
  UI Web le rende visibili senza promuovere maturità oltre `catalog-only`.
  Non dimostra firma, sicurezza del pacchetto o readiness production; la firma
  resta in `SEC-F`.

### DEV-D-01 — Versionamento fisico degli store

- Componente/superfici: Athena/engagements/findings.
- Problema/evidenza: Statica: CREATE IF NOT EXISTS; solo job store ha user_version.
- Gravità/probabilità/impatto e motivo P1: Upgrade futuro non controllato; rischio dedotto.
- Soluzione: Versioni fisiche, migrazioni transazionali e rifiuto schema futuro.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Fixture vecchie migrate senza perdita; future rifiutate; rollback documentato.
- Test: upgrade/interruption/restore.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): Athena, engagements e findings
  migrano gli store legacy `user_version=0` allo schema 1 tramite DDL e marker
  nella stessa transazione `BEGIN IMMEDIATE`. Versioni future sono rifiutate;
  failure injection conferma rollback di schema e marker. Fixture legacy con
  righe sintetiche conserva i dati. `ThemisJobStore` aveva già un proprio
  versionamento e non è stato modificato. Il backup/restore coordinato resta
  separato in `WEB-J-01`.

### WEB-J-01 — Backup e restore coordinato

- Componente/superfici: Tutti gli store/evidenze/identità.
- Problema/evidenza: Statica: backup Metis parziale; verify_backup non esegue integrity_check/FK.
- Gravità/probabilità/impatto e motivo P1: Recovery piattaforma non dimostrato; impatto alto.
- Soluzione: Snapshot coerente con digest/versioni, chiavi separate, integrity/FK e restore drill.
- Dipendenze/blocchi: DEV-D-01.
- Accettazione misurabile: Ripristino engagement/job/finding/custody coerente; RPO/RTO misurati su dataset dichiarato.
- Test: backup concorrente, corruzione, restore in directory pulita.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, resta `[~]`): `verify_backup` di Metis ora esegue anche
  `PRAGMA integrity_check` e `foreign_key_check` prima di restituire i conteggi;
  una fixture crea una riga orfana sintetica e verifica il rifiuto. Questo chiude
  solo il controllo del backup Metis. Il backup ora viene costruito in un file
  temporaneo privato, verificato e pubblicato con replace atomico; il restore usa
  una connessione sorgente verificata, verifica anche il database temporaneo e lo
  sostituisce atomicamente solo a fine operazione. Test offline verificano
  round-trip, sostituzione e conservazione della destinazione quando la verifica
  fallisce. `ThemisJobStore` ora offre backup, verifica e restore per il solo
  database job, anche tramite `olympus themis jobs backup`, `verify-backup` e
  `restore`: SQLite online backup, schema v3, integrity/FK, file owner-only e
  destinazione restore nuova e assente. La SHA-256 restituita è un fingerprint
  da registrare separatamente, non un manifest autenticato. Il sidecar lease
  `.requests` e gli store engagements, findings, identity, audit, scope,
  custody/vault restano fuori; il coordinamento globale, manifest versionato e
  restore drill con RPO/RTO restano da realizzare. Nessun backup di piattaforma
  è dichiarato verificato.

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
- Problema/evidenza (baseline 28 ottobre): solo labels.yml; make check locale, nessun lock runtime committato.
- Gravità/probabilità/impatto e motivo P1: Release non automaticamente verificata; impatto alto.
- Soluzione: Workflow least privilege con pin SHA, matrice 3.11–3.14/OS, wheel, test, coverage/mutation, schema/link/security; branch policy verificata.
- Dipendenze/blocchi: runner/repository policy per enforcement remoto.
- Accettazione misurabile: Run remoti verdi sul commit pubblicato e check richiesti; nessuna riduzione soglie.
- **Workflow ripristinato (2026-10-30):** `.github/workflows/ci.yml` reintegrato (revert
  pulito della regressione `58ba209`, autorizzato dall'owner) con i 10 job
  `quality` (ruff/format/mypy strict, richiesto), `tests` (matrice Python
  3.11–3.14), `coverage` (soglia branch ≥75%), `mutation`, `posix-sandbox`,
  `portable-smoke`, `package-smoke` (wheel+SBOM), `native-container`,
  `dependency-audit` (pip-audit), `secret-scan` (gitleaks+SARIF). YAML validato e
  i comandi del job *required* `quality` verificati verdi in locale
  sull'intero repo; ogni script/target referenziato (`check_branch_coverage`,
  `check_audit_exceptions`, `smoke_native_runtime`, `manage_scanner_apparmor`,
  `make test-mutation`/`test-container`) esiste. **Resta da confermare su
  GitHub:** i run `41226565373` del commit `0911d0b` e CodeQL `41226565375`
  sono verdi: qualità, matrix, coverage, mutation, POSIX, Windows/macOS, wheel,
  container, Gitleaks e pip-audit passano. I workflow sul commit successivo
  `17ec9f9` sono in coda. La branch protection che rende `quality` required non
  è verificabile via integrazione GitHub (403).
- Test: CI reale, wheel clean install, container separato. Il 29 ottobre la suite locale manteneva 17 fallimenti sandbox EINVAL/chown. **Aggiornamento 2026-10-31:** rieseguita su host POSIX idoneo (VM Ubuntu 25.10, kernel 6.17, parent privilegiato) → `test-coverage` 3 fallimenti residui (tutti ambiente/privilegi/toolchain, non bug: isolamento container senza runtime marker, `dd` di uutils Rust che va in SIGABRT sul limite, interprete non eseguibile dal `nobody` sotto `/home` 0750), `root_only` 1 passato, suite container 1 passata; Gitleaks (8.30.1) eseguito → 0 leak; hash lock generato e install `--require-hashes` verificato. Firma/attestazioni e matrice CI completa restano aperte.
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
- Stato (verifica locale 2026-10-31, resta `[⏸]`): **riproducibilità dimostrata** —
  due `python -m build --wheel` con `SOURCE_DATE_EPOCH` fisso producono wheel
  **byte-identici** (sha256 `9c98d05e442b187d7b035e1b11b20b56ceae4e9646810d4bd00692d3ad20f570`);
  `gitleaks` (8.30.1) sull'albero: **0 leak**; SBOM CycloneDX e `olympus core lock`
  con install `--require-hashes` verificati (vedi SEC-F-02). Restano: firma/attestazioni
  **Cosign** + registry (D11) e la revisione licenze per versione, non eseguibili senza
  chiavi/registry.

### SEC-F-02 — Chiusura dipendenze SBOM conforme ai marker

- Componente/superfici: core.sbom/core.lockfile.
- Problema/evidenza: Statica: _direct_dependencies interpreta extra con regex, non marker PEP 508 completi.
- Gravità/probabilità/impatto e motivo P1: SBOM/lock possono includere/escludere dipendenze errate; rischio dedotto.
- Soluzione: Parser standard requisiti e propagazione extra transitivi; schema CycloneDX validato.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Marker piattaforma/Python/extra complessi e dipendenze transitive corrispondono installazione.
- Test: unit marker matrix e clean-install closure.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (verifica locale 2026-10-31, `[x]`): corretta la propagazione degli extra
  dichiarati da una dipendenza sul proprio target (`textual` →
  `markdown-it-py[linkify]` → `linkify-it-py`; idem gli extra di `uvicorn[standard]`),
  che prima venivano scartati — la chiusura passa da 36 a 43 pacchetti e
  `pip install --require-hashes -r <lock>` ora installa pulito (prima falliva).
  I marker d'ambiente diversi da `extra` (`python_version`, `sys_platform`, …)
  sono risolti dall'insieme installato (un dep escluso dal marker non è installato
  → non entra nella chiusura), scelta documentata nel modulo per restare solo-stdlib
  senza un valutatore PEP 508 nel percorso caldo. Test: `test_direct_dependencies_marker_matrix`,
  `test_closure_follows_extras_a_dependency_activates_on_its_target` e conformità
  CycloneDX 1.5 (`test_render_sbom_conforms_to_cyclonedx_1_5_structure`). 21/21 verdi,
  ruff+mypy puliti.

### DEV-G-01 — Riconciliazione dichiarazioni e inventario

- Componente/superfici: Docs/README/roadmap/ADR.
- Problema/evidenza: Statica: audit storico, testing, verification-status e roadmap contengono claim CI obsoleti.
- Gravità/probabilità/impatto e motivo P1: Operatori possono confondere codice/test storico con readiness.
- Soluzione: Snapshot attuale distinto; inventario generato, link gate, completare ADR 003–005 e policy mypy coerente.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Nessun claim CI corrente senza run; stati aggiornati e ID tracciabili.
- Test: doc links, confronto registry/documenti e revisione bilingue.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, resta `[~]`): aggiornati i claim CI in `docs/testing.md`
  e `docs/threat-model.md`; lo stato storico in `docs/verification-status.md`
  distingue baseline e verifiche successive. ADR-003/004/005 sono ora documenti
  decisionali collegati nell'indice. Il gate link Markdown è stato aggiunto al
  job `quality`. Verifiche locali: 70 Markdown senza link interni rotti,
  `olympus themis matrix --check` senza drift e Mypy strict su 217 file. Run
  GitHub `41226565373` e CodeQL `41226565375` sul commit `0911d0b` sono verdi;
  la CI ha convalidato il fix del lifecycle TUI su Python 3.11 e tutte le suite
  pytest 3.11–3.14, coverage e mutation. La CI sul successivo commit `17ec9f9`
  è in coda. Il mismatch `/incidents` del run `41225520765` è corretto nel
  manifest di parità. Branch protection non accessibile (API 403); confronto
  bilingue end-to-end ancora aperto.

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
- Stato (2026-10-31, `[x]`): implementato. **Server** (`web.py` `/jobs/{id}/events`):
  ogni evento `state` porta ora `id: <stato>` più un hint `retry: 1000`, e la route
  legge `Last-Event-ID` per riprendere dallo stato già consegnato senza
  ripeterlo (una transizione persa nel frattempo viene comunque emessa al tick
  successivo). **Client** (`app.js`): `onerror` non chiude più lo stream — lascia
  riconnettere `EventSource` (che rinvia `Last-Event-ID`) e mostra uno stato
  visibile "riconnessione in corso…" in un elemento `role="status"
  aria-live="polite"` (anche a beneficio di UX-E-01). Test: `test_themis_web.py`
  verifica l'emissione di `id:`/`retry:` e la ripresa con `Last-Event-ID` senza
  replay (86/86 verdi); web app avviata e verificata nel browser integrato
  (login accessibile con skip-link/landmark, dashboard funzionante).
### WEB-B-01 — Store guasto distinto da vuoto

- Componente/superfici: Web engagement/dashboard.
- Problema/evidenza: Statica: eccezioni convertite in [] o widget omessi.
- Gravità/probabilità/impatto e motivo P1: Guasti mascherati da assenza dati; impatto decisionale alto.
- Soluzione: Stati unavailable/not-configured/empty distinti con errori redatti.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Store corrotto non mostra onboarding vuoto; widget non disponibili espliciti.
- Test: TestClient negativo e browser.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, resta `[~]`): elenco engagements distingue store non
  configurato, vuoto e illeggibile/corrotto; le form Assessment e Smart Scan
  mostrano un avviso quando non possono verificare gli engagement. TestClient
  copre store configurato vuoto e DB SQLite corrotto. Dashboard, al 31 ottobre,
  segnala findings e incident store illeggibili senza mostrare conteggi falsi;
  fixture corrotta per entrambi. Il catalogo read-only `/incidents`, gated da
  `incidents:read`, ora distingue non configurato/vuoto/illeggibile e usa i
  documenti Minerva canonici. Nuovi test TestClient iniettano `PermissionError` e `RuntimeError`
  durante `Path.resolve()` di entrambi gli store: dashboard espone lo stato
  unavailable e non rivela il dettaglio del percorso. La
  revisione browser è stata tentata il 31 ottobre 2026, ma il browser collegato
  non raggiunge il server loopback del workspace (`ERR_CONNECTION_REFUSED`);
  il server non è stato esposto in rete e il DoD browser resta aperto.

### WEB-G-01 — Conteggi dashboard corretti

- Componente/superfici: Web/store.
- Problema/evidenza: Statica: list(limit=200) etichettata jobs total.
- Gravità/probabilità/impatto e motivo P2: Conteggi parziali fuorvianti con più job.
- Soluzione: Aggregati SQL o etichetta finestra esplicita, nessuna omissione job attivi.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Fixture >200 job produce totali veri o finestra chiaramente dichiarata.
- Test: integrazione dashboard.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, `[x]`): la dashboard usa un aggregato SQLite per
  stato sull'intera tabella; totale, istogramma e progresso non dipendono dalla
  finestra di 200 job recenti. Fixture con 205 job verifica il totale e la
  coda esatti, mentre gli ultimi job mostrati restano limitati per la UI.

### OPS-PURPLE-01 — Coverage telemetria distinta da detection

- Componente/superfici: Apollo/Athena/Purple.
- Problema/evidenza: Dinamica: dict solo event_type accettato e JSON malformato ignorato.
- Gravità/probabilità/impatto e motivo P1: Falsa fiducia copertura; impatto alto.
- Soluzione: Validare Event, contare scarti/troncamento; distinguere presence/schema/match/test pass.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Input invalidi non covered; test detection lega atteso/osservato e FP.
- Test: contratti negativi e regressione regole; lab D8 separato.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, `[x]`): NDJSON di telemetria viene validato con il
  modello `Event`; input non valido viene contato come rejected, il limite righe
  espone `truncated`, e il report dichiara `telemetry_input.status=partial`.
  `--strict` restituisce un exit code non-zero se l'input è parziale, anche se
  i tipi validi rendono alcune tecniche covered. Fixture sintetiche coprono
  evento valido, record incompleto, JSON malformato e troncamento; test regole
  Red/Blue coprono evento atteso e variante benigna. Il test Purple live D8 resta
  separato e non è stato eseguito.

### UX-E-01 — Accessibilità e parità IT/EN dimostrate

- Componente/superfici: TUI/Web/docs.
- Problema/evidenza: Statica: lang=en/stringhe EN; TestClient non browser; live region assente.
- Gravità/probabilità/impatto e motivo P1: Fruibilità non dimostrata, impatto utenti alto.
- Soluzione: Cataloghi IT/EN, tastiera/focus/live region, browser axe e review screen reader/contrasto.
- Dipendenze/blocchi: nessuna.
- Accettazione misurabile: Flussi critici in due lingue; zero issue critiche automatiche e checklist manuale registrata.
- Test: browser/keyboard/screen reader; nessuna certificazione presunta.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (audit locale 2026-10-31, `[~]`): web app avviata e ispezionata nel
  browser integrato. Positivi: `lang="en"`, `<title>` per pagina, landmark
  completi (banner/nav/main/contentinfo), skip-link funzionante, gerarchia heading
  senza salti (h1→h2), **contrasto testo 15.53:1 (AAA)**, nessun input senza label
  né pulsante/link senza nome accessibile. Corretti/aggiunti: indicatore di focus
  **esplicito** `:focus-visible` (WCAG 2.4.7) in `app.css` — prima solo lo
  skip-link aveva uno stile di focus — e la live region `role="status"
  aria-live="polite"` per lo stato SSE (vedi WEB-A-01). Resta per il `[x]`: parità
  catalogo IT/EN dimostrata e una review manuale con screen reader su tutti i
  flussi (non automatizzabile).
### DEV-E-02 — Modello single-node e soglie scalabilità

- Componente/superfici: Web sessioni/rate limit/SQLite.
- Problema/evidenza: Statica: chiave sessione e rate limiter locali al processo.
- Gravità/probabilità/impatto e motivo P2: Multiworker incoerente; rischio dedotto.
- Soluzione: Documentare single-worker; misurare p95/lock/errori prima di session store/Postgres.
- Dipendenze/blocchi: DEV-E-01.
- Accettazione misurabile: Carico dichiarato e SLO misurati; migrare solo se SQLite viola budget riproducibile.
- Test: load/recovery/multiworker.
- DoD/owner/taglia/milestone: tabella e campi comuni sopra; evidenza in [audit](docs/ecosystem-audit.md).
- Stato (31 ottobre 2026, resta `[~]`): documentato il limite one-process per
  API/Web (`RateLimiter` in-process e secret sessione generato all'avvio); i job
  SQLite restano coordinati fra worker e soggetti al cap persistente. Benchmark
  sintetico standard, singolo processo, 250 job e cinque campioni: mediana
  1,684 s, worst 1,779 s, CPU mediana 1,010 s, allocazione tracciata 0,019 MiB.
  Harness multiprocesso aggiunto: tre run offline, 4 writer × 50 job per run,
  200/200 job persistiti e zero errori SQLite; p95 per submit 11,328/10,674/
  17,992 ms sullo stesso host (Linux 6.18.57, Python 3.12.14). È diagnostico
  del solo store SQLite, non p95 Web né SLO. Mancano workload HTTP dichiarato,
  p95 delle richieste Web, recovery e prove su host/volume rappresentativi; nessuna
  decisione di migrazione è supportata dai soli numeri locali.

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
- **Fatto (2026-10-30):** `SqliteEngagementStore.create_next` e
  `SqliteFindingTransitionStore.append_next` allocano l'id (SELECT del massimo) e
  inseriscono **nella stessa transazione**, con retry limitato sul vincolo di
  chiave primaria: due writer in gara sullo stesso progressivo non possono
  riuscire entrambi — il perdente colpisce il vincolo UNIQUE, ricalcola sul record
  ormai committato e prende l'id successivo — quindi ciascuno ottiene un id
  distinto senza record persi né errore duplicato affiorante. I tre chiamanti
  (`engagement create` CLI, `vulcan transition` CLI, gestore transizioni Web)
  usano ora i metodi atomici invece di `next_*_id`+`create/append` separati; i
  primitivi insert-only restano come ultima linea di difesa. Contratti ID
  (`ENG-YYYY-NNNNN`, `FTR-YYYY-NNNNN`) invariati. Test di concorrenza con 8 writer
  sincronizzati (barrier) in `tests/unit/test_engagements.py` e
  `tests/unit/test_finding_transitions.py`: tutti gli id distinti, tutti persistiti,
  zero errori.
- DoD: criteri e campi comuni, test/documentazione, commit e verifica remota; stato `[x]`. Link: [audit](docs/ecosystem-audit.md).

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
| 0 | Baseline e coerenza documentale | `[~]` | `DEV-G` `[~]`, `DEV-H` `[~]`, `DEV-C` `[~]` (gate locali via `make check`; workflow CI ripristinato 2026-10-30 → enforcement remoto da confermare su GitHub) |
| 1 | Security hardening (**P0**) | `[~]` | `SEC-A`, `SEC-B`, `SEC-C`, `SEC-H`, `UX-B` |
| 2 | Architettura e qualità di release | `[~]` | `DEV-A`, `DEV-B`, `DEV-C`, `DEV-D`, `DEV-E`, `SEC-F` |
| 3 | UX operativa bilingue | `[ ]` | `UX-A`, `UX-C`, `UX-D`, `UX-E`, `UX-F`, `UX-G` |
| 4 | Capability Red/Blue/Purple | `[~]` | `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE`, `OPS-SCAN` |
| 5 | Production readiness scanner | `[ ]` | `D1`, `D2` |
| 6 | Distribuzione e osservabilità | `[~]` | `DEV-E`, `DEV-F`, `SEC-F` |
| 7 | Rename Themis + Web control plane | `[~]` | `DEV-I` ✓, `WEB-A` ✓, `WEB-B` ✓, `WEB-C` ✓, `WEB-D` ✓, `WEB-E` ✓, `WEB-F` ✓, `WEB-G`…`WEB-J` |
| 8 | Comunicazione, adozione e vetrina pubblica | `[ ]` | `COMM-A`, `COMM-B`, `COMM-C`, `COMM-D`, `COMM-E` |

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
- [~] generatori SBOM/hash lock e comandi audit presenti; `SEC-F-02` (chiusura con extra transitivi) corretto e `pip install --require-hashes` del lock verificato in locale il 2026-10-31; workflow CI ripristinato (`DEV-C-01`), enforcement remoto e firma/attestazioni (`SEC-F-01`) da confermare su GitHub;
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
| Supply chain | SBOM, hash lock, audit dipendenze, secret scan e workflow SAST CodeQL | mancano attestazioni di build e firma immagini/release; CodeQL va reso check *required* via branch protection per essere bloccante |
| Qualità (baseline audit 28 ottobre) | Ruff/Mypy/test/schema/coverage/mutation sono comandi locali; matrice dichiarata 3.11–3.14 non rieseguita nell'audit | CI qualità assente alla baseline; workflow ripristinato il 30 ottobre. Container/live lab opt-in presenti ma non eseguiti |
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
| M1 Fondamenta | base stabile e coerente | 🟡 `DEV-I` ✅, `SEC-A` ✅, suite/coverage ✅ (gate locali via `make check`; workflow CI ripristinato 2026-10-30 → enforcement remoto da confermare) | `DEV-G`,`DEV-H`,`DEV-C` | **ripristinare un workflow CI** (link checker/gate verdi su push/PR); 0 import runtime da `vendor/` |
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
Le menzioni di job CI precedenti alla rimozione e al ripristino del workflow non
sono stato corrente: vedere DEV-C-01 e verification-status. I criteri di
accettazione restano requisiti, non prove di esecuzione.


### Stato di sicurezza attuale

Non è stato rilevato hardcoding di API key o password nel codice first-party
analizzato. `src/olympus/core/config.py` carica impostazioni da TOML e variabili
d'ambiente; i moduli che richiedono token usano variabili dedicate. Il comando locale Gitleaks è disponibile quando il binario è installato.
Il workflow qualità è presente dal 30 ottobre; green run e enforcement tramite
branch protection non sono verificati (`DEV-C-01`). Scansione working
tree/history e canary non sono gate CI configurati.

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
lo associa ai container e prova sia `/proc/self/attr/current`…22990 tokens truncated…rict/bounded della CLI; fonti non configurate degradano
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
  **Emissione automatica sulla chiusura job fatta (2026-10-30):** il worker
  nativo Themis emette ora una notifica redatta a ogni job **terminale**.
  `themis/runtime.notification_from_themis_job` mappa il `ThemisJob` nativo sul
  contratto `olympus.notification` (testo via `safe_terminal_text`+`redact_text`,
  errore via `redact_error`, label via `redact_mapping`: nessun controllo di
  terminale forgiato né segreto in chiaro) e `job_notifier(dispatcher, also=…)`
  avvolge il callback `on_job` del loop `work_queue` — dispatch **solo** sugli
  stati terminali (un retry rimesso in coda è saltato), delivery mai sollevata e
  comunque isolata così un problema di notifica non può bloccare il worker.
  Esposto su `olympus themis workers --notify-webhook … [--notify-email-to … /
  --notify-email-from … / --notify-smtp-host …]`, **spento di default** (nessun
  canale → nessuna chiamata di rete; resta solo l'output JSON per job); stessa
  costruzione SSRF-safe del canale webhook di `vulcan notify`. Test
  `tests/unit/test_themis_runtime.py` (builder redatto e control-safe, redazione
  del segreto-URL nell'errore, dispatch solo terminale, un sink che solleva non
  propaga). **Emissione per-finding fatta (2026-10-30):** con
  `--notify-finding-severity <sev>` il worker emette anche una notifica redatta
  **per finding** del job al di sopra della soglia, riusando
  `notification_from_finding`; `themis/runtime.finding_notifications` legge i
  finding dal documento di risultato del job, filtra per severità, ordina
  dal più grave e **limita** il numero (`MAX_FINDING_NOTIFICATIONS`) così una
  scansione rumorosa non può inondare il sink, saltando in modo difensivo i
  record malformati (mai sollevato). Senza la soglia resta la sola notifica di
  job. Test aggiuntivi in `tests/unit/test_themis_runtime.py` (filtro+ordine+skip,
  cap, assenza di risultato, job+finding vs solo-job). **`Iris` completo per il
  percorso worker** (job e finding); l'emissione da API/Web sullo stesso port
  resta un'estensione futura non bloccante.

**Criterio di completamento (soddisfatto):** un operatore confronta due assessment
e riceve una notifica redatta alla chiusura di un job (e, se richiesto, per i
finding sopra soglia), senza logica di report duplicata — lo stesso port Iris è
usato dal `vulcan notify` manuale e dal worker automatico.

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
- [x] Rendere visibile la provenienza degli enrichment KEV/EPSS e la loro data.
  **Fatto (2026-10-30):** `vulcan/enrichment` espone `CatalogProvenance` e le
  funzioni pure `kev_catalog_provenance` (sorgente «CISA KEV», `catalogVersion`,
  `dateReleased`) ed `epss_response_provenance` (sorgente «FIRST EPSS», data del
  modello condivisa dalle righe, vuota se non concordano — mai inventata; JSON
  malformato → `EnrichmentError`). `olympus vulcan enrich` stampa ora, per ogni
  feed locale usato, una riga di provenienza redatta (sorgente, versione, data),
  e una riga «fetched live» nel percorso `--fetch`, così un feed KEV/EPSS stantio
  non viene scambiato per aggiornato. L'overlay (contratto lista) resta invariato
  — la provenienza è additiva. Test `tests/unit/test_vulcan_enrichment.py`
  (versione+data KEV, assenza non inventata, EPSS data singola vs discordante,
  JSON malformato).

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

## 📣 Prospettiva Comunicazione & Adozione (Vetrina pubblica)

Olympus è tecnicamente solido, ma la sua forza non è ancora *visibile* all'esterno.
Questa prospettiva porta il progetto da "forte sul codice" a "trovato, provato,
citato e installabile", **senza mai allentare i guardrail**: ogni artefatto
pubblico (sito, report, Action, demo) ribadisce scope e autorizzazione, non invita
all'uso non autorizzato e non sovrastima la maturità delle capability. Nessun
target reale e nessun dato reale: la vetrina usa esclusivamente il lab locale
autorizzato (`labs/mars/`) e dati fittizi/sintetici. Gli ID sono `COMM-*`.

### Intervento A · `COMM-A` — Sito di documentazione pubblico bilingue (**P2**)

- [ ] Generare da `docs/` un sito statico brandizzato (es. Astro Starlight o MkDocs
  Material), IT/EN, con quickstart, architettura, threat model, scanner-maturity e
  galleria; deploy su Pages/Vercel con build in CI, mantenendo `docs/` come unica
  fonte della verità (nessuna divergenza dal repo).
- [ ] Ricerca, navigazione e versioni; link canonici dal README e dal sito personale.
- [ ] SEO di base (sitemap, meta description, OpenGraph) sulle pagine ad alto intento.

**Criterio di completamento:** la documentazione esistente è navigabile come sito
pubblico, rigenerata in CI dalla stessa fonte `docs/`, senza divergere dal codice.

### Intervento B · `COMM-B` — Report di esempio pubblico da lab autorizzato (**P1/P2**)

- [ ] Eseguire la catena `recon → scan → enrich → report` end-to-end **solo** contro
  `labs/mars/` (doppio opt-in, `make test-live-lab`) e pubblicare un **report di
  esempio** (PDF/HTML Vulcan) versionato e redatto, con metodologia, executive
  summary, finding → impatto → remediation ed evidenze.
- [ ] Marcare chiaramente l'origine (lab sintetico autorizzato), senza alcun target
  reale; nessun segreto o dato personale negli artifact (DoD punto 6).
- [ ] Collegare il report da README e sito come dimostrazione dell'output professionale.

**Criterio di completamento:** esiste un report pubblico riproducibile dal lab che
mostra la qualità del deliverable senza esporre bersagli reali né invitare all'uso
non autorizzato.

### Intervento C · `COMM-C` — Distribuzione a basso attrito (**P2**)

- [ ] Completare la pubblicazione su **PyPI** via Trusted Publishing (aggancia
  `DEV-F`/`SEC-F`): `pipx install olympus-security`, badge versione e quickstart
  verificato.
- [ ] Pubblicare una **GitHub Action** riutilizzabile che esegua di default solo
  capability **passive e scope-safe** (es. secret scan Hermes, `core sbom`, recon
  passivo Argus su domini dichiarati), con scope e `--i-am-authorized` obbligatori
  per qualunque operazione attiva e nessun default pericoloso.
- [ ] Documentare l'uso in CI e pubblicare l'Action nel Marketplace.

**Criterio di completamento:** un utente installa Olympus con un comando e lo usa in
CI tramite un'Action che non espone alcuna operazione attiva senza scope e
autorizzazione espliciti.

### Intervento D · `COMM-D` — Onboarding e asset visivi (**P2/P3**)

- [ ] README con **asciinema/GIF** del percorso `recon → assessment → report`,
  screenshot della TUI e diagramma architettura coerente con la Prospettiva Designer.
- [ ] "good first issue", esempi copiabili e guida al primo contributo (riuso di
  `CONTRIBUTING.md`).

**Criterio di completamento:** un nuovo visitatore capisce in meno di un minuto cosa
fa Olympus e come iniziare, dal solo README.

### Intervento E · `COMM-E` — Plugin SDK e plugin di esempio (**P3**)

- [ ] Documentare e stabilizzare il **plugin SDK** (aggancia `adr-004`) e pubblicare
  un **plugin di esempio** in un repository separato, con contract test, come
  riferimento per i contributi esterni.

**Criterio di completamento:** un terzo può scrivere un plugin seguendo l'SDK
documentato e il plugin di esempio, senza modificare il core.

**Criterio di completamento (Comunicazione & Adozione):** ogni artefatto pubblico è
riproducibile dalla stessa fonte del repo, ribadisce scope e autorizzazione, non usa
né target né dati reali, e converte il visitatore in utente o contributore senza
sovrastimare la maturità delle capability.

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
- [x] **Profili Light/Deep.** Introdurre profili di scansione nominati che
  generano il piano Athena, come il Light/Deep scan della suite: `light` passivo e
  veloce (recon + header + TLS, nessuna autenticazione), `deep` completo
  (aggiunge gli adapter attivi AEGIS). Ispezionabili e senza target predefiniti.
  **Fatto:** `athena/application/profiles.py` definisce `ScanProfile` e i due
  preset — `light` (`dns`, `web-headers`, `whois`: solo lookup passivi e un
  singolo fetch di header non autenticato, nessuna autenticazione) e `deep`
  (`light` + `themis`, il passo di scansione attiva AEGIS). Un profilo **non
  porta target propri** (descrive il *come*, non il *cosa*): `build_plan`
  trasforma gli input di ingaggio (target, scope, autorizzazione) in un
  `AssessmentPlan` validato, e `--confirm` è obbligatorio — un profilo non
  auto-autorizza mai un run. La distinzione attivo/passivo poggia sul registry
  (`active_adapters()` → `{themis}`), con invariante verificato a import:
  `light` non contiene adapter attivi, `deep` è un soprainsieme stretto di
  `light`. CLI `olympus athena profiles` (ispezione: adapter, attivo/passivo,
  limiti) e `olympus athena plan from-profile <light|deep> --engagement …
  --approval … --target kind:value --allowed-domain … --confirm [--name]
  [--report-format] [--output]` (il piano generato ri-valida con `athena plan
  validate` e gira con `athena run`). Test `tests/unit/test_athena_profiles.py`
  (motore: invarianti, `build_plan`, rifiuto autorizzazione non confermata e
  scope vuoto) e `tests/integration/test_athena_cli.py` (round-trip
  genera→valida, rifiuto senza `--confirm`, profilo ignoto, target malformato).
  Doc [`docs/professional-platform.md`](docs/professional-platform.md) (sezione
  «Scan profiles») e quickstart README IT/EN; `docs/cli-reference.md` rigenerato.
- [x] **Catalogo capability allineato.** Mappare esplicitamente ogni capacità
  della suite (Website/Network/SSL/CMS scanner, Port Scanner, Subdomain/Domain
  Finder, Password Auditor) sui moduli Olympus esistenti o mancanti, così il
  `catalog` dichiara cosa c'è, cosa è simulato e cosa manca, senza sovrastimare.
  **Fatto:** `integrations/suite_catalog.py` dichiara le 8 capacità della suite
  mappandole su moduli/engine Olympus, con stato di copertura in tre valori
  **derivati, mai asseriti**: `present` (engine con parser provato su output
  reale, maturity ≥ `offline-tested`, oppure modulo first-party con test
  committati), `simulated` (adapter registrato `adapter-ready` ma parser non
  ancora provato → onesto solo in simulazione) e `missing` (nessuna copertura
  oltre, al più, una voce di catalogo). La derivazione poggia sul maturity ledger
  (`integrations/maturity.record_for`) per gli engine e sull'esistenza di test
  committati per le capacità native, così non può gonfiarsi in marketing. Esito
  onesto attuale: **present** website (nuclei/sqlmap/… live-tested) + Artemis,
  ssl (testssl offline-tested), port (nmap live-tested), subdomain (Argus CT
  nativo), domain (Argus DNS/WHOIS nativo); **missing** network-vuln
  (nessus/openvas solo catalogati), cms (wpscan solo catalogato; whatweb copre la
  sola *detection*), password-auditor (nessun modulo). `verify_catalog()`
  ri-deriva ciò che il repo può dimostrare (ogni engine esiste nel registry; ogni
  evidenza nativa esiste) e un test asserisce lista vuota, come il ledger di
  maturity. CLI `olympus catalog` (documento versionato
  `olympus.suite-capability-catalog` 1.0.0 con istogramma di copertura). Test
  `tests/unit/test_suite_catalog.py` (gate di onestà, stati noti, ramo
  `simulated`, evidenza nativa mancante, CLI). Doc
  [`docs/professional-platform.md`](docs/professional-platform.md) («Capability
  alignment»); `docs/cli-reference.md` rigenerato.
- [x] **Report template e sommario esecutivo riusabile.** Sezioni riusabili
  (scope, metodologia, disclaimer, executive summary) parametrizzate
  dall'engagement manifest (`SEC-C`), per report ripetibili tra ingaggi.
  **Fatto:** `vulcan/engagement_report.py` estrae da un `EngagementManifest`
  (firmato o semplice) un `EngagementReportContext` di soli dati di
  visualizzazione; `vulcan/report.py` rende quattro sezioni riusabili subito
  dopo i conteggi, in Markdown e HTML e in entrambe le slice `full`/`executive`:
  **Scope** (client, contratto, autorizzatore/owner, finestra di validità,
  pattern in/out-of-scope, limiti targets/concurrency/runtime), **Methodology**
  (tecniche autorizzate dal manifest, esercitate solo entro scope e finestra),
  **Disclaimer** (riservatezza + testing autorizzato, parametrizzato con
  client/approver/contratto/finestra) ed **Executive summary** (paragrafo
  guidato dai conteggi: asset valutati, finding per severità, presenza di
  high/critical). Essendo proprietà dell'ingaggio, le sezioni restano identiche
  tra report dello stesso ingaggio e cambiano solo col manifest, quindi i report
  sono ripetibili tra ingaggi. Costruire le sezioni **non** è una decisione di
  autorizzazione (nessuna firma verificata qui): la provenance verificata resta
  `--signed-manifest`/`--manifest-public-key`. Ogni valore derivato dal manifest
  è ripulito da sequenze di controllo ed escapato Markdown/HTML (`SEC-H`); senza
  `--manifest` il report è invariato (aggiunta puramente additiva). CLI `olympus
  vulcan report --manifest <engagement-manifest.json>` (accetta forma semplice o
  firmata). Test `tests/unit/test_vulcan_engagement_report.py` (motore: estrazione,
  sezioni, executive con/senza finding, neutralizzazione ANSI/metacaratteri,
  slice executive) e CLI in `tests/unit/test_vulcan.py` (manifest semplice,
  firmato, malformato). Doc [`docs/vulcan.md`](docs/vulcan.md) («Reusable report
  sections»); `docs/cli-reference.md` rigenerato.
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
  Nota (verifica locale 2026-10-31): ciclo purple eseguito contro il range
  autorizzato **Mars** (solo 127.0.0.1, dati sintetici). Lato red gli adapter web
  **Artemis** (`fingerprint` → nginx/PHP, `content` → 3 esposizioni, `xss` → 1,
  `metabase` → CVE-2026-72898) hanno prodotto finding reali con enforcement dello
  scope; lato blue **Apollo** rileva **7 alert** dalla traccia sintetica. Corretto
  inoltre `labs/mars/target/mars-post-exploitation.ndjson`, privo dei campi
  contratto `event_id`/`observed_at`, per cui `olympus apollo run` documentato dava
  0 alert (il test d'integrazione passava usando un loader proprio). `testssl`/
  `whatweb`/Wapiti (scanner di rete) restano da `live-tested` su target dedicati.
  Lavoro locale 2026-10-31 su rete privata UTM (`192.168.64.0/24`, target Mars su
  `192.168.64.10`). Gate verificati (entrambi by design): (1) autorizzazione —
  `olympus themis run` rifiuta senza `--lab-policy`/manifest; con **lab-policy
  firmata** (`OLYMPUS_POLICY_LAB_KEY`; rete privata eleggibile — il loopback è
  *escluso*) passa; (2) isolamento — `require_scanner_isolation()` rifiuta fuori
  dal container hardened. `Dockerfile.scanners` **include già** whatweb (apt),
  testssl.sh (git) e wapiti (pip). Durante il tentativo di eseguirli **dentro**
  l'immagine hardened sono emersi e **corretti due difetti reali**:
  (a) l'immagine **non si costruiva** su Debian attuale perché un'unica
  `apt-get install` includeva `nikto` (non più nei repo) e abortiva tutta la build,
  contro il commento "best-effort" del file → ora toolchain strict + scanner apt
  tolleranti; (b) dentro l'immagine **olympus non si importava**
  (`typing_extensions 4.10` retrocesso da un pip scanner vs `pydantic_core`) → ora
  si ripristina `typing_extensions>=4.13` in coda, con uno smoke di build
  `import olympus, pydantic_core` che fa fallire la build se la closure si rompe.
  Dopo i fix l'immagine builda e olympus gira; l'esecuzione live manuale via
  `docker run` incontra però una tensione **inerente** (non un bug): la scratch dir
  del sandbox richiede `chown`/`setuid` (CAP_CHOWN/SETUID) mentre
  `require_scanner_isolation` esige `capabilities_empty` (`--cap-drop ALL`) — i due
  non si soddisfano insieme a mano. La promozione a `live-tested` richiede quindi
  l'orchestrazione **compose worker** (`docker-compose.scanners.yml`: scratch
  pre-provisionata e set cap/utente corretto), non un `docker run` manuale.
- [ ] **(D4)** Adapter recon ProjectDiscovery/OSINT verificati su sorgenti/fixture reali.
- [ ] **(D5)** `nosqlmap` e `wpscan` contro target NoSQL/WordPress controllati (token via SecretProvider).
- [ ] **(D6)** Exploitation orchestration (Metasploit RPC) con `msfrpcd` isolato e allowlist moduli.
- [ ] **(D7)** Proteus simulated delivery in lab chiuso con identità sintetiche.
- [ ] **(D8)** Detection loop con Atomic Red Team su endpoint di test ripristinabile.
- [ ] **(D9)** Connettori SIEM/EDR (Splunk HEC, Elastic, Microsoft) su endpoint dev dedicati.
- [ ] **(D10)** CTI live (TAXII 2.1, MISP, OpenCTI) contro istanze di test.
- [ ] **(D11)** Firma container **Cosign** contro un registry + hardening seccomp/AppArmor.
  Nota firma (verifica locale 2026-10-31): flusso **Cosign** dimostrato end-to-end —
  `cosign` 2.5.0 su VM, registry locale `registry:2`, immagine nativa pushata e
  **firmata+verificata** per digest (`cosign verify` → "signatures verified against
  the specified public key", claims validati). Usa **chiavi di test** (non chiavi di
  release) e un registry locale; la release reale userà chiavi dell'organizzazione,
  un registry ufficiale ed eventualmente firma keyless OIDC. Box non flippato finché
  non è nella pipeline CI con chiavi reali.
  Nota hardening (verifica locale 2026-10-31): lo smoke di isolamento dell'immagine nativa
  (`make test-container`: `--network none --read-only --cap-drop ALL
  --no-new-privileges --seccomp`, negazione di `process_vm_readv`, escape probe)
  passa su VM Linux dopo aver corretto il mode del trust-anchor
  `/etc/olympus/scanner-runtime.json` nei Dockerfile (vedi SEC-B-01); la firma
  Cosign + registry resta da fare.
- [ ] **(D12)** Release multi-platform sulla matrice OS/Python dei runner CI.
  Nota (verifica locale 2026-10-31): eseguite due celle della matrice —
  macOS 15/arm64 + CPython 3.14 e Ubuntu 25.10/aarch64 + CPython 3.13
  (lint/format/mypy/schema/audit verdi; suite verde salvo i casi sandbox
  Linux-privilegiati). Matrice completa sui runner CI ancora da fare.
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

### Fase 8 — Comunicazione, adozione e vetrina pubblica (trasversale, continua)

- [ ] Pubblicare il sito docs bilingue da `docs/` con build in CI (`COMM-A`).
- [ ] Generare e pubblicare il report di esempio dal lab autorizzato `labs/mars/` (`COMM-B`).
- [ ] Completare la distribuzione PyPI e una GitHub Action scope-safe (`COMM-C`, aggancio `DEV-F`/`SEC-F`).
- [ ] Rifinire README e onboarding con asciinema, screenshot e diagramma (`COMM-D`).
- [ ] Stabilizzare e documentare il plugin SDK con un plugin di esempio (`COMM-E`).

**Exit gate:** Olympus è installabile con un comando, documentato come sito pubblico,
dimostrato da un report di lab riproducibile e utilizzabile in CI, senza che alcun
materiale pubblico inviti all'uso non autorizzato o sovrastimi le capability.

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
| 11 | Report di esempio da lab + sito docs pubblico (`COMM-B`, `COMM-A`) | Comunicazione + Cybersecurity | Lab autorizzato + `docs/` coerente |
| 12 | Distribuzione PyPI/Action, onboarding e plugin SDK (`COMM-C`, `COMM-D`, `COMM-E`) | Comunicazione + Development | Release firmata (`DEV-F`/`SEC-F`) e SDK (`adr-004`) |

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
| Sito di documentazione pubblico | assente | pubblicato e linkato, rigenerato in CI | workflow Pages/Vercel (`COMM-A`) |
| Pacchetto installabile da PyPI | assente | `pipx install olympus-security` | PyPI + Trusted Publishing (`COMM-C`/`SEC-F`) |
| GitHub Action pubblicata | assente | nel Marketplace, passiva/scope-safe di default | repo Action + README (`COMM-C`) |

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
| Materiale di vetrina (sito/report/Action) interpretato come invito all'uso non autorizzato | Media | Alto | scope e autorizzazione ribaditi ovunque, report solo da `labs/mars`, Action passiva di default, nessun target reale (`COMM-A`–`COMM-C`) |
| Dipendenza da hosting esterni per la vetrina pubblica | Bassa | Basso | sito statico riproducibile e rigenerato in CI dalla fonte `docs/` (`COMM-A`) |

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

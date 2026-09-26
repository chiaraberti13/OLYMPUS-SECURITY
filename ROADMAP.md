# 🏛️ OLYMPUS-SECURITY Roadmap

> **Obiettivo:** consolidare Olympus come piattaforma Red/Blue/Purple Team sicura,
> verificabile, distribuibile e usabile in contesti professionali autorizzati.
>
> **Stato rilevato:** analisi del branch `main` effettuata il 24 settembre 2026.
> Le priorità qui indicate sono basate sul codice e sulla documentazione realmente
> presenti nel repository, non sulla precedente versione monolitica `OLYMPUS.py`.

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
  registro storico dei cicli di integrazione ARGUS/VAP e non va usato per
  pianificare nuove attività.
- Una casella passa a `[x]` solo rispettando la
  [Definition of Done trasversale](#definition-of-done-trasversale); un `[~]` deve
  sempre indicare, nella stessa voce, cosa manca.
- Un intervento `[⏸]` indica il prerequisito di sblocco nella tabella
  [Prerequisiti per le attività differite](#prerequisiti-per-le-attività-differite).

### Cruscotto di avanzamento

| Fase | Focus | Stato | Interventi principali |
| --- | --- | --- | --- |
| 0 | Baseline e coerenza documentale | `[~]` | `DEV-G`, `DEV-H`, `DEV-C` (suite e coverage) |
| 1 | Security hardening (**P0**) | `[ ]` | `SEC-A`, `SEC-B`, `SEC-C`, `SEC-H`, `UX-B` |
| 2 | Architettura e qualità di release | `[ ]` | `DEV-A`, `DEV-B`, `DEV-C`, `DEV-D`, `SEC-F` |
| 3 | UX operativa bilingue | `[ ]` | `UX-A`, `UX-C`, `UX-D`, `UX-E`, `UX-F`, `UX-G` |
| 4 | Capability Red/Blue/Purple | `[~]` | `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE` |
| 5 | Production readiness scanner | `[ ]` | `D1`, `D2` |
| 6 | Distribuzione e osservabilità | `[ ]` | `DEV-E`, `DEV-F`, `SEC-F` |

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
- [x] SBOM CycloneDX, lockfile con hash, `pip-audit` e `gitleaks` bloccanti in CI;
- [x] wheel buildata e installata in ambiente pulito durante la pipeline;
- [x] test offline e ledger di maturità per non sovrastimare gli adapter scanner.

La roadmap non deve quindi riproporre attività già concluse come “modularizzare lo
script” o “spostare le API key in variabili d'ambiente”. Deve portare la piattaforma
dallo stato attuale — ampio e tecnicamente promettente, ma con alcuni componenti
legacy e nessun adapter dichiarato `production-ready` — a un prodotto con confini
di sicurezza forti, release riproducibili e flussi operativi comprensibili.

### Evidenze e gap principali rilevati

| Area | Evidenza nel repository | Gap da chiudere |
| --- | --- | --- |
| Architettura | `src/olympus/` contiene moduli separati e un contratto dati comune | `aegis serve`, `migrate` e `workers` dipendono ancora dal VAP in `vendor/` |
| Sicurezza runtime | `core.execution`, `core.http`, `core.pinning`, `aegis.sandbox` | manca un egress allowlist per gli scanner e non sono applicati seccomp/AppArmor |
| Credenziali | i segreti first-party sono letti dall'ambiente e redatti | manca un backend opzionale per secret manager e una policy uniforme di rotazione |
| Autorizzazione | scope file + conferma esplicita prima dell'esecuzione | lo scope non è ancora un engagement manifest firmato, con scadenza e approvatore |
| Supply chain | SBOM, hash lock, audit dipendenze e secret scan | mancano attestazioni di build, firma immagini/release e SAST CodeQL bloccante |
| Qualità | Ruff lint/format, Mypy strict, pytest portabile 3.11–3.14 e branch coverage first-party ≥75% sono gate obbligatori; unit/contract/integration hanno selezioni CI separate e la sandbox POSIX un job dedicato | container e live-lab non hanno ancora casi eseguibili; mutation testing e CodeQL da aggiungere |
| Input ostili | report HTML Vulcan con `html.escape`; RichLog TUI con `markup=False` | `aegis/adapters/nmap.py` parsa XML con `xml.etree` considerandolo “trusted local”, ma banner e script output sono controllati dal target; nessun fuzzing dei parser |
| Scanner | ledger in `integrations/maturity.py` con prove verificabili | 12 `live-tested`, 3 `offline-tested`, 0 `production-ready` |
| TUI | esecuzione senza shell e streaming dell'output | un solo campo libero per gli argomenti, UI solo inglese, poco supporto decisionale |
| Documentazione | README bilingue, threat model, ADR e guide operative | link interni corretti, ma manca un link checker in CI; alcuni conteggi non allineati |
| Governance | `ROADMAP.md` canonica, `upgrade.md` storico in sola aggiunta, `CONTRIBUTING.md` allineato alla CI, template issue/PR, label versionate e indice ADR | gli indicatori e la maturity table non sono ancora generati automaticamente |

## 🛡️ Prospettiva Cybersecurity (Analisi e Rinforzo)

### Stato di sicurezza attuale

Non è stato rilevato hardcoding di API key o password nel codice first-party
analizzato. `src/olympus/core/config.py` carica impostazioni da TOML e variabili
d'ambiente; i moduli che richiedono token usano variabili dedicate. La CI esegue
inoltre `gitleaks` sul working tree e, su `main`, sull'intera history, con un canary
che verifica che lo scanner sia realmente funzionante.

Il rischio maggiore non è quindi una singola credenziale in chiaro, ma il confine
tra il control plane nativo e la superficie VAP vendorizzata, seguito
dall'isolamento di rete dei processi scanner e dalla forza probatoria dello scope e
delle evidenze.

### Intervento A · `SEC-A` — Ritirare la superficie VAP vendorizzata (**P0**)

- [ ] Reimplementare nativamente le funzioni ancora delegate da
  `src/olympus/integrations/cli.py` a `vendor/vulnerability-assessment-platform`:
  API/web app, migrazioni e worker.
- [ ] Definire una matrice di parità per endpoint, job state, persistenza, audit,
  report e cancellazione prima di rimuovere il codice legacy.
- [ ] Rendere il control plane nativo fail-closed: autenticazione obbligatoria,
  autorizzazioni minime per rotta, scope registrati, limiti di concorrenza e live
  scan disabilitate di default.
- [ ] Eseguire una threat-model review prima di ogni milestone di migrazione.

**Criterio di completamento:** wheel e container eseguono API, worker e migrazioni
senza importare `vendor/`; i test di parità e regressione sono verdi; la directory
vendorizzata può essere rimossa senza perdita di funzionalità dichiarata.

### Intervento B · `SEC-B` — Isolamento forte degli scanner (**P0**)

`src/olympus/aegis/sandbox.py` applica già drop dei privilegi, limiti CPU/memoria/
processi/file descriptor, directory temporanea privata e terminazione del process
group. Il file dichiara correttamente ciò che manca.

- [ ] Eseguire ogni scanner in un namespace/container con filesystem root
  read-only, capability Linux azzerate, `no-new-privileges` e profilo seccomp.
- [ ] Applicare AppArmor o SELinux dove disponibile e pubblicare un profilo
  versionato nel repository.
- [ ] Separare control plane e scan plane; consentire egress solo verso IP e porte
  derivati dallo scope già validato.
- [ ] Bloccare metadata endpoint cloud, loopback, link-local, reti private non
  dichiarate e redirect fuori scope anche dal network namespace dello scanner.
- [ ] Aggiungere test di fuga: scrittura fuori scratch, fork bomb, accesso a file
  sensibili, connessione a target fuori scope e timeout non cooperativo.

**Criterio di completamento:** un adapter compromesso non può leggere il filesystem
host, elevare privilegi o raggiungere un indirizzo non autorizzato; le prove sono
automatizzate e allegate come evidenza di release.

### Intervento C · `SEC-C` — Engagement manifest firmato (**P1**)

`core.execution.ExecutionPolicy` richiede oggi `authorized=True` e può registrare
un `approval_reference`, ma una conferma booleana non prova chi abbia autorizzato
cosa e per quanto tempo.

- [ ] Introdurre `EngagementManifest` versionato con cliente/owner, approvatore,
  target inclusi ed esclusi, finestre temporali, tecniche consentite, limiti,
  identificativo del contratto e data di scadenza.
- [ ] Firmare il manifest con Ed25519 riusando `olympus.core.signing` e verificarlo
  prima di qualsiasi operazione attiva.
- [ ] Legare ogni job all'hash del manifest e registrarlo in audit, report ed
  evidenze; impedire il riuso dopo revoca o scadenza.
- [ ] Prevedere un profilo lab separato, esplicito e limitato a reti dichiarate,
  senza scorciatoie globali come “allow all”.

**Criterio di completamento:** nessuna live scan può partire con un semplice flag;
il report consente di dimostrare manifest, firma, scope e policy effettivi usati.

### Intervento D · `SEC-D` — Gestione credenziali e identità (**P1**)

- [ ] Conservare le variabili d'ambiente come fallback locale, senza introdurre
  `.env` caricati automaticamente in produzione.
- [ ] Definire un'interfaccia `SecretProvider` con implementazioni opzionali per
  keyring OS e secret manager esterni; i valori devono restare `SecretStr` o byte
  buffer il più a lungo possibile.
- [ ] Per AEGIS API, affiancare alle API key hashate un'opzione OIDC/mTLS per
  deployment multiutente; mantenere permessi per azione e revoca immediata.
- [ ] Rendere uniforme la rotazione: overlap breve, scadenza obbligatoria, audit
  dell'identità e mai del segreto.
- [ ] Aggiungere property-based test alla redazione in `core.execution` per query
  URL, header, mapping annidati, output scanner, Unicode e chiavi inattese.

**Criterio di completamento:** nessun segreto compare in log, eccezioni, report,
telemetria o file temporanei nei test canary; tutte le credenziali di servizio sono
ruotabili senza downtime.

### Intervento E · `SEC-E` — Evidenze e chain of custody verificabili (**P1**)

- [ ] Integrare la firma Ed25519 direttamente nell'append path del ledger Minerva,
  non solo come firma detached successiva del file.
- [ ] Aggiungere timestamp attendibile RFC 3161 o servizio equivalente per
  attestare anche il momento di acquisizione.
- [ ] Memorizzare hash, tool/versione, policy, scope, command template, stato di
  coverage e motivo di ogni risultato parziale.
- [ ] Cifrare a riposo findings ed evidenze sensibili con chiavi separabili dai
  dati e definire cancellazione verificabile secondo retention policy.

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

- [ ] Classificare ogni comando come `passive`, `active`, `intrusive` o
  `destructive-prohibited` e mostrare la classe prima dell'esecuzione.
- [ ] Consentire le operazioni intrusive solo se esplicitamente abilitate nel
  manifest firmato; mantenere DoS, persistenza, credential harvesting reale ed
  evasione fuori dallo scope di prodotto.
- [ ] Implementare dry-run con visualizzazione dell'argv redatto, destinazioni,
  rate/deadline e file che verranno creati.
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

- [ ] Trattare ogni output scanner come input non fidato: rimuovere il commento
  “trusted local” in `aegis/adapters/nmap.py`, adottare `defusedxml` (o un parser
  equivalente con entità disabilitate) e imporre limiti di dimensione e
  profondità prima del parsing XML/JSON.
- [ ] Aggiungere fuzzing (Hypothesis o Atheris) per tutti i parser in
  `aegis/adapters/`, `apollo` e `metis`, con corpus iniziale dalle fixture reali:
  nessun input deve causare crash non gestiti, consumo illimitato o finding
  inventati.
- [ ] Neutralizzare sequenze di escape ANSI/OSC e caratteri di controllo prima di
  mostrarle in CLI, TUI e log (terminal injection, falsificazione di righe di log).
- [ ] Garantire escaping contestuale in tutti gli export: HTML con Content Security
  Policy restrittiva e nessuno script inline, Markdown, SARIF e CSV/XLSX con
  protezione da formula injection (`=`, `+`, `-`, `@` in testa alla cella).
- [ ] Vietare che valori provenienti dal target diventino path, argv, URL di
  follow-up o nomi file senza passare per validazione e scope gate (path traversal,
  SSRF di secondo ordine, argument injection).
- [ ] Creare fixture “malevole” versionate (XML bomb, banner con escape ANSI,
  payload XSS nel titolo, nomi file con `../`) eseguite a ogni run di CI.

**Criterio di completamento:** un target controllato dall'attaccante non può
eseguire codice, alterare la visualizzazione, iniettare contenuto nei report o
esaurire le risorse dell'host che esegue Olympus; ogni regressione fa fallire la CI.

### Intervento I · `SEC-I` — Security operations del progetto (**P2**)

- [ ] Definire in `SECURITY.md` tempi di presa in carico e di risoluzione per
  severità (es. critica: triage 48 h, fix 7 giorni) e un canale di segnalazione
  privato (GitHub Private Vulnerability Reporting).
- [ ] Collegare Dependabot a una SLA di aggiornamento per le dipendenze con CVE
  note e registrare le eccezioni motivate con scadenza, mai allowlist permanenti.
- [ ] Redigere un runbook di incident response per compromissione di chiavi di
  firma, token CI o API key AEGIS: revoca, rotazione, re-firma e comunicazione.
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
- [ ] Aggiungere test di architettura che vietino import inversi e accessi diretti
  al network dal dominio.

**Criterio di completamento:** dipendenze tra layer documentate e verificate in
CI; nessuna logica di dominio dipende da Typer, Textual, FastAPI o SQLite.

### Intervento B · `DEV-B` — SDK per adapter e plugin registry (**P1**)

- [ ] Estrarre un protocollo pubblico stabile per adapter: metadata, capability,
  input, argv, parser, health check, maturity ed evidence manifest.
- [ ] Scoprire adapter opzionali tramite entry point Python, mantenendo una
  allowlist di plugin firmati/approvati per le installazioni professionali.
- [ ] Validare output scanner con schema versionato e quarantena dei record non
  conformi; mai “best effort” silenzioso.
- [ ] Fornire un template e contract test riutilizzabile per nuovi adapter.

**Criterio di completamento:** un adapter esterno può essere sviluppato e testato
senza modificare il core, ma non può bypassare scope, policy, audit o sandbox.

### Intervento C · `DEV-C` — Compatibilità e qualità misurabile (**P1**)

- [x] Rendere Mypy un gate CI bloccante sul codice first-party e aggiungere
  `ruff format --check`: il job obbligatorio esegue lint, format, type checking
  strict e test; il repository è stato normalizzato dal formatter.
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
  suite vuota fallisce come “no tests collected”. Le suite container/live-lab
  non contengono ancora casi: non attestano isolamento o scanner live.
- [ ] Aggiungere mutation test mirati a scope gate, redaction, parser, exit code e
  state machine dei job.

**Criterio di completamento:** matrice supportata dichiarata uguale a quella
effettivamente testata; regressioni dei guardrail provocano sempre un fallimento.

### Intervento D · `DEV-D` — Contratti, migrazioni e backward compatibility (**P1**)

- [ ] Pubblicare JSON Schema versionati per input/output e applicare SemVer ai
  contratti oltre che al package.
- [ ] Aggiungere golden contract test per CLI JSON/NDJSON, API OpenAPI, SQLite e
  report; documentare deprecazioni e finestra di compatibilità.
- [ ] Introdurre migrazioni esplicite per scope, assessment plan, job, evidence e
  case CTI; nessun aggiornamento deve rendere il dato storico illeggibile.
- [ ] Centralizzare exit code e stati (`clean`, `findings`, `partial`, `failed`,
  `cancelled`) in tutti i moduli e verificarne la coerenza end-to-end.

**Criterio di completamento:** una release nuova legge gli artifact supportati
dalla precedente oppure restituisce un errore di migrazione esplicito e sicuro.

### Intervento E · `DEV-E` — Performance, resilienza e osservabilità (**P2**)

- [ ] Creare benchmark ripetibili per ingest, normalizzazione, deduplica, grandi
  report e code AEGIS; definire budget di memoria, CPU e latenza.
- [ ] Usare streaming e backpressure per file/log grandi, evitando di caricare
  interi dataset in memoria.
- [ ] Aggiungere metriche OpenTelemetry/Prometheus con cardinalità limitata e
  redazione by design; correlare assessment, job, evidence e report.
- [ ] Testare crash recovery, retry idempotenti, lock SQLite, migrazioni interrotte
  e cancellazione durante l'esecuzione di un tool esterno.

**Criterio di completamento:** esistono SLO e performance budget misurati; un
riavvio non duplica scansioni né perde lo stato terminale di un job.

### Intervento F · `DEV-F` — Release PyPI professionale (**P2**)

- [ ] Automatizzare versione, changelog, build, test, firma e pubblicazione PyPI
  tramite Trusted Publishing/OIDC, senza token statici.
- [ ] Testare sia dipendenze minime sia extra (`api`, `aegis`, `dev`) e dichiarare
  chiaramente cosa è incluso nella wheel e cosa richiede binari esterni.
- [ ] Pubblicare release candidate e procedura di rollback; evitare release se
  documentazione, schema o maturity ledger sono incoerenti.
- [ ] Generare una CLI reference dalla command tree per eliminare duplicazioni.

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
- [ ] Allineare README e `integrations/maturity.py`: il
  ledger attuale dichiara 12 adapter `live-tested`, 3 `offline-tested` incluso
  Wapiti e nessun `production-ready`.
- [ ] Aggiungere un link checker, esempi eseguibili e test che rigenerino tabelle
  di capacità/maturità dal registry invece di mantenerle a mano.
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

- [ ] Generare controlli TUI dalla metadata Click/Typer: text field, select,
  checkbox, path picker e repeatable option, invece di un'unica stringa libera.
- [ ] Mostrare required/default/range/example e validare localmente prima del run.
- [ ] Conservare una modalità “raw arguments” per utenti esperti, separata e
  chiaramente indicata.
- [ ] Riutilizzare lo stesso schema per eventuale web UI, evitando logiche diverse
  tra CLI e TUI.

**Criterio di completamento:** un nuovo utente può configurare una scansione senza
consultare `--help`; l'argv prodotto è visibile, redatto e riproducibile.

### Intervento B · `UX-B` — Safety preview e conferme proporzionate (**P0/P1**)

- [ ] Prima del run mostrare target normalizzato, scope match, classe di rischio,
  manifest/approvazione, timeout, rate, concorrenza, output e tool esterno.
- [ ] Per comandi `active` o `intrusive`, richiedere una conferma esplicita che
  riporti il target; nessuna conferma aggiuntiva per operazioni passive e locali.
- [ ] Evidenziare `simulation`, `unavailable`, `partial` e `failed` come stati
  distinti: un risultato parziale non deve sembrare “nessuna vulnerabilità”.
- [ ] Integrare un kill switch sempre visibile con feedback su processo terminato,
  cleanup ed evidenze conservate.

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
- [ ] **P2 — Mapping MITRE ATT&CK dei finding offensivi:** associare tecnica,
  tattica, confidence e motivazione ai finding Vulcan, conservando il mapping
  versionato e distinguendo associazioni automatiche da revisioni umane.
- [⏸] **P3 — Proteus simulated delivery:** evolvere la modellazione in campagne
  simulate esclusivamente in lab, con click e credential-harvest sintetici e
  nessun invio o dato riferito a utenti reali.

**Criterio di completamento Red Team:** ogni adapter eredita scope, autorizzazione,
policy, audit, sandbox e stati di coverage; nessuna funzione offensiva diventa
eseguibile solo perché il binario esterno è installato.

### Blue Team · `OPS-BLUE` — Detection, SIEM, CTI e DFIR

- [~] **P1 — Ingest Apollo:** aggiungere Sysmon/Windows Event e Zeek oltre al
  formato access-log già disponibile. Separare sempre acquisizione e parsing,
  usare fixture sanitizzate reali e non inventare campi mancanti.
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
- [ ] Aggiungere una matrice “tecnica ATT&CK → telemetria → regola → test” per
  mostrare copertura reale, copertura parziale e assenza di dati.

**Criterio di completamento Purple Team:** la pipeline non misura soltanto se una
regola scatta, ma se la telemetria necessaria è stata prodotta, ingerita e
correlata senza perdita di coverage.

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

## 📅 Pianificazione Temporale

Le durate sono stime per un team piccolo e presuppongono decisioni architetturali
rapide. Le attività che richiedono scanner reali devono essere validate solo in un
lab autorizzato; in assenza del lab restano aperte e non cambiano maturità.

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

- [ ] Completare control plane AEGIS nativo e rimuovere la dipendenza runtime da
  `vendor/`.
- [ ] Pubblicare SDK/contract test per adapter.
- [x] Attivare matrice Python, branch coverage gate e suite unit/contract/integration
  separate; POSIX resta in un job dedicato.
- [ ] Aggiungere CodeQL e mutation test; le suite container/live-lab restano
  esplicitamente non validate finché non esistono casi e relative prove.
- [ ] Stabilizzare schema, migrazioni, exit code e recovery dei job.

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
- [ ] Metriche e tracing redatti, dashboard operative e SLO.
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
| Import runtime da `vendor/` | presenti (`aegis serve`, `migrate`, `workers`) | 0 | test di architettura `DEV-A` |
| Link interni rotti | ≥ 6 file → 0 (verifica manuale del 24/09/2026) | 0, garantito dalla CI | link checker `DEV-G` |
| Lingue dell'interfaccia | 1 (EN) | 2 (IT/EN) | cataloghi `UX-E` |

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

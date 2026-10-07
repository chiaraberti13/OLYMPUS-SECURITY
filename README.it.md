<p align="center">
  <img src="assets/banner.svg" alt="Olympus-security" width="100%">
</p>

<p align="center"><a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a></p>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-F2C94C?style=flat-square" alt="Project status: active">
  <img src="https://img.shields.io/badge/category-CYBERSECURITY-22D3EE?style=flat-square" alt="CYBERSECURITY">
  <img src="https://img.shields.io/badge/stack-Python%203.11%2B-8B949E?style=flat-square" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/languages-EN%20%7C%20IT-8B5CF6?style=flat-square" alt="English and Italian">
  <img src="https://img.shields.io/badge/licence-GPL--3.0-2EA043?style=flat-square" alt="GPL-3.0 + third-party licences">
</p>

> Un’unica CLI con controllo dello scope per assessment, rilevamento, raccolta delle evidenze e reporting di sicurezza.

<p align="center"><a href="SECURITY.md">Sicurezza</a> · <a href="LICENSE">Licenza principale</a> · <a href="THIRD_PARTY_NOTICES.md">Licenze di terze parti</a></p>

---

## Navigazione rapida

- **[Cos'è Olympus?](#cosè-olympus)** — cosa fa, e a chi si rivolge.
- **[Moduli](#-moduli)** — ogni tool, cosa fa e il suo punto d'ingresso.
- **[Installazione](#-installazione)** — un solo comando, Python 3.11+.
- **[Avvio rapido](#-avvio-rapido)** — un percorso verificato recon → assessment → report.
- **[Configurazione](#-configurazione)** — file di scope, config e segreti.
- **[Struttura del progetto](#-struttura-del-progetto)** — com'è organizzato il repository.
- **[Sviluppo](#-sviluppo)** — controlli CI obbligatori e comandi locali.
- **[Modello di sicurezza](#-modello-di-sicurezza)** — scope, autorizzazione, SSRF, audit.
- **[Migrazione](#-migrazione--motori-specialistici)** — ARGUS nativo, THEMIS e motori specialistici.
- **[Licenze](#-ambito-delle-licenze)** — codice nativo GPL-3.0 e licenze vendor preservate.
- **[Uso legale ed etico](#-uso-legale-ed-etico)** — solo autorizzato, in pratica.

---

## Cos'è Olympus?

Olympus è una piattaforma di sicurezza offensiva-e-difensiva pilotata da un
unico binario. Invece di un cassetto di script scollegati, ogni capacità è un
sotto-comando di una sola CLI e parla lo **stesso contratto dati** — lo stesso
`Asset`, `Finding`, `Event`, `Evidence`, `Alert` e `Incident` prodotto da un
modulo può essere consumato da qualsiasi altro senza conversioni.

Due regole di progettazione attraversano l'intero progetto:

- **Offline-first, I/O iniettato.** La logica di dominio non parla mai
  direttamente con la rete; dipende da piccole porte tipizzate (client HTTP,
  resolver DNS, tool runner) così i test sono deterministici e offline, mentre
  in produzione si inietta il trasporto reale.
- **Sicuro-per-scope per costruzione.** Ogni comando che tocca un bersaglio
  reale lo verifica prima contro uno scope autorizzato esplicito, blocca i
  bersagli fuori scope e scrive un record di audit — mai uno scarto silenzioso.

```console
$ olympus --help
$ olympus argus dns --domain example.com --scope scope.json
$ olympus athena run plan.json --storage ./.athena
```

## 🧰 Moduli

| Modulo | Punto d'ingresso | Cosa fa |
| --- | --- | --- |
| **Argus** | `olympus argus` | OSINT & recon passivo: DNS, WHOIS/RDAP, header web, IP, telefono, email, MAC, account, CDN fronting, grafi di investigazione. |
| **Athena** | `olympus athena` | **Orchestrazione e ciclo di vita** dell'assessment: piani validati, esecuzione job limitata, storage SQLite durevole, audit trail, reporting. |
| **Helios** | `olympus helios` | Scansione della superficie in scope ed export dei finding. |
| **Artemis** | `olympus artemis` | Probing di applicazioni web (fingerprint, contenuti, XSS) in scope. |
| **Proteus** | `olympus proteus` | Modellazione di campagne di social engineering (autorizzate, simulate). |
| **Hermes** | `olympus hermes` | Scansione di segreti e dati sensibili con output SARIF. |
| **Apollo** | `olympus apollo` | Motore di regole di detection (red/blue) su eventi normalizzati. |
| **Minerva** | `olympus minerva` | Triage degli incidenti e catena di custodia. |
| **Vulcan** | `olympus vulcan` | Aggregazione, deduplica, ranking e rendering dei report. |
| **Metis** | `olympus metis` | Routing deterministico delle competenze, piani d'ingaggio, casi CTI, correlazione IOC e report operativi. |
| **core** | `olympus core` | Utility del contratto dati condiviso (es. `export-schemas`). |
| **THEMIS** | `olympus themis` | Orchestrazione scanner con scope, stato capacità, job SQLite persistenti, cancellazione, audit e stati di esecuzione espliciti. |
| **TUI unificata** | `olympus ui` | Interfaccia da tastiera su tutti i comandi reali Olympus, con output in streaming e cancellazione del processo. |

> [!TIP]
> Esegui qualsiasi modulo con `--help` per vederne i comandi, oppure
> `olympus <modulo> <comando> --help` per le opzioni di un comando.

## 🚀 Installazione

Olympus richiede **Python 3.11+**.

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"      # oppure: make install
olympus --version
olympus ui
```

## 🎯 Avvio rapido

Ogni comando attivo in rete richiede un file di scope che nomina i domini che
sei autorizzato a toccare:

```bash
cat > scope.json <<'JSON'
{ "engagement": "demo-2026", "allowed_domains": ["example.com"] }
JSON
```

Recon passivo con Argus (scrive un bundle `core.Asset`/`core.Finding`):

```bash
olympus argus dns   --domain example.com --scope scope.json
olympus argus whois --domain example.com --scope scope.json
olympus argus web   --url https://example.com --scope scope.json --output web.json
```

Orchestra un intero assessment con Athena, poi leggi i risultati:

```bash
olympus athena plan validate examples/input/athena-plan.json
olympus athena run examples/input/athena-plan.json --storage ./.athena --report
olympus athena status <ASSESSMENT_ID> --storage ./.athena
```

Athena usa gli stessi exit code canonici di ogni altro modulo — `0` pulito,
`1` finding, `2` input non valido, `3` negazione di scope, `5` parziale,
`6` errore d'esecuzione, `7` annullato — quindi si integra bene in CI e negli
script. Un'esecuzione parziale non viene mai riportata come pulita; vedi
[stato e copertura delle esecuzioni](docs/run-status.md).

## ⚙️ Configurazione

- **File di scope** (JSON) autorizzano i bersagli per ingaggio:
  `{"engagement": "...", "allowed_domains": [...], "excluded_domains": [...]}`.
  Gli scope IP/telefono/account di Argus usano chiavi proprie — vedi
  [`examples/input/`](examples/input).
- **`olympus.toml`** (opzionale) imposta i default HTTP condivisi e
  l'osservabilità con redazione preventiva (`none`, Prometheus autenticato o
  OTLP); l'ordine di
  risoluzione è `OLYMPUS_CONFIG` → `./olympus.toml` → `~/.olympus.toml`.
- **I segreti** sono letti solo da variabili d'ambiente (es.
  `OLYMPUS_NUMVERIFY_KEY`) e **non** vengono mai loggati, esportati o inseriti
  nei report.

Vedi [`docs/configuration.md`](docs/configuration.md) per precedenza e validazione
e [`docs/observability.md`](docs/observability.md) per metriche limitate, scraping
autenticato e correlazione delle trace.

## 🗂️ Struttura del progetto

```text
src/olympus/
├── cli.py            # punto d'ingresso unificato `olympus`
├── tui/              # interfaccia terminale unificata da tastiera
├── core/             # contratto dati condiviso: modelli, enum, http, config, ids
├── argus/            # OSINT & recon passivo (incl. integrazione ARGUS)
├── athena/           # orchestrazione degli assessment (integrazione VAP)
│   ├── domain/       # piani, job, macchine a stati, audit immutabili
│   ├── application/  # coordinator, registry, use case di planning
│   ├── adapters/     # sqlite, audit, reporting e adapter dei tool
│   └── cli.py
├── helios/ artemis/ proteus/ hermes/ apollo/ minerva/ vulcan/
docs/                 # architettura (ADR), manifest di parità, reference
examples/             # file di scope, piani, input/output di esempio
tests/                # test unitari e di contratto, offline e deterministici
```

Vedi la [guida dell'interfaccia terminale](docs/tui.md) per navigazione,
esecuzione e comportamento di sicurezza.

## 🧪 Sviluppo

Ruff e l'intera suite pytest sono gate CI obbligatori. Il type checking resta
un controllo locale aggiuntivo. La prontezza funzionale richiede inoltre prove
di esecuzione reali: una CI verde, da sola, non viene definita parità.

```bash
make lint      # Ruff; obbligatorio in CI
make test      # pytest; obbligatorio in CI
make type      # mypy; controllo locale aggiuntivo
make check     # esegue l'intera suite locale
```

Vedi [`docs/architecture/`](docs/architecture) per le decisioni di progetto
accettate, [`docs/contracts.md`](docs/contracts.md) per le regole di compatibilità
dei contratti versionati, [`docs/execution-policy.md`](docs/execution-policy.md) per autorizzazione
e limiti di esecuzione condivisi, [`docs/observability.md`](docs/observability.md)
per metriche redatte e correlazione delle trace, [`docs/parity/`](docs/parity) per i manifest di capacità upstream e
[`docs/professional-platform.md`](docs/professional-platform.md) per la migrazione del control plane professionale.

## 🔐 Modello di sicurezza

- **Enforcement dello scope** prima di ogni lookup reale; i bersagli bloccati
  vengono registrati in audit.
- **Autorizzazione esplicita** (`--i-am-authorized`) per l'OSINT sensibile alla
  privacy (es. enrichment di telefono/email su una persona reale).
- **Guardia SSRF**: gli adapter di Athena rifiutano i bersagli che risolvono a
  IP non globali e ri-validano lo scope prima di ogni richiesta.
- **Esecuzione limitata**: timeout/retry/rate limit HTTP condivisi, e in Athena
  concorrenza, timeout per-job e deadline complessive con massimi sicuri.
- **Audit trail con redazione**: eventi append-only con soli metadati in
  allowlist — mai credenziali, corpi di risposta o finding grezzi.

## 🔁 Migrazione & motori specialistici

La migrazione di **ARGUS** standalone è completa. L'implementazione mantenuta è
`src/olympus/argus/`, esposta soltanto come `olympus argus`; il sorgente
duplicato `vendor/argus` e il passthrough `argus-native` sono stati rimossi.

THEMIS esegue ora API, Web UI (`serve`/`web`), migrazioni e worker continui dalla
wheel nativa. Scope, autorizzazione, adapter, job SQLite, cancellazione e audit
redatto condividono una sola implementazione, senza Redis/Celery né import
runtime da `vendor/`. Il sorgente VAP resta un archivio per la futura verifica
completa della parità endpoint/dati (`SEC-A`); import dei database legacy e
milestone Web avanzate restano punti distinti. Configurazione e rollback sono
nella [guida al runtime nativo](docs/themis-runtime.md), bilingue IT/EN.

I motori di scansione specialistici sono **integrati e governati, non copiati**.
Olympus ne rileva versioni e configurazione, li esegue entro lo scope autorizzato,
normalizza l'output e registra le evidenze; licenze e canali d'installazione dei
motori restano quelli ufficiali.

```bash
olympus argus --help                       # superficie OSINT/recon nativa
olympus argus doctor                       # readiness dipendenze/configurazione

olympus themis capabilities                 # stati configured/available/ready
olympus themis jobs init                    # archivio job locale persistente
olympus themis jobs submit nmap --target example.com --scope scope.json --i-am-authorized
olympus themis jobs work                    # elabora un job in coda
OLYMPUS_THEMIS_API_KEY='<32+ caratteri casuali>' olympus themis api --scope-directory .olympus/scopes
olympus themis scanners                     # catalogo motori specialistici
olympus themis migrate                       # migrazioni del database job nativo
olympus themis workers                       # worker nativo continuo
```

### Avviare il control plane nativo

```bash
pip install -e ".[themis]"
olympus themis migrate --database .olympus/themis-jobs.sqlite3
# Configurare prima credenziali/registro identità e scope autorizzati:
olympus themis api --scope-directory .olympus/scopes
olympus themis serve --scope-directory .olympus/scopes \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
olympus themis workers --database .olympus/themis-jobs.sqlite3
```

`serve` e `web` sono identici. Le sessioni browser usano HTTPS. Ogni job in
coda richiede autorizzazione esplicita e scope; le scansioni live sono
normalmente disabilitate. `workers --once` mantiene gli exit code canonici;
il worker continuo prosegue dopo singoli fallimenti e gestisce SIGINT/SIGTERM.

Dopo aver preparato scope, identità e TLS secondo la
[`guida al runtime`](docs/themis-runtime.md):

```bash
docker compose up --build
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
docker compose down
```

| Aspetto | Deployment nativo |
| --- | --- |
| Servizi | `themis-migrate`, `themis-api`, `themis-app`, `themis-worker`; SQLite senza broker |
| Porte | API `https://localhost:8443`, Web `https://localhost:8600`; pubblicate solo su loopback host |
| Archivio | `themis-data`; dati VAP separati, la migrazione nativa rifiuta database estranei |
| Sicurezza | Identità/TLS obbligatori, non-root, rootfs read-only, capability rimosse, live disabilitato |
| Scanner | Immagine opzionale soltanto sul worker; dipendenze assenti producono coverage parziale esplicita |
| Verifiche | Smoke della wheel e suite container eseguibile in CI, su loopback senza scansioni live |

**Scansioni reali, mai inventate:** `olympus themis run <scanner> --target <t> --scope s.json --i-am-authorized` esegue uno scanner reale con stati espliciti — `live` / `unavailable` / `failed` / `disabled` / `simulation`. La simulazione è prodotta **solo** con `--simulate` (o `THEMIS_SIMULATION_MODE=true`); un binario mancante dà `unavailable`, mai un finding falso. Vedi [`docs/scanner-matrix.md`](docs/scanner-matrix.md) e [`docs/themis-execution-evidence.md`](docs/themis-execution-evidence.md).

I **binari** degli scanner esterni si installano separatamente o tramite
l'immagine opzionale del worker nativo. Il runtime mantenuto non usa l'installer
VAP archiviato o il relativo stack Redis/Celery.

Olympus offre implementazioni **native**: `olympus argus …` (OSINT scope-first),
`olympus themis …` (controllo motori specialistici) e `olympus athena …`
(orchestrazione degli assessment). I loro
contratti di capacità e la provenienza sono in [`docs/parity/`](docs/parity) e
[`docs/provenance.md`](docs/provenance.md); l'architettura di Athena è
[ADR-002](docs/architecture/adr-002-athena-target-architecture.md). Le procedure
esaustive sono in [`docs/reference.md`](docs/reference.md).

## 📄 Ambito delle licenze

Il codice nativo Olympus, inclusi ARGUS e THEMIS nativi, è distribuito con licenza **GNU GPL-3.0** — vedi
[LICENSE](LICENSE). I componenti vendorizzati e di terze parti mantengono le rispettive licenze
applicabili; la licenza root non sovrascrive i termini di licenza di terze parti. Vedi [note di terze parti](THIRD_PARTY_NOTICES.md)
e [provenienza](docs/provenance.md).

## ⚠️ Uso legale ed etico

Olympus effettua test di sicurezza **autorizzati**. I moduli passivi
interrogano solo informazioni pubblicamente disponibili; i moduli attivi si
connettono solo a bersagli dentro uno scope dichiarato. Usalo esclusivamente
dove hai **permesso documentato** (i tuoi sistemi, un ingaggio firmato o un lab
che controlli). L'uso improprio è responsabilità esclusivamente tua.

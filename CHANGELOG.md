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

### Added — EXPL-1 (shared finding-explainability contract, first slice)

- Core condiviso `vulcan.explain.explain_finding` → `FindingExplanation`: spiega,
  in modo identico per ogni superficie, perché un finding è segnalato, perché quel
  rischio e con quale affidabilità. Derivato **solo** dai campi del finding
  (nessuna scansione, nessuna rete, nulla di inventato); separa **observed**
  (evidenza allegata, KEV, CVSS, CVE/CWE, EPSS), **inferred** (punteggio di
  rischio) e **limits** (caveat espliciti). Il razionale del rischio è ricostruito
  dalle stesse costanti del punteggio — `SEVERITY_RISK_BASE`, `KEV_RISK_FLOOR`,
  `CONFIDENCE_RISK_MODIFIER`, ora costanti pubbliche in `core.models` e unica fonte
  anche per `Finding.risk_score` — così punteggio e spiegazione non possono
  divergere; un solo fattore è `decisive`, e un'escalation KEV/EPSS lo è solo se ha
  davvero alzato il punteggio. CLI `olympus vulcan explain` (blocchi testuali o
  `--format json` col contratto completo), findings in ordine di rischio
  decrescente. ROADMAP `EXPL-1` → parziale (restano il contratto versionato con
  classe epistemica per campo e l'integrazione provenance/ATT&CK).

### Changed — QA (copertura di mutazione dello spacchettamento evidenze protette)

- Rafforzata la copertura di mutazione di `olympus.minerva.vault._unpack`
  (47% → **80%**), il decoder che autentica una evidenza protetta prima di
  restituirla: framing/`_MAGIC`, limiti della lunghezza header, parse dei
  metadata, `content_length` e **digest SHA-256** di integrità. Il test del gate
  colpiva solo i primi controlli di framing con payload corti; ora costruisce un
  frame valido (via `_pack`) e lo manomette per ogni invariante — header length 0
  e oltre il massimo, header da 1 byte che non è JSON valido, metadata non-JSON,
  `content_length` non corrispondente, e **stesso contenuto-length ma digest
  diverso** (manomissione dell'integrità) — asserendo il *messaggio* specifico di
  ciascun ramo, così un mutante che instrada un input al ramo sbagliato o azzera
  la diagnostica viene ucciso. I sopravvissuti residui sono mutanti equivalenti
  (`int.from_bytes` senza `"big"` = default già big in 3.11+; confronti al limite
  esatto non costruibili con payload validi) o wrapper di messaggio. Nessun
  cambiamento al codice di produzione.

### Changed — QA (copertura di mutazione dell'enforcement dello scope)

- Rafforzata la copertura di mutazione di `olympus.athena.scope._reject_out_of_scope`
  (50% → **80%**), il gate che rifiuta i bersagli fuori dall'ambito autorizzato. Il
  test del gate usava un unico dominio già normalizzato, lasciando non testata la
  **normalizzazione del lato `allowed`** (spazi/maiuscole/punto finale) e quella del
  lato **host** (quest'ultima mai esercitata via `ensure_target_allowed` perché
  `host_of` pre-normalizza). Aggiunto un test che chiama il gate direttamente con un
  host non normalizzato (`Example.COM.` in ambito) e usa una entry di scope
  loosely-written (`" EXAMPLE.COM. "`), verificando match esatto e di dominio padre
  senza allargare l'ambito. I sopravvissuti residui sono mutanti equivalenti
  (`rstrip(".")` ≡ `rstrip("X.")` su stringhe già minuscole) o sul solo testo del
  messaggio. Nessun cambiamento al codice di produzione.

### Changed — QA (copertura di mutazione del confine di autorizzazione del manifest)

- Rafforzata la copertura di mutazione delle due funzioni di **autorizzazione**
  dell'engagement manifest — `EngagementManifest.authorizes` (38% → **73%**) e
  `SignedEngagementManifest.authorize` (45% → **69%**) — il confine che decide se
  una scansione è autorizzata (firma, scope, tempo, tecnica, revoca, classe di
  rischio). Il test del gate copriva solo happy-path, target fuori-scope, tempo
  scaduto e firma con chiave sbagliata; ora fissa anche: tecnica non autorizzata,
  istante **prima** della finestra di validità, `now` senza timezone → `ValueError`,
  **revoca** per digest/`manifest_id`/`engagement_id` e la validazione della lista
  di revoca (niente stringa nuda, voci vuote o non-stringa), e il **tetto di
  rischio** (`allowed_risk`: un'operazione oltre il tetto è rifiutata, entro è
  consentita). I sopravvissuti residui sono mutanti equivalenti
  (`astimezone(None)` = stesso istante) o sul solo testo dei messaggi d'errore.
  Nessun cambiamento al codice di produzione.

### Changed — QA (copertura di mutazione al 100% per `safe_terminal_text`)

- Rafforzata la copertura della funzione di sicurezza del terminale
  `olympus.core.execution.safe_terminal_text` (confine del mutation gate): il test
  del gate non fissava la sostituzione di CR/LF/TAB con uno **spazio** (né il join
  a singolo spazio), lasciando sopravvivere 7 mutanti (score 71%). Aggiunta
  un'asserzione di uguaglianza esatta (`"a\rb\nc\td  e"` → `"a b c d e"`) che pinna
  la proprietà anti-forging (i separatori di riga diventano spazi *prima* dello
  strip dei controlli, così i token restano separati e non fusi/cancellati): tutti
  i 24 mutanti ora uccisi (**100%**). Nessun cambiamento al codice di produzione;
  aggiunto anche un test unitario diretto in `tests/unit/test_core_execution.py`.

### Fixed — CLI (render_table: una cella non-stringa non fa più crashare il formatter)

- `olympus.core.output.render_table` (il formatter tabellare condiviso da tutti i
  comandi CLI) passava ogni cella direttamente a `safe_terminal_text`, che assume
  una `str`: una cella non-stringa (un conteggio `int`, `None`) faceva sollevare
  `AttributeError` e **crashare l'intero comando**. Ora le celle sono coercite con
  `str()` prima della sanificazione, esattamente come già fa `render()`, così uno
  scivolone di tipo di un chiamante degrada con grazia invece di interrompere
  l'output. Nessun cambiamento per le celle già stringa. Regressione in
  `tests/unit/test_core_output.py`.

### Fixed — SEC (hermes secret-scanner: righe `++`/`--` non più scartate — evasione/falso negativo)

- `olympus.hermes.scanner._scan_git_patch` escludeva dal contenuto le righe che
  iniziano con `+++`/`---` (senza spazio) per distinguerle dagli header di file.
  Ma gli header veri `+++ `/`--- ` (con **spazio finale**) sono già consumati a
  monte: la guardia scartava quindi una **riga di contenuto** il cui testo inizia
  con `++` (patch line `+++…`) o una riga rimossa che inizia con `--` (patch line
  `---…`), **mancando silenziosamente un segreto** su quella riga — un falso
  negativo/evasione in uno scanner di segreti. Rimossa la guardia ridondante:
  ogni riga `+`/`-` residua è contenuto di hunk e viene scansionata; gli header
  con spazio restano consumati e non scansionati. Regressione in
  `tests/unit/test_hermes.py` (chiavi distinte su righe `++`, normale e `--`).

### Fixed — SEC (hermes secret-scanner: provenienza corretta dei segreti in file eliminati)

- `olympus.hermes.scanner._scan_git_patch` (scansione dei segreti nella history
  Git) ricavava il percorso del file solo dall'header `+++ b/<path>`. Per un file
  **eliminato** quell'header è `+++ /dev/null`, quindi `current_path` restava
  quello del file precedente del diff (o `"unknown"`): un segreto nelle righe
  rimosse di un file eliminato veniva attribuito al **file sbagliato**, e il
  percorso errato inquinava anche il `fingerprint_scope` (dedup/baseline). Il
  segreto era comunque rilevato (nessun falso negativo), ma con provenienza
  fuorviante per il triage/la remediation di una credenziale trapelata. Ora il
  parser traccia `old_path` (da `--- a/<path>`) e `new_path` separatamente e
  attribuisce ogni riga rimossa al vecchio file e ogni riga aggiunta al nuovo —
  corretto anche per i rename. I finding su file modificati sono invariati; i
  fingerprint cambiano solo per i casi prima mal-attribuiti (file eliminati e
  rinominati). Regressione in `tests/unit/test_hermes.py`.

### Fixed — SEC (legacy VAP import: un `id` ostile fallisce fail-closed, non crasha)

- `olympus.themis.legacy_vap` importa uno **SQLite legacy esterno non fidato**.
  `_scan_inventory` leggeva l'id con `int(row["id"])`; poiché SQLite è tipizzato
  dinamicamente, un database ostile o corrotto può contenere un `id` NULL
  (→ `TypeError`), testo/blob non numerico (→ `ValueError`) o float anche se la
  colonna esiste. Quelle eccezioni **sfuggivano** al contratto d'errore del
  modulo (`LegacyVapSnapshotError`, catturato dai chiamanti) — il `try` di import
  cattura solo `sqlite3.DatabaseError` e per il resto rilancia grezzo — facendo
  **crashare l'import** invece di fallire fail-closed con un errore di dominio
  chiaro. Nuovo helper `_legacy_scan_id` che accetta solo un intero (o stringa
  numerica) e altrimenti solleva `LegacyVapSnapshotError`. I nuovi artefatti di
  snapshot sono ripuliti in rollback come per ogni altra riga invalida.
  Regressione (NULL/testo/blob/float) in `tests/unit/test_themis_legacy_vap.py`.

### Fixed — TOOLS-4.4 (wapiti: un `level` malformato non fa più crashare il parse)

- `olympus.themis.adapters.wapiti` calcolava la severità con
  `int(item.get("level", 1) or 1)`. Un report malformato con `level` di tipo
  lista/oggetto fa sollevare a `int()` un **`TypeError`** (non un `ValueError`),
  che **sfugge** al confine dell'adapter (`run()` cattura solo `ParseError`/
  `ValueError`) e fa **crashare il run** invece di fallire fail-closed. L'output
  dello scanner è input non fidato, quindi è una violazione del contratto di
  stato canonico (TOOLS-4.4). Nuovo helper `_level_value` che coerce il livello a
  int solo quando è numerico (int/float/stringa numerica, `bool` escluso) e
  altrimenti ricade su `INFO`, come qualunque livello non riconosciuto: nessun
  crash, nessun report valido annullato per un singolo campo errato. Regressione
  in `tests/unit/test_themis_output_grammar.py`; i livelli validi 1–4 restano
  mappati su LOW/MEDIUM/HIGH/CRITICAL.

### Fixed — SEC (redazione argv: segreti dentro valori di header/form)

- `olympus.core.execution.redact_arguments` (argv display-safe, salvato in
  `ScanResult.command`) non lascia più in chiaro un segreto contenuto nel
  **valore** di un header o di un body passato come argomento, quando il nome
  dell'opzione non è esso stesso sensibile: `-H 'Authorization: Bearer <tok>'`,
  `--header=Cookie: SESSIONID=…`, `--data=user=admin&token=…`. Prima il ramo
  pass-through applicava solo `safe_terminal_text` (redazione dei soli URL), così
  il segreto nell'header sopravviveva.
- La logica di redazione delle assegnazioni header-style è stata **estratta in
  `olympus.core.execution.redact_assignments`** (fonte unica, predicato
  `is_sensitive_key`, regex lineare ReDoS-safe) e ora è condivisa tra
  `redact_arguments` e le evidenze Themis (`themis/base._evidence`), che prima ne
  avevano una copia locale (`_SECRET_ASSIGNMENT`). La classe-valore esclude ora
  anche `&`, così i parametri form/query sono redatti singolarmente. `redact_text`
  e `safe_terminal_text` restano invariati (solo URL), per non over-redigere la
  prosa di display di Olympus. Regressione in `tests/unit/test_core_execution.py`.

### Fixed — SEC (redazione audit strutturato: segreti URL nel testo libero)

- `olympus.core.execution.redact_mapping` (il redattore dei record di audit
  strutturati — `StructuredAuditRecord.metadata`, scritto da API/Web/jobs/CLI)
  non perde più un segreto contenuto in un **URL annidato in un valore di testo
  libero** sotto una chiave non sensibile (es. `{"detail": "scanner fetched
  https://api/?api_key=…"}`). `_redact_value` rediggeva le stringhe con
  `redact_url`, che riscrive solo una stringa che *è* un URL, lasciando in chiaro
  un URL dentro una frase; ora usa `redact_text`, che redige ogni URL trovato nel
  testo ed è un superset di `redact_url` per una stringa che è già un URL (nessuna
  sotto-redazione, testo non-URL invariato). Allinea il percorso di audit al
  redattore delle evidenze Themis. Regressione in
  `tests/unit/test_core_execution.py`; mutation gate (`x_redact_mapping`) verde.

### Fixed — SEC (redazione segreti nelle evidenze Themis: fughe e coerenza)

- `olympus.themis.base._evidence` (la cattura redatta di stdout/stderr degli
  scanner, salvata come `raw_evidence`) non perdeva più segreti che il percorso
  di audit strutturato considera sensibili. La vecchia regex `_SECRET_ASSIGNMENT`
  usava confini di parola (`\b`) e un'alternanza fissa di keyword, così **tre
  classi di segreto sopravvivevano** nelle evidenze: (1) i valori JSON quotati
  `"api_key": "…"` / `"access_token": "…"` (le virgolette e i due punti rompevano
  il separatore); (2) i nomi composti il cui termine sensibile non è a inizio
  identificatore (`aws_secret_access_key`, `refresh_token`, `client_secret`),
  che `is_sensitive_key` — usato da `redact_mapping`/`redact_arguments` — redige
  invece sempre; (3) i crumb successivi di un header `Cookie` multi-valore. Ora la
  redazione delle evidenze decide la sensibilità del *nome* con lo **stesso
  predicato** dell'audit (`is_sensitive_key`, promosso da `_sensitive_key` a API
  pubblica e unica fonte di verità), così un nome redatto in un percorso non resta
  mai in chiaro nell'altro.
- La nuova regex del nome è **ancorata a inizio-segmento con look-behind** e resta
  strettamente **lineare**: il redattore scandisce l'intero output non fidato
  (fino a `max_output_bytes`, milioni di byte) *prima* del troncamento, quindi un
  pattern con backtracking catastrofico sarebbe un ReDoS innescabile dal target.
  Regressioni + guardia di linearità in `tests/unit/test_themis_execution.py`;
  nessuna over-redazione dei campi non sensibili.

### Added — TOOLS-4 (engines list: output JSON come contratto versionato)

- `olympus engines list --format json` emette ora il **contratto versionato**
  `olympus.engine-list` 1.0.0 (`EngineListReport` con `schema_name`/`schema_version`
  e una lista `engines` di voci tipizzate: engine, category, maturity, mandatory,
  distribution, pinned_version, commit, adapter, in_scanner_image) invece di una
  lista JSON nuda. Pubblicato nel catalogo (`schemas/contracts/olympus.engine-list/
  1.0.0.schema.json`, 28 contratti totali) con direzione `output`. Con questo i tre
  comandi `engines list|doctor|preflight` espongono tutti output machine-readable
  contrattuali per l'automazione CI/CD. La logica è in `engines/listing.py`
  (`build_list_report`, puro); la tabella è invariata. **Breaking** (solo output
  JSON di `list`): i consumatori leggono ora `engines` invece dell'array top-level.
  Regressioni in `tests/unit/test_engine_doctor.py`.

### Fixed — SEC-4.2 (audit required-check: valutare l'ultimo run, non «uno qualsiasi»)

- `scripts/audit_required_checks.py` valuta ora ogni check richiesto in base al suo
  **run più recente** (per `started_at`, tie-break `id`), come fa GitHub, invece di
  considerarlo soddisfatto se *un qualsiasi* run era verde. Con la logica precedente
  (`any(conclusion == "success")`) un check il cui ultimo run era **failure** ma con
  un run precedente **success** veniva dichiarato PASS dall'audit post-merge, mentre
  GitHub lo considera rosso: una perdita di fedeltà fail-closed del gate. Ora un
  re-run fallito successivo prevale (→ non soddisfatto, `terminal_failure`), e un
  re-run riuscito successivo soddisfa il check. Nessun caso a run singolo cambia
  comportamento. Regressioni in `tests/unit/test_required_checks_audit.py`.

### Added — TOOLS-4.1 (engines preflight: output JSON come contratto versionato)

- `olympus engines preflight --format json` emette ora il **contratto versionato**
  `olympus.engine-preflight` 1.0.0 (`EnginePreflightReport` con `schema_name`/
  `schema_version`) invece di un dizionario ad-hoc. Il report porta `required`,
  `ready`, `exit_code` e `blocking` arricchito (per ogni engine bloccante:
  `name`, `state`, `detail`, `install_command`), così un gate CI/automazione può
  pinnare nome e versione e sapere esattamente cosa manca e come installarlo.
  Pubblicato nel catalogo (`schemas/contracts/olympus.engine-preflight/1.0.0.schema.json`,
  27 contratti totali) con direzione `output`. Regressioni in
  `tests/unit/test_engine_preflight.py`; gate `export_schema_catalog.py --check`.

### Added — TOOLS-4.2 (engines doctor: output JSON come contratto versionato)

- `olympus engines doctor --format json` emette ora un **contratto versionato**,
  `olympus.engine-doctor` 1.0.0 (modello Pydantic `EngineDoctorReport` con
  `schema_name`/`schema_version`), invece di un dizionario ad-hoc. Lo schema è
  pubblicato nel catalogo (`schemas/contracts/olympus.engine-doctor/1.0.0.schema.json`,
  26 contratti totali) con direzione `output`, così un consumatore CI/CD può pinnare
  nome e versione e rifiutare un report incompatibile. I campi del report (engines,
  blocking, optional_missing, exit_code) sono invariati; si aggiungono solo
  `schema_name` e `schema_version`. Regressioni in `tests/unit/test_engine_doctor.py`;
  gate `export_schema_catalog.py --check`.

### Added — TOOLS-4.2 (engines doctor: prerequisiti runtime di comando)

- Nuovo campo opzionale del manifest engine `requires_commands`: i comandi di
  sistema ausiliari che un engine invoca a runtime oltre al proprio eseguibile
  (solo nomi, mai path o command line). `engines doctor` / `inspect_engine`
  verifica ora che ogni comando dichiarato sia su `PATH` — dopo i controlli di
  presenza, versione, commit e dati — e riporta il nuovo stato
  **`prerequisite-missing`** quando ne manca uno. Lo stato è non-ok, quindi
  **blocca sotto `--strict`** (e il preflight non considera «pronto» un engine
  presente ma privo dei suoi prerequisiti): un engine installato ma inutilizzabile
  non si legge più come pronto (fail-closed). Primo caso reale popolato: `testssl`
  dichiara `hexdump`. I 23 manifest che non dichiarano il campo restano invariati.
  Regressioni in `tests/unit/test_engine_doctor.py`.

### Fixed — TOOLS-4.4 (commix: un errore di connessione non si legge come assenza di command injection)

- L'adapter commix (`themis.adapters.commix`), derivato da sqlmap, applica ora lo
  stesso schema fail-closed dell'adapter sqlmap. Una riga `[critical]` di
  connessione/accesso (`unable to connect`, `connection timed out`,
  `unable to resolve`, …) significa che commix non ha testato il target → il run è
  **`failed`** se non ci sono finding, **`partial`** se qualche finding è comunque
  presente. Il `[critical]` legittimo di commix «All tested parameters do not
  appear to be injectable» **resta un esito pulito** (nessun falso fallimento).
  Regressioni in `tests/unit/test_themis_adapters_dirsearch_commix.py`.

### Fixed — TOOLS-4.4 (wpscan: una scansione abortita non si legge come WordPress pulito)

- L'adapter wpscan (`themis.adapters.wpscan`) riconosce ora il campo `scan_aborted`.
  WPScan emette un JSON valido contenente solo `scan_aborted` (e il banner) quando
  non ha potuto valutare il sito — target non WordPress, accesso bloccato,
  rate-limit, errore — senza alcun contenitore di vulnerabilità. Prima questo si
  leggeva come «nessuna vulnerabilità WordPress» su un sito **mai valutato**; ora il
  run **fallisce fail-closed** (`ParseError`) riportando il motivo di WPScan, invece
  di apparire pulito. Un report normale (senza `scan_aborted`) resta invariato.
  Regressioni in `tests/unit/test_wpscan_adapter.py`.

### Fixed — TOOLS-4.4 (sqlmap e nikto: un errore di scansione non si legge come target pulito)

- Due adapter a exit-code (`themis.adapters.{sqlmap,nikto}`) seguono ora la
  grammatica rigorosa TOOLS-4.4, evitando che un errore di scansione produca zero
  finding letti come «nessuna vulnerabilità».
  - **sqlmap**: una riga `[CRITICAL]` di connessione/accesso (`unable to connect`,
    `connection timed out`, `unable to resolve`, …) significa che il target non è
    stato testato → **`failed`** se non ci sono finding, **`partial`** se qualche
    finding è comunque presente. Il `[CRITICAL]` legittimo di sqlmap «all tested
    parameters do not appear to be injectable» **resta un esito pulito** (nessun
    falso fallimento).
  - **nikto**: il run diventa **`partial`** quando il summary riporta `N error(s)`
    con N>0 (alcune richieste non completate) o quando è stato interrotto
    (`Scan terminated`, es. cutoff `-maxtime`); un summary con `0 error(s)` e scan
    completo resta un esito pulito.
  - Regressioni in `tests/unit/test_themis_execution.py`.

### Fixed — TOOLS-4.4 (whatweb: la copertura multi-riga non va più persa in silenzio)

- L'adapter whatweb (`themis.adapters.whatweb`) analizza ora **tutte** le righe di
  fingerprint, non solo la prima. whatweb emette una riga per URL del target: su un
  redirect (`301`→`200`) il parser leggeva solo la riga del redirect e scartava in
  silenzio quella della pagina finale, così un target che divulga tecnologie poteva
  leggersi come «nessuna tecnologia». Ora ogni riga con un fingerprint viene letta e
  le divulgazioni identiche sono de-duplicate (lo stesso banner su redirect e pagina
  finale è riportato una volta sola). Invariato: output senza alcuna riga di
  fingerprint → `failed` (`ParseError`), mai letto come target pulito. Regressioni in
  `tests/unit/test_themis_execution.py`. Con questo i **6/13 adapter non-mandatory**
  seguono la grammatica TOOLS-4.4 (restano i 7 a exit-code).

### Fixed — TOOLS-4.4 (wapiti, wafw00f, testssl: output inatteso/incompleto non si legge come run pulito)

- Tre adapter non-mandatory a report JSON (`themis.adapters.{wapiti,wafw00f,testssl}`)
  seguono ora la grammatica rigorosa TOOLS-4.4.
  - **wapiti** (report JSON): una categoria il cui valore non è una lista di
    finding, e un finding che non è un oggetto, sono conteggiati come **record
    scartati** → run **`partial`** (exit 5) via `coverage_loss`.
  - **wafw00f** (array JSON): un root JSON che non è un array ora è **`failed`**
    (prima letto come «nessun WAF»); un elemento non-oggetto è conteggiato come
    scartato → **`partial`**; `detected:false` resta un esito legittimo.
  - **testssl** (array JSON): un root non-array è **`failed`**; le righe
    informative `OK`/`INFO`/`DEBUG` (check superati) restano rumore atteso, mentre
    una riga di errore o di livello sconosciuto (es. `FATAL`, errore di scansione)
    è conteggiata come scartata → **`partial`**.
  - Regressioni in `tests/unit/test_themis_output_grammar.py`.

### Fixed — TOOLS-4.4 (katana e dalfox: output inatteso non si legge come run pulito)

- Gli adapter non-mandatory **katana** e **dalfox** (`themis.adapters.{katana,dalfox}`)
  seguono ora la grammatica rigorosa TOOLS-4.4.
  - **katana** (crawler JSONL, `-jsonl -silent -no-color`): una riga non-JSON su
    stdout e un record JSONL senza `endpoint` (non è un record di crawl) sono
    conteggiati come **record scartati** (`_skipped_records`) → run **`partial`**
    (exit 5) via `coverage_loss`. Resta `failed` l'output che non contiene alcun
    crawl record (strumento sbagliato/errore); un crawl che non raggiunge nulla
    resta un esito vuoto legittimo.
  - **dalfox** (array JSON, `--format json`): il padding `[{}]` del target pulito
    resta un esito pulito (mai conteggiato); ogni altro elemento dell'array privo
    di `payload`, o non-oggetto, è conteggiato come scartato → run **`partial`**.
    Resta `failed` l'output privo di array JSON.
  - Regressioni in `tests/unit/test_themis_adapters_projectdiscovery.py`.

### Fixed — TOOLS-4.4 (httpx: un errore su stdout o un record non-probe non si legge come run pulito)

- L'adapter httpx (`themis.adapters.httpx`) non scarta più in silenzio l'output
  inatteso. httpx gira con `-json -silent -no-color`, quindi stdout trasporta solo
  record JSONL del probe: una **riga non-JSON** su stdout (un diagnostico o un
  errore) e un **record JSONL che non è un probe** (privo di `url`) sono ora
  conteggiati come **record scartati** (`_skipped_records`) e riportati da
  `coverage_loss` → il run diventa **`partial`** (exit 5) con motivo esplicito,
  invece di passare inosservati e lasciar leggere il target come «pulito». Restano
  invariati: un output **senza alcun probe** → `failed` (collisione con il binario
  `httpx` della libreria Python, messaggio dedicato); un probe **`failed:true`** →
  esito legittimo di host non raggiungibile, non uno scarto (nessun falso parziale).
  Regressioni in `tests/unit/test_themis_adapters_projectdiscovery.py`. Con questo,
  i **3/3 adapter mandatory** (nmap, nuclei, httpx) seguono la grammatica TOOLS-4.4.

### Fixed — TOOLS-4.4 (nmap: una scansione fallita o incompleta non si legge come target pulito)

- L'adapter nmap (`themis.adapters.nmap`) distingue ora gli stati canonici invece
  di restituire «zero porte aperte» per qualunque output ben formato. nmap può
  **uscire 0 e dichiarare il fallimento** nel suo trailer
  (`<runstats><finished exit="error" errormsg="…">`): questo è un **errore noto**
  e rende il run **`failed`** riportando l'`errormsg` di nmap. Un **XML valido ma
  non-`<nmaprun>`** (strumento sbagliato sul `PATH`, documento d'errore) → `failed`,
  mai letto come target pulito. Una scansione **senza trailer di successo**, con
  l'host `state != "up"` (down/unknown) o **senza alcun record host** per il target
  → **`partial`** (exit 5) tramite il nuovo `coverage_loss`, perché in quei casi
  «nessuna porta aperta» non è un risultato affidabile. Una scansione pulita e
  completa (exit `success`, host `up`) resta invariata (nessun falso parziale).
  Regressioni in `tests/unit/test_nmap_output_grammar.py`. ROADMAP `TOOLS-4.4`
  (migrati 2/3 adapter mandatory: nmap, nuclei).

### Fixed — TOOLS-4.4 (nuclei: nessun errore su stdout si legge come run pulito)

- L'adapter nuclei (`themis.adapters.nuclei`) non ignora più in silenzio le righe
  non-JSON su stdout. `nuclei` gira con `-jsonl -silent`, quindi stdout trasporta
  solo record JSONL: una riga non vuota che non inizia con `{` è ora conteggiata
  come **record scartato** (`_skipped_records`), esattamente come un record JSON
  malformato. Di conseguenza un errore o un diagnostico stampato per errore su
  stdout (es. `[ERR] rate limit exceeded`) rende il run **`partial`** (exit 5) con
  motivo esplicito, invece di passare inosservato e lasciar leggere il target come
  «pulito». I diagnostici legittimi restano attesi su stderr; il comportamento già
  esistente per output senza alcun oggetto JSONL (`ParseError` → `failed`) è
  invariato. Nessun cambiamento alla superficie CLI. ROADMAP `TOOLS-4.4` (slice
  nuclei).

### Added — VAL-1 (finding lifecycle across the assessment history)

- Motore di lifecycle dei finding `vulcan.lifecycle.classify_lifecycle` e CLI
  `olympus vulcan lifecycle`: classifica i finding dell'ultimo snapshot contro
  l'intera storia ordinata in **nuovi / persistenti / ricomparsi / risolti**.
  «Ricomparso» (presente ora, assente nello snapshot precedente, visto in uno
  precedente) è derivato dallo storico e dall'identità logica condivisa
  (`finding_fingerprint`), **senza** introdurre un nuovo stato canonico sul
  finding; porta `absent_for` e il delta di severità dall'ultima comparsa. Puro,
  offline e deterministico, riusa identità, folding e ordinamento (`rank_key`,
  ora pubblico) di `vulcan.compare`/`vulcan.trend`. Exit code `1` quando l'ultimo
  run introduce finding nuovi o ricomparsi, `0` altrimenti. ROADMAP `VAL-1` →
  parziale.

### Added — API-4 (fail-closed CORS/origin policy)

- Policy CORS *fail-closed* sull'API Themis: `ApiSettings.cors_allowed_origins`
  e il flag ripetibile `olympus themis api --cors-allow-origin`. Di default non
  viene emesso alcun header `Access-Control-Allow-Origin`, così nessun sito
  cross-origin può leggere una risposta. Gli origin sono una allowlist esatta
  `scheme://host[:port]` (`http`/`https`, niente path/query/fragment/userinfo/
  slash finale); il wildcard `*` è rifiutato in `validate()` all'avvio e l'origin
  non è mai riflesso. Le credenziali sono ammesse solo contro l'allowlist
  esplicita, con metodi (`GET`, `POST`) e header consentiti ristretti. ROADMAP
  `API-4` → parziale.

### Added — BLUE-2 (SIEM transport boundary)

- Porta Python di dispatch SIEM `apollo.dispatch.deliver_alerts` per Splunk HEC,
  Elasticsearch `_bulk` e Azure Monitor/Sentinel: `SiemTransport` iniettato,
  `ExecutionPolicy` autorizzata, approval reference, gate scope destinazione,
  credenziali solo da env `OLYMPUS_SIEM_*`, limiti payload/response e controllo
  degli esiti applicativi HEC/Elastic. Test offline via fake transport.
  Nessun trasporto HTTP live o opzione CLI di invio attivata: serve prima
  adapter e validazione in laboratorio autorizzato.

### Added

- **BLUE-2 — Microsoft Sentinel / Azure Monitor export offline:** `apollo test` e
  `apollo run` accettano `--sentinel PATH` e producono un array JSON di record
  per la Logs Ingestion API, con campi stabili per DCR e tabella custom.
  Scrittura atomica con permessi `0o600`, nessuna rete o credenziale.
  Test di contratto, escaping, input vuoto e integrazione CLI. Il dispatch live
  resta separato e subordinato a scope e autorizzazione.

### Security

- **Supply chain: versione di gitleaks allineata tra pre-commit e CI.** Il hook
  pre-commit usava `v8.18.4` mentre la scansione CI bloccante girava su `v8.28.0`: due
  versioni (e rule set) diverse dello stesso scanner di segreti tra controllo locale e
  gate CI, con il rischio che un segreto colto da uno sfugga all'altro. Pre-commit
  allineato a `v8.28.0` (la versione, più recente, già usata in CI). Nuova guardia
  `tests/unit/test_threat_model.py::test_gitleaks_version_is_consistent_between_pre_commit_and_ci`
  impedisce il futuro disallineamento.

- **CI: `GITHUB_TOKEN` least-privilege anche in `ci.yml`.** Il workflow `ci.yml` era
  l'unico senza un blocco `permissions` **top-level**: i suoi job ereditavano lo scope
  di default del token del repository (potenzialmente con permessi di scrittura non
  necessari). Aggiunto `permissions: contents: read` a livello di workflow (come già in
  `codeql.yml`/`docker-build.yml`/`labels.yml`); il job di upload SARIF mantiene la sua
  elevazione per-job `security-events: write`. Nuova guardia di regressione
  `tests/unit/test_threat_model.py::test_every_workflow_sets_least_privilege_token_permissions`
  impone a ogni workflow un `permissions` top-level con `contents: read`.

### Fixed

- **Docs: il README dichiarava 15 engine nativi invece di 16.** La riga Themis del
  README (`Native for N of 24 catalogued engines`) era rimasta a `15` dopo l'aggiunta
  del 16° adapter nativo. Corretta a `16` (conteggio reale verificato via
  `resolve_adapter` e dai manifest con `[adapter]`). Nuova guardia di regressione
  `tests/unit/test_themis_scanners.py::test_readme_native_engine_count_matches_reality`
  lega il numero del README al conteggio reale, così un nuovo adapter deve aggiornare
  il claim e non può più divergere in silenzio. Il claim è stato aggiunto anche al
  **README italiano** (`Nativo per 16 dei 24 motori`), mantenuto in parità EN/IT, e la
  guardia ora verifica entrambe le lingue.
- **Supply chain: gli hint d'installazione degli engine derivano dal pin del
  manifest (`TOOLS-4`).** `ScannerAdapter.install` non è più una stringa scritta a
  mano ma è derivato da `engine.toml` tramite `olympus.engines.loader.install_hint`
  (singola fonte di verità). Elimina i riferimenti **mobili** `@latest` mostrati
  all'operatore per `nuclei`/`httpx` (entrambi `mandatory`), `katana` e `dalfox`, e
  il suggerimento **errato** `pip install commix` (su PyPI `commix` è un pacchetto
  di terze parti, non `commixproject/commix`: rischio di dependency-confusion); ora
  l'hint è il comando esatto e pinnato che la build verifica. Gli hint non possono
  più divergere dal pin. **Esteso al catalogo** `olympus.integrations.scanners`:
  anche `ScannerSpec.install` (mostrato da `olympus themis scanners`) deriva ora dal
  pin del manifest, chiudendo gli stessi riferimenti non pinnati e i suggerimenti al
  pacchetto PyPI errato per `commix` e `theHarvester` (entrambi distribuiti da `git`).
  Nuovo test di regressione `tests/unit/test_engine_install_hints.py` vieta ogni
  riferimento mobile o pacchetto errato e àncora adapter **e** catalogo al manifest.

### Added

- **Apollo: export degli alert in Elasticsearch `_bulk` (`BLUE-2`).** Nuovo
  `olympus.apollo.elastic` e opzioni `--elastic-bulk` / `--elastic-index` su
  `apollo test`/`apollo run` che scrivono gli alert come corpo di richiesta
  `_bulk` (riga azione `create` keyata sull'`alert_id` + documento ECS, newline
  finale), file owner-only `0o600`. Ingest idempotente per `alert_id`; formatter
  puro e offline accanto a ECS/OCSF/HEC, la consegna live al cluster resta
  separata e gated. Secondo formatter offline di BLUE-2.
- **Engine: preflight fail-closed condiviso e comando `olympus engines preflight`
  (`TOOLS-4.1`).** Nuovo servizio puro e offline `olympus.engines.preflight` (I/O
  iniettato, nessuna rete né target) che decide se una scansione può partire: richiede
  ogni engine `mandatory` (nmap, nuclei, httpx) più quelli nominati con `--engine`, ed
  esce **8** (`ENGINE_MISSING`) con il comando d'installazione **pinnato** per ogni engine
  assente/sbagliato, **0** se tutto è pronto; gli engine `api`/commerciali non bloccano mai
  (nessun artefatto locale). Pensato come gate operatore/CI prima di lanciare una scansione.
  La decisione è fail-closed per costruzione: un engine assente è deciso senza avviare
  alcun processo (il probe non viene raggiunto). **Primo cablaggio in `themis preview`:** il
  preview ora riporta la prontezza dell'engine richiesto (solo lookup su PATH, nessuna
  esecuzione) in output umano e JSON (`engine_ready`/`engine_install`), e il nuovo flag
  opt-in **`--require-engine`** fa uscire il preview con **8** se l'engine governato non è
  pronto. Il gate ora usa la **readiness completa** scope-ata al singolo scanner (binario,
  tool corretto, versione/commit rispetto al pin **e dipendenze dati pinnate**, es. i
  template di nuclei) via `olympus.engines.preflight.scanner_readiness` — non più solo la
  presenza del binario, così `nuclei` con template al commit sbagliato è correttamente «non
  pronto». Così un'automazione può gatare una scansione sulla prontezza reale. Default
  invariato: un preview normale descrive soltanto (nessun processo avviato). Resta da cablare
  l'invocazione automatica negli altri percorsi (run/API/Web/worker) con la parità
  cross-interfaccia e la verifica in CI/lab.

- **Apollo: export degli alert in Splunk HEC (`BLUE-2`).** Nuovo
  `olympus.apollo.hec` e opzione `--hec` su `apollo test`/`apollo run` che
  scrivono gli alert come envelope Splunk HTTP Event Collector (NDJSON,
  owner-only `0o600`), con il documento ECS riusato come payload `event`.
  Formatter puro e offline accanto a ECS (`--ecs`) e OCSF (`--ocsf`); la consegna
  a un SIEM live resta un passo separato e gated. Primo tassello offline di BLUE-2.

- **Demo: pagina dashboard statica (`DEMO-2`).** Nuova `public/dashboard.html`
  (voce nav "Dashboard") che riproduce la dashboard operativa nella demo Vercel:
  stato sistema con le versioni reali, findings per severità e copertura ATT&CK per
  tattica prodotti dai motori reali (`severity_breakdown`, `tactic_counts`) su dati
  sintetici etichettati; conteggi job illustrativi. Mantiene la demo fedele alla
  Web UI dopo l'incremento WEB-4. Offline, coperta dal drift gate preview.
- **Dashboard WEB-4: card stato sistema e coverage ATT&CK per tattica.** La
  dashboard principale `/` guadagna una card **System status** (versione della
  piattaforma, versione della mappa ATT&CK e stato per-sottosistema
  configurato/non configurato — job store, catalogo/lifecycle/baseline findings,
  engagements, incidenti, rule pack Apollo) e una sezione **Tactic coverage** che
  mostra le tecniche distinte per tattica ATT&CK tramite il nuovo helper offline
  `olympus.vulcan.attack.tactic_counts`. Tutto read-only e derivato dalle sorgenti
  reali già esposte, gated per scope; con questo `WEB-4` è completo.
- **Workbench Argus e Artemis su Web e API (`WEB-3` / `API-2`).** Due slice offline
  che completano la copertura Web per-tool dell'ecosistema. **Argus:** `GET /argus`
  + `POST /api/v1/argus/ct-subdomains` (`olympus.argus-ct-subdomains` `1.0.0`)
  estraggono i sottodomini in-dominio da un export Certificate Transparency
  (crt.sh JSON) con il core condiviso `parse_crtsh_response` — normalizzati,
  deduplicati, ordinati; nessuna query CT inviata. **Artemis:** `GET /artemis` +
  `POST /api/v1/artemis/fingerprint` (`olympus.artemis-fingerprint` `1.0.0`)
  effettuano il fingerprint passivo di una risposta HTTP acquisita (status, header,
  body opzionale) contro le signature tecnologiche con il core condiviso
  `fingerprint_response` — nessuna richiesta inviata. Nuovi scope `argus:read` e
  `artemis:read`; CSRF, rate limit e bound su input sulla Web. Demo statiche
  `public/argus.html` e `public/artemis.html` generate dai motori reali. Con questo
  incremento ogni tool dell'ecosistema ha una pagina Web dedicata.
- **Pianificatore Athena su Web e API (`WEB-3` / `API-2` / `INT-3`).** Nuovo
  workbench `GET /athena` e slice tipizzata `GET /api/v1/athena/profiles`
  (`olympus.athena-profile-list` `1.0.0`) + `POST /api/v1/athena/plan`
  (`olympus.athena-plan` `1.0.0`): si scelgono un profilo di scansione (target-free),
  uno o più target autorizzati, lo scope d'ingaggio e un riferimento di
  autorizzazione confermato, e si ottiene un piano firmabile `olympus.athena.plan`
  con digest del piano e dello scope, pronto per `olympus athena run`. Browser, API
  e CLI (`athena plan from-profile`) usano lo stesso core offline
  `ScanProfile.build_plan`, quindi producono piani identici. Nuovo scope
  `athena:read`; CSRF, rate limit e bound su target/domini. La costruzione è
  deterministica e senza rete: genera un documento, non esegue alcuna scansione, e
  un profilo non si auto-autorizza mai (senza conferma esplicita la richiesta è
  rifiutata con 422). Demo statica `public/athena.html` generata dal motore reale.
- **Verifica della catena di custodia Minerva da Web e API (`WEB-3`/`API-2`/`INT-3`).**
  Nuovo workbench `GET /minerva` + `POST /minerva/verify` e endpoint tipizzato
  `POST /api/v1/minerva/verify-ledger` (contratto `olympus.minerva-ledger-verification`
  `1.0.0`): si incolla un ledger `olympus.custody` e la catena di hash è verificata
  offline dallo stesso motore della CLI. Il core è stato rifattorizzato estraendo
  `inspect_ledger_text(text, …)`, condiviso da CLI/API/Web. Nuovo scope
  `minerva:read`; firma Ed25519 verificata quando il server è avviato con
  `--minerva-custody-public-key <file>` (chiave pubblica, non segreto), altrimenti
  un ledger firmato è riportato come non verificato. Nessun input di chiavi, path o
  evidenze dal client; CSRF, rate limit e audit esistenti mantenuti. Demo statica
  `public/minerva.html` che verifica il ledger d'esempio con il motore reale.
- **Workbench Metis di estrazione CTI su API e Web (`WEB-3` / `API-2`).** Nuovo
  motore condiviso offline `olympus.metis.extraction.extract_from_source` che
  unifica testo libero, bundle STIX 2.1 e eventi MISP in un'unica forma onesta
  (indicatori normalizzati + elementi scartati con motivazione). `POST
  /api/v1/metis/extract` espone il contratto versionato `olympus.metis-extraction`
  `1.0.0`; la pagina Web `/metis` riusa lo stesso motore (scope `metis:read`, CSRF,
  rate limit, input e numero di item limitati). Parsing locale e deterministico,
  nessuna raccolta o chiamata di rete; un set vuoto di indicatori non implica input
  pulito quando ci sono elementi scartati. Demo statica `public/metis.html`
  generata dal motore reale. Doc [`docs/web.md`](docs/web.md); test
  `tests/unit/test_metis_extraction.py`, `tests/unit/test_themis_api.py`,
  `tests/unit/test_themis_web.py`, `tests/unit/test_build_preview.py`.
- `olympus core restore-drill --jobs`: il drill copre anche il database job Themis;
  `ThemisJobStore.backup` non lascia più sidecar `-wal/-shm` orfani (ROADMAP `WEB-J-01`).
- `olympus themis scope backup|verify-backup|restore`: validated, create-only,
  owner-only snapshots of the Themis scope file (ROADMAP `WEB-J-01`).
- **Test browser reale per gli stati dello store Web (`WEB-B-01`).** Chromium via
  Playwright (opzionale, saltato se assente) conferma che store corrotti non
  appaiono come vuoti.
- **Demo interattiva a fixture su Vercel (`WEB-K-c`).** `public/demo.html` e
  `demo-report.html` generati da `scripts/build_preview.py`: job simulato
  recon → scan → enrich → report con output registrati, parser e renderer reali,
  nessuna esecuzione; CSP `script-src 'self'` solo sulla route `/demo`.
- **Wizard New Assessment guidato (`WEB-E`).** La Web UI Themis espone un flusso
  activity-first (`GET /assessments/new`): engagement → target → scope → tipo di
  attività (recon/network/web/vulnerability) → tool o **Automatic** → anteprima
  "Olympus is about to run" (`POST /assessments/preview`, che non accoda nulla e
  ri-valida scope ed engagement) con classe di rischio `PASSIVE`/`ACTIVE`/
  `INTRUSIVE` → autorizzazione → launch (`POST /jobs`) → stato SSE reale. Secret
  Scan/Detection/Full sono dichiarate oneste come gestite da altri moduli con
  hint CLI, mai simulate; Automatic rifiuta se nessun tool è `ready`. Nuova
  classificazione interface-agnostica `olympus.integrations.activity` (attività
  dalla categoria del registry, rischio da mappa revisionata con default sicuro
  `ACTIVE`, riassunti in linguaggio semplice), modalità Advanced e enhancement
  progressivo conforme alla CSP. Doc [`docs/web.md`](docs/web.md); test
  `tests/unit/test_scanner_activity.py` e `tests/unit/test_themis_web.py`.

### Changed
- **Runtime Themis nativo (`SEC-A`, primo punto).** `serve`/`web` avviano la stessa
  Web UI autenticata; `migrate` aggiorna il database job nativo con rifiuto di
  database legacy/estranei e versioni non supportate; `workers` usa SQLite,
  lease e cancellazione SIGINT/SIGTERM senza Redis/Celery/Alembic. Diagnostica
  senza modifiche a `sys.path`, extra `themis` ridotto al web stack nativo.
  Docker/Compose distribuiscono la wheel senza `vendor/`, con utente non-root,
  rootfs read-only e TLS/identità obbligatori. Smoke wheel e container in CI,
  test del lifecycle condiviso e guida IT/EN con backup/rollback.
  Il sorgente VAP resta archiviato per la successiva matrice completa di parità;
  `vap.db` non viene convertito e i vecchi flag Celery/web legacy sono rimossi.
  Corretto un falso positivo documentale del secret scan storico tramite il
  fingerprint esatto del finding; nessuna allowlist generale aggiunta.
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

### Fixed
- **Test deadline/timeout del coordinator Athena reso deterministico
  (`fix(verify)`).** Il runner di test `_Runner(block=True)` dormiva per un tempo
  fisso (1.2s) che correva contro la finestra di attesa del coordinator (~1.0s):
  con un margine di 0.2s, una macchina sotto carico poteva far terminare il
  worker *prima* che `wait()` scadesse, così il job veniva classificato come
  `SUCCEEDED`/`TIMED_OUT` per completamento invece di esercitare il percorso di
  cancellazione per deadline sotto test (flakiness osservata in
  `test_deadline_limits_running_batch`). Ora il runner finto rispetta il token di
  cancellazione cooperativa (con un tetto di sicurezza), eliminando la race e
  modellando un adapter ben educato. Nessuna modifica al codice di produzione: il
  coordinator resta corretto. Test: `tests/unit/test_athena_engine.py`.

### Security
- **Hash Gravatar MD5 marcato `usedforsecurity=False` in `argus.email_osint`
  (`fix(verify)`).** L'MD5 serve solo a ricostruire l'URL pubblico dell'avatar
  Gravatar, non come primitiva di sicurezza. Dichiararlo esplicitamente comunica
  l'intento al backend `hashlib` e agli analizzatori statici, azzerando l'unico
  finding Bandit di severità *High* (B324) sull'albero sorgente senza alterare il
  digest prodotto. Test invariati: `tests/unit/test_argus_email.py`.

### Added
- **Web control plane nativo (`WEB-A`).** Nuova interfaccia browser
  `olympus.themis.web` (FastAPI + Jinja2 + server-sent events) servita da
  `olympus themis web`, costruita **sopra** l'API Themis esistente senza
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
  references and Metis cases without inventing missing provenance (`DEV-D`).
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

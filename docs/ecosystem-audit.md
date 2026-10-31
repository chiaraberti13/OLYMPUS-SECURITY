# Audit multidisciplinare — 28 ottobre 2026

Baseline `main`: `b5cc491ac466fc5875a40266151e3aa55730c82e`, versione package 0.2.0.
Clone nuovo, working tree pulito, origin HTTPS del repository chiaraberti13/OLYMPUS-SECURITY;
nessun tag nel clone. Commit recenti: PDF Web b5cc491, sezioni report 0b8d671,
riconciliazione CI 2cdbffd/352b9dc. Nessuna modifica concorrente presente localmente.
Le prospettive prodotto, architettura, AppSec/offensive, Blue/DFIR, backend,
frontend, UX/accessibilità, dati, QA/SRE, privacy e documentazione sono analisi
tecniche degli agenti, non consultazioni con persone reali.

La slice P0 `SEC-E-01` è stata implementata e verificata (commit `e8dea67`,
51 test mirati dopo merge); il finding descrive il baseline. Restano aperti il
confinamento scanner P0 e gli altri gap tracciati: nessuna readiness professionale
è dichiarata. Esiti e limiti finali nella pagina verification-status.

## Riallineamento del 29 ottobre

`origin/main` è avanzato a `e177498e7982c5ae41abc2207de561e42ec8791d`.
I commit 91d60d4/108a30b/f55825d/e177498 sono stati integrati senza riscrittura:
transizioni finding da CLI, allocazione ID per restart, creazione engagement
insert-only, cifratura bundle finding/asset. Revisionati i diff di codice/test/docs;
la verifica generale è ripetuta sul merge `bca1daa`. L'inventario JSON resta una
fotografia del baseline, non viene falsamente presentato come albero finale.

Le allocazioni `next_engagement_id` e `next_transition_id` correggono restart
sequenziali ma leggono prima di un INSERT distinto: non prenotano l'ID contro
writer simultanei. INSERT protegge la perdita dati; rimane possibile un conflitto
operativo. Disposizione `DEV-E-03` (rischio statico, non race riprodotta).
La branch API GitHub indica `protected=false` e nessun required status check al
momento della lettura; nessuna policy remota è stata modificata.

## Metodo e copertura

Inventario di **632 file tracciati**, 234 sotto src, 215 sotto tests, 55 sotto docs;
418 file Python complessivi. [Manifest baseline](verify/audit-2026-10-28-inventory.json)
registra ogni percorso, dimensione e digest. È un inventario, non prova che ogni
riga sia stata revisionata. Ispezione semantica mirata di tutte le famiglie di
componenti di prima parte, contratti, test, deployment e documentazione; profondità
maggiore su autorizzazione, esecuzione, persistenza, UI e release.
**L'audit non è una revisione esaustiva riga per riga né una certificazione.**
Resta parziale nella verifica dinamica: browser/accessibilità manuale, scanner
reali, container, licenze upstream, matrice OS/Python, carico e crash/restore
completo richiedono le attività canoniche indicate sotto.

Presenti: src/olympus, tests, pyproject, Makefile, README IT/EN, ROADMAP,
SECURITY, threat model, ADR, schemas, examples, Docker/Compose/deploy/labs.
Assenti: AGENTS.md, vendor runtime, lock/constraints runtime con hash committato,
workflow qualità/release (esiste solo labels.yml), suite browser Playwright/axe.
Schemi generati esaminati tramite catalogo/check; fixture/esempi tramite contratti
ed esecuzioni test; immagini binarie non sottoposte ad analisi semantica; Git
object/cache/build esclusi. Nessuna attività network-active verso target.

Stack verificato in pyproject: Python >=3.11, Typer/Click, Textual, Pydantic 2,
SQLite stdlib, FastAPI/Jinja2/uvicorn extra API, reportlab extra report,
Prometheus/OTel opzionali. Dipendenze prevalentemente con limite minimo, quindi
installazioni future non riproducibili senza lock. Installazione pulita locale
in venv Python 3.12.14 con dev/api/report/observability. Offline-first significa
fixture e import/export locali; lookup/feed/scanner richiedono rete e autorizzazione.

## Mappa responsabilità e contratti

| Componente | Responsabilità/entry point e I/O | Superfici e maturità/criticità |
|---|---|---|
| core | modelli Pydantic, execution/scope HTTP/pinning, file I/O, crypto, contratti JSON, SBOM/retention/observability | CLI e servizi condivisi; lettori FIFO ora non bloccanti |
| engagements / findings | manifest firmati, revoca, record engagement SQLite; lifecycle finding e transizioni | CLI/API/Web; schema fisico/backup da uniformare |
| Argus | recon/OSINT DNS/RDAP/HTTP, pipeline/graph/diff | CLI/TUI, adapter Athena; lookup dipendono dalla rete, test offline non equivalgono a lab |
| Athena | dominio/ports/application separati, coordinator e SQLite, piani/result/audit | CLI/TUI; adapter dns/whois/web-headers/themis (quest'ultimo nmap); P0 audit restart |
| Themis | 15 adapter, parser/runner/sandbox, SQLite jobs/lease/retry/recovery | CLI/TUI/API/Web/worker; egress, plugin e release non completi |
| Helios / Artemis | discovery rete / assessment web, HTTP e scope condivisi | CLI/TUI; validazione live limitata dal lab |
| Hermes | secret scanning file/git, baseline, SARIF | CLI/TUI e hook; segreti sintetici nei test, non prova Gitleaks history |
| Apollo | Event ingest, regole exact-match, Sigma subset, ECS/OCSF | CLI/TUI/Purple; coverage non dimostra detection end-to-end |
| Minerva | incident triage, timeline, evidence vault e custody firmata | CLI/TUI, lettura dashboard; non case management Web completo |
| Metis | planner/capability e CTI case SQLite, STIX/MISP subset offline | CLI/TUI; import/export non connettori live, backup parziale |
| Vulcan | dedup/rank, CVE/EPSS/KEV, finding diff/trend, JSON/MD/HTML/CSV/PDF/SARIF | CLI/TUI e Web; punto unico per remediation/retest/report |
| Proteus | modello campagne e training sintetico | CLI/TUI; nessun servizio reale invio/harvesting dimostrato |
| integrations / tui | catalogo readiness/maturity e navigazione Click | discovery plugin separata da runtime; TUI esclude config/engagement/policy |
| tests/scripts/tools | unit/contract/integration/property/mutation, schema/link, benchmark, labels | gate locali; browser e enforcement remoto mancanti |
| docker/deploy/labs | wheel native, split control/scan, attestation/AppArmor, lab Mars | configurazioni presenti, esecuzione non verificata qui |

## Flussi, utenti e risultati

Operatori assessment: installazione→doctor→configurazione manuale TLS/identità/scope→
engagement firmato→preview→job→finding→triage→report. Il Web è collegato ai servizi,
ma onboarding, autorizzazione e creazione engagement richiedono ancora CLI/admin.
La TUI usa argomenti liberi: schema form presente non significa form consumato.
Il percorso Athena recovery/cancel può perdere audit (P0 riprodotto).
Finding lifecycle/dedup e report esistono; correlazione/retest multi-run non deve
essere confusa con validazione automatica della vulnerabilità. Le fixture parser
non dimostrano falsi positivi/negativi del motore né compatibilità versione reale.

SOC/DFIR: ingest→Event→regola→Alert→Minerva→custody→Vulcan è composto da servizi
reali, con subset Sigma/STIX/MISP dichiarati. Coverage Apollo misura presenza tipo
telemetria, non prova regola efficace. Connettori SIEM/EDR/CTI e loop Atomic richiedono
lab. Governance: retention/accessi/provenance disponibili come primitive; non è
provata conformità normativa o conservazione probatoria opponibile.

Metriche di uscita prodotto: successo dei flussi critici offline; zero errori
presentati come clean/empty; zero perdita audit; tempo onboarding misurato con
operatori; denominatori FP/FN su dataset annotato; tempo triage/retest; p95/lock
sotto carico dichiarato. Nessun valore misurato viene inventato.

## Finding e disposizioni canoniche

Fatti statici, riproduzioni dinamiche e rischi dedotti sono distinti nella tabella.
Ogni finding ha un ID figlio di una voce esistente in ROADMAP; le madri non sono
completate dalla singola slice. Priorità P0 audit deriva da perdita verificata;
P0 egress da controllo di confinamento assente, senza exploit live eseguito.

| ID / madre | Evidenza e natura | Conseguenza | Disposizione |
|---|---|---|---|
| `SEC-E-01` | Dinamica: sqlite.append_audit sostituisce la stessa chiave; coordinator._sequence riparte da zero | Perdita dello storico durante recover/cancel; probabilità alta al riavvio, impatto probatorio alto | P0: INSERT rigoroso e allocazione sequenza atomica nel sink persistente; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-B-01` | Statica: base.py valida DNS; nmap.py usa ancora hostname; scan-egress senza allowlist | Possibile traffico fuori scope; impatto critico, probabilità dipende dal motore; exploit non eseguito | P0: Pinning compatibile con ogni protocollo ed egress per-job fail-closed; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-H-01` | Statica e semantica stdlib: api.ApiSettings.validate resolve prima di is_symlink | Controllo inefficace su directory configurate; impatto alto, probabilità dipende da accesso locale | P1: completato 2026-10-31; controllo del percorso originale prima di resolve e test su link validi/rotti per scope, finding, baseline e incidenti. Link nei parent e TOCTOU restano rischi residui; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-H-02` | Primitiva OS riprodotta: open FIFO bloccava prima di fstat; fileio.py | DoS locale con input speciale; probabilità condizionata, impatto disponibilità alto | P1: completato 2026-10-31; i due reader aprono non-blocking, verificano il descriptor e mantengono no-follow/limiti; test subprocess con deadline; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-D-01` | Statica: tui/app.py stampava argv grezzo | Potenziale esposizione token/URL nel terminale; probabilità condizionata, impatto alto | P1: completato 2026-10-31; formatter condiviso maschera opzioni secret e URL nel log TUI senza alterare l'argv del subprocess; test con token sintetici; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-G-01` | Statica: terminate solo figlio immediato, nessun gruppo/cleanup robusto | Rischio figli sopravvissuti, non riprodotto; impatto alto | P1: in corso 2026-10-31; process group POSIX e cleanup Windows implementati; test locale dimostra parent+child POSIX. Restano verifica Windows e chiusura UI durante il job; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-E-01` | Statica: transizioni senza CAS; stato e append audit in transazioni separate | Race o crash poteva lasciare stato senza audit; rischio dedotto alto | P1: completato 2026-10-31; CAS e update+audit atomici per job/assessment; test a due connessioni e fault injection del fallimento audit provano rollback; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-E-02` | Statica: load_result non confrontava digest/lunghezza persistiti | Corruzione o modifica del documento senza aggiornamento metadati poteva passare la validazione | P1: completato 2026-10-31; lettura verifica lunghezza, SHA-256, ID derivato e binding assessment/job; regressione con JSON valido alterato. Un writer DB capace di aggiornare tutti i metadati resta fuori dalla garanzia; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-E-01` | Statica: transizioni senza CAS; stato e append audit in transazioni separate | Race o crash può lasciare stato senza audit; rischio dedotto alto | P1: CAS sullo stato persistito e unità di lavoro stato+audit; outbox se necessaria; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-E-02` | Statica: load_result legge document senza sha256/length salvati | Corruzione JSON valida non rilevata; probabilità non misurata, impatto alto | P1: Verificare digest/lunghezza e binding identity prima del consumo; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-B-01` | Dinamica: classe astratta accettata; statica: available_adapters non consumata dal runtime (baseline 2026-10-28) | Plugin dichiarato integrato non eseguibile; impatto funzionale alto | P1: corretto il 2026-10-31; resolver runtime/preview condiviso, metadata provenance, rifiuto abstract/duplicati/native name/override e test offline end-to-end; firma resta SEC-F; [roadmap](../ROADMAP.md#dev-b-01--plugin-concreti-e-realmente-integrati) |
| `DEV-D-01` | Statica: CREATE IF NOT EXISTS; solo job store ha user_version | Upgrade futuro non controllato; rischio dedotto | P1: Versioni fisiche, migrazioni transazionali e rifiuto schema futuro; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `WEB-J-01` | Statica: backup Metis parziale; verify_backup non esegue integrity_check/FK | Recovery piattaforma non dimostrato; impatto alto | P1: Snapshot coerente con digest/versioni, chiavi separate, integrity/FK e restore drill; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `WEB-J-02` | Statica: primitive retention presenti, applicazione globale non dimostrata | Policy diverse possono cancellare prove o lasciare copie; rischio dedotto | P2: Policy per engagement, legal hold, minimizzazione, chiavi e backup; documentare accessi e finalità; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-C-01` | Statica: solo labels.yml; make check locale, nessun lock runtime committato | Release non automaticamente verificata; impatto alto | P1: Workflow least privilege con pin SHA, matrice 3.11–3.14/OS, wheel, test, coverage/mutation, schema/link/security; branch policy verificata; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-F-01` | Statica: pip/git/gem mobili e || true; WPScan non-OSI classificato OSS | Composizione immagine e diritto distribuzione non dimostrati; impatto alto | P1: Pin/hash/versioni, manifest installato, mandatory vs optional, revisione licenze per versione; SBOM/advisory/signing; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `SEC-F-02` | Statica: _direct_dependencies interpreta extra con regex, non marker PEP 508 completi | SBOM/lock possono includere/escludere dipendenze errate; rischio dedotto | P1: Parser standard requisiti e propagazione extra transitivi; schema CycloneDX validato; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-G-01` | Statica: audit storico, testing, verification-status e roadmap contengono claim CI obsoleti | Operatori possono confondere codice/test storico con readiness | P1: Snapshot attuale distinto; inventario generato, link gate, completare ADR 003–005 e policy mypy coerente; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `UX-A-01` | Dinamica: config/engagement/policy assenti TUI; statica: cli_forms non consumato | Onboarding incompleto e claim intero albero falso | P1: Navigazione completa e form realmente collegati mantenendo escape hatch; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `WEB-A-01` | Statica: app.js close su error, server termina stream dopo 300s | Job lunghi perdono aggiornamenti; probabilità alta oltre limite | P1: Retry bounded, stato connessione, refresh manuale e terminal close; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `WEB-B-01` | Statica: eccezioni convertite in [] o widget omessi | Guasti mascherati da assenza dati; impatto decisionale alto | P1: Stati unavailable/not-configured/empty distinti con errori redatti; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `WEB-G-01` | Statica: list(limit=200) etichettata jobs total | Conteggi parziali fuorvianti con più job | P2: Aggregati SQL o etichetta finestra esplicita, nessuna omissione job attivi; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `OPS-PURPLE-01` | Dinamica: dict solo event_type accettato e JSON malformato ignorato | Falsa fiducia copertura; impatto alto | P1: Validare Event, contare scarti/troncamento; distinguere presence/schema/match/test pass; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `UX-E-01` | Statica: lang=en/stringhe EN; TestClient non browser; live region assente | Fruibilità non dimostrata, impatto utenti alto | P1: Cataloghi IT/EN, tastiera/focus/live region, browser axe e review screen reader/contrasto; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `DEV-E-02` | Statica: chiave sessione e rate limiter locali al processo | Multiworker incoerente; rischio dedotto | P2: Documentare single-worker; misurare p95/lock/errori prima di session store/Postgres; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |
| `OPS-SCAN-01` | Inventario: 24 catalogati, 15 adapter; live storico non rieseguito | Espansione non verificata accresce manutenzione e rischio | P2: Completare adapter e flussi prima di nuovi tool; schede proposta e gate per ogni livello; [roadmap](../ROADMAP.md#riconciliazione-audit-2026-10-28) |

## Decisioni e compromessi

- **Audit durevole:** adottare sequenza assegnata nello store, non offset del
  coordinator (race tra processi) né solo INSERT (romperebbe recovery dopo una
  transizione). Conservare INSERT rigoroso per import esplicito. ADR-008 registra
  i limiti: stato/audit non ancora unica transazione, nessuna protezione da DBA ostile.
- **SQLite:** conservare default single-node. Postgres e code esterne hanno costi
  di gestione; introdurli solo con misure di lock/p95/RPO e requisiti multi-host.
- **Tool:** completare moduli competenti prima di aggiungerne. Nessun nuovo modulo
  mitologico necessario; Hermes non è asset inventory, Themis non va duplicato in
  Aegis, Hephaestus resta proposta da giustificare. Proposte sotto OPS-SCAN-01.
- **Maturità:** catalogato/implementato/offline/lab/candidato/rilasciato sono fasi
  diverse. `live-tested` nel ledger è storico, non verifica della sessione. Un
  candidato richiede DoD, manifest/digest/SBOM/advisory/versioni; rilasciato richiede
  tag/artefatti firmati e run verificabili. Nessun adapter promosso qui.
- **UI e sicurezza:** correggere stati e flussi prima di espandere catalogo.
  Single-worker Web finché sessioni e quota per processo non sono rese condivise.
- **Supply chain/licenze:** metadata del catalogo non sono verifica legale. La
  classificazione WPScan non-OSI/OSS va riconciliata; Nmap richiede verifica della
  licenza della versione distribuita. Nessuna compatibilità legale attestata.

Alternative, owner, dipendenze e criteri di riesame sono nella roadmap. Evidenze
storiche restano in git; questo documento sostituisce lo snapshot operativo 2026-08.
Le verifiche eseguite e i limiti sono in [verification status](verification-status.md).

## Inventario completo scanner al baseline

Licenze: metadata dichiarati, non verifica legale/upstream. Esecuzione network-active; parser/fixture offline. Prerequisiti comuni: adapter, binario/API, autorizzazione/scope/sandbox. Superfici CLI/API/Web e TUI tramite CLI; contratto ScanRequest/ScanResult/Finding. Test tests/unit/test_themis* e contract. Limiti: SEC-B-01, versioni/lab non rieseguiti, nessuna promozione di maturità.

| Nome | Responsabilità | Prerequisito | Licenza dichiarata | Maturità storica | Evidenza/limite |
|---|---|---|---|---|---|
| nmap | Network port & service enumeration | nmap | GPL-2.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| nikto | Web server misconfiguration scan | nikto | GPL-2.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| whatweb | Web technology fingerprinting | whatweb | GPL-3.0 | offline-tested | tests/unit/test_themis_execution.py; No authorized live run yet: the captured run failed on a broken Ruby environment, so the adapter has never parsed real engine output. |
| wafw00f | WAF detection | wafw00f | BSD-3-Clause | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| sqlmap | SQL injection detection/exploitation | sqlmap | GPL-2.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| arjun | HTTP parameter discovery | arjun | AGPL-3.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| wapiti | Web application vulnerability scan | wapiti | GPL-2.0 | offline-tested | tests/unit/test_themis_execution.py; No authorized live run through the scope-gate yet: the committed evidence is a real wapiti JSON report (labs/mars) exercising the parser only. |
| commix | Command-injection detection | commix | GPL-3.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| xsstrike | XSS detection | xsstrike | GPL-3.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| dirsearch | Content/path discovery | dirsearch | GPL-2.0 | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| nosqlmap | NoSQL injection detection | nosqlmap | GPL-3.0 | catalog-only | Nessun adapter |
| nuclei | Template-based vulnerability scan | nuclei | MIT | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| httpx | Fast HTTP probing/toolkit | httpx | MIT | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| katana | Crawling / endpoint discovery | katana | MIT | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| subfinder | Passive subdomain enumeration | subfinder | MIT | catalog-only | Nessun adapter |
| dalfox | XSS scanning/parameter analysis | dalfox | MIT | live-tested | docs/themis-execution-evidence.md; Definition of Done incomplete: no per-adapter evidence manifest or SBOM. |
| testssl | TLS/SSL configuration analysis | testssl.sh | GPL-2.0 | offline-tested | tests/unit/test_themis_execution.py; No authorized live run yet: the captured evidence covers the parser only. |
| theharvester | OSINT email/subdomain harvesting | theHarvester | GPL-2.0 | catalog-only | Nessun adapter |
| wpscan | WordPress vulnerability scan | wpscan | WPScan Public Source (non-OSI) | catalog-only | Nessun adapter |
| zap | OWASP ZAP DAST (API/daemon) | API/daemon e credenziali | Apache-2.0 | catalog-only | Nessun adapter |
| openvas | OpenVAS/GVM network vulnerability scan | API/daemon e credenziali | GPL-2.0 | catalog-only | Nessun adapter |
| nessus | Tenable Nessus vulnerability scan | API/daemon e credenziali | Commercial (Tenable) | catalog-only | Nessun adapter |
| burp | PortSwigger Burp Suite (Pro API) | API/daemon e credenziali | Commercial (PortSwigger) | catalog-only | Nessun adapter |
| acunetix | Invicti/Acunetix DAST | API/daemon e credenziali | Commercial (Invicti) | catalog-only | Nessun adapter |

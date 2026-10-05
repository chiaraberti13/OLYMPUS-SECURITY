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
| 1 | Security hardening (**P0**) | `[~]` | `SEC-A`, `SEC-B`, `SEC-C`, `SEC-H`, `UX-B` |
| 2 | Architettura e qualità di release | `[~]` | `DEV-A`, `DEV-B`, `DEV-C`, `DEV-D`, `DEV-E`, `SEC-F` |
| 3 | UX operativa bilingue | `[ ]` | `UX-A`, `UX-C`, `UX-D`, `UX-E`, `UX-F`, `UX-G` |
| 4 | Capability Red/Blue/Purple | `[~]` | `OPS-RED`, `OPS-BLUE`, `OPS-PURPLE`, `OPS-SCAN` |
| 5 | Production readiness scanner | `[ ]` | `D1`, `D2` |
| 6 | Distribuzione e osservabilità | `[~]` | `DEV-E`, `DEV-F`, `SEC-F` |
| 7 | Rename Themis + Web control plane | `[~]` | `DEV-I` ✓, `WEB-A` ✓, `WEB-B` ✓, `WEB-C` ✓, `WEB-D` ✓, `WEB-E`…`WEB-J` |

L'ordine di esecuzione concordato per la Fase 7 mette le **fondamenta dati prima
delle interfacce**: `DEV-I` (rename) → `WEB-B` (engagement entità di primo
livello) → **Finding strutturato** (`WEB-C`, campi CVE/CWE/EPSS/KEV tipizzati con
migrazione) → `WEB-A` (API/SSE + web skeleton sicuro) → `WEB-D` (tools) →
`WEB-E` (new assessment) → `WEB-C` (findings UI) → `WEB-J`/`WEB-I` (dati e
reporting) → `WEB-F` (smart scan) → `WEB-H` (persistenza) → ritiro runtime VAP
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
| Architettura | `src/olympus/` contiene moduli separati e un contratto dati comune | runtime `themis api/serve/migrate/workers` nativo e testato dalla wheel; resta la parità completa endpoint/dati legacy (`SEC-A`) |
| Sicurezza runtime | `core.execution`, `core.http`, `core.pinning`, `aegis.sandbox` | manca un egress allowlist per gli scanner e non sono applicati seccomp/AppArmor |
| Credenziali | i segreti first-party sono letti dall'ambiente e redatti | manca un backend opzionale per secret manager e una policy uniforme di rotazione |
| Autorizzazione | scope file + conferma esplicita prima dell'esecuzione | lo scope non è ancora un engagement manifest firmato, con scadenza e approvatore |
| Supply chain | SBOM, hash lock, audit dipendenze e secret scan | mancano attestazioni di build, firma immagini/release e SAST CodeQL bloccante |
| Qualità | Ruff lint/format, Mypy strict, pytest portabile 3.11–3.14, branch coverage first-party ≥75% e mutation score mirato ≥35% per funzione sono gate obbligatori; unit/contract/integration sono separate e la sandbox POSIX ha un job dedicato | CodeQL/SAST bloccante; live-lab senza casi eseguibili. La suite container nativa SEC-A è eseguibile e collegata alla CI |
| Input ostili | report HTML Vulcan con `html.escape`; RichLog TUI con `markup=False` | `themis/adapters/nmap.py` parsa XML con `xml.etree` considerandolo “trusted local”, ma banner e script output sono controllati dal target; nessun fuzzing dei parser |
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
| 7 | Deduplicazione + ciclo di vita finding | ✅ | `vulcan/aggregate.py` (`dedupe_findings` per ID + `merge_duplicate_findings` cross-scanner lossless), `FindingStatus` (7 stati), macchina a stati + audit trail + suppression `core/finding_lifecycle.py`/`findings/store.py` (`WEB-C`) | Transizioni, dedup, audit trail, suppression, tagging/ricerca tutti ✅ |
| 8 | Severità, confidence, risk scoring contestuale | ✅ | `Severity`, `Finding.confidence` (`WEB-C`), `Finding.risk_score()` 0–100 (`WEB-C`), `vulcan/enrichment.prioritize` (KEV>EPSS>CVSS>severità) | Confidence + risk score numerico ✅; mantenere |
| 9 | Mapping CVE/CWE/CVSS/MITRE ATT&CK | 🟡 | `Finding.cvss` + campi `cve`/`cwe`/`epss`/`kev` strutturati (`WEB-C`); link NVD/MITRE in `vulcan/pdf.py`; EPSS/KEV `vulcan/enrichment.py`; ATT&CK detection `apollo/attack.py`, `Alert.mitre_attack` | Campi strutturati ✅; **ATT&CK offensivo sui finding** → `OPS-RED` |
| 10 | Inventario centralizzato asset | 🟡 | `core.Asset`, `argus/assets.py`, persistenza per-assessment in Athena; `Asset.engagement_id` opzionale e stamping dal coordinator Athena per id canonici (`WEB-B` slice 2); engagement esposti via API/Web sullo stesso store con scope enforcement (`WEB-B` slice 3) | Engagement leggibili/operabili dai quattro canali ✅; **viste di aggregazione asset cross-engagement** (widget) → `WEB-G` |
| 11 | Scheduler, code, worker isolati, ripresa job | 🟡 | job store SQLite `themis/jobs.py` (stati+`recover`), `olympus themis jobs recover`, sandbox e worker continuo nativo (`SEC-A`) | Queue+recover+sandbox ✅; **scheduler nativo** ❌ → `D13`; runtime Celery ritirato ✅; parità dati/route legacy → `SEC-A` |
| 12 | Scansioni incrementali + confronto risultati | 🟡 | `argus/diff.py` (diff recon) | **Finding/scan diff cross-run** → `WEB-I` |
| 13 | Dashboard, notifiche, report JSON/CSV/HTML/PDF/SARIF | 🟡 | report JSON/MD/HTML/PDF `vulcan/`, SARIF `hermes/sarif.py`, OCSF/ECS/NDJSON `apollo/` | **CSV** ❌ (basso costo) → `WEB-I`; **dashboard/notifiche** → `WEB-G`/`WEB-I` |
| 14 | API, webhook, CI/CD, ticketing, SIEM, CTI | 🟡 | API tipizzata `themis/api.py`; CTI nativo Metis (`metis/misp.py`,`stix.py`) | API+CTI ✅; **webhook/ticketing/CI** → `WEB-J`; **SIEM** → `OPS-BLUE` |
| 15 | Test unit/integration/e2e + demo sicuro | ✅ | ~132 file di test (unit/contract/integration/container/live_lab), demo `labs/mars/`; web-security + job-lifecycle della Web UI nativa e tools page dal capability inventory (`tests/unit/test_themis_web.py`, `WEB-A`/`WEB-D`) | Estendere e2e Web sulle slice successive (`WEB-E`) |

### B. Moduli proposti (FASE 3) — valutazione

| Modulo proposto | Problema | Equivalente esistente | Decisione |
| --- | --- | --- | --- |
| **Hermes** (inventario asset) | asset inventory | ♻️ **conflitto di nome**: Hermes è già il **secret scanning** (`src/olympus/hermes/`) | **Scartare il nome**; inventario in `core.Asset`+`argus/assets.py`, centralizzato da `WEB-B` |
| **Aegis** (vuln management) | vulnerability management | ♻️ è **Themis** (ex-AEGIS: `src/olympus/themis/`) | **Scartare**: già Themis; lifecycle vuln → `WEB-C` |
| **Prometheus** (monitoraggio) | monitoring continuo | ♻️ **doppio conflitto**: il noto sistema Prometheus e il backend `observability` già chiamato `prometheus` (`core/observability.py`) | **Scartare il nome**; monitoring → estende `core/observability.py` + scheduler (`D13`) |
| **Hestia** (secret detection) | secret detection | ♻️ è **Hermes** (nativo: regex+entropia+git history, `hermes/scanner.py`) | **Scartare**: già Hermes |
| **Hephaestus** (supply-chain) | supply-chain security | 🟡 SBOM `core/sbom.py`, lockfile, pip-audit/gitleaks in CI; nome già **riservato** per hardening/CIS (`OPS-BLUE`) | **Integrare** in `SEC-F` (provenance/SLSA/Cosign) + candidati Trivy/OSV (`OPS-SCAN`); non un modulo nuovo |
| **Iris** (notifiche) | notifiche | ❌ assente | **Integrare** come `WEB-I` (porta di output sul core), non modulo dominio |
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
| M1 Fondamenta | base stabile e coerente | 🟡 `DEV-I` ✅, suite/coverage ✅ | `DEV-G`,`DEV-H`,`DEV-C`,`SEC-A` | link checker in CI verde; 0 import runtime da `vendor/` |
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

### Stato di sicurezza attuale

Non è stato rilevato hardcoding di API key o password nel codice first-party
analizzato. `src/olympus/core/config.py` carica impostazioni da TOML e variabili
d'ambiente; i moduli che richiedono token usano variabili dedicate. La CI esegue
inoltre `gitleaks` sul working tree e, su `main`, sull'intera history, con un canary
che verifica che lo scanner sia realmente funzionante.

Restano da verificare la parità completa dei dati/endpoint VAP e il loro piano
di migrazione, l'isolamento di rete dei processi scanner e la forza probatoria
dello scope e delle evidenze. Il runtime mantenuto è ora interamente nativo.

### Intervento A · `SEC-A` — Ritirare la superficie VAP vendorizzata (**P0**)

- [x] Reimplementare nativamente le funzioni ancora delegate da
  `src/olympus/integrations/cli.py` a `vendor/vulnerability-assessment-platform`:
  API/web app, migrazioni e worker. `serve`/`web` condividono la Web UI nativa,
  `migrate` aggiorna soltanto il database job nativo e `workers` consuma la coda
  SQLite con cancellazione SIGINT/SIGTERM, senza Redis/Celery/Alembic o import
  VAP. Immagini native dalla wheel, smoke API/Web HTTPS/worker, test di lifecycle
  e CI container; guida IT/EN e rollback in
  [`docs/themis-runtime.md`](docs/themis-runtime.md). Il sorgente legacy resta
  archiviato; import di `vap.db` e parità completa sono il punto successivo.
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

`src/olympus/themis/sandbox.py` applica già drop dei privilegi, limiti CPU/memoria/
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
  “trusted local” in `themis/adapters/nmap.py`, adottare `defusedxml` (o un parser
  equivalente con entità disabilitate) e imporre limiti di dimensione e
  profondità prima del parsing XML/JSON.
- [ ] Aggiungere fuzzing (Hypothesis o Atheris) per tutti i parser in
  `themis/adapters/`, `apollo` e `metis`, con corpus iniziale dalle fixture reali:
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
  suite vuota fallisce come “no tests collected”. La suite container SEC-A ha
  un caso eseguibile in CI; la suite live-lab resta senza casi e non attesta
  scanner live o isolamento egress.
- [x] Aggiungere mutation test mirati a scope gate, redaction, parser, exit code e
  state machine dei job: la suite dedicata e un gate CI Linux selezionano le
  funzioni critiche; il checker richiede almeno il 35% di mutazioni uccise per
  ciascuna funzione, blocca gli esiti non verificati e segnala i mutanti superstiti.

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
(`WEB-E`, `WEB-G`…) estendono questa UI, non la sostituiscono.

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

**Criterio di completamento:** un finding attraversa tutto il ciclo di vita con
audit; la deduplica non perde evidenza né remediation; ogni finding è navigabile
fino alla sua evidenza verificabile.

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

- [ ] Flusso: scegli engagement → target → controllo scope → tipo attività
  (Recon / Network / Web / Vulnerability Assessment / Secret Scan / Detection /
  Full) → tool o modalità automatica → **anteprima "Olympus sta per eseguire"**
  con livello `PASSIVE/ACTIVE/INTRUSIVE` → autorizzazione quando necessaria →
  avvio → progress → risultati → evidenze → finding → report.
- [ ] Spiegazioni brevi non tecniche per ogni strumento e una modalità
  **Advanced** per utenti esperti; onboarding guidato.

**Criterio di completamento:** un utente che non ricorda i flag CLI completa un
assessment passivo end-to-end; nessuna operazione attiva parte senza preview e
autorizzazione.

### Intervento F · `WEB-F` — Smart Scan (pipeline proposta) (**P2**)

- [ ] Da target + engagement + obiettivo, Olympus **propone** una pipeline
  deterministica, spiegabile, scope-aware, policy-aware, limitata, configurabile e
  **visualizzabile prima dell'esecuzione**; mai esecuzione automatica di qualunque
  scanner. L'utente approva il piano.

**Criterio di completamento:** la pipeline proposta è riproducibile e approvata
esplicitamente; nessun ramo parte fuori scope o senza autorizzazione.

### Intervento G · `WEB-G` — Dashboard, accessibilità, i18n (**P2**)

- [ ] Dashboard con widget che rispondono a domande operative reali (asset, job
  in corso, scansioni completate, finding per severità/scanner, incident aperti,
  attività recente, scanner readiness, avanzamento assessment); nessun widget
  decorativo.
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

- [ ] **Report builder** sopra Vulcan: comporre un report (executive/tecnico/raw)
  da un engagement scegliendo sezioni, scope e formato (JSON/MD/HTML/PDF), senza
  duplicare la logica di rendering già esistente.
- [ ] **Report comparison / scan diff**: confrontare due run o due report dello
  stesso scope evidenziando finding nuovi, risolti e persistenti.
- [ ] **Trend storici e attack-surface evolution**: andamento di finding per
  severità nel tempo e variazione della superficie (asset/porte/servizi/subdomain)
  tra run, riusando il diff già presente in Argus.
- [ ] **Notifiche**: canali opzionali (webhook/e-mail) su eventi di job e finding,
  con payload redatto e nessun segreto; disattivate di default.

**Criterio di completamento:** un operatore confronta due assessment e riceve una
notifica redatta alla chiusura di un job, senza logica di report duplicata.

### Intervento J · `WEB-J` — Operabilità dei dati (**P2**)

- [ ] **Backup / restore** verificabile di engagement, job, finding, evidence e
  identità, con integrità controllabile; **data retention** applicata in modo
  uniforme (riusa `core.retention`).
- [ ] **Import / export** di engagement/finding/asset in formati versionati
  (JSON/NDJSON/SARIF) per portabilità tra installazioni, senza rompere i
  contratti dati.
- [ ] **OpenAPI pubblicata e documentata**: esporre e versionare lo schema
  OpenAPI del control plane (`themis.api`) come superficie di integrazione
  stabile, con esempi.

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

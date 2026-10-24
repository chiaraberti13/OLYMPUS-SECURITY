Warning: truncated output (original token count: 36962)
Total output lines: 2156

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
| 0 | Baseline e coerenza documentale | `[x]` | `DEV-G` ✓, `DEV-H` ✓, `DEV-C` ✓ (suite e coverage) |
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
| 9 | Mapping CVE/CWE/CVSS/MITRE ATT&CK | ✅ | `Finding.cvss` + campi `cve`/`cwe`/`epss`/`kev` strutturati (`WEB-C`); link NVD/MITRE in `vulcan/pdf.py`; EPSS/KEV `vulcan/enrichment.py`; ATT&CK detection `apollo/attack.py`, `Alert.mitre_attack`; **ATT&CK offensivo sui finding** `vulcan/attack.py` (`OPS-RED`) | Campi strutturati ✅; overlay ATT&CK offensivo ✅ (auto vs reviewed, mapping versionato) |
| 10 | Inventario centralizzato asset | 🟡 | `core.Asset`, `argus/assets.py`, persistenza per-assessment in Athena; `Asset.engagement_id` opzionale e stamping dal coordinator Athena per id canonici (`WEB-B` slice 2); engagement esposti via API/Web sullo stesso store con scope enforcement (`WEB-B` slice 3) | Engagement leggibili/operabili dai quattro canali ✅; **viste di aggregazione asset cross-engagement** (widget) → `WEB-G` |
| 11 | Scheduler, code, worker isolati, ripresa job | 🟡 | job store SQLite `themis/jobs.py` (stati+`recover`), `olympus themis jobs recover`, sandbox e worker continuo nativo (`SEC-A`) | Queue+recover+sandbox ✅; **scheduler nativo** ❌ → `D13`; runtime Celery ritirato ✅; parità dati/route legacy → `SEC-A` |
| 12 | Scansioni incrementali + confronto risultati | 🟡 | `argus/diff.py` (diff recon); **finding/scan diff cross-run** `vulcan/compare.py` + `olympus vulcan diff` + Web `/findings/diff` (`WEB-I` slice 2); **trend severità** `vulcan/trend.py` + `olympus vulcan trend` (`WEB-I` slice 3a) | Finding/scan diff ✅, trend finding ✅; **attack-surface evolution** → `WEB-I` |
| 13 | Dashboard, notifiche, report JSON/CSV/HTML/PDF/SARIF | 🟡 | report JSON/MD/HTML/PDF `vulcan/`, SARIF `hermes/sarif.py`, OCSF/ECS/NDJSON `apollo/` | **CSV** ❌ (basso costo) → `WEB-I`; **dashboard/notifiche** → `WEB-G`/`WEB-I` |
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
| M1 Fondamenta | base stabile e coerente | 🟡 `DEV-I` ✅, `SEC-A` ✅, suite/coverage ✅ | `DEV-G`,`DEV-H`,`DEV-C` | link checker in CI verde; 0 import runtime da `vendor/` |
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

- [~] Eseguire ogni scanner in un namespace/container con filesystem root
  read-only, capability Linux azzerate, `no-new-privileges` e profilo seccomp.
- [ ] Applicare AppArmor o SELinux dove disponibile e pubblicare un profilo
  versionato nel repository.
- [ ] Separare control plane e scan plane; consentire egress solo verso IP e porte
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
la CLI host non è ancora containerizzata obbligatoriamente, AppArmor/SELinux e
la separazione scan-plane con egress allowlist non sono implementati.

**Avanzamento verificato (2026-10-24, escape test):** la suite container esegue
ora probe offline e limitati per root filesystem read-only, assenza di file host,
accesso a `/proc/kcore`, capability azzerate, `no-new-privileges`, seccomp e
creazione di user namespace. Una fork bomb simulata è limitata a 32 PID, ha un
massimo di 128 tentativi e termina sempre i processi creati. Il test non contatta
target. Restano aperte la prova di egress verso un target fuori scope e la
containerizzazione obbligatoria delle esecuzioni CLI dirette; il criterio resta
pertanto `[~]`.

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
- [~] Firmare il manifest con Ed25519 riusando `olympus.core.signing`; il
  verificatore a chiave pubblica fissata controlla digest, target, tecnica e
  finestra, ma non è ancora collegato a tutti i percorsi attivi.
- [~] Legare ogni job all'hash del manifest e registrarlo in audit, report ed
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
- [ ] Prevedere un profilo lab separato, esplicito e limitato a reti dichiarate,
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
- [x] Aggiungere property-based test alla redazione in `core.execution` per query
  URL, header, mapping annidati, output scanner, Unicode e chiavi inattese
  (`tests/unit/test_property_security.py`); i casi generati verificano la rimozione
  del token, la conservazione dei campi diagnostici non sensibili e il trattamento
  di URL embedded in output scanner Unicode.

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
- [ ] Generare provenan…16962 tokens truncated…ngagement …] [--format table|json]` (tabella
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

- [~] Dashboard con widget che rispondono a domande operative reali (asset, job
  in corso, scansioni completate, finding per severità/scanner, incident aperti,
  attività recente, scanner readiness, avanzamento assessment); nessun widget
  decorativo. **Fatto finora:** totali e istogramma stati job + job recenti; e il
  widget **finding per severità/scanner** sulla dashboard (`GET /`), scope-gated
  a `findings:read` e attivo solo con `--findings-directory`, che riusa
  `vulcan.aggregate.severity_breakdown` e `source_breakdown` (quest'ultimo elenca
  solo le sorgenti che hanno prodotto finding, ordinate per conteggio) e linka
  alla vista findings filtrata per severità e per sorgente; degrada onestamente
  (assente) se non configurato o non leggibile; e
  il widget **scanner readiness** (`GET /`), scope-gated a `capabilities:read`,
  che proietta fedelmente l'inventario capability (`integrations.capabilities.inventory`
  — stessa fonte di `olympus themis capabilities` e della pagina Tools) in
  conteggi ready/installati/adattati/catalogati e linka alla pagina Tools,
  rispondendo a «quali scanner adattati posso eseguire ora su questo host?»; e
  il widget **avanzamento assessment** (`GET /`), calcolato dai job già caricati
  (nessuna query extra) sulla partizione autorevole `TERMINAL_STATES`: percentuale
  completata, job in corso / terminati / completati con successo pulito, presente
  solo quando esistono job, rispondendo a «quanto lavoro è ancora in volo e quanto
  è finito bene?». Test `tests/unit/test_themis_web.py`; doc
  [`docs/web.md`](docs/web.md).
  **Resta:** widget asset/incident.
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
  etichetta engagement sanitizzata (`SEC-H`) e slug per il filename. Test
  `tests/unit/test_themis_web.py`; doc [`docs/web.md`](docs/web.md). **Resta da
  fare:** sezioni executive/tecnico selezionabili, PDF dal browser (oggi CLI-only
  `olympus vulcan report --pdf`).
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
- [ ] **Notifiche**: canali opzionali (webhook/e-mail) su eventi di job e finding,
  con payload redatto e nessun segreto; disattivate di default.

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

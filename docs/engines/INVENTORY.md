# Inventario degli engine esterni

Stato: **Fase 0 — analisi** (nessun codice modificato). Fonte di verità del catalogo:
`olympus.integrations.scanners.REGISTRY` (24 voci) e il ledger di maturità
`olympus.integrations.maturity.DECLARED`. La colonna *stato* riflette il ledger
(`verify_declarations()` restituisce `[]` su questo commit); non è stata
riclassificata nessuna voce.

## Tabella

Legenda stato: `catalog-only` · `adapter-ready` · `offline-tested` · `live-tested` ·
`production-ready` (scala di `docs/scanner-maturity.md`; **nessun engine è
`production-ready`**). *Adapter* = esiste un `ScannerAdapter` in
`olympus.themis.registry` (16 su 24). *Pin oggi* = ciò che `docker/Dockerfile.scanners`
fissa effettivamente.

| Engine | Categoria | Stato | Adapter | Upstream | Licenza | Linguaggio | Distribuzione oggi | Pin oggi | Binario (probe) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `acunetix` | web | catalog-only | no | https://www.acunetix.com | Commercial (Invicti) | proprietario | manuale + licenza (API) | n/a (non installato) | `—` |
| `arjun` | web | live-tested | sì | https://github.com/s0md3v/Arjun | AGPL-3.0 | Python | pip | nessuno | `arjun` |
| `burp` | web | catalog-only | no | https://portswigger.net/burp | Commercial (PortSwigger) | Java (proprietario) | manuale + licenza (API) | n/a (non installato) | `—` |
| `commix` | web | live-tested | sì | https://github.com/commixproject/commix | GPL-3.0 | Python | pip | nessuno | `commix` |
| `dalfox` | web | live-tested | sì | https://github.com/hahwul/dalfox | MIT | Go | go install | v2.13.0 | `dalfox` |
| `dirsearch` | web | live-tested | sì | https://github.com/maurosoria/dirsearch | GPL-2.0 | Python | pip | nessuno | `dirsearch` |
| `httpx` | web | live-tested | sì | https://github.com/projectdiscovery/httpx | MIT | Go | go install | v1.11.0 | `httpx` |
| `katana` | web | live-tested | sì | https://github.com/projectdiscovery/katana | MIT | Go | go install | v1.7.0 | `katana` |
| `nessus` | vuln | catalog-only | no | https://www.tenable.com/products/nessus | Commercial (Tenable) | proprietario | manuale + licenza (API) | n/a (non installato) | `—` |
| `nikto` | web | live-tested | sì | https://github.com/sullo/nikto | GPL-2.0 | Perl | apt | nessuno (apt) | `nikto` |
| `nmap` | network | live-tested | sì | https://github.com/nmap/nmap | GPL-2.0 | C/C++ | apt | nessuno (apt, versione distro) | `nmap` |
| `nosqlmap` | web | catalog-only | no | https://github.com/codingo/NoSQLMap | GPL-3.0 | Python | git clone | nessuno (HEAD, `--depth 1`) | `nosqlmap` |
| `nuclei` | web | live-tested | sì | https://github.com/projectdiscovery/nuclei | MIT | Go | go install | v3.11.1 | `nuclei` |
| `openvas` | vuln | catalog-only | no | https://github.com/greenbone/openvas-scanner | GPL-2.0 | C (stack GVM) | docker/manuale (API) | n/a (non installato) | `—` |
| `sqlmap` | web | live-tested | sì | https://github.com/sqlmapproject/sqlmap | GPL-2.0 | Python | pip | nessuno | `sqlmap` |
| `subfinder` | dns | catalog-only | no | https://github.com/projectdiscovery/subfinder | MIT | Go | go install | v2.16.0 | `subfinder` |
| `testssl` | tls | offline-tested | sì | https://github.com/drwetter/testssl.sh | GPL-2.0 | Bash | git clone | nessuno (HEAD, `--depth 1`) | `testssl.sh` |
| `theharvester` | dns | catalog-only | no | https://github.com/laramies/theHarvester | GPL-2.0 | Python | pip | nessuno | `theHarvester` |
| `wafw00f` | web | live-tested | sì | https://github.com/EnableSecurity/wafw00f | BSD-3-Clause | Python | pip | nessuno | `wafw00f` |
| `wapiti` | web | offline-tested | sì | https://github.com/wapiti-scanner/wapiti | GPL-2.0 | Python | pip (`wapiti3`) | nessuno | `wapiti` |
| `whatweb` | web | offline-tested | sì | https://github.com/urbanadventurer/WhatWeb | GPL-3.0 | Ruby | apt | nessuno (apt) | `whatweb` |
| `wpscan` | web | adapter-ready | sì | https://github.com/wpscanteam/wpscan | WPScan Public Source (non-OSI) | Ruby | gem | nessuno | `wpscan` |
| `xsstrike` | web | live-tested | sì | https://github.com/s0md3v/XSStrike | GPL-3.0 | Python | git clone | nessuno (HEAD, `--depth 1`) | `xsstrike` |
| `zap` | web | catalog-only | no | https://github.com/zaproxy/zaproxy | Apache-2.0 | Java | docker/daemon (API) | n/a (non installato) | `—` |

Note sulle fonti:

- **Categoria, stato, licenza, binario, presenza adapter**: derivati dal codice del
  repo (registry + ledger + registry degli adapter). Le licenze sono quelle già
  dichiarate in `ScannerSpec`, non riverificate upstream.
- **Upstream e linguaggio**: URL pubblici dei progetti. Quelli di XSStrike, NoSQLMap,
  testssl.sh e dei 5 engine Go compaiono già nel Dockerfile; gli altri non sono
  citati dal repo e **vanno verificati** contro la pagina release ufficiale quando
  `olympus engines check-updates` (Fase 4) li interrogherà per la prima volta.
- **Pin oggi**: solo i 5 engine Go sono fissati a una versione esatta; il digest
  dell'immagine base è fissato. Tutto il resto è non riproducibile (vedi sotto).
- La spec del registry per nuclei dice `go install github.com/projectdiscovery/nuclei`:
  il percorso corretto del modulo è `.../nuclei/v3/cmd/nuclei` (come nel Dockerfile).
  Da correggere nel manifest.

## Cosa esiste già (da riusare, non duplicare)

| Esigenza del brief | Cosa c'è nel repo | Dove |
| --- | --- | --- |
| Interfaccia adapter | `ScannerAdapter` (ABC): `build_argv`, `parse`, `run(ScanRequest)`, `version()`, `simulate()` | `src/olympus/themis/base.py` |
| Registro adapter | `_ADAPTERS: dict[str, type[ScannerAdapter]]` + plugin allowlistati | `themis/registry.py`, `themis/plugins.py` |
| I/O iniettato | `Resolver` (Protocol), `run_command` (runner sandbox, no shell, rlimit, utente non privilegiato), `Cancellation` | `themis/scope.py`, `themis/runner.py`, `core/execution.py` |
| Scope-gating | `ensure_allowed` + `resolve_and_validate` (anti-SSRF, anti-rebinding) dentro `ScannerAdapter.run`, più manifest firmato per `themis run` | `themis/scope.py`, `themis/base.py` |
| Audit trail | `StructuredAuditRecord` / `append_structured_audit` con redazione | `core/execution.py`, `themis/application.py` |
| Stati d'esecuzione | `ExecutionState`: live / unavailable / failed / disabled / simulation | `themis/states.py` |
| Segreti | solo da variabili d'ambiente (`THEMIS_*`), redazione in `redact_*` | `core/secrets.py`, `core/execution.py` |
| Evidence | `Evidence` con sha256 calcolato a cattura; `raw_evidence_sha256` nel risultato | `core/evidence.py`, `themis/model.py` |
| Firma | Ed25519 | `core/signing.py` |
| SBOM | CycloneDX 1.5 **solo del runtime Python** (`olympus core sbom`) | `core/sbom.py` |
| Lock con hash | `olympus core lock` (pip `--require-hashes`) | `core/lockfile.py` |
| Audit vulnerabilità | `pip-audit` bloccante + registro waiver con scadenza | `ci.yml` (`dependency-audit`), `.github/audit-exceptions.toml` |
| Readiness vs maturità | `Capability`/`inspect()`; `themis doctor --scanner`, `themis capabilities` | `integrations/capabilities.py`, `scanner_doctor.py` |
| Exit code | `ExitCode` 0–7, contratto stabile (`normalize_exit_code` rimappa gli ignoti a `FAILED`) | `core/exit_codes.py` |

## Scostamenti tra il brief e lo stato reale del repo

Il brief presuppone una struttura che qui **non esiste**. Prima di scrivere codice
servono decisioni su questi punti (le raccomandazioni sono mie).

1. **Non esiste `olympus/engines/`, né `BaseEngineAdapter`, `Scope`, `EngineIO`,
   `PresenceResult`, `EngineRunResult`.** Gli adapter vivono in
   `olympus/themis/adapters/<nome>.py` e ereditano `ScannerAdapter`; la richiesta è
   `ScanRequest`, il risultato `ScanResult`. Il brief dice "interfaccia comune già
   usata dagli engine esistenti (es. `BaseEngineAdapter`)": l'interfaccia comune
   esistente è `ScannerAdapter`.
   *Raccomandazione*: **non** creare una gerarchia parallela. `olympus/engines/<nome>/engine.toml`
   contiene solo il manifest (dati); `[adapter].entrypoint` punta agli adapter esistenti
   (`olympus.themis.adapters.nuclei:NucleiAdapter`). `probe()` e `partial` si aggiungono
   a `ScannerAdapter` come estensioni retro-compatibili.
2. **Solo 16 engine su 24 hanno un adapter.** Senza adapter: `nosqlmap`, `subfinder`,
   `theharvester` (binari OSS, fattibili) e `zap`, `openvas`, `nessus`, `burp`,
   `acunetix` (API/daemon/commerciali: servono endpoint, licenza e un client HTTP
   iniettato; non verificabili qui). "Un adapter per ogni engine" per questi 5 non è
   onestamente raggiungibile senza accesso a quei prodotti.
   *Raccomandazione*: manifest per tutti i 24; adapter nuovi per i 3 binari OSS; i 5
   API-driven restano `catalog-only` con manifest `mandatory = false` e probe di
   configurazione (variabili d'ambiente), senza dichiarare maturità che non hanno.
3. **`distribution` nel brief ammette `binary | pip | npm | docker | go`**, ma il repo
   usa anche `apt` (nmap, nikto, whatweb), `git` (xsstrike, nosqlmap, testssl.sh) e `gem`
   (wpscan). Nessun engine usa npm.
   *Raccomandazione*: estendere l'enum a `apt | gem | git` e trattare i `git` come
   *source-build con commit pinnato* (il brief propone git submodule; per tool Python
   puri come XSStrike è più semplice un pin a commit SHA verificato al `probe`, senza
   submodule — da decidere).
4. **Il Dockerfile contraddice i vincoli**: `|| true` su ogni install di scanner
   (incompatibile con fail-closed), pip/gem/apt non pinnati, `git clone --depth 1` di
   HEAD. Va riscritto in Fase 5 contro i manifest.
5. **`EXIT_ENGINE_MISSING` cambia un contratto pubblico**: `ExitCode` è 0–7, descritto
   in `core/exit_codes.py`, `docs/run-status.md` e coperto da
   `tests/contract/test_exit_status_contract.py`. Aggiungere `8` è una modifica
   deliberata (docs + test di contratto + CLI reference), non un dettaglio.
6. **"mandatory" va definito per comando, non globale.** Proposta di semantica:
   `mandatory = true` ⇒ se il comando richiede quell'engine e manca, abort con
   `EXIT_ENGINE_MISSING` (o `degraded` con `--allow-missing-engines`);
   `mandatory = false` ⇒ l'assenza produce esecuzione **parziale** (exit 5), mai
   successo pieno. Servono i criteri su *quali* engine marcare mandatory (vedi domanda).
7. **Rete "reale" non verificabile in questa sandbox**: i test live sono opzionali per
   brief, e qui non ci sono i binari upstream. Nessuna riga del ledger verrà promossa
   senza evidenza committata.
8. **Fuori portata di un singolo passaggio**: promuovere gli engine a `production-ready`
   richiede evidenza live per ciascuno (lab autorizzato). L'infrastruttura (manifest,
   SBOM, evidence, probe) si può costruire per tutti; la *promozione* di stadio resta
   un passo separato per engine, come da brief (punto 7 dell'ordine consigliato).

## Piano per le fasi successive (invariato rispetto al brief, adattato al repo)

| Fase | Contenuto | File principali (nuovi) |
| --- | --- | --- |
| 1 | Schema `engine.toml` (Pydantic) + loader + test di completezza/adapter esistente + 24 manifest | `src/olympus/engines/{schema,loader}.py`, `engines/<nome>/engine.toml`, `tests/unit/test_engine_manifests.py` |
| 2 | `probe()`/`version()` su `ScannerAdapter`; pilota **nuclei** (argv da allow-list, `partial`, evidence manifest) | `themis/base.py`, `engines/evidence.py` |
| 3 | Preflight fail-closed, `ExitCode.ENGINE_MISSING`, `engines doctor`, `--allow-missing-engines` | `engines/preflight.py`, `engines/cli.py` |
| 4 | `engines check-updates` / `update`, `UPDATES.md`, SBOM esteso agli engine, CI (checksum, osv-scanner) | `engines/updates.py`, `core/sbom.py`, `ci.yml` |
| 5 | Replica a tutti gli engine con adapter; riscrittura Dockerfile | — |
| 6 | README/maturity solo per engine che soddisfano la DoD | — |

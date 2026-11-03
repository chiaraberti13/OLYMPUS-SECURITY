# Inventario degli engine esterni

Roadmap: **TOOLS-4**. Le tabelle qui sotto sono **generate**: derivano dai manifest
`src/olympus/engines/<nome>/engine.toml` (pin, upstream, distribuzione), dal registry
`olympus.integrations.scanners` (categoria, licenza, presenza nell'immagine) e dal ledger
`olympus.integrations.maturity` (stato). Non modificarle a mano: `tests/unit/test_engine_inventory_doc.py`
fallisce quando il file diverge, e `python scripts/generate_engine_inventory.py --write` le riscrive.

Nessun engine è `production-ready`. Nessuna riga del ledger è stata promossa da questo lavoro.

## Come leggere le tabelle

- **Stato**: scala di `docs/scanner-maturity.md`. L'asse è la maturità *del progetto*, non la presenza su questa macchina.
- **Mandatory**: l'engine fa parte della baseline d'infrastruttura (`nmap`, `nuclei`, `httpx`): i default di
  `recommended_scanner`, dello Smart Scan e del profilo Athena `deep`. Un test blocca l'insieme: allargarlo è una
  decisione da rivedere, non un effetto collaterale. Gli altri engine con adapter useranno `required_for_commands`
  (Fase 3, con la mappa dei comandi); l'engine nominato esplicitamente da un comando è sempre richiesto.
- **Upstream verificato**: `no` per tutti. Lo diventa solo quando `olympus engines check-updates` (Fase 4) risolve
  l'URL e trova tag compatibili col pin. Il 2026-11-03 i 21 repo GitHub rispondevano a `git ls-remote`; i siti dei
  tre prodotti commerciali non sono stati controllati.
- **Pin**: versione/tag esatto; per gli engine git anche il commit (7 caratteri) che il probe dovrà verificare con
  `git rev-parse HEAD`. Nessun `latest`, `main` o `master`.
- **Evidenza (esito pin)**: versione su cui è stata catturata l'evidenza di maturità
  (`docs/themis-execution-evidence.md`) e confronto col pin. `match`: identiche. `compatible`: l'evidenza registra
  solo la linea maggiore (`2.x`). **`RECONFIRM`: l'evidenza è su una versione diversa dal pin, quindi lo stato va
  ri-provato sul pin prima di fidarsene** (Fase 2 per nuclei, Fase 3 per gli altri). Un engine `live-tested` senza
  `evidence_version` fa fallire i test.
- **In immagine**: se `docker/Dockerfile.scanners` lo installa davvero. Un test confronta ogni pin dei manifest con
  il Dockerfile e, in senso inverso, ogni pin del Dockerfile con un manifest.

<!-- GENERATED:engine-inventory START -->

### Engine locali (installabili)

| Engine | Categoria | Stato | Adapter | Mandatory | Upstream | Upstream verificato | Licenza | Linguaggio | Distribuzione | Pin | Evidenza (esito pin) | In immagine |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `arjun` | web | live-tested | sì | - | https://github.com/s0md3v/Arjun | no | AGPL-3.0 | Python | pip | `2.2.7` | 2.x (compatible) | sì |
| `commix` | web | live-tested | sì | - | https://github.com/commixproject/commix | no | GPL-3.0 | Python | git | `v4.1` @ `06beb62` | 4.x (compatible) | sì |
| `dalfox` | web | live-tested | sì | - | https://github.com/hahwul/dalfox | no | MIT | Go | go | `v2.13.0` | v2.13.0 (match) | sì |
| `dirsearch` | web | live-tested | sì | - | https://github.com/maurosoria/dirsearch | no | GPL-2.0 | Python | pip | `0.5.0` | v0.5.0 (match) | sì |
| `httpx` | web | live-tested | sì | sì | https://github.com/projectdiscovery/httpx | no | MIT | Go | go | `v1.11.0` | 1.x (compatible) | sì |
| `katana` | web | live-tested | sì | - | https://github.com/projectdiscovery/katana | no | MIT | Go | go | `v1.7.0` | 1.x (compatible) | sì |
| `nikto` | web | live-tested | sì | - | https://github.com/sullo/nikto | no | GPL-2.0 | Perl | git | `2.6.1` @ `d201dac` | 2.5 (RECONFIRM) | no |
| `nmap` | network | live-tested | sì | sì | https://github.com/nmap/nmap | no | Nmap Public Source License 0.95 (non-OSI) | C/C++ | git | `v7.992` @ `0ee5616` | 7.94SVN (RECONFIRM) | sì |
| `nosqlmap` | web | catalog-only | no | - | https://github.com/codingo/NoSQLMap | no | GPL-3.0 | Python | git | `0.5` @ `898a60b` | - (-) | no |
| `nuclei` | web | live-tested | sì | sì | https://github.com/projectdiscovery/nuclei | no | MIT | Go | go | `v3.11.1` | v3.11.1 (match) | sì |
| `sqlmap` | web | live-tested | sì | - | https://github.com/sqlmapproject/sqlmap | no | GPL-2.0 | Python | pip | `1.10.11` | 1.10.8 (RECONFIRM) | sì |
| `subfinder` | dns | catalog-only | no | - | https://github.com/projectdiscovery/subfinder | no | MIT | Go | go | `v2.16.0` | - (-) | sì |
| `testssl` | tls | offline-tested | sì | - | https://github.com/drwetter/testssl.sh | no | GPL-2.0 | Bash | git | `v3.2.4` @ `97763a4` | 3.x (compatible) | sì |
| `theharvester` | dns | catalog-only | no | - | https://github.com/laramies/theHarvester | no | GPL-2.0 | Python | git | `4.11.1` @ `fd832de` | - (-) | no |
| `wafw00f` | web | live-tested | sì | - | https://github.com/EnableSecurity/wafw00f | no | BSD-3-Clause | Python | pip | `2.4.2` | 2.x (compatible) | sì |
| `wapiti` | web | offline-tested | sì | - | https://github.com/wapiti-scanner/wapiti | no | GPL-2.0 | Python | pip | `3.3.2` | - (-) | sì |
| `whatweb` | web | offline-tested | sì | - | https://github.com/urbanadventurer/WhatWeb | no | GPL-2.0 | Ruby | git | `v0.6.4` @ `d279d93` | - (-) | sì |
| `wpscan` | web | adapter-ready | sì | - | https://github.com/wpscanteam/wpscan | no | WPScan Public Source (non-OSI) | Ruby | gem | `4.2.0` | - (-) | sì |
| `xsstrike` | web | live-tested | sì | - | https://github.com/s0md3v/XSStrike | no | GPL-3.0 | Python | git | `3.1.6` @ `65dd68a` | 3.1.5 (RECONFIRM) | sì |

### Engine che richiedono un prodotto esterno (solo manifest, `catalog-only`)

Nessun adapter, nessun pin, `mandatory = false`: Olympus non li ha mai eseguiti. Nessus, Burp e Acunetix richiedono un prodotto commerciale; ZAP e OpenVAS sono open source ma vanno eseguiti come servizio separato.

| Engine | Categoria | Stato | Upstream | Licenza | Prodotto richiesto | Variabili d'ambiente (solo nomi) |
| --- | --- | --- | --- | --- | --- | --- |
| `acunetix` | web | catalog-only | https://www.acunetix.com | Commercial (Invicti) | Invicti Acunetix (commercial licence) | `THEMIS_ACUNETIX_URL`, `THEMIS_ACUNETIX_API_KEY` |
| `burp` | web | catalog-only | https://portswigger.net/burp | Commercial (PortSwigger) | PortSwigger Burp Suite Professional (commercial licence) | `THEMIS_BURP_URL`, `THEMIS_BURP_API_KEY` |
| `nessus` | vuln | catalog-only | https://www.tenable.com/products/nessus | Commercial (Tenable) | Tenable Nessus (commercial licence) | `THEMIS_NESSUS_URL`, `THEMIS_NESSUS_TOKEN` |
| `openvas` | vuln | catalog-only | https://github.com/greenbone/openvas-scanner | GPL-2.0 | Greenbone GVM stack (open source, heavy multi-service deployment) | `THEMIS_OPENVAS_URL`, `THEMIS_OPENVAS_TOKEN` |
| `zap` | web | catalog-only | https://github.com/zaproxy/zaproxy | Apache-2.0 | OWASP ZAP daemon (open source, runs as a separate service) | `THEMIS_ZAP_URL`, `THEMIS_ZAP_API_KEY` |

<!-- GENERATED:engine-inventory END -->

## Criterio di promozione a `production-ready`

Un engine passa a `production-ready` solo se **tutte** queste condizioni sono vere, ciascuna con evidenza committata:

1. **Manifest completo**: `engine.toml` valido, con pin esatto, `evidence_version` uguale al pin, e `upstream_verified = true`.
2. **SBOM**: l'engine compare nell'SBOM CycloneDX di Olympus con versione e digest/commit.
3. **Test offline verdi**: parser esercitato su output reale registrato (`test_<engine>_parser*`) e test di contratto.
4. **Test live opzionale documentato**: eseguito end-to-end in un lab autorizzato sul **pin** (non su un'altra versione),
   con la procedura e l'esito in `docs/themis-execution-evidence.md`.
5. **Presence probe funzionante**: `probe()` riconosce l'engine giusto (non uno omonimo), verifica il commit per gli
   engine git, e l'assenza produce il fail-closed atteso (exit 8 se `mandatory`).
6. **Evidence manifest**: ogni run produce un manifest che referenzia engine, versione, comando redatto, scope applicato
   e hash degli output grezzi.

`verify_declarations()` continua a rifiutare `production-ready` finché esiste un blocker aperto.

## Supply chain: cosa è stato trovato e deciso

| Tema | Fatto verificato | Decisione |
| --- | --- | --- |
| `pip install commix` | Il pacchetto PyPI `commix` 0.1 è di un autore terzo (*Bhai4You*), non di `commixproject/commix`. Era nell'immagine. | Installato da git (`v4.1`, commit pinnato). Lo schema rifiuta un manifest `pip` che nomini `commix` o `theHarvester`. |
| `theHarvester` | PyPI `theHarvester` 0.0.1 è una release obsoleta; la 4.11.1 richiede Python >= 3.12, l'immagine è 3.11. | Fuori dall'immagine, `catalog-only`, TODO nel Dockerfile. Debito tecnico: portare la base a Python 3.12. |
| `nikto` | Non è più installabile da apt; la 2.6.1 da git richiede il modulo Perl `XML::Writer`. | Fuori dall'immagine finché la build non è verificata (TODO nel Dockerfile). |
| Toolchain Go | I `go.mod` dei pin richiedono Go 1.25-1.26; nessun `golang-go` Debian è così recente. Il vecchio `\|\| true` mascherava il fallimento. | `GOTOOLCHAIN=go1.26.10` pinnato; i 5 engine Go compilati e avviati in sandbox con questi pin. |
| apt | Debian rimuove le versioni vecchie e `snapshot.debian.org` non era raggiungibile. | Nessun engine via apt. `nmap` è compilato dal commit pinnato (il tarball firmato su nmap.org non era raggiungibile). |
| Licenze | `nmap` è sotto Nmap Public Source License 0.95 (non OSI), non GPL-2.0; `whatweb` è GPL-2.0, non GPL-3.0; `arjun` è AGPL-3.0 (corretto nel registry; i metadati PyPI dicono GPL-3). | Registry corretto. La NPSL e l'AGPL hanno implicazioni sulla ridistribuzione dell'immagine: da far valutare prima di pubblicarla. `nikto` ha una licenza propria (codice GPL, database non GPL, distribuibili solo con nikto): non modificata, da rivedere. |
| `xsstrike` | Il tag `3.1.6` punta a un commit il cui script stampa `v3.1.5`. | Il pin è il **commit**; la stringa di versione dell'engine non è usata come prova. |
| Installazioni non pinnate | Le dipendenze transitive di pip e gem restano libere. | Residuo noto: ambiente con hash per engine (Fase 4). |
| Template di nuclei | `nuclei-templates` è una dipendenza dati non pinnata. | Da pinnare nel pilota nuclei (Fase 2). |

## Stato delle fasi

| Fase | Contenuto | Stato |
| --- | --- | --- |
| 0 | Inventario | fatta |
| 1 | Schema `engine.toml`, 24 manifest, `ExitCode.ENGINE_MISSING` (8), `probe()`/`partial` in `ScannerAdapter`, Dockerfile fail-closed, test di coerenza e di drift | fatta (vedi i TODO del Dockerfile) |
| 2 | Pilota nuclei: allow-list argv, `partial`, pin dei template, evidence manifest | da fare |
| 3 | Preflight fail-closed, `olympus engines list/doctor`, `--allow-missing-engines`, mappa dei comandi per `required_for_commands`, testo di installazione dal manifest | da fare |
| 4 | `engines check-updates` / `update`, SBOM esteso agli engine, osv-scanner in CI, `docs/engines/UPDATES.md` | da fare |
| 5 | Adapter per `nosqlmap`, `subfinder`, `theharvester`; replica del pattern | da fare |
| 6 | Aggiornamento README e tabella di maturità, solo per gli engine che rispettano il criterio sopra | da fare |

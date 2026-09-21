# Roadmap Operativa — Olympus come toolkit Red Team + Blue Team

> **Scopo di questo documento.** Non un corso, non laboratori didattici: una **roadmap per far
> diventare Olympus un kit di strumenti operativi** usabile in incarichi reali (penetration test,
> detection engineering, DFIR, consulenza), da un professionista che lavora sia in **Red Team** sia
> in **Blue Team**. Ogni voce è *azionabile* e ancorata allo stato reale del repository.
>
> **Principio distintivo (da non perdere mai).** Il valore di Olympus rispetto a "una cartella di
> script" è che ogni azione è **scope-gated, autorizzata, limitata e tracciata**, con **evidenze a
> integrità verificabile** (ledger HMAC, firma Ed25519, digest). È esattamente ciò che rende un tool
> utilizzabile in un contesto professionale/legale. Ogni nuova capability **eredita questi vincoli**.

Data: 2026-09-21 · Branch di lavoro: `claude/sostituisci-file-repo-rbu19m`

**Legenda stati:** `[x]` fatto e verificato (codice + test + evidenza) · `[~]` parziale ·
`[ ]` da fare, eseguibile ora · `[⏸]` **differito**: bloccato dall'ambiente/infrastruttura o
troppo grande per questo ciclo — parcheggiato nel **§6 Backlog differito** con il prerequisito
concreto di sblocco. **Disciplina invariata:** non si dichiara `live-tested`/`production-ready`
né si alza la maturità senza le evidenze della Definition of Done — un blocco si documenta, non si
finge (nessuna forzatura delle metriche).

---

## 1. Stato reale delle capacità (mappa operativa)

Legenda maturità (asse *progetto*, non *macchina* — vedi `docs/scanner-maturity.md`):
`catalog-only` → `adapter-ready` → `offline-tested` → `live-tested` → `production-ready`.

| Capability operativa | Modulo | Funzione | Maturità reale |
|---|---|---|---|
| OSINT & recon passivo (DNS, WHOIS/RDAP, IP, email, phone, MAC, account, CDN fronting, grafo indagine) | `argus` | 🔴 Red | operativo |
| Orchestrazione scanner scope-gated (14/24 motori nativi) | `aegis` | 🔴 Red | **12 live-tested**, **2 offline-tested** |
| Web probing (fingerprint, content discovery, XSS) | `artemis` | 🔴 Red | operativo |
| Aggregazione + dedup + **arricchimento KEV/EPSS** + ranking + report | `vulcan` | 🔴🔵 | operativo |
| Motore di **detection** (Sigma import, ATT&CK layer, export OCSF/ECS) | `apollo` | 🔵 Blue | operativo |
| **Threat intelligence** / IOC (STIX 2.1, MISP, correlazione, cifratura a riposo) | `metis` | 🔵 Blue (CTI) | operativo |
| **DFIR**: triage incidenti + **catena di custodia firmata HMAC** + backup | `minerva` | 🔵 Blue | operativo |
| Secret & sensitive-data scanning (SARIF, baseline, pre-commit/CI) | `hermes` | 🔵🔴 | operativo |
| Orchestrazione ciclo di vita assessment (piani validati, job SQLite, audit, reporting) | `athena` | 🟣 Purple | operativo |
| Modellazione campagne social-engineering (simulata, autorizzata) | `proteus` | 🔴 Red | **solo modellazione** |
| Provenance (firma Ed25519), SBOM, cifratura, policy/scope | `core` | 🟣 cross | operativo |
| TUI unificata + CLI singola | `ui` | 🟣 | operativo |

**Adapter AEGIS (dettaglio, autorevole da `integrations/maturity.py`):**
- `live-tested` (12): nmap, nikto, wafw00f, sqlmap, httpx, nuclei, katana, dalfox, dirsearch, commix, arjun, xsstrike
- `offline-tested` (2): testssl, whatweb
- `production-ready` (0) — **nessun adapter** soddisfa ancora la Definition of Done completa.
- Motori catalogati senza adapter nativo (≈10): nosqlmap, wapiti, subfinder, theHarvester, wpscan, zap, openvas, nessus, burp, acunetix.

---

## 2. Gap analysis operativa

### 2.1 — Catena Red Team (kill chain)

| Fase kill chain | Copertura Olympus | Gap operativo |
|---|---|---|
| Reconnaissance | 🟢 forte (`argus`, `aegis`) | mancano subfinder/dnsx/naabu/amass/theHarvester come adapter nativi |
| Weaponization | 🟡 parziale | nessuna generazione/gestione payload; delivery non coperta |
| Delivery (phishing) | 🔴 assente in esecuzione | `proteus` **modella** ma non esegue campagne |
| Exploitation | 🟡 orchestrazione scanner sì (sqlmap, nuclei, dalfox…), exploitation attiva no | nessun wrapper scope-gated verso un framework di exploitation |
| Command & Control | 🔴 assente | nessuna gestione sessioni/C2 |
| Privilege Esc / Lateral | 🔴 assente | nessun tooling post-exploitation |
| Exfil (simulata/controllata) | 🔴 assente | — |
| **Reporting** | 🟢 forte (`vulcan`, `athena`) | manca mapping automatico ATT&CK sui finding offensivi |

### 2.2 — Funzioni Blue Team

| Funzione blue | Copertura Olympus | Gap operativo |
|---|---|---|
| Detection engineering | 🟢 forte (`apollo`: Sigma/ATT&CK/OCSF/ECS) | manca il **loop di validazione** (deploy regola → test → tuning) |
| Ingest telemetria | 🔴 assente | Apollo **esporta** in ECS/OCSF ma non **ingerisce** log/EDR/Sysmon/Zeek |
| SIEM/EDR runtime | 🔴 assente | export solo su file; nessun connettore live (Splunk/Elastic/Sentinel) |
| Threat Intel operativa | 🟡 (`metis` STIX/MISP offline) | mancano feed **live** (TAXII/OpenCTI/MISP server) |
| DFIR / IR | 🟢 (`minerva` custody+triage) | manca timeline automatica e IOC sweep guidato |
| Hardening / posture | 🟡 | CIS/benchmark host non coperti (`hephaestus` proposto) |
| Reporting blu | 🟢 (`vulcan`) | — |

---

## 3. Roadmap per fasi (prioritizzata e azionabile)

Ogni task ha: **owner-value operativo**, deliverable concreto, tag 🔴/🔵/🟣, e — dove serve — il
**blocco onesto** dell'ambiente. I task senza blocco sono eseguibili **subito e offline**.

### FASE 0 — Consolidamento (subito, nessun blocco) 🟣

Prima di aggiungere, rendere *affidabile* ciò che c'è.

- [⏸] **P0** Portare i 12 adapter `live-tested` a **`production-ready`**: evidence manifest con
      digest, SBOM per-tool, compatibilità di versione documentata (Definition of Done in
      `docs/scanner-maturity.md`). *Deliverable:* manifest committati + record maturità aggiornati.
      **Bloccato (parziale):** il salto a `production-ready` richiede evidenza di esecuzione
      *live attraverso lo scope-gate* in un lab autorizzato + assemblaggio del manifest DoD; non
      lo dichiaro senza tutte le evidenze (disciplina: non alzare la maturità senza DoD).
- [⏸] **P0** Portare `whatweb` e `testssl` da `offline-tested` a `live-tested` end-to-end
      (i parser sono già validati su output reale — vedi `tests/unit/test_aegis_adapters_live_capture.py`).
      **Bloccato-da-ambiente:** l'`apt` di questo host installa `whatweb` 0.5.5 che gira solo
      sotto `ruby3.2` (non il launcher `whatweb`/rbenv) e `testssl` (non `testssl.sh`) che rifiuta
      `--jsonfile /dev/stdout`; una run genuina *attraverso l'adapter* fallirebbe qui per quirk di
      packaging, non del codice. Da completare su un host con i binari canonici + lab autorizzato.
- [⏸] **P1** Ritirare la dipendenza `vendor/` per `aegis serve` / `migrate` / `workers`
      (oggi in `integrations/cli.py` delegano al VAP vendorizzato). **Differito (grande):** non è un
      cambiamento contenuto ma una **re-implementazione nativa** dell'API/worker layer; il VAP è
      dichiarato *in ritiro* dal threat model, quindi va sostituito con codice nativo, non esteso.
- [x] **P1** `athena` playbook end-to-end: `recon → scan → enrich → report`, un solo comando,
      scope-safe. **Completo** (2026-09-21). Enrich→report (2026-09-20): `athena run
      --enrich-kev/--enrich-epss` sovrappone KEV/EPSS da feed **locali**, riordina il report per
      rischio, scrive sidecar `*.enriched.json`. **Scan AEGIS** (2026-09-21): `aegis` è ora un
      adapter di piano (`AegisScanAdapter`, `tests/unit/test_athena_aegis_scan.py`) che delega a un
      AEGIS `ScannerAdapter` reale, **doppiamente scope-gated** (guard Athena + `ensure_allowed`
      AEGIS); con `AEGIS_ENABLE_LIVE_SCANS` off usa la **simulazione scope-gated** di AEGIS (finding
      etichettati `[SIMULATION]`, nessun binario), e la scansione reale quando il live è abilitato.
      Verificato end-to-end offline (`athena run` con `adapters:["dns","aegis"]` + `--enrich` +
      `--report`). **Nota:** scanner fisso a `nmap`; selezionarne altri richiede un'estensione del
      contratto del piano (follow-on). Il *live-tested* pieno resta gated da binari + lab autorizzato.

### FASE 1 — Red Team: completare la catena offensiva scope-safe 🔴

- [⏸] **P1** Adapter recon ProjectDiscovery/OSINT: **subfinder, dnsx, naabu, amass, theHarvester**
      (stesso pattern degli adapter esistenti: argv + parser + fixture su output reale).
      *Blocco:* i binari Go arrivano da release GitHub — installabili su un host con egress; in
      questo ambiente `apt` copre solo i tool a pacchetto Debian.
- [~] **P1** Adapter web residui: **wapiti, nosqlmap, wpscan**. **wapiti: fatto** (2026-09-20,
      `offline-tested`) — adapter nativo che parsa il report JSON, validato su output **reale**
      catturato da uno scan bounded di `labs/mars` (XSS riflesso reale); porta il catalogo a
      15/24 nativi. **Resta:** `nosqlmap`, `wpscan` (per `wpscan`, token del vuln-DB via secret
      manager). Il salto di `wapiti` a `live-tested` richiede una run end-to-end attraverso lo
      scope-gate in lab autorizzato.
- [⏸] **P2** **Exploitation orchestration** scope-gated: wrapper controllato verso un framework di
      exploitation (es. Metasploit via `msfrpcd`/RPC) con guardrail — autorizzazione esplicita per
      target, allowlist, dry-run di default, logging integrale. *Nota etica/tecnica:* niente
      esecuzione senza scope firmato; è la stessa disciplina degli scanner.
- [ ] **P2** Mapping **MITRE ATT&CK** automatico sui finding offensivi (Vulcan → tecnica/tattica)
      per report da consegnare al cliente.
- [⏸] **P3** `proteus`: dalla *modellazione* alla *esecuzione simulata* di campagne di phishing in
      lab autorizzato (tracking click/credential-harvest **sintetico**, mai su utenti reali).

### FASE 2 — Blue Team: pipeline detection + DFIR 🔵

- [~] **P1** **Ingest di telemetria** in Apollo: normalizzazione verso `core.Event`.
      **Fatto il primo formato** (2026-09-20): `apollo ingest --format access-log` normalizza log
      HTTP reali (Apache/nginx Common & Combined, e la variante `http.server`) in `core.Event`
      NDJSON consumato da `apollo run`; parsing bounded, skip-never-guess, fixture **reale**
      catturata (`tests/fixtures/apollo/ingest/access.log`), catena end-to-end ingest→run→alert
      testata (`tests/unit/test_apollo_ingest.py`). **Resta:** formati **Sysmon/Windows Event** e
      **Zeek** (stessa forma; Sysmon reale richiede telemetria Windows non disponibile qui).
- [⏸] **P1** **Loop di detection engineering**: `apollo` esegue una regola Sigma su eventi reali →
      esito → tuning; validazione con **Atomic Red Team** in lab (blocco: richiede lab autorizzato).
- [⏸] **P2** Connettori **SIEM/EDR runtime** (export *live*, non solo file): Splunk HEC, Elastic,
      Microsoft Sentinel. *Blocco:* richiedono endpoint/credenziali reali → sviluppo con "separare
      fetch da parse", test offline sui payload.
- [⏸] **P2** **CTI live** in Metis: connettori **TAXII 2.1**, **MISP server**, **OpenCTI**
      (feed IOC/campagne). *Blocco:* feed remoti → parser testati offline, fetch dietro config.
- [~] **P2** **DFIR** in Minerva: **timeline** + export firmato. **Fatto** (2026-09-20): la
      `minerva timeline` esisteva già (timeline di custodia verificata); aggiunto l'**export
      firmato** (`--export`/`--sign-key`, artefatto `olympus.minerva-timeline` + envelope Ed25519
      via `core.signing`, verificabile con `olympus core verify`; test in
      `tests/unit/test_minerva_timeline_export.py`). **IOC sweep** guidato da Metis: **fatto**
      (2026-09-20) — `metis case sweep <db> <case> <artefatto>` estrae osservabili con la stessa
      normalizzazione dell'ingest e li confronta con gli IOC del caso (type+value, mai substring),
      exit 1 su match; test in `tests/unit/test_metis_sweep.py`.
- [ ] **P3** Nuovo modulo **`hephaestus`**: hardening/benchmark **CIS** su host e configurazioni.

### FASE 3 — Purple Team & automazione 🟣

- [ ] **P2** **Purple loop**: attacco simulato (Red, `aegis`/`proteus`) → detection (Blue, `apollo`)
      → report del gap di copertura. Un comando `athena purple` che chiude il ciclo.
- [ ] **P3** Profilo **`lab`** ripetibile contro `labs/mars` (già presente): esercizi operativi
      end-to-end con evidenze committate, come regressione operativa continua.

### FASE 4 — Produzione & supply chain 🟣

Rimanda e si integra con [`ROADMAP_HARDENING.md`](ROADMAP_HARDENING.md):
- [⏸] Firma immagini container (cosign) + build multi-stage + seccomp/AppArmor. *Blocco:* registry
      Docker (egress dei blob `Forbidden` in questo ambiente).
- [⏸] CI: matrice Python/OS, SAST/CodeQL, suite separate (unit/contract/integration/live-e2e).

---

## 4. Vincoli onesti dell'ambiente (cosa è offline vs cosa richiede infra)

| Canale | Stato in questo ambiente | Conseguenza |
|---|---|---|
| `apt` (repo Debian principali) | ✅ funziona | scanner classici installabili → adapter live |
| PyPI diretto | ❌ bloccato (timeout) | nessuna nuova dep runtime senza hash offline; dev-dep via apt |
| Binari Go (release GitHub) | ❌ non installabili qui | subfinder/dnsx/naabu/amass rimandati a host con egress |
| Registry Docker (blob) | ❌ `Forbidden` | nessuna build/run immagini → Fase 4 su host dedicato |
| Servizi/feed esterni (SIEM, TAXII, OpenCTI, cloud) | ❌ non disponibili | sviluppo "fetch separato da parse", test offline |
| Lab remoto autorizzato | ❌ non disponibile | `live-tested` pieno degli adapter rimandato; usare `labs/mars` in locale |

> **Disciplina di consegna.** Si marca `[x]` solo ciò che ha **codice + test + evidenza
> verificabile**; ciò che dipende da infra esterna resta dichiarato con il suo blocco, mai finto.

---

## 5. Sprint 1 — priorità immediate (eseguibili subito, offline)

1. 🟣 **Athena playbook** `recon→scan→enrich→report` in un comando (Fase 0). — **completo** (scan AEGIS + enrich + report)
2. 🔴 [⏸] Portare **whatweb/testssl** a live-tested end-to-end sullo scope-gate + `labs/mars`. — **differito → §6** (quirk packaging)
3. 🟣 [⏸] Definition of Done → **primi 3 adapter `production-ready`** (nmap, httpx, nuclei). — **differito → §6** (evidenza live + manifest DoD)
4. 🔵 **`apollo ingest`** per un formato reale (es. log web/JSON) con fixture reali. — **fatto** (access-log)
5. 🔵 **Minerva timeline** minima da eventi di un caso + export firmato. — **fatto** (export Ed25519)
6. 🟣 [⏸] Ritiro dipendenza `vendor/` per `aegis serve/migrate/workers`. — **differito → §6** (re-implementazione nativa)

**Esito Sprint 1:** 5 item completati (playbook Athena completo, enrich, ingest, timeline firmata, +
IOC sweep e adapter wapiti in Fase 1/2); i 3 item bloccati dall'ambiente sono ufficialmente differiti
al §6. Chiusura amministrativa del ciclo: **nessuna metrica forzata**.

> Ogni sprint chiude con: test verdi, `ruff`/`mypy` puliti, CHANGELOG aggiornato, commit firmato e
> push sul branch di lavoro.

---

## 6. Backlog differito — bloccato dall'ambiente/infrastruttura (rivedere all'upgrade del lab)

Questi task **non sono eseguibili con evidenza genuina** nell'ambiente attuale. Sono parcheggiati qui
(non cancellati) con il **prerequisito concreto** che li sblocca. **Non si alza la maturità e non si
dichiara `live-tested`/`production-ready` finché il prerequisito non è soddisfatto** — la Definition
of Done resta il solo criterio (Scenario B: accettazione del blocco, mai forzatura delle metriche).

| # | Task | Fase orig. | Prerequisito concreto di sblocco | Target |
|---|------|-----------|----------------------------------|--------|
| D1 | 12 adapter `live-tested` → `production-ready` | F0 | Run live *attraverso lo scope-gate* in **lab autorizzato** + manifest DoD (evidence+digest, SBOM per-adapter, matrice versioni) | Q3 |
| D2 | `whatweb`/`testssl` → `live-tested` | F0 | Host con **binari canonici** (`whatweb` non-rbenv, `testssl.sh`) + target di lab autorizzato | Q3 |
| D3 | Ritiro `vendor/` per `aegis serve/migrate/workers` | F0 | Decisione di prodotto + **re-implementazione nativa** dell'API/worker layer (feature grande) | Q3+ |
| D4 | Adapter recon **subfinder/dnsx/naabu/amass/theHarvester** | F1 | **Egress** per installare i binari Go (release GitHub) + fonti OSINT raggiungibili per output reale | Q3 |
| D5 | Adapter **nosqlmap/wpscan** | F1 | Target reali (**MongoDB/NoSQL**; **WordPress** + token vuln-DB via secret manager) per output reale | Q3 |
| D6 | **Exploitation orchestration** (Metasploit RPC) | F1 | `msfrpcd` disponibile + design guardrail (scope firmato, dry-run) + lab autorizzato | Q4 |
| D7 | `proteus`: esecuzione **simulata** di phishing | F1 | Lab autorizzato con tracking sintetico (nessun utente reale) | Q4 |
| D8 | **Loop detection engineering** (Sigma→deploy→test→tuning) | F2 | **Atomic Red Team** in lab autorizzato per generare telemetria reale | Q3 |
| D9 | Connettori **SIEM/EDR runtime** (Splunk/Elastic/Sentinel) | F2 | Endpoint/credenziali reali (l'export su file è già disponibile) | Q3 |
| D10 | **CTI live** (TAXII 2.1 / MISP server / OpenCTI) | F2 | Feed/istanze remote raggiungibili (parser offline già presenti in Metis) | Q3 |
| D11 | Firma immagini container + build multi-stage + seccomp/AppArmor | F4 | **Registry Docker** raggiungibile (blob egress) su host dedicato | Q4 |
| D12 | CI: matrice Python/OS, SAST/CodeQL, suite separate | F4 | Configurazione **GitHub/CI** (non locale) | Q3 |

**Ancora eseguibili offline in questo ciclo** (restano nella roadmap attiva, non differiti): Purple
loop (Fase 3, sim `aegis` → detection `apollo` → gap), profilo `lab` su `labs/mars`, secondo formato
`apollo ingest` con fixture generabile localmente, mapping ATT&CK sui finding, `hephaestus` (check CIS
di configurazione offline).

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

Data: 2026-09-20 · Branch di lavoro: `claude/sostituisci-file-repo-rbu19m`

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

- [ ] **P0** Portare i 12 adapter `live-tested` a **`production-ready`**: evidence manifest con
      digest, SBOM per-tool, compatibilità di versione documentata (Definition of Done in
      `docs/scanner-maturity.md`). *Deliverable:* manifest committati + record maturità aggiornati.
- [ ] **P0** Portare `whatweb` e `testssl` da `offline-tested` a `live-tested` end-to-end
      (i parser sono già validati su output reale — vedi `tests/unit/test_aegis_adapters_live_capture.py`;
      manca l'esecuzione attraverso lo scope-gate contro un target del lab).
- [ ] **P1** Ritirare la dipendenza `vendor/` per `aegis serve` / `migrate` / `workers`
      (oggi richiedono un path relativo `vendor/`). *Deliverable:* runtime nativo, `vendor/` isolato.
- [ ] **P1** `athena` playbook end-to-end committato: `recon (argus) → scan (aegis) → enrich
      (vulcan) → report`, un solo comando, scope-safe. *Deliverable:* preset + test offline.

### FASE 1 — Red Team: completare la catena offensiva scope-safe 🔴

- [ ] **P1** Adapter recon ProjectDiscovery/OSINT: **subfinder, dnsx, naabu, amass, theHarvester**
      (stesso pattern degli adapter esistenti: argv + parser + fixture su output reale).
      *Blocco:* i binari Go arrivano da release GitHub — installabili su un host con egress; in
      questo ambiente `apt` copre solo i tool a pacchetto Debian.
- [ ] **P1** Adapter web residui: **wapiti, nosqlmap, wpscan** (per `wpscan`, gestione sicura del
      token del vuln-DB via secret manager, mai in chiaro).
- [ ] **P2** **Exploitation orchestration** scope-gated: wrapper controllato verso un framework di
      exploitation (es. Metasploit via `msfrpcd`/RPC) con guardrail — autorizzazione esplicita per
      target, allowlist, dry-run di default, logging integrale. *Nota etica/tecnica:* niente
      esecuzione senza scope firmato; è la stessa disciplina degli scanner.
- [ ] **P2** Mapping **MITRE ATT&CK** automatico sui finding offensivi (Vulcan → tecnica/tattica)
      per report da consegnare al cliente.
- [ ] **P3** `proteus`: dalla *modellazione* alla *esecuzione simulata* di campagne di phishing in
      lab autorizzato (tracking click/credential-harvest **sintetico**, mai su utenti reali).

### FASE 2 — Blue Team: pipeline detection + DFIR 🔵

- [ ] **P1** **Ingest di telemetria** in Apollo: lettori per log web/sistema, **Sysmon/Windows
      Event**, **Zeek**, con normalizzazione verso il modello già usato in export (ECS/OCSF).
      *Deliverable:* `apollo ingest <formato>` + fixture reali.
- [ ] **P1** **Loop di detection engineering**: `apollo` esegue una regola Sigma su eventi reali →
      esito → tuning; validazione con **Atomic Red Team** in lab (blocco: richiede lab autorizzato).
- [ ] **P2** Connettori **SIEM/EDR runtime** (export *live*, non solo file): Splunk HEC, Elastic,
      Microsoft Sentinel. *Blocco:* richiedono endpoint/credenziali reali → sviluppo con "separare
      fetch da parse", test offline sui payload.
- [ ] **P2** **CTI live** in Metis: connettori **TAXII 2.1**, **MISP server**, **OpenCTI**
      (feed IOC/campagne). *Blocco:* feed remoti → parser testati offline, fetch dietro config.
- [ ] **P2** **DFIR** in Minerva: **timeline** automatica degli eventi di un incidente + **IOC
      sweep** guidato da Metis; export del caso firmato.
- [ ] **P3** Nuovo modulo **`hephaestus`**: hardening/benchmark **CIS** su host e configurazioni.

### FASE 3 — Purple Team & automazione 🟣

- [ ] **P2** **Purple loop**: attacco simulato (Red, `aegis`/`proteus`) → detection (Blue, `apollo`)
      → report del gap di copertura. Un comando `athena purple` che chiude il ciclo.
- [ ] **P3** Profilo **`lab`** ripetibile contro `labs/mars` (già presente): esercizi operativi
      end-to-end con evidenze committate, come regressione operativa continua.

### FASE 4 — Produzione & supply chain 🟣

Rimanda e si integra con [`ROADMAP_HARDENING.md`](ROADMAP_HARDENING.md):
- [ ] Firma immagini container (cosign) + build multi-stage + seccomp/AppArmor. *Blocco:* registry
      Docker (egress dei blob `Forbidden` in questo ambiente).
- [ ] CI: matrice Python/OS, SAST/CodeQL, suite separate (unit/contract/integration/live-e2e).

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

1. 🟣 **Athena playbook** `recon→scan→enrich→report` in un comando (Fase 0). — *alto impatto, zero blocchi*
2. 🔴 Portare **whatweb/testssl** a live-tested end-to-end sullo scope-gate + `labs/mars`.
3. 🟣 Definition of Done → **primi 3 adapter `production-ready`** (nmap, httpx, nuclei): evidence manifest + SBOM.
4. 🔵 **`apollo ingest`** per un formato reale (es. log web/JSON) con fixture reali.
5. 🔵 **Minerva timeline** minima da eventi di un caso + export firmato.
6. 🟣 Ritiro dipendenza `vendor/` per `aegis serve/migrate/workers` (o isolamento chiaro).

> Ogni sprint chiude con: test verdi, `ruff`/`mypy` puliti, CHANGELOG aggiornato, commit firmato e
> push sul branch di lavoro.

# Reconnaissance: OSINT & Scanning

> **Livello:** 🟢 Base · **Tempo stimato:** ~75 minuti · **Fase:** Reconnaissance (fase 1 PTES)

## 🎯 Obiettivi

- Distinguere ricognizione **passiva** e **attiva** e sapere quando usarle.
- Fare footprinting OSINT di un target autorizzato.
- Eseguire **port/service scanning** con nmap e leggerne l'output.
- Collegare la fase al modulo **Argus** (OSINT/recon) e **AEGIS** (scanning) di Olympus.

## ⚙️ Prerequisiti

- Basi di **DNS**, **HTTP**, indirizzi IP e porte.
- Lab: `labs/mars` avviato, oppure una VM di lab. nmap installato (Kali).

## 📖 Teoria

La ricognizione è la **prima e più importante** fase: più conosci il bersaglio, più mirato (e meno
rumoroso) sarà l'attacco. Due modalità:

- **Passiva** — raccogli informazioni **senza toccare** direttamente il target: motori di ricerca,
  DNS pubblico, certificati (crt.sh), record WHOIS, social, data breach pubblici. Non lascia tracce
  sul bersaglio.
- **Attiva** — interagisci col target (ping, port scan, banner grabbing). È più informativa ma
  **rumorosa** e già rilevabile: nei log del bersaglio compari.

> 💡 In un incarico reale si parte **passivi** per costruire la superficie d'attacco, poi si passa
> all'**attivo** solo entro lo scope autorizzato.

## 🧪 Laboratorio Pratico

### 1. OSINT passivo (footprinting)

Per un dominio autorizzato, tecniche tipiche (da eseguire solo su ciò che possiedi/gestisci):
```bash
whois example.com                 # intestatario, date, name server
dig example.com ANY +noall +answer   # record DNS
# subdomain enumeration passiva via Certificate Transparency: crt.sh (browser)
```
> 🔎 **Con Olympus.** Il modulo **Argus** automatizza gran parte di questo in modo scope-safe
> (account OSINT, DNS, WHOIS, fronting, correlazione). Esempi di scope in
> [`../../examples/input/argus-scope.json`](../../examples/input/argus-scope.json).

### 2. Host discovery (attivo, in lab)

```bash
nmap -sn 192.168.56.0/24     # -sn: ping sweep, quali host sono vivi (nessuna scansione porte)
```

### 3. Port & service scanning

```bash
# -sV: rileva servizio+versione; -Pn: salta il ping (utile se l'host filtra l'ICMP)
nmap -sV -Pn 127.0.0.1
# scansione mirata di una porta nota (es. il target Mars su 8081)
nmap -sV -p 8081 127.0.0.1
```
Leggi l'output: **porta** (es. 8081/tcp), **stato** (open/filtered/closed), **service** e **versione**
(es. `SimpleHTTPServer 0.6`). La versione è l'aggancio alla fase successiva (ricerca CVE).

### 4. Fingerprinting web

```bash
whatweb http://127.0.0.1:8081     # tecnologie: server, framework, header rivelatori
```
Su Mars vedrai header **fingerprintabili** (`Server`, `X-Powered-By`) e risorse "nascoste"
(`/app/admin`, `/app/.env`) — punti di partenza per content discovery.

> 🔎 **Con Olympus.** Il modulo **AEGIS** esegue questi scanner (nmap, whatweb, ecc.) attraverso un
> percorso *scope-gated*: rifiuta bersagli fuori allowlist e ha una guardia SSRF. In lab impari il
> comando "nudo"; con AEGIS lo esegui in modo sicuro e tracciato.

## 🔵 Analisi Blue Team

Uno scan attivo è **rumoroso**: nei log del target compaiono molte connessioni a porte diverse in
poco tempo (pattern tipico di nmap). IDS come Suricata hanno firme per gli scan. La ricognizione
passiva, al contrario, è quasi invisibile al bersaglio — per questo i difensori monitorano anche le
fonti esterne (certificati, domini registrati, leak).

## 🛡️ Contromisure

- **Ridurre la superficie**: chiudere porte/servizi non necessari; niente banner verbosi.
- **Rate limiting / IDS-IPS** per rilevare e rallentare gli scan.
- **Minimizzare l'esposizione OSINT**: attenzione a metadati, sottodomini dimenticati, repository
  pubblici con segreti (vedi il modulo **Hermes** di Olympus per lo scanning dei secret).

## 🔗 Riferimenti

- Nmap — documentazione ufficiale: <https://nmap.org/book/man.html>
- OWASP WSTG — Information Gathering: <https://owasp.org/www-project-web-security-testing-guide/>
- Certificate Transparency (crt.sh): <https://crt.sh/>
- MITRE ATT&CK — Reconnaissance (TA0043): <https://attack.mitre.org/tactics/TA0043/>

## 📝 Note Etiche

> ⚖️ OSINT su persone/organizzazioni e scanning attivo vanno fatti **solo** entro un ambito
> autorizzato. Uno scan non autorizzato può già configurare un illecito. Vedi
> [`01_Ethics_and_Legal.md`](../00_Getting_Started/01_Ethics_and_Legal.md).

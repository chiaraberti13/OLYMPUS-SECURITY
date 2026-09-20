# Setup del Laboratorio

> **Livello:** 🟢 Base · **Tempo stimato:** ~45–60 minuti · **Fase:** Pre-requisito a tutto il corso

## 🎯 Obiettivi

- Costruire un laboratorio di hacking **isolato**, sicuro e ripetibile.
- Capire la separazione **attaccante ↔ bersaglio** e perché la rete deve essere segregata.
- Avere pronti i primi bersagli vulnerabili (`labs/mars`, DVWA, OWASP Juice Shop).

## ⚙️ Prerequisiti

- Un PC con almeno **8 GB di RAM** (16 GB consigliati) e ~60 GB liberi su disco.
- Un hypervisor: **VirtualBox** (gratuito) o **VMware Workstation/Fusion**.
- **Docker** + Docker Compose (per i target containerizzati).
- Connessione a Internet **solo** per scaricare le immagini, poi si lavora offline.

## 📖 Teoria — perché un laboratorio isolato

Non si fa pratica di attacco su sistemi di produzione, su Internet o sulla rete di casa/lavoro:
oltre a essere **illegale** su bersagli non tuoi, un exploit può causare danni reali. La regola
d'oro è: **l'ambiente di test deve essere isolato dal resto del mondo.**

Un laboratorio minimo ha due ruoli:

- **Macchina attaccante** — la tua "postazione". Distribuzione tipica: **Kali Linux** o
  **Parrot OS**, che includono già la maggior parte degli strumenti (nmap, Metasploit, Burp,
  sqlmap, ecc.).
- **Macchine bersaglio** — sistemi *volutamente vulnerabili* su cui esercitarsi.

La chiave è la **rete**: attaccante e bersaglio devono comunicare **solo tra loro**. In
VirtualBox/VMware si usa una rete **"Host-Only"** o **"Internal Network"**, mai "Bridged". Con
Docker si usano bind su `127.0.0.1` e reti dedicate. Così un attacco non può "sfuggire" verso
Internet o la LAN.

> 💡 **Snapshot.** Prima di ogni sessione, scatta uno *snapshot* delle VM. Dopo un exploit
> potresti lasciare il sistema in uno stato sporco: lo snapshot ti riporta allo stato pulito in
> pochi secondi.

## 🧪 Laboratorio Pratico

### 1. Macchina attaccante (Kali Linux)

1. Scarica l'immagine VM pre-costruita di Kali (formato VirtualBox/VMware) dal sito ufficiale
   (vedi Riferimenti) — evita di installarla da zero all'inizio.
2. Importa la VM nell'hypervisor.
3. **Scheda di rete → Host-Only Adapter** (o *Internal Network*). Verifica che **non** sia in
   modalità Bridged/NAT verso la tua LAN.
4. Avvia e aggiorna i pacchetti:
   ```bash
   sudo apt update && sudo apt full-upgrade -y   # aggiorna gli strumenti all'ultima versione
   ```

### 2. Bersaglio incluso nel repo — `labs/mars`

Il repository include già un range locale, **Mars**, pensato per esercitarsi con i tool reali su un
target autorizzato (solo `127.0.0.1`, solo dati sintetici):

```bash
# dalla root del repository Olympus
python labs/mars/target/app.py            # espone http://127.0.0.1:8081
# oppure, containerizzato:
docker compose -f labs/mars/docker-compose.yml up
```

Debolezze *volute* di Mars (le useremo nei Lab di Web Hacking e Recon):
- `/app/search?q=…` riflette il parametro **non-escapato** → XSS riflesso;
- `/app/admin`, `/app/.env`, `/app/backup.zip` → risorse "nascoste" sintetiche (content discovery);
- header `Server`/`X-Powered-By` fingerprintabili;
- un endpoint con versione **affetta da CVE** (solo fingerprint, nessun payload distruttivo).

### 3. Bersagli web classici (Docker)

```bash
# DVWA — Damn Vulnerable Web Application (SQLi, XSS, ecc.)
docker run --rm -it -p 127.0.0.1:8080:80 vulnerables/web-dvwa

# OWASP Juice Shop — app moderna, intenzionalmente insicura
docker run --rm -it -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

> ⚠️ Nota il bind **`127.0.0.1:`** davanti alla porta: espone il servizio **solo** al tuo host,
> non alla rete. È una piccola abitudine che evita esposizioni accidentali.

### 4. Verifica dell'ambiente

Dalla macchina attaccante, controlla di "vedere" il bersaglio e **solo** quello:
```bash
ping -c1 <IP_bersaglio>       # raggiungibilità nella rete host-only
nmap -sn <rete_host_only>/24  # quali host esistono nel segmento isolato
```

## 🔵 Analisi Blue Team

Anche in laboratorio, abitúati a osservare i **log** del bersaglio mentre attacchi (access log del
web server, journal di sistema). Vedere l'attacco "dall'altra parte" è metà del mestiere: è ciò che
in seguito ti permetterà di **scrivere regole di detection** (vedi il modulo Apollo di Olympus).

## 🛡️ Contromisure (buone pratiche del lab)

- Rete **host-only/internal**, mai bridged.
- **Snapshot** prima di ogni sessione.
- Bersagli in **bind locale** (`127.0.0.1`) quando containerizzati.
- Nessun dato reale, nessuna credenziale reale nel lab.

## 🔗 Riferimenti

- Kali Linux (immagini VM ufficiali): <https://www.kali.org/get-kali/>
- Parrot Security OS: <https://parrotsec.org/>
- VirtualBox: <https://www.virtualbox.org/> · VMware: <https://www.vmware.com/>
- Docker: <https://docs.docker.com/get-docker/>
- DVWA: <https://github.com/digininja/DVWA> · OWASP Juice Shop: <https://owasp.org/www-project-juice-shop/>
- OWASP Web Security Testing Guide (WSTG): <https://owasp.org/www-project-web-security-testing-guide/>

## 📝 Note Etiche

> ⚖️ Tutto ciò che costruisci qui serve ad allenarti su bersagli **tuoi e isolati**. Le stesse
> tecniche, fuori da questo perimetro autorizzato, sono illegali. Vedi
> [`01_Ethics_and_Legal.md`](01_Ethics_and_Legal.md).

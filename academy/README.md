<p align="center">
  <img src="../assets/banner.svg" alt="Olympus Security Academy" width="100%">
</p>

<h1 align="center">🏛️ Olympus Security Academy</h1>

<p align="center"><i>Un percorso didattico strutturato di Ethical Hacking e Penetration Testing,
costruito accanto alla piattaforma di tooling <a href="../README.md">Olympus</a>.</i></p>

<p align="center">
  <img src="https://img.shields.io/badge/scopo-educativo-2EA043?style=flat-square" alt="Scopo educativo">
  <img src="https://img.shields.io/badge/uso-solo%20autorizzato-D7263D?style=flat-square" alt="Solo uso autorizzato">
  <img src="https://img.shields.io/badge/lingua-Italiano-8B5CF6?style=flat-square" alt="Italiano">
</p>

---

## ⚖️ Disclaimer etico (leggere PRIMA di tutto)

> **Questo materiale è fornito a solo scopo educativo.** Le tecniche descritte vanno eseguite
> **esclusivamente** su sistemi di tua proprietà o per cui disponi di un'**autorizzazione scritta**
> esplicita (un laboratorio isolato, un ambiente CTF, o un incarico di penetration test formale).
>
> L'accesso abusivo, l'intercettazione o il danneggiamento di sistemi informatici altrui è un
> **reato** — in Italia gli artt. **615-ter, 615-quater, 617-quater, 635-bis** e seguenti del
> Codice Penale; in altri ordinamenti norme equivalenti (es. *Computer Fraud and Abuse Act* negli
> USA, *Computer Misuse Act* nel Regno Unito). **Non esistono scuse tecniche a un problema legale.**
>
> Dettagli, checklist di autorizzazione e testo di scoping in
> [`00_Getting_Started/01_Ethics_and_Legal.md`](00_Getting_Started/01_Ethics_and_Legal.md).

---

## 🎓 A chi è rivolto

A chi vuole imparare la sicurezza **offensiva** in modo graduale ed etico: da zero fino a
condurre le fasi di un penetration test in un laboratorio autorizzato. Ogni argomento è un **Lab**
autonomo con teoria, pratica riproducibile, analisi blue-team e contromisure.

Il corso è progettato per essere usato **insieme** a Olympus: dove ha senso, un Lab mostra sia la
tecnica manuale (per capire *cosa* succede) sia come lo strumento Olympus corrispondente
(`argus`, `aegis`, `vulcan`, `apollo`…) la automatizza in modo scope-safe.

## 🚀 Come iniziare

1. **Prepara il laboratorio** → [`00_Getting_Started/00_Setup_Lab.md`](00_Getting_Started/00_Setup_Lab.md)
   (macchine virtuali, Docker, target vulnerabili isolati).
2. **Leggi le regole etiche** → [`00_Getting_Started/01_Ethics_and_Legal.md`](00_Getting_Started/01_Ethics_and_Legal.md).
3. **Segui i moduli in ordine** (`01_` → `04_`): ognuno assume ciò che hai imparato nel precedente.
4. **Allénati sul range locale** `labs/mars`, un bersaglio *volutamente vulnerabile* già incluso nel
   repo (solo `127.0.0.1`, solo dati sintetici) — vedi [`../labs/mars/README.md`](../labs/mars/README.md).

---

## 🗺️ Indice dei contenuti

Il percorso segue le fasi di un penetration test (modello **PTES** / Cyber Kill Chain).

### 00 · Getting Started
| Lab | Descrizione |
|-----|-------------|
| [00 Setup del Laboratorio](00_Getting_Started/00_Setup_Lab.md) | VM, Docker, target vulnerabili, isolamento di rete |
| [01 Etica & Aspetti legali](00_Getting_Started/01_Ethics_and_Legal.md) | Uso responsabile, autorizzazione, scoping, legge |

### 01 · Reconnaissance
| Lab | Descrizione |
|-----|-------------|
| [01 OSINT & Scanning](01_Reconnaissance/01_OSINT_and_Scanning.md) | Ricognizione passiva/attiva, footprinting, port/service scanning |

### 02 · Vulnerability Analysis
| Lab | Descrizione |
|-----|-------------|
| [01 Analisi delle vulnerabilità](02_Vulnerability_Analysis/01_Vulnerability_Analysis.md) | Da servizio a CVE, CVSS, KEV/EPSS, prioritizzazione del rischio |

### 03 · Exploitation
| Lab | Descrizione |
|-----|-------------|
| [Web · 01 SQL Injection](03_Exploitation/01_Web_Hacking/01_SQL_Injection.md) | Manuale prima di `sqlmap`, intercettazione con Burp, difese |
| [Web · 02 Cross-Site Scripting (XSS)](03_Exploitation/01_Web_Hacking/02_Cross_Site_Scripting.md) | Riflesso/stored/DOM, praticato su `labs/mars` |
| [Metasploit · 01 Fondamenti](03_Exploitation/02_Metasploit/01_Metasploit_Fundamentals.md) | Architettura del framework e il *perché* dei comandi |
| [Crittografia · 01 Hashing, Encoding, Cifratura](03_Exploitation/03_Cryptography/01_Hashing_Encoding_Encryption.md) | Le tre cose sempre confuse, chiarite con esempi |

### 04 · Post-Exploitation
| Lab | Descrizione |
|-----|-------------|
| [01 Post-Exploitation](04_Post_Exploitation/01_Post_Exploitation.md) | Mantenimento accesso, escalation, pivoting, catena di custodia |

---

## 🧩 Standard dei moduli

Ogni Lab segue lo stesso template — [`_TEMPLATE_LAB.md`](_TEMPLATE_LAB.md) — con le sezioni:
🎯 Obiettivi · ⚙️ Prerequisiti · 📖 Teoria · 🧪 Laboratorio Pratico · 🔵 Analisi Blue Team ·
🛡️ Contromisure · 🔗 Riferimenti · 📝 Note Etiche. Contribuendo, **parti da quel template**.

> **Nota di provenienza.** Questi moduli sono stati **redatti ex novo** e verificati tecnicamente:
> la Wiki GitHub del progetto non era accessibile al momento della stesura, quindi non si tratta di
> una migrazione automatica. Se recuperi contenuti dalla Wiki, apri una PR per riconciliarli con
> questi Lab mantenendo il template.

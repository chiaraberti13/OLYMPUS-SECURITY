# Etica & Aspetti Legali

> **Livello:** 🟢 Base · **Tempo stimato:** ~20 minuti · **Fase:** Pre-requisito a tutto il corso

## 🎯 Obiettivi

- Comprendere il **confine legale** tra un test autorizzato e un reato informatico.
- Saper definire e documentare un **ambito (scope)** e un'**autorizzazione**.
- Interiorizzare l'etica dell'hacker: divulgazione responsabile, minimizzazione del danno.

## ⚙️ Prerequisiti

Nessuno. Questo è il modulo che rende legittimo tutto il resto: **leggilo prima di attaccare qualunque cosa.**

## 📖 Teoria

### La sola differenza che conta: l'autorizzazione

La stessa esatta azione tecnica — una scansione, un'iniezione SQL, un accesso a una shell — è
**didattica** su un sistema tuo o autorizzato, e **criminale** su un sistema altrui. Non cambia il
comando: cambia il **permesso**. Un pentester professionista non è definito dai suoi strumenti, ma
dal **mandato scritto** che lo copre.

### Cosa dice la legge (sintesi non esaustiva)

- 🇮🇹 **Italia — Codice Penale:**
  - **art. 615-ter** — accesso abusivo a un sistema informatico o telematico;
  - **art. 615-quater** — detenzione/diffusione abusiva di codici di accesso;
  - **art. 615-quinquies** — diffusione di programmi diretti a danneggiare sistemi;
  - **art. 617-quater/quinquies** — intercettazione illecita di comunicazioni informatiche;
  - **art. 635-bis e ss.** — danneggiamento di informazioni, dati e sistemi.
- 🇪🇺 Direttiva **2013/40/UE** sugli attacchi ai sistemi di informazione.
- 🇺🇸 **Computer Fraud and Abuse Act (CFAA)** · 🇬🇧 **Computer Misuse Act 1990**.

> ⚠️ Non è necessario causare un danno per commettere reato: il **solo accesso non autorizzato** è
> già punibile. E "stavo solo studiando" non è una difesa se il bersaglio non era tuo.

### I tre pilastri dell'hacking etico

1. **Autorizzazione esplicita e scritta** — prima di toccare qualsiasi bersaglio.
2. **Ambito (scope) definito** — cosa puoi toccare, cosa è vietato, quando, con quali tecniche.
3. **Minimizzazione del danno** — nessuna interruzione non necessaria, nessuna esfiltrazione di
   dati reali oltre la prova strettamente necessaria, ripristino dello stato.

### Divulgazione responsabile (Responsible Disclosure)

Se scopri una vulnerabilità reale (fuori dal lab), non la pubblichi né la sfrutti: la comunichi in
modo riservato al proprietario/vendor, concedendo un tempo ragionevole per la correzione. Molte
organizzazioni hanno programmi **bug bounty** o file `SECURITY.md` con i contatti.

## 🧪 Laboratorio Pratico — definire uno scope

Prima di ogni esercizio, anche in laboratorio, compila mentalmente (o davvero) una **scheda di scope**.
Olympus stesso rende obbligatorio un file di scope prima di agire — è la stessa disciplina:

```jsonc
{
  "engagement": "Lab personale — Mars",
  "authorized_by": "Io medesimo (proprietario del lab)",
  "targets_in_scope": ["127.0.0.1:8081"],
  "targets_out_of_scope": ["qualunque cosa non sia il mio lab"],
  "techniques_allowed": ["recon", "web exploitation", "post-exploitation locale"],
  "window": "sempre (ambiente isolato e personale)",
  "data_handling": "solo dati sintetici; nessuna esfiltrazione verso l'esterno"
}
```

Confronta con gli esempi reali di scope della piattaforma in
[`../../examples/input/`](../../examples/input/) (es. `argus-scope.json`, `proteus-scope.json`).

## 🛡️ Contromisure (per chi difende)

L'etica vale anche dal lato blu: gestione responsabile dei dati, rispetto della privacy durante le
indagini, catena di custodia delle evidenze (vedi il modulo **Minerva** di Olympus).

## 🔗 Riferimenti

- Normattiva — Codice Penale (testo vigente): <https://www.normattiva.it/>
- OWASP Code of Ethics: <https://owasp.org/>
- EC-Council / (ISC)² Codes of Ethics (principi professionali).
- Il file [`../../SECURITY.md`](../../SECURITY.md) del progetto (politica di disclosure).

## 📝 Note Etiche

> ⚖️ **Testo standard da riportare in ogni Lab.** Il materiale è a solo scopo educativo. Esegui le
> tecniche unicamente su sistemi di tua proprietà o con autorizzazione scritta esplicita. L'uso non
> autorizzato è illegale e può comportare conseguenze penali e civili. Sei l'unico responsabile
> delle tue azioni.

# Security Policy

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

## English
### Supported versions
Security fixes target the latest revision on the default branch unless a release is explicitly documented as supported.

### Scope
All native Olympus modules, shared data contracts, CLI/TUI entry points, scope enforcement, sandbox/tool execution, evidence handling, reporting, vendored integrations and build/CI configuration.

### Reporting
Do not open a public issue for an unpatched vulnerability. Report privately through the repository's **Security → Advisories → Report a vulnerability** (GitHub Private Vulnerability Reporting); if that is unavailable, request a private channel by opening a minimal issue that asks a maintainer to enable it, without disclosing details. Include the affected commit/version, impact, minimal reproducible proof, environment assumptions and possible mitigations. Remove unrelated sensitive data.

### Response targets
These are good-faith targets for this project, measured from a triaged, reproducible report; they are commitments of process, not of calendar guarantees, and do not assert production readiness.

| Severity | Acknowledge | Triage decision | Target fix |
| --- | --- | --- | --- |
| Critical (scope bypass, RCE/command execution, sandbox escape, secret leakage, auth failure) | 48 hours | 48 hours | 7 days |
| High | 72 hours | 5 days | 30 days |
| Medium | 7 days | 14 days | 90 days |
| Low / informational | 14 days | 30 days | next scheduled release |

If a fix cannot meet the target, the reporter is told the reason, the interim mitigation and the revised date. Coordinated disclosure follows the **Disclosure** section below. For compromise of signing keys, CI tokens or AEGIS/Themis API keys, follow the [incident-response runbook](docs/incident-response.md).

### Responsible testing
Test only systems, data, devices and networks you own or are explicitly authorized to assess. No denial of service, destructive actions, persistence, social engineering, unauthorized interception or third-party access.

### Security requirements
Keep secrets outside source control; validate untrusted input; preserve authorization/scope checks; review dependency and CI changes; prefer reproducible builds; never present partial or unverified evidence as a confirmed fact. Reports involving scope bypass, SSRF, command execution, sandbox escape, secret leakage, evidence tampering or authorization failure are especially important.

### Dependency & supply-chain updates
Dependencies are updated weekly through Dependabot (pip and GitHub Actions). A vulnerability that the blocking `pip-audit` gate reports against the runtime closure is treated as a security issue and fixed within the **Response targets** above, by severity. There is no permanent allowlist: a vulnerability may be waived only through the time-boxed registry at [`.github/audit-exceptions.toml`](.github/audit-exceptions.toml), where each entry records a motivation, an owner, the date added and an expiry. `scripts/check_audit_exceptions.py` fails CI when any waiver is expired or malformed, so an exception cannot silently become permanent.

### Disclosure
Allow reasonable remediation time and coordinate publication of exploit-enabling details.

## Italiano
### Versioni supportate
Le correzioni riguardano la revisione più recente del branch predefinito, salvo release esplicitamente supportate.

### Ambito
Tutti i moduli nativi di Olympus, i contratti dati condivisi, gli entry point CLI/TUI, l'enforcement dello scope, l'esecuzione sandbox/tool, la gestione delle evidenze, il reporting, le integrazioni vendorizzate e la configurazione build/CI.

### Segnalazione
Non aprire issue pubbliche per vulnerabilità non corrette. Segnala in privato tramite **Security → Advisories → Report a vulnerability** del repository (GitHub Private Vulnerability Reporting); se non disponibile, richiedi un canale privato aprendo una issue minima che chieda a un manutentore di abilitarlo, senza divulgare dettagli. Indica commit/versione, impatto, PoC minimo riproducibile, assunzioni ambientali e mitigazioni, eliminando dati sensibili non necessari.

### Tempi di risposta
Sono obiettivi in buona fede del progetto, misurati da una segnalazione triage e riproducibile; sono impegni di processo, non garanzie di calendario, e non attestano production readiness.

| Severità | Presa in carico | Decisione di triage | Obiettivo di fix |
| --- | --- | --- | --- |
| Critica (bypass dello scope, RCE/command execution, evasione sandbox, leak di segreti, fallimento di autorizzazione) | 48 ore | 48 ore | 7 giorni |
| Alta | 72 ore | 5 giorni | 30 giorni |
| Media | 7 giorni | 14 giorni | 90 giorni |
| Bassa / informativa | 14 giorni | 30 giorni | prossima release pianificata |

Se un fix non può rispettare l'obiettivo, al segnalante vengono comunicati il motivo, la mitigazione provvisoria e la nuova data. La divulgazione coordinata segue la sezione **Divulgazione**. Per la compromissione di chiavi di firma, token CI o API key AEGIS/Themis, segui il [runbook di incident response](docs/incident-response.md).

### Test responsabili
Esegui test solo su sistemi, dati, dispositivi e reti propri o esplicitamente autorizzati. Sono esclusi DoS, azioni distruttive, persistenza, social engineering, intercettazioni non autorizzate e accessi a terzi.

### Requisiti di sicurezza
Mantieni i segreti fuori dal repository; valida gli input; conserva i controlli di autorizzazione/scope; controlla dipendenze e CI; preferisci build riproducibili; non presentare evidenze parziali o non verificate come fatti confermati. Sono particolarmente importanti le segnalazioni che riguardano bypass dello scope, SSRF, command execution, evasione della sandbox, leak di segreti, manomissione delle evidenze o fallimento dell'autorizzazione.

### Aggiornamenti delle dipendenze e supply chain
Le dipendenze sono aggiornate settimanalmente tramite Dependabot (pip e GitHub Actions). Una vulnerabilità segnalata dal gate bloccante `pip-audit` sulla closure di runtime è trattata come problema di sicurezza e corretta entro i **Tempi di risposta** sopra, per severità. Non esiste alcuna allowlist permanente: una vulnerabilità può essere derogata solo tramite il registro a scadenza [`.github/audit-exceptions.toml`](.github/audit-exceptions.toml), dove ogni voce registra motivazione, owner, data di inserimento e scadenza. `scripts/check_audit_exceptions.py` fa fallire la CI se una deroga è scaduta o malformata, così un'eccezione non può diventare silenziosamente permanente.

### Divulgazione
Concedi tempo ragionevole per la correzione e coordina la pubblicazione di dettagli sfruttabili.

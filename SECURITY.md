# Security Policy

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

## English
### Supported versions
Security fixes target the latest revision on the default branch unless a release is explicitly documented as supported.

### Scope
All native Olympus modules, shared data contracts, CLI/TUI entry points, scope enforcement, sandbox/tool execution, evidence handling, reporting, vendored integrations and build/CI configuration.

### Reporting
Do not open a public issue for an unpatched vulnerability. Use GitHub private vulnerability reporting / Security Advisories when available. Include the affected commit/version, impact, minimal reproducible proof, environment assumptions and possible mitigations. Remove unrelated sensitive data.

### Responsible testing
Test only systems, data, devices and networks you own or are explicitly authorized to assess. No denial of service, destructive actions, persistence, social engineering, unauthorized interception or third-party access.

### Security requirements
Keep secrets outside source control; validate untrusted input; preserve authorization/scope checks; review dependency and CI changes; prefer reproducible builds; never present partial or unverified evidence as a confirmed fact. Reports involving scope bypass, SSRF, command execution, sandbox escape, secret leakage, evidence tampering or authorization failure are especially important.

### Disclosure
Allow reasonable remediation time and coordinate publication of exploit-enabling details.

## Italiano
### Versioni supportate
Le correzioni riguardano la revisione più recente del branch predefinito, salvo release esplicitamente supportate.

### Ambito
All native Olympus modules, shared data contracts, CLI/TUI entry points, scope enforcement, sandbox/tool execution, evidence handling, reporting, vendored integrations and build/CI configuration.

### Segnalazione
Non aprire issue pubbliche per vulnerabilità non corrette. Usa la segnalazione privata / Security Advisories quando disponibile. Indica commit/versione, impatto, PoC minimo riproducibile, assunzioni ambientali e mitigazioni, eliminando dati sensibili non necessari.

### Test responsabili
Esegui test solo su sistemi, dati, dispositivi e reti propri o esplicitamente autorizzati. Sono esclusi DoS, azioni distruttive, persistenza, social engineering, intercettazioni non autorizzate e accessi a terzi.

### Requisiti di sicurezza
Mantieni i segreti fuori dal repository; valida gli input; conserva i controlli di autorizzazione/scope; controlla dipendenze e CI; preferisci build riproducibili; non presentare evidenze parziali o non verificate come fatti confermati. Reports involving scope bypass, SSRF, command execution, sandbox escape, secret leakage, evidence tampering or authorization failure are especially important.

### Divulgazione
Concedi tempo ragionevole per la correzione e coordina la pubblicazione di dettagli sfruttabili.

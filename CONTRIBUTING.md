# Contributing to OLYMPUS-SECURITY

<p align="center"><a href="#english">🇬🇧 English</a> · <a href="#italiano">🇮🇹 Italiano</a></p>

## English
This repository covers a scope-safe Python security platform spanning recon, assessment, detection, evidence, incident triage and reporting.

### Before you start
1. Read `README.md`, `SECURITY.md`, the roadmap and relevant architecture/design documentation.
2. Search existing issues and keep each pull request focused.
3. Use only owned or explicitly authorized targets, systems, datasets and signals.
4. Never commit credentials, tokens, private keys, personal data or sensitive evidence.
5. Report vulnerabilities privately.

### Setup
```bash
python -m pip install -e ".[dev]"\nmake install
```

### Required checks
```bash
make lint\nmake typecheck\nmake test
```
Network-active changes must preserve explicit authorized-scope enforcement, canonical exit semantics, audit records and deterministic offline tests through injected I/O.

### Engineering expectations
Preserve scope/authorization guards, validate untrusted input, fail safely, keep secrets outside source control, add tests for behavioural changes, and document compatibility or schema changes. Security-related functionality must not weaken logging, provenance, auditability or isolation. Update English documentation first and keep Italian documentation semantically aligned.

### Pull requests
Describe what changed, why, how it was tested, affected security boundaries, compatibility impact and rollback/migration notes. Participation follows `CODE_OF_CONDUCT.md`.

## Italiano
Questo repository riguarda a scope-safe Python security platform spanning recon, assessment, detection, evidence, incident triage and reporting.

### Prima di iniziare
1. Leggi `README.md`, `SECURITY.md`, roadmap e documentazione di architettura pertinente.
2. Controlla le issue esistenti e mantieni ogni pull request focalizzata.
3. Usa solo target, sistemi, dataset e segnali propri o esplicitamente autorizzati.
4. Non committare credenziali, token, chiavi private, dati personali o evidenze sensibili.
5. Segnala privatamente le vulnerabilità.

### Setup
```bash
python -m pip install -e ".[dev]"\nmake install
```

### Controlli richiesti
```bash
make lint\nmake typecheck\nmake test
```
Network-active changes must preserve explicit authorized-scope enforcement, canonical exit semantics, audit records and deterministic offline tests through injected I/O.

### Aspettative tecniche
Mantieni i controlli di scope/autorizzazione, valida gli input, usa comportamenti fail-safe, conserva i segreti fuori dal repository, aggiorna i test e documenta modifiche di compatibilità/schema. Le funzioni di sicurezza non devono indebolire logging, provenienza, auditabilità o isolamento. Aggiorna prima la documentazione inglese e mantieni quella italiana equivalente.

### Pull request
Descrivi cosa cambia, perché, test eseguiti, confini di sicurezza interessati, compatibilità e note di rollback/migrazione. Si applica `CODE_OF_CONDUCT.md`.

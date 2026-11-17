# Contributing to OLYMPUS-SECURITY

This repository covers a scope-safe Python security platform spanning recon, assessment, detection, evidence, incident triage and reporting.

## Before you start
1. Read `README.md`, `SECURITY.md`, the roadmap and relevant architecture/design documentation.
2. Search existing issues and keep each pull request focused.
3. Use only owned or explicitly authorized targets, systems, datasets and signals.
4. Never commit credentials, tokens, private keys, personal data or sensitive evidence.
5. Report vulnerabilities privately.

## Setup
```bash
python -m pip install -e ".[dev]"\nmake install
```

## Required checks
```bash
make lint\nmake typecheck\nmake test
```
Network-active changes must preserve explicit authorized-scope enforcement, canonical exit semantics, audit records and deterministic offline tests through injected I/O.

## Engineering expectations
Preserve scope/authorization guards, validate untrusted input, fail safely, keep secrets outside source control, add tests for behavioural changes, and document compatibility or schema changes. Security-related functionality must not weaken logging, provenance, auditability or isolation. Write documentation in English and keep README.md and README.it.md semantically aligned.

## Pull requests
Describe what changed, why, how it was tested, affected security boundaries, compatibility impact and rollback/migration notes. Participation follows `CODE_OF_CONDUCT.md`.

## Reporting and contribution checks

Use the [issue templates](https://github.com/chiaraberti13/OLYMPUS-SECURITY/issues/new/choose) and check for duplicates first. Useful context: Python version, module, command, authorized lab scope and synthetic fixture.

Write community and technical documentation in English; maintain equivalent English and Italian READMEs. Preserve existing application translations. Fill in the pull request template with commands, results and checks not performed, including the reason. Use synthetic examples without secrets or personal data.

See [the code of conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md) and [accessibility statement](ACCESSIBILITY.md). Report vulnerabilities only through the security policy process.

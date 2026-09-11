# Changelog

All notable changes to Olympus are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html): once a first
tagged release exists, breaking changes bump MAJOR, backward-compatible features
bump MINOR, and fixes bump PATCH.

Signed release tags, database migrations and a documented rollback procedure are
still open (see `ROADMAP_HARDENING.md` §5.4); until a release is tagged,
everything below lives under **Unreleased**.

## [Unreleased]

### Added
- **Minerva** — HMAC-SHA256 signed custody ledger (schema 2.1.0,
  `OLYMPUS_CUSTODY_HMAC_KEY`) detecting truncation and full rewrite; consistent
  `backup`/`verify-backup`/`restore` of the SQLite case store via the online
  backup API.
- **Metis** — STIX 2.1 and MISP export/import of indicators (deterministic,
  faithful-subset with explicit skips); backup/restore of the case store;
  authenticated encryption of a case document at rest (`export-encrypted` /
  `decrypt`, `OLYMPUS_METIS_KEY`); optional encrypted whole-store backups
  (`backup --encrypt`, auto-detected and decrypted by `restore`).
- **Core** — `core.crypto`: authenticated symmetric encryption (Fernet + scrypt)
  over the vetted `cryptography` library; `core.signing`: Ed25519 detached
  signatures with pinned-public-key verification (`core keygen`/`sign`/`verify`)
  for third-party verifiable provenance on any artifact (ledger, evidence, SBOM,
  report).
- **Vulcan** — `enrich` overlay adding CISA KEV and FIRST EPSS to findings and
  ranking them by real-world risk (KEV → EPSS → CVSS → severity).
- **Hermes** — shape-based allowlist (path globs / value regexes) and a
  `pre-commit` hook command with a `.pre-commit-hooks.yaml` declaration,
  completing baseline + allowlist + entropy + SARIF + pre-commit/CI.
- **Argus** — investigation-graph correlation (`argus correlate`): connected
  components, degree-ranked pivots, n-hop neighbors, and shared-value
  correlation, plus a JSON round-trip loader for the graph.
- **Apollo** — ECS and OCSF (Detection Finding) NDJSON export for SIEM ingestion,
  a MITRE ATT&CK Navigator layer export, and dependency-free import of the
  faithful subset of Sigma rules.
- **Core** — evidence digests computed from real artifact bytes at capture
  (`core.evidence`, `minerva capture`); pre-write target validation and race-free
  create-only atomic writes (`core.fileio.ensure_write_target`).
- **Supply chain** — CycloneDX SBOM (`core sbom`), hash-pinned constraints
  (`core lock`), a blocking pip-audit CI job, and digest-pinned container images.
- **Governance** — CODEOWNERS on security-critical paths and a grounded threat
  model (`docs/threat-model.md`).

### Changed
- All Argus persistence writes routed through atomic, owner-only, no-symlink
  writes (`core.fileio.atomic_write_text`).
- `docker-compose.yml` core services hardened with `no-new-privileges`,
  `cap_drop: [ALL]` and resource limits; the ZAP engine requires an API key
  (`AEGIS_ZAP_API_KEY`) instead of disabling it; a dedicated `backend` network.

### Security
- Closed the custody-ledger truncation/rewrite gap via HMAC signing.
- Removed the unauthenticated ZAP API default.
- Bounded the scrypt KDF parameters read from an encryption envelope, so a
  hostile document cannot turn decryption into a memory-exhaustion bomb
  (self-review finding).

_Runtime-dependent items (live scanner runs, container runtime behaviour, remote
feeds) are tracked with their blockers in `ROADMAP_HARDENING.md`._

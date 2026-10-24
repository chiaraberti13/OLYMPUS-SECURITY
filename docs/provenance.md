# Provenance and upstream attribution

This file records completed source migrations and the immutable identifiers used
for historical review. Olympus has no runtime Git dependencies or submodules.

## Argus

- Upstream: <https://github.com/chiaraberti13/argus>
- The maintained implementation is `src/olympus/argus/`.
- No standalone Argus source or passthrough is retained below `vendor/`.

## Vulnerability Assessment Platform

- Historical upstream: <https://github.com/chiaraberti13/Vulnerability-Assessment-Platform>
- Reviewed revision: `6c6b395d79f358372e028fe7094cc673374dd88f`.
- Reviewed `app.py` SHA-256:
  `1df54b7b8f0656e470b31b8e6c47476c920428860642a245f9b32847c370d66a`.
- Historical licence: GPL-3.0-only.
- Physical source removal completed on 2026-10-24 under roadmap item `SEC-A`.
  The source remains available from the historical upstream and Git history; it
  is no longer distributed or executable from the Olympus tree.
- The immutable route/lifecycle inventory is
  `docs/parity/themis-vap-runtime.json`; the disposition of every route and
  data boundary is `docs/parity/themis-vap-retirement.json`.
- Native Themis API, Web, migrations, workers, scanner catalogue and diagnostics
  do not import VAP, Redis, Celery or Alembic.
- Reviewed terminal history can be moved through
  `legacy-snapshot` → `legacy-verify` → `legacy-plan` →
  `legacy-approve` → `legacy-import`. Imported rows remain unauthorized and
  non-executable; active or ambiguous rows stay in the operator-controlled
  backup.

Contract tests pin the historical revision, digest, 39-route inventory and all
retirement decisions while also requiring the source directory to remain
absent. These controls do not certify scanner live readiness.

## Licence scope

Olympus-owned source is distributed under the root GPL-3.0-only licence.
Third-party dependencies retain their own licences. No legacy VAP source is
included in the current source distribution.

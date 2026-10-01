# Provenance and upstream attribution

This file records completed source migrations and the one remaining temporary
vendored compatibility boundary. Olympus does not use runtime Git dependencies
or submodules.

## ARGUS (OSINT & reconnaissance toolkit)

- Upstream: <https://github.com/chiaraberti13/ARGUS>
- Last assessed standalone revision: `1c7a8310ee64e005878dfa183ca8a384760706c6`.
- Migration status: **complete**. The maintained implementation is
  `src/olympus/argus/` and the only entry point is `olympus argus …`.
- Native coverage: domain/DNS/RDAP, IP, public IP, phone, email, accounts, MAC,
  web posture, CDN fronting, investigation graphs, snapshot diff, bounded event
  pipelines and diagnostics. Configuration is centralized under Olympus;
  dependency updates are handled by Dependabot rather than a self-updater.
- Verification: `tests/unit/test_argus_native_replacement.py`, the Argus unit
  suite and `docs/parity/argus.json` remain the executable migration contract.
- No standalone ARGUS source is retained below `vendor/` and no `argus-native`
  passthrough remains.

## Vulnerability Assessment Platform

- Upstream: <https://github.com/chiaraberti13/Vulnerability-Assessment-Platform>
- Vendored revision: `6c6b395d79f358372e028fe7094cc673374dd88f`
- Location: `vendor/vulnerability-assessment-platform/` — complete source: the
  FastAPI application (`app.py`, ~40 API/UI routes), all **24 scanner
  integrations** (`scanners/`), the database layer and Alembic migrations
  (`database.py`, `db_migrations/`, `alembic.ini`), report generation
  (`report_generator.py`), background tasks (`celery_app.py`, `background_jobs.py`,
  `tasks.py`), `templates/`, `static/`, `assets/`, `docs/`, `tests/`, the pinned
  `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `installer.sh`, and
  `LICENSE`, preserved verbatim.
- Licence: **GPL-3.0-only**
  (`vendor/vulnerability-assessment-platform/LICENSE`). The previous Olympus
  documentation incorrectly labelled this component MIT; the vendored licence
  text and upstream repository metadata both identify GNU GPL version 3.
  Redistribution must preserve the GPL source and notice obligations for this
  component.
- Olympus-facing name: **THEMIS** (see `docs/vap-to-themis-rename.md`). Native
  entry points are `api`, `capabilities`, `jobs`, `run`, `scan`, `scanners` and
  `doctor`. `scan` submits to the authenticated native job API. The temporary
  `serve`, `migrate` and `workers` commands retain the legacy VAP web boundary
  during migration; `olympus vap` remains a deprecated alias.

## Running the vendored tools

- `bash scripts/setup-vendored-tools.sh` installs the temporary VAP Python
  dependencies into one checkout.
- `pip install -e ".[vap]"` installs the legacy web extra;
  Python extras; the authoritative VAP pin set is its own `requirements.txt`.
- External scanner **binaries** (nmap, nuclei, sqlmap, wpscan, …) and the full
  runtime (Redis/Celery) are provisioned reproducibly by the vendored
  `installer.sh` and `docker-compose.yml`. When a binary is absent, the scanner
  reports a clear "tool not installed" state instead of failing silently — this
  is upstream behaviour and a sandbox limitation, never a removed feature.

## Notes

- The vendored web app keeps its upstream *simulated* scanner mode. The
  Olympus-native execution layer (`olympus.themis`, `olympus themis run`) is
  separate Olympus-owned code that runs the real external scanners with explicit
  execution states and never fabricates findings; it does not modify vendored
  source. See `docs/scanner-matrix.md` and `docs/themis-execution-evidence.md`.
- No upstream secrets, credentials, or API keys were copied.
- Vendored code is preserved verbatim and held to its own quality tooling, not
  Olympus's optional helpers.
- Native replacement tests cover ARGUS. Temporary VAP compatibility tests remain
  until its API, persistence and report surfaces are fully migrated.

## Repository licence scope

Olympus-owned files under `src/olympus/` are offered under the root MIT
`LICENSE`. The vendored
Vulnerability Assessment Platform remains GPL-3.0-only. This is therefore a
multi-licence source distribution; the root MIT licence does not replace or
weaken any licence stored below `vendor/`.

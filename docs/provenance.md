# Provenance and upstream attribution

This file records completed source migrations and archived source retained for
provenance and parity review. Olympus does not use runtime Git dependencies or
submodules, and native THEMIS does not load or execute the archived VAP runtime.

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
  entry points include `api`, `capabilities`, `jobs`, `run`, `scan`, `scanners`,
  `serve`, `web`, `migrate`, `workers` and `doctor`. They use the authenticated
  native SQLite job store and do not load VAP, Redis, Celery or Alembic. The
  deprecated `olympus vap` command remains an alias for the native THEMIS CLI.
  Route, lifecycle, persistence, audit, report and cancellation decisions are
  tracked in `docs/parity/themis-vap-runtime.json`; legacy database conversion
  and source removal are still open SEC-A work.

## Archived VAP source

The archived tree is retained for provenance and migration review; it is not a
supported Olympus runtime. Do not launch its web app or worker as a substitute
for the native runtime. Legacy database import is not implemented. Native
`themis migrate` rejects VAP/foreign databases; preserve and back up those files
until an explicit read-only importer and rollback procedure are completed.

## Notes

- Olympus-native execution (`olympus themis run`) uses explicit execution states
  and never fabricates findings. External scanner live operation is separately
  scope-gated and disabled by default. See `docs/scanner-matrix.md` and
  `docs/themis-execution-evidence.md`.
- No upstream secrets, credentials, or API keys were copied.
- Vendored code is preserved verbatim and held to its own quality tooling, not
  Olympus's optional helpers.
- Contract tests pin the complete archived VAP route inventory against the
  route-by-route parity matrix. They do not certify data import or scanner live
  readiness.

## Repository licence scope

Olympus-owned files under `src/olympus/` are offered under the root MIT
`LICENSE`. The vendored
Vulnerability Assessment Platform remains GPL-3.0-only. This is therefore a
multi-licence source distribution; the root MIT licence does not replace or
weaken any licence stored below `vendor/`.

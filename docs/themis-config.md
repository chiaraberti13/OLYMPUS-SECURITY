# THEMIS configuration (`THEMIS_*`) with `AEGIS_*` and legacy `VAP_*` fallback

Olympus-owned THEMIS configuration uses `THEMIS_*` environment variables. The
subsystem was renamed AEGIS → Themis (ROADMAP `DEV-I`), and the vendored upstream
source reads `VAP_*`, so each canonical `THEMIS_*` value **falls back** — in order
— to the previous `AEGIS_*` name and then to the legacy `VAP_*` name when unset.
Precedence: `THEMIS_*` → `AEGIS_*` → `VAP_*` → built-in default. Setting two of
them to *different* values is rejected as ambiguous. Existing deployments that set
`AEGIS_*` (or `VAP_*`) keep working unchanged.

Implemented in `olympus.themis.config`; used by the native execution layer
(`olympus themis run`) and the `doctor` diagnostics.

## Mapping

| THEMIS variable | Legacy fallback | Purpose | Default |
| --- | --- | --- | --- |
| `THEMIS_ENABLE_LIVE_SCANS` | `VAP_ENABLE_LIVE_SCANS` | Enable real scans (else `disabled`) | `false` |
| `THEMIS_SIMULATION_MODE` | `VAP_SIMULATION_MODE` | Global explicit simulation (else off) | `false` |
| `THEMIS_HOST` | `VAP_HOST` | Web app bind host | `0.0.0.0` |
| `THEMIS_PORT` | `VAP_PORT` | Web app port | `8000` |
| `THEMIS_DATABASE_URL` | `VAP_DATABASE_URL` | Database URL | `sqlite:///./vap.db` |
| `THEMIS_REPORTS_DIR` | `VAP_REPORTS_DIR` | Reports directory | `reports` |
| `THEMIS_CELERY_BROKER_URL` | `VAP_CELERY_BROKER_URL` | Celery broker | `redis://localhost:6379/0` |
| `THEMIS_SANDBOX_*` | — | Scanner process isolation (user, rlimits, kill grace) | see [`themis-sandbox.md`](themis-sandbox.md) |

## Notes

- The **vendored** FastAPI app, Celery, and Compose services still read `VAP_*`
  directly (their source is unchanged); the root Compose sets `VAP_*` for them.
- The **Olympus-native** execution layer prefers `THEMIS_*`. Setting only
  `THEMIS_ENABLE_LIVE_SCANS=true` enables `olympus themis run`; setting only the
  legacy `VAP_ENABLE_LIVE_SCANS=true` also works via fallback.
- Migration: prefer `THEMIS_*` in new deployments. `VAP_*` support is retained
  for backward compatibility and is expected to remain as long as the upstream
  contract is vendored.
- Secrets (`VAP_API_KEY`, `VAP_JWT_SECRET`, …) are never printed by diagnostics —
  only whether they are set.

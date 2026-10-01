# THEMIS configuration (`THEMIS_*`) and legacy `VAP_*` compatibility

New Olympus-owned THEMIS configuration uses `THEMIS_*` environment variables. To
avoid altering the vendored upstream source (which reads `VAP_*`), each
`THEMIS_*` value **falls back** to the legacy `VAP_*` variable when the `THEMIS_*`
one is unset. Precedence: `THEMIS_*` → `VAP_*` → built-in default.

Implemented in `olympus.themis.config`; used by the native execution layer
(`olympus themis run`) and the `doctor` diagnostics.

## Mapping

| THEMIS variable | Legacy fallback | Purpose | Default |
| --- | --- | --- | --- |
| `AEGIS_ENABLE_LIVE_SCANS` | `VAP_ENABLE_LIVE_SCANS` | Enable real scans (else `disabled`) | `false` |
| `AEGIS_SIMULATION_MODE` | `VAP_SIMULATION_MODE` | Global explicit simulation (else off) | `false` |
| `AEGIS_HOST` | `VAP_HOST` | Web app bind host | `0.0.0.0` |
| `AEGIS_PORT` | `VAP_PORT` | Web app port | `8000` |
| `AEGIS_DATABASE_URL` | `VAP_DATABASE_URL` | Database URL | `sqlite:///./vap.db` |
| `AEGIS_REPORTS_DIR` | `VAP_REPORTS_DIR` | Reports directory | `reports` |
| `AEGIS_CELERY_BROKER_URL` | `VAP_CELERY_BROKER_URL` | Celery broker | `redis://localhost:6379/0` |
| `AEGIS_SANDBOX_*` | — | Scanner process isolation (user, rlimits, kill grace) | see [`themis-sandbox.md`](themis-sandbox.md) |

## Notes

- The **vendored** FastAPI app, Celery, and Compose services still read `VAP_*`
  directly (their source is unchanged); the root Compose sets `VAP_*` for them.
- The **Olympus-native** execution layer prefers `THEMIS_*`. Setting only
  `AEGIS_ENABLE_LIVE_SCANS=true` enables `olympus themis run`; setting only the
  legacy `VAP_ENABLE_LIVE_SCANS=true` also works via fallback.
- Migration: prefer `THEMIS_*` in new deployments. `VAP_*` support is retained
  for backward compatibility and is expected to remain as long as the upstream
  contract is vendored.
- Secrets (`VAP_API_KEY`, `VAP_JWT_SECRET`, …) are never printed by diagnostics —
  only whether they are set.

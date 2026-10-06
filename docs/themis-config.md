# THEMIS configuration (`THEMIS_*`) with `AEGIS_*` and legacy `VAP_*` fallback

Olympus-owned THEMIS configuration uses `THEMIS_*` environment variables. The
subsystem was renamed AEGIS → Themis (ROADMAP `DEV-I`), so each canonical
`THEMIS_*` value **falls back** — in order — to the previous `AEGIS_*` name and
then to the legacy `VAP_*` name when unset. Precedence:
`THEMIS_*` → `AEGIS_*` → `VAP_*` → built-in default. Setting two of them to
*different* values is rejected as ambiguous. Existing deployments that set
`AEGIS_*` (or `VAP_*`) keep working unchanged.

Implemented in `olympus.themis.config`; the native execution layer
(`olympus themis run`) and the `doctor` diagnostics read the flags below.
Host, port and database are **command-line flags** on `olympus themis api`,
`serve` and `workers` — not environment variables — and the native runtime has
no message broker.

## Mapping

| THEMIS variable | Legacy fallback | Purpose | Default |
| --- | --- | --- | --- |
| `THEMIS_ENABLE_LIVE_SCANS` | `VAP_ENABLE_LIVE_SCANS` | Enable real scans (else `disabled`) | `false` |
| `THEMIS_SIMULATION_MODE` | `VAP_SIMULATION_MODE` | Global explicit simulation (else off) | `false` |
| `THEMIS_SANDBOX_*` | — | Scanner process isolation (user, rlimits, kill grace) | see [`themis-sandbox.md`](themis-sandbox.md) |

The `THEMIS_SANDBOX_*` family is read by `olympus.themis.sandbox`:
`THEMIS_SANDBOX_USER`, `THEMIS_SANDBOX_ALLOW_ROOT`, `THEMIS_SANDBOX_CPU_SECONDS`,
`THEMIS_SANDBOX_MEMORY_BYTES`, `THEMIS_SANDBOX_FILE_SIZE_BYTES`,
`THEMIS_SANDBOX_OPEN_FILES`, `THEMIS_SANDBOX_MAX_PROCESSES` and
`THEMIS_SANDBOX_GRACE_SECONDS`.

## Notes

- The **Olympus-native** execution layer prefers `THEMIS_*`. Setting only
  `THEMIS_ENABLE_LIVE_SCANS=true` enables `olympus themis run`; setting only the
  legacy `VAP_ENABLE_LIVE_SCANS=true` also works via fallback.
- Migration: prefer `THEMIS_*` in new deployments. `AEGIS_*`/`VAP_*` support is
  retained for backward compatibility.
- The compatibility resolver also maps the legacy VAP-era names
  `THEMIS_HOST`, `THEMIS_PORT`, `THEMIS_DATABASE_URL`, `THEMIS_REPORTS_DIR` and
  `THEMIS_CELERY_BROKER_URL`. These are **not consumed by the native runtime**
  (host/port/database are CLI flags and there is no Celery broker); they are kept
  only against the archived vendored VAP contract (ROADMAP `SEC-A` parity matrix)
  and setting them has no effect today.
- Secrets are never printed by diagnostics — only whether they are set.

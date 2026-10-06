# Unified installation & operation

Olympus-native ARGUS and THEMIS and the specialist-engine catalogue from one
checkout. Linux (Debian/Ubuntu shown; adapt the package manager for RHEL/Arch).

THEMIS runs on the Olympus-owned native control plane (SQLite job store, native
migration and worker services): **no Redis, Celery or Alembic**. The mandatory
scope, identity and TLS setup lives in `docs/themis-runtime.md`; this page is the
install and day-to-day operation overview.

## 1. Base install (Olympus + native modules)

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"
olympus --version
olympus doctor            # environment diagnostics (binaries, services, deps)
```

## 2. Native ARGUS and THEMIS dependencies

```bash
olympus argus --help                      # already installed by the base package
bash scripts/setup-vendored-tools.sh      # installs the native .[themis,dev] runtime
# or:
pip install -e ".[themis]"                # native THEMIS API/Web/worker stack
```

## 3. THEMIS — native operation (single host)

The Olympus-owned control plane needs no Redis or Celery. See
`docs/themis-runtime.md` for the full scope/identity/TLS setup and the migration
and rollback procedure.

```bash
mkdir -p .olympus/scopes
# Place validated scope documents here as <scope-id>.json
export OLYMPUS_THEMIS_API_KEY='<at least 32 random characters>'
olympus themis migrate --database .olympus/themis-jobs.sqlite3   # create/upgrade the native job DB
olympus themis api --scope-directory .olympus/scopes             # terminal 1
olympus themis workers --database .olympus/themis-jobs.sqlite3   # terminal 2 / supervisor
olympus themis scan --scanner nmap --target example.com \
  --kind domain --scope-id customer-1 --i-am-authorized
```

Use `--ssl-certfile` and `--ssl-keyfile` to bind the API outside localhost;
remote plaintext HTTP is rejected by the server and client.

### Native web control plane

```bash
olympus themis migrate --database .olympus/themis-jobs.sqlite3   # initialize / upgrade the native job DB
olympus themis doctor                        # check web stack, DB, live-scan flag, secrets, scanners
olympus themis serve --host 127.0.0.1 --port 8600 \
  --scope-directory .olympus/scopes \
  --ssl-certfile cert.pem --ssl-keyfile key.pem   # web app  (terminal 1)
olympus themis workers --database .olympus/themis-jobs.sqlite3   # native scan worker (terminal 2)
```

The web UI sets `Secure` cookies, so use HTTPS even for a local browser session.
Shutdown: Ctrl-C each process (`SIGINT`/`SIGTERM` cancel the active scan and
stop). Reset: stop them, delete the SQLite DB (`.olympus/themis-jobs.sqlite3`)
and the reports dir.

## 4. THEMIS — Docker operation (full stack)

The Compose stack is native and broker-free: `themis-migrate` (native SQLite
migration), `themis-api` (HTTPS API), `themis-app` (HTTPS web) and
`themis-worker` (native SQLite worker). TLS certificates, the scoped identity
register and the registered scopes are mounted read-only and **must be prepared
before startup** — see `docs/themis-runtime.md` for the required files under
`.olympus/`.

```bash
docker compose up --build                  # themis-migrate + themis-api + themis-app + themis-worker
docker compose ps                          # health status
docker compose logs -f themis-app           # follow logs
docker compose down                        # stop
docker compose down -v                     # STOP + reset (removes the themis-data volume)
docker compose pull && docker compose up --build -d   # update

# With open-source scanner binaries baked into the worker image:
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
```

Env: copy `.env.docker.example` → `.env` to override `THEMIS_API_PORT`,
`THEMIS_WEB_PORT`, `THEMIS_ENABLE_LIVE_SCANS` and the optional
`THEMIS_ZAP_API_KEY`. Ports: API on `127.0.0.1:${THEMIS_API_PORT:-8443}`, web on
`127.0.0.1:${THEMIS_WEB_PORT:-8600}`. Volume: `themis-data` (`/data`: SQLite DB,
audit log and reports). The `themis-migrate` one-shot runs the native
`themis migrate` before the API, web and worker start. Avoid `docker compose
down -v` if you want to preserve evidence and jobs.

## 5. Scanner binaries

19 open-source scanners are installed by `docker/Dockerfile.scanners`
(apt/pip/go/git/gem). Check what is actually present:

```bash
olympus themis scanners --check      # per-scanner binary availability + licence
olympus themis deps                  # web stack + every scanner binary + version
```

The 5 API/commercial engines (zap, openvas, nessus, burp, acunetix) require
manual install and licence/API configuration via their `THEMIS_*` settings — see
`docs/scanner-matrix.md`. Live scanning also requires
`THEMIS_ENABLE_LIVE_SCANS=true` and explicit authorization/scope; otherwise
the native execution path refuses the run or returns an explicit unavailable /
disabled state. Simulation occurs only when the operator explicitly requests it.

## 6. Diagnostics

```bash
olympus doctor           # ecosystem-wide: python deps, git/docker/curl, scanners
olympus themis doctor     # THEMIS: web stack, DB/reports dir, live-scan flag, secrets(set?), scanners
olympus argus doctor     # ARGUS: dnspython/phonenumbers, optional API keys (set?)
```

All `doctor` output is secret-safe: it reports whether a secret env var is
*set*, never its value.

## 7. Manual-install dependencies (summary)

| Dependency | Needed for | Install |
| --- | --- | --- |
| 19 OSS scanners | live THEMIS scans | `docker-compose.scanners.yml` or `docker/Dockerfile.scanners` |
| OWASP ZAP | `zap` scanner | ZAP daemon/docker image + API config |
| OpenVAS/GVM | `openvas` scanner | Greenbone GVM stack (docker/manual) |
| Nessus / Burp / Acunetix | those scanners | vendor installer + commercial licence + API config |

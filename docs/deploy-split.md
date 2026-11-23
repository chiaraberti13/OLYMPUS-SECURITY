# Split deployment: static Vercel frontend + container Execution backend

Olympus' control plane is a stateful ASGI service (SQLite, a background worker, SSE
streaming, scanner subprocesses) and cannot run on Vercel's static + ephemeral
model. The deployment is therefore **split** (`DEPLOY-2`/`DEPLOY-3`):

- **Frontend (Vercel):** the static site under `public/` (built by
  `scripts/build_preview.py` and `scripts/build_docs_site.py`) plus thin serverless
  functions under `api/`. **No scanner ever runs here.**
- **Execution backend (container host):** the real Olympus Themis service, from
  `docker/Dockerfile`, on Render / Railway / Fly.io / Cloud Run / a VPS — wherever a
  long-lived container with a writable volume can run. This is where authorization,
  scope, isolation and scanner execution happen.

```
browser ──▶ Vercel static site (public/)
        └─▶ /bff/<path>  ──▶  api/bff.py (serverless proxy)  ──▶  https backend /<path>
                                   │
                                   └── pure forwarder: no olympus import, no subprocess
```

## The BFF proxy (`DEPLOY-3`)

`api/bff.py` (handler) and `api/_bff.py` (logic) are a **backend-for-frontend**: a
pure HTTP forwarder to the one configured backend. They import nothing from
`olympus` and spawn no process — relaying only. The safety model (enforced in
`api/_bff.py`, verified offline in `tests/unit/test_bff.py`):

- **One fixed backend, no SSRF.** The target host comes only from the
  `OLYMPUS_BACKEND_URL` environment variable and must be `https://`. The client
  supplies only a path, which is validated (server-absolute, no scheme/host, no
  `..`) and appended — it can never redirect the proxy elsewhere.
- **Fail-closed allowlist.** Only allow-listed method+path pairs are forwarded;
  everything else is refused (`403`) without touching the network.
  `ALLOWED_GET_PREFIXES` covers the read-only API surface; `ALLOWED_POST_PATHS` is
  **empty by default** — add a write/trigger route there only when a real frontend
  needs it.
- **Bounded, non-amplifying.** Bodies are capped (`MAX_BODY_BYTES`), a timeout is
  always set, redirects are never followed (a `3xx` is passed through), and
  hop-by-hop headers and ambient cookies are stripped.

### Routing

`vercel.json` rewrites `/bff/<path>` to `/api/bff?p=/<path>`, so a frontend call to
`/bff/api/v1/engines/preflight` is forwarded to
`${OLYMPUS_BACKEND_URL}/api/v1/engines/preflight`.

## Owner steps to go live

1. Deploy the container backend (`docker/Dockerfile`) on your host; note its public
   `https://` URL.
2. In the Vercel project, set the environment variable `OLYMPUS_BACKEND_URL` to that
   URL (no trailing slash, no query/fragment).
3. Deploy the Vercel project. Until step 2 is done the BFF fails closed with `503`,
   so nothing proxies by accident.
4. Extend `ALLOWED_GET_PREFIXES` / `ALLOWED_POST_PATHS` in `api/_bff.py` to exactly
   the routes the frontend needs, and re-run `pytest tests/unit/test_bff.py`.

The backend remains the only place that executes scans, checks authorization and
enforces scope and container isolation; the Vercel layer is static assets plus a
constrained relay.

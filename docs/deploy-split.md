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
named-route HTTP forwarder to the one configured backend. They import nothing from
`olympus` and spawn no process — relaying only. The safety model (enforced in
`api/_bff.py`, verified offline in `tests/unit/test_bff.py`):

- **One fixed backend, no SSRF.** The target host comes only from the
  `OLYMPUS_BACKEND_URL` environment variable and must be `https://`. The client
  never supplies a URL or a path: it names a **route**, and the outbound path is a
  constant looked up in `ROUTES`. No request data is ever concatenated into the
  request URL, so neither the host nor the path can be steered.
- **Fail-closed allowlist.** Only the read-only routes in `ROUTES` are forwarded
  (`GET`/`HEAD`); an unknown route or a write method is refused (`403`/`405`)
  without touching the network. Add a route (and review any query/body forwarding)
  only when a real frontend needs it.
- **Bounded, non-amplifying.** A timeout is always set, redirects are never
  followed (a `3xx` is passed through), and hop-by-hop headers and ambient cookies
  are stripped.

### Routing

`vercel.json` rewrites `/bff/<route>` to `/api/bff?p=<route>`. For example
`/bff/engines-preflight` forwards to `${OLYMPUS_BACKEND_URL}/api/v1/engines/preflight`
(the constant path mapped by `ROUTES["engines-preflight"]`).

## Owner steps to go live

1. Deploy the container backend (`docker/Dockerfile`) on your host; note its public
   `https://` URL.
2. In the Vercel project, set the environment variable `OLYMPUS_BACKEND_URL` to that
   URL (no trailing slash, no query/fragment).
3. Deploy the Vercel project. Until step 2 is done the BFF fails closed with `503`,
   so nothing proxies by accident.
4. Extend `ROUTES` in `api/_bff.py` with exactly the read routes the frontend needs
   (each a constant backend path), and re-run `pytest tests/unit/test_bff.py`.

The backend remains the only place that executes scans, checks authorization and
enforces scope and container isolation; the Vercel layer is static assets plus a
constrained relay.

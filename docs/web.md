# Web control plane

Olympus exposes four interfaces over the **same** core use cases: the Typer
CLI, the Textual TUI, the authenticated HTTP API (`olympus.themis.api`) and the
browser **web control plane** (`olympus.themis.web`). None of them carries its
own cybersecurity logic. A job queued in the browser is run through the identical
registered-scope resolution, authorization gate, execution policy, sandbox,
rate limit, retention and redacted audit trail as the command line — so it is
indistinguishable, by policy and by audit, from a CLI job (ROADMAP `WEB-A`).

There is **no** `POST /run-command` and no arbitrary shell. The browser only
submits a typed request — `scanner`, `target`, `target_kind`, `scope_id` — that
the server validates with the same `JobSubmission` contract the API uses and
translates into the same scope- and policy-gated `ThemisJobStore.submit`.

## Running it

```bash
export OLYMPUS_THEMIS_API_KEY="$(head -c 48 /dev/urandom | base64)"   # ≥ 32 chars
olympus themis web --scope-directory .olympus/scopes --database .olympus/themis-jobs.sqlite3
```

The web plane shares its command surface with `olympus themis api`:

- **Loopback by default.** A non-loopback `--host` requires both `--ssl-certfile`
  and `--ssl-keyfile`; the session cookie is `Secure`, so it is only sent back
  over HTTPS (browsers treat `http://localhost` as a secure context).
- **Credentials never on the command line.** They come from
  `OLYMPUS_THEMIS_API_KEY` or an identity register passed with `--identities`
  (scoped, revocable, expiring credentials — see
  [`themis-api-identities.md`](themis-api-identities.md)).
- **Same durable store.** `--database` and `--scope-directory` point at the same
  SQLite job store and registered scopes the CLI and API use.

## Authentication and session

Login exchanges a valid THEMIS API credential for a short-lived, HMAC-signed
session cookie (`olympus_session`). The cookie is:

- `HttpOnly` — unreadable from JavaScript;
- `Secure` — never sent over plain HTTP;
- `SameSite=Strict` — not attached to cross-site requests.

The signing secret is generated per process, so restarting the server
invalidates every session. Revocation and expiry of the underlying identity take
effect immediately: each request re-resolves the identity from the register, so
a revoked credential cannot ride an already-issued cookie.

## CSRF, headers and Content-Security-Policy

Every state-changing form (`/jobs`, `/jobs/{id}/cancel`) carries a synchroniser
CSRF token bound to the session nonce and checked in constant time. Combined with
`SameSite=Strict`, a cross-site page cannot forge a submission.

Responses set a restrictive Content-Security-Policy with **no inline script or
style** —

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

— plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The one stylesheet
and the one progressive-enhancement script are same-origin static files, so the
policy needs no `'unsafe-inline'`. The request body is bounded to 64 KiB exactly
as on the API.

## Pages

| Route | Purpose |
| --- | --- |
| `GET /login`, `POST /login`, `POST /logout` | Session lifecycle. |
| `GET /` | Dashboard: job totals, a state histogram and the ten most recent jobs. |
| `GET /jobs` | Every job, newest first. |
| `GET /engagements`, `GET /engagements/{id}` | The shared engagements and their scope (requires `engagements:read`); available only when the server is started with `--engagement-storage`. |
| `GET /assessments/new`, `POST /jobs` | Typed, scope-gated job submission (requires `jobs:write`). An optional engagement scopes the target. |
| `GET /jobs/{id}` | Job detail with a live state line and, with `jobs:cancel`, a **Cancel** button wired to real Olympus cancellation. |
| `POST /jobs/{id}/cancel` | Cancel a job (CSRF-protected). |
| `GET /jobs/{id}/events` | Server-sent events stream of state transitions. |

Scope enforcement is per route: a `jobs:read` identity can browse but cannot open
the new-assessment form or submit; `jobs:cancel` is required to cancel;
`engagements:read` is required to view engagements.

## Engagements (`WEB-B`)

Started with `--engagement-storage <dir>`, the web control plane reads the same
`engagements.db` as `olympus engagement` and the same engagements as the API —
one store, one model, no per-interface notion of scope. The engagement pages are
read-only here (engagements are created from the CLI). When the new-assessment
form has an engagement selected, the server resolves it from that store and
refuses — with the engagement's own `covers()` logic, the host taken from the
typed target (a `url` target by its hostname) — any target outside the
authorized perimeter **before** the job is queued. The identical check runs on
`POST /api/v1/jobs` when a submission carries an `engagement_id`, so an
engagement's scope is enforced the same way from the browser, the API and the
command line.

## Live job state (server-sent events)

The job detail page works without JavaScript — it renders the authoritative
server-side state on each load. When JavaScript is available, a same-origin
`EventSource` subscribes to `/jobs/{id}/events` and updates the state line as the
job advances, reloading once to show the final detail when the job reaches a
terminal state.

The stream reports the store's real lifecycle states: `queued`, `running`,
`succeeded`, `partial` (nothing ran — a missing dependency or live scanning off),
`failed`, `timed_out`, `cancelled` and `policy_denied`. Sub-phases the worker
does not record (parsing, normalising) are **not** invented: an honest state
never implies coverage that did not happen.

## Hostile data from targets (`SEC-H`)

Everything a target can influence — a hostname, a scanner error — is stripped of
terminal control bytes and of URL query secrets before rendering, and Jinja2
autoescaping defuses HTML. A banner carrying an ANSI escape or a `<script>`
payload cannot rewrite the operator's terminal, forge a log line or execute in
the browser.

## Relationship to the legacy VAP web

The vendored Vulnerability Assessment Platform web surface
(`olympus themis serve`) remains quarantined to loopback and is being retired
(`SEC-A`). The native web control plane here is its authenticated, scope-gated
replacement and does not depend on `vendor/`.

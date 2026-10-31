# ADR-007: Native web control plane (FastAPI + Jinja/HTMX + SSE)

- **Status:** Accepted
- **Date:** 2026-10-01
- **Decision owners:** Olympus maintainers
- **Roadmap:** `WEB-A`…`WEB-H`
- **Depends on:** ADR-006 (Themis), the existing `themis.api` FastAPI surface
- **Relates to:** ADR-003 (retire the vendored VAP surface)

> **Non-binding** except for the security invariants under *Security
> consequences*, which are requirements.

## Context

Olympus must be usable three ways — CLI, TUI and browser — as different
interfaces over the **same** core, never parallel implementations of the
security logic:

```
            OLYMPUS CORE
                 │
      ┌──────────┼──────────┐
     CLI        TUI        API
                            │
                         WEB UI
```

Today a native typed API already exists (`themis.api`, ex `aegis.api`):
API-key auth per scope, accountability + body-limit middleware, `/health`,
`/ready`, `/metrics`, `/api/v1/capabilities` and `/api/v1/jobs`. There is **no**
native web UI; the only web surface is the quarantined vendored VAP (loopback
only), slated for retirement (`SEC-A`). The web UI must be built on the existing
API, not as a second platform, and must not duplicate business logic in the
frontend.

## Decision

Build the web UI with **FastAPI + Jinja2 + HTMX + Server-Sent Events**, served
by the same application that already exposes the typed API.

Compared with a separate SPA (React/Vue):

| Criterion | FastAPI + Jinja/HTMX + SSE | FastAPI + SPA |
|---|---|---|
| Maintenance | one codebase, one language | extra JS build/toolchain |
| Security surface | smaller (server-rendered) | larger (bundle, CORS, token storage) |
| Project size fit | matches a small Python project | heavier than needed |
| Real-time output | SSE/`EventSource` is enough for job streams | WebSocket/SSE either way |
| Packaging / Docker | one image, no node build | node build step |
| Testing | server-side, httpx/pytest | adds JS test stack |

HTMX wins on every axis that matters here; a SPA is reserved for a future team
with dedicated frontend ownership.

The web UI calls typed use cases only. There is **no** `POST /run-command` and
no arbitrary shell. A scan is requested as typed data
(`POST /api/jobs {scanner, target, engagement, profile}`) and the server builds
the execution internally — the same use case whether it is invoked from
`olympus themis run nmap`, the TUI, or a web button.

## Security consequences (requirements)

- Every browser-initiated operation passes through the **same** controls as the
  CLI: scope, authorization, execution policy, rate limit, deadline, sandbox,
  audit, retention, redaction. The GUI can never reduce them.
- No `run-command` endpoint, no arbitrary shell, no untyped command strings.
- Security headers, a restrictive CSP, `Secure`/`SameSite` cookies, CSRF
  protection where state-changing, input validation, rate limiting,
  authentication, RBAC and an audit trail.
- The frontend is never the source of truth; it renders server state.
- Live scans remain disabled by default; a missing engine is an explicit
  non-ready state, never a fabricated result. Job output is shown redacted.

## Alternatives rejected

- **Separate SPA** — more maintenance and a larger security surface than this
  project warrants (see table).
- **Extending the vendored VAP web UI** — rejected: it would entrench the very
  dependency `SEC-A` retires and build a second platform.

## Migration and rollback

The web UI is additive: CLI and TUI are unaffected. It ships behind the same
authentication as the API and off by default for live scans, so a deployment can
simply not serve it. The engagement model (`WEB-B`) and persistence abstraction
(`WEB-H`) are shared with the other interfaces, so no separate database is
introduced.

## Verification criteria

- A job created via the web API is indistinguishable, by policy and audit, from
  one created via the CLI (integration + authorization tests).
- Web-security tests cover headers, CSP, CSRF and authz; job-lifecycle and
  cancellation tests cover the SSE stream and the Cancel control.
- The Tools page is rendered from the real registry/capability inventory, not a
  hardcoded list (a test asserts parity with `themis capabilities`).

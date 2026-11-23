# ADR-010: Frontend stack — server-rendered control plane, SvelteKit for the split frontend

- **Status:** Accepted — non-binding except the security invariants below
- **Date:** 2026-11-23
- **Decision owners:** Olympus maintainers
- **Roadmap:** `TECH-2` (depends on `ADR-007`, `DEPLOY-2`, `DEPLOY-3`)
- **Supersedes / depends on:** depends on ADR-007 (native web control plane)

> **Non-binding** unless stated: only the invariants under *Security consequences*
> are requirements.

## Context

The production control plane is a FastAPI service that renders HTML server-side
with Jinja2, enhances it with HTMX, and streams progress over SSE (ADR-007). It is
adequate and has strong security properties, but it is limited for richer, highly
interactive views, and `TECH-2` asks to evaluate and select a modern stack on
technical grounds.

Forces specific to Olympus, with evidence in the repo:

- **Strict CSP.** The static surface ships `default-src 'none'; style-src
  'unsafe-inline'` (`vercel.json`, the Vulcan report, `scripts/build_preview.py`,
  `scripts/build_docs_site.py`). A stack that needs inline/eval'd JS or a large
  opaque client runtime fights this posture.
- **Split deployment.** The control plane cannot run on Vercel (stateful ASGI,
  worker, SSE, scanner subprocesses); the deployment is static Vercel + a thin BFF
  (`api/_bff.py`, DEPLOY-3) in front of a container Execution backend (DEPLOY-2).
  The frontend talks to the backend only through the BFF.
- **Offline-first, supply-chain caution.** Engines, data and container bases are
  pinned (`TOOLS-4`); a frontend toolchain pulling an unpinned dependency tree at
  build time is a new, large supply-chain surface.
- **No execution in the browser.** Authorization, scope and scanner execution are
  backend concerns; the frontend must never embed scanner logic or secrets.

## Decision

Two tiers, chosen deliberately:

1. **The control plane stays server-rendered: FastAPI + Jinja2 + HTMX + SSE
   (ADR-007 unchanged).** For the operator control plane — where every view is a
   security action — server rendering with progressive enhancement remains the
   default. It needs no client build step, no mandatory client runtime, and is
   trivially CSP-compatible.

2. **When a view genuinely needs SPA-grade interactivity (the split frontend served
   from Vercel in front of the BFF), the selected modern stack is
   [SvelteKit](https://kit.svelte.dev/)** with its static/edge adapter. Rationale:
   it compiles to small, framework-runtime-light output (no large virtual-DOM
   runtime shipped), supports static export and SSR, and produces output that fits
   a strict CSP without inline scripts. It talks to the backend **only** through the
   BFF named routes (`api/_bff.py`), never directly and never with embedded
   secrets.

This is a direction, not a migration mandate: nothing in the current control plane
is rewritten by this ADR. A SvelteKit surface is introduced only when a concrete
view needs it.

## Security consequences (requirements)

- Any new frontend surface MUST serve under a CSP at least as strict as the current
  one: no `unsafe-inline`/`unsafe-eval` for scripts, no remote script origins
  beyond pinned, Subresource-Integrity-pinned assets.
- The frontend MUST reach the backend only through the BFF (`/bff/<route>`), which
  stays a no-execution forwarder (no `olympus` import, no subprocess — enforced by
  `tests/unit/test_bff.py`). No scanner logic, authorization logic, or secret may
  live in client code.
- Any adopted toolchain MUST pin its dependencies (lockfile committed) and MUST NOT
  run scanners or reach non-allowlisted hosts at build time.

## Alternatives rejected

- **React + Next.js:** largest client runtime and the broadest dependency/supply
  chain surface; SSR helps but the default posture ships more JS than the CSP-first
  model wants.
- **Vue + Nuxt:** similar trade-offs to Next with no decisive advantage here.
- **A bare SPA (CRA/Vite + React) with no SSR:** pushes routing/auth to the client
  and tends toward `unsafe-inline`, conflicting with the CSP invariant.
- **Replacing HTMX/SSR wholesale:** rejected — it would discard a working,
  CSP-friendly, build-stepless control plane for no security gain.

## Migration and rollback

No migration is forced. The control plane continues on HTMX/SSR. If a SvelteKit
surface is added and proves unwarranted, it is removed without touching the
control plane, since the two tiers are independent and the backend contract (the
BFF routes) is unchanged.

## Verification criteria

- The BFF stays execution-free and allowlisted: `tests/unit/test_bff.py`.
- Static surfaces keep the strict CSP: `tests/unit/test_build_preview.py` and
  `tests/unit/test_docs_site.py` assert the CSP/self-containment of generated pages.
- A future SvelteKit surface is accepted only with a committed lockfile and a CSP
  test mirroring the above.

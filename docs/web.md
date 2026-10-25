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

For a live-capable deployment, enable the signed-authorization gate and use the
same store and key for the API, Web and workers:

```bash
olympus themis web --scope-directory .olympus/scopes \
  --engagement-storage .olympus/engagements \
  --manifest-public-key approver-ed25519-public.pem
```

With `--manifest-public-key`, the New assessment form requires the complete
signed JSON document. Preview and launch independently verify Ed25519 signature,
digest, revocation, validity window, engagement id, target and scanner. Launch
persists the exact document for worker-time revalidation and binds its SHA-256
digest to the job. A missing, malformed, expired, revoked, out-of-scope or
wrong-technique manifest is rejected before queueing. Supplying a manifest to a
server without a pinned key is also rejected. Without this option the legacy
boolean-confirmation mode may still queue offline work for compatibility, but a
live worker refuses every job without a bound manifest before the scanner
application. It therefore cannot become live traffic by enabling the worker.

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
- **Signed authorization.** `--manifest-public-key` plus
  `--engagement-storage` enables the same signed-manifest gate as the API and
  provides the retained document/revocation state used by workers.
- **Optional findings review.** `--findings-directory` points at a folder of
  `core.Finding` JSON bundles — the same read-only producer artifacts
  `olympus vulcan findings` consumes — and enables the **Findings** pages;
  `--findings-storage` points at the append-only lifecycle store so triage
  decisions made in the browser are recorded (and audited) there.
- **Optional scan diff.** `--baseline-directory` points at a folder of
  `core.Finding` bundles from an earlier run and enables the **Scan diff** page,
  which compares that baseline against the current findings.

## Authentication and session

Login exchanges a valid Themis API credential for a short-lived, HMAC-signed
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
| `GET /` | Dashboard: job totals, a state histogram, the ten most recent jobs, an assessment-progress widget (percent complete, in-flight / finished / clean-completion counts, from the authoritative terminal-state partition) shown whenever there are jobs, and — for a `findings:read` identity with `--findings-directory` — a findings-by-severity widget (with a by-source/scanner breakdown) linking into the filtered findings view; a `capabilities:read` identity also sees a scanner-readiness widget (ready / installed / adapted / catalogued) drawn from the capability inventory, linking to the tools page. |
| `GET /jobs` | Every job, newest first. |
| `GET /findings` | Findings, filtered and ranked by risk exactly as the CLI does (requires `findings:read`); available only with `--findings-directory`. |
| `GET /findings/report` | Download a Vulcan report of the currently filtered findings as Markdown, HTML, JSON or SARIF (requires `findings:read`). |
| `GET /findings/diff` | Compare a baseline run against the current findings — new / resolved / persistent (requires `findings:read`); available only with `--baseline-directory`. `?format=json` returns the machine-readable diff. |
| `GET /findings/{id}` | Finding detail, evidence chain and lifecycle history (requires `findings:read`). |
| `POST /findings/{id}/transition` | Record a lifecycle transition for one finding (requires `findings:write`, CSRF-protected); available only with `--findings-storage`. |
| `GET /engagements`, `GET /engagements/{id}` | The shared engagements and their scope (requires `engagements:read`); available only when the server is started with `--engagement-storage`. |
| `GET /tools` | The tool catalogue, read straight from the real capability inventory (requires `capabilities:read`). |
| `GET /assessments/new` | Guided New Assessment wizard (requires `jobs:write`): engagement → target → scope → activity → tool or automatic. |
| `GET /assessments/smart` | Smart Scan form (requires `jobs:write`): objective → target → scope → engagement → risk ceiling. |
| `POST /assessments/smart/plan` | Proposes a deterministic, scope- and policy-aware pipeline; queues nothing (requires `jobs:write`, CSRF-protected). |
| `POST /assessments/preview` | Renders the "Olympus is about to run" preview with the `PASSIVE`/`ACTIVE`/`INTRUSIVE` risk level; queues nothing (requires `jobs:write`, CSRF-protected). |
| `POST /jobs` | Typed, scope-gated job submission from the preview's launch form (requires `jobs:write`). An optional engagement scopes the target. |
| `GET /jobs/{id}` | Job detail with a live state line and, with `jobs:cancel`, a **Cancel** button wired to real Olympus cancellation. |
| `POST /jobs/{id}/cancel` | Cancel a job (CSRF-protected). |
| `GET /jobs/{id}/events` | Server-sent events stream of state transitions. |

Scope enforcement is per route: a `jobs:read` identity can browse but cannot open
the new-assessment form or submit; `jobs:cancel` is required to cancel;
`engagements:read` is required to view engagements; `capabilities:read` is
required to view the tools page; `findings:read` is required to browse findings
and `findings:write` to record a lifecycle transition.

## Findings (`WEB-C`)

`GET /findings` surfaces the findings/verification end of the cycle in the
browser, so an operator no longer has to drop to the terminal to review results.
It is a faithful projection of the same interface-agnostic building blocks the
CLI uses — no security or presentation logic is re-implemented in the page:

- **Source.** Findings are loaded from `--findings-directory` with the identical
  strict, bounded `load_findings` the CLI uses. The bundles are **read-only
  producer artifacts**; the page never rewrites them.
- **List and filter.** The filter form reuses `vulcan.search.FindingFilter`
  (status, minimum severity, source, engagement, tags, CISA KEV, has-CVE, free
  text, minimum risk) and the result is ranked by `vulcan.view.rank_by_risk`, so
  the browser produces the same set an operator gets from
  `olympus vulcan findings list` — tags use AND semantics like the CLI `--tag`.
- **Detail.** The detail cells come from `FindingView.display_items`, honest
  about absence (a datum the finding does not carry renders as `—`, never a
  fabricated `0`). The **evidence** table comes from
  `vulcan.evidence_view.build_finding_evidence_view`; with no custody ledger
  wired in, a structured reference is shown honestly as `no-custody` rather than
  disappearing, and inline snippets are redacted (`SEC-H`).
- **Lifecycle.** The transition choices are exactly
  `core.finding_lifecycle.allowed_transitions` of the finding's current status —
  the page cannot invent an illegal workflow edge. Recording a transition writes
  an immutable `olympus.finding-transition` record to the append-only
  `--findings-storage` store (who/when/from→to/why), and the **effective** status
  of a finding is folded from that history over the bundle's base status, so a
  decision made here is reflected everywhere the finding is shown without
  touching the producer artifact. Accepting a risk or marking a false positive
  requires a non-empty reason, mirroring
  `core.finding_lifecycle.suppress`.

Without `--findings-directory` the pages state plainly that the feature is not
configured; without `--findings-storage` findings are shown read-only. Both
degrade honestly rather than pretending there are no findings.

### Report export (`WEB-I`)

The findings view offers a one-click **Vulcan report** of exactly what is on
screen. `GET /findings/report` takes the same filter query parameters as
`GET /findings` (status, severity, source, text, KEV, has-CVE, min-risk,
`engagement`, `tag`) plus `format` (`md`, `html`, `json` or `sarif`), narrows the
catalogue with the identical `vulcan.search.FindingFilter` (so the report is
exactly the filtered table), builds the canonical `SecurityReport` with
`vulcan.report.build_report_model`, and renders it with the **existing**
`render_report_markdown` / `render_report_html` / the model's JSON dump — no
rendering logic is duplicated in the web layer, so a report from the browser is
byte-for-byte what the CLI produces for the same finding set. The `sarif` format
emits SARIF 2.1.0 (`application/sarif+json`) of the filtered findings via the
shared `vulcan.sarif.findings_to_sarif`, so the browser feeds the same
interoperability format as `olympus vulcan sarif-export`. The response is a
download (`Content-Disposition: attachment`), so what reaches the browser is a
report, not a page. When set, `engagement` both filters the findings to that
engagement and labels the report; it is sanitised (`SEC-H`) and slugified for the
filename. `tag` is a comma-separated list with AND semantics, exactly like the
CLI `olympus vulcan findings list --tag`. PDF stays CLI-only for now (`olympus vulcan report --pdf`,
optional `report` extra); trends and notifications are the remaining `WEB-I`
slices.

### Scan diff (`WEB-I`)

`GET /findings/diff` compares a **baseline** run against the **current** findings
and classifies every logical issue as **new** (a regression, or newly
discovered), **resolved** (the evidence a remediation landed) or **persistent**
(still open, with any severity/risk change shown). It reuses
`vulcan.compare.diff_findings` — the same engine as `olympus vulcan diff` — so the
browser and CLI agree, and matches findings by logical identity (same asset +
same vulnerability), never by the per-run id. Both inputs are read-only producer
artifacts: the baseline is `--baseline-directory`, the current set is
`--findings-directory`. Without a baseline the page says plainly that the feature
is not configured. `GET /findings/diff?format=json` returns the same
`ScanDiff` projection as `olympus vulcan diff --format json`, for automation and
CI regression gates.

## New assessment (`WEB-E`)

`GET /assessments/new` is a guided, activity-first wizard for an operator who
does not remember the CLI flags. It walks one path:

1. **Engagement** (optional) → **target** and **target kind** → **registered
   scope**.
2. **Activity** — *Reconnaissance*, *Network*, *Web application* or
   *Vulnerability assessment*. These are the activities that run as a Themis
   scanner job; *Secret scan*, *Detection engineering* and *Full assessment* are
   listed honestly as living in other modules (with their CLI command) rather
   than faked here.
3. **Tool** — *Automatic* (Olympus picks a ready tool for the activity) or a
   specific scanner. Each tool shows a plain-language summary and its risk
   badge; a catalogued-but-not-ready tool is shown disabled, never as runnable.
4. **Preview** (`POST /assessments/preview`) — an "Olympus is about to run"
   screen that re-validates the scope and engagement, resolves the scanner
   (honouring automatic mode), and states the **risk class**:
   - `PASSIVE` — observes public information, little or no traffic to the target;
   - `ACTIVE` — sends requests directly to enumerate and probe, non-destructive;
   - `INTRUSIVE` — attempts injection/exploitation, authorization mandatory.
   Nothing is queued by previewing.
5. **Authorize and launch** — the preview's launch form posts to `POST /jobs`.
   Documented authorization is **always** required (the GUI cannot weaken the
   CLI's gate); for an `ACTIVE` or `INTRUSIVE` operation the preview adds a
   prominent warning naming the target.

The classification itself carries no GUI logic: the activity type is derived
from each scanner's registry category and the risk class from a single reviewed
map in `olympus.integrations.activity` (an unmapped scanner defaults to
`ACTIVE`, never `PASSIVE`), so the web, and any future CLI/TUI wizard, read the
same answers. Automatic mode refuses honestly when no scanner for the activity
is ready on the host rather than queueing a job that cannot run.

Progressive enhancement only: the wizard works without JavaScript (every option
is present and the server re-validates the activity/tool pairing on preview); a
same-origin `assessment.js` simply filters the tool list to the chosen activity
and shows the live hint.

## Smart Scan (`WEB-F`)

`GET /assessments/smart` turns a *goal* — an objective, a target and (optionally)
an engagement — into an **ordered pipeline the operator reads before anything
runs**. It only *proposes*: `POST /assessments/smart/plan` queues nothing, runs
no scanner and contacts no target. Each proposed step is a form that hands off to
the normal `POST /assessments/preview`, so launching a step still passes the real
scope gate, authorization check and risk preview — the Smart Scan page never
weakens that gate.

An objective expands to a reviewed, ordered list of native activities
(reconnaissance always first, so louder stages act on a mapped surface):

- **recon** — reconnaissance only;
- **web-app** — recon → web application → vulnerability assessment;
- **network** — recon → network → vulnerability assessment;
- **full** — recon → network → web → vulnerability assessment.

The proposal is:

- **deterministic and reproducible** — the plan shows a stable SHA-256 *digest*
  of its inputs and ordered steps; the same inputs always produce the same plan;
- **scope-aware** — with an engagement chosen, a target outside its authorized
  perimeter yields a plan with **no steps** (no branch is ever proposed out of
  scope);
- **policy-aware** — a **risk ceiling** (default *Active*) drops any tool louder
  than the ceiling with an explicit reason; *Intrusive* techniques appear only
  when the operator selects the *Intrusive* ceiling explicitly;
- **bounded and honest** — only tools that are *ready* on this host are proposed,
  and every dropped activity is listed with a reason rather than hidden.

The engine is the interface-agnostic `olympus.integrations.smartscan`
(`propose_pipeline`), the same one the CLI `olympus themis smart-scan` uses, so
the web and the command line propose identically. Progressive enhancement only: a
same-origin `smart_scan.js` mirrors the chosen objective's summary into a hint.

## Tools (`WEB-D`)

`GET /tools` renders one card per catalogued engine **straight from the real
capability inventory** — the same `olympus.integrations.capabilities.inventory()`
that backs `olympus themis capabilities` and `GET /api/v1/capabilities`. The GUI
never hardcodes a tool list, so the page shows exactly what this host knows:

- **name, category and a plain-language purpose** for each engine;
- its **deployment class** (local OSS binary, containerised OSS service,
  proprietary remote API) and **licence**;
- the honest **readiness state** — `Ready`, `No Olympus adapter`,
  `Engine not installed` or `Not configured` — and the separate `adapted`,
  `installed/configured` and `runnable here` facts;
- the **Olympus maturity** stage (how far the project has validated the
  integration) and the next step that would advance it;
- the **requirements** still missing before the engine can run.

Because readiness is computed by the capability system and only an *adapted* and
*available* engine is `Ready`, a catalogued-but-unadapted scanner (for example an
API engine without an Olympus adapter) can never appear runnable. The page makes
no network request and executes no engine, so an engine's installed version is
detected at run time, not catalogued, and is deliberately not shown.

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

`olympus themis serve` now launches the same authenticated, scope-gated native
Web UI as `olympus themis web`. The legacy source remains an archive for the
pending full SEC-A parity review; Olympus does not launch it or import it.
See [`themis-runtime.md`](themis-runtime.md) for native migration, workers,
Docker deployment and rollback.

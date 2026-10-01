# Engagements

An **engagement** is Olympus's top-level container for an authorized assessment.
It owns the perimeter (included and excluded targets) and the authorization
reference; assets, scans, jobs, findings, evidence, alerts, incidents and
reports are associated with it by `engagement_id`. CLI, TUI, API and the Web UI
reference the **same** `olympus.engagement` contract and the **same** database,
never a private per-interface notion of scope (ROADMAP `WEB-B`).

## Contract

`olympus.engagement` (`src/olympus/core/models.py`, versioned like every other
contract) carries:

- `engagement_id` (e.g. `ENG-2026-00001`), `name`, `client`, `status`
  (`planned` / `active` / `closed`);
- `scope`: an `EngagementScope` with `included` (at least one) and optional
  `excluded` targets. A host is in scope when it matches an included entry (the
  entry covers itself and its subdomains) **and** does not match an excluded
  entry. IP/CIDR matching is a planned extension; until then list IPs verbatim;
- `authorization_reference`: a contract/approval id — never a secret;
- timestamps, `tags` and a free-form string `metadata` map;
- a deterministic `digest()` over the canonical encoding.

## CLI

The engagement database lives in the `--storage` directory (`engagements.db`,
written owner-only).

```bash
# Create an engagement with an explicit in/out-of-scope perimeter
olympus engagement create --name "ACME Oct 2026" --client ACME \
  --include example.com --include api.example.com \
  --exclude prod-db.example.com \
  --authorization-reference CONTRACT-123 \
  --storage ./workspace

# List engagements (most recent first) and show one in full
olympus engagement list --storage ./workspace
olympus engagement show ENG-2026-00001 --storage ./workspace
```

Every command prints JSON for machine use. `show` on an unknown id exits `2`
(usage), consistent with the canonical Olympus exit codes.

## Linking objects to an engagement

Every engagement-scoped contract — `Asset`, `Finding`, `Event`, `Evidence`,
`Alert`, `Incident` and `Observation` — carries an optional `engagement_id`
(`core/models.py`, via the shared `EngagementScopedModel` base). It ties the
object to the engagement that owns it, so CLI, TUI, API and Web scope the same
objects identically instead of each inventing a private notion of ownership.

The field is **optional and additive** (the contract stays at `schema_version`
`1.0.0`): objects produced outside any engagement, or persisted before `WEB-B`,
leave it `None`. When set it must be a canonical engagement id
(`ENG-YYYY-NNNNN`); the value is upper-cased and validated, and a malformed id
raises a `ValidationError`.

```python
from olympus.core.models import Finding
from olympus.core.enums import Source

finding = Finding(
    asset_id="AST-2026-00001",
    source=Source.THEMIS,
    title="Outdated component",
    engagement_id="ENG-2026-00001",  # ties this finding to the engagement
)
```

### Association primitives

Rather than copy the `engagement_id` by hand, producers use the helpers on the
`Engagement` model so the link is set the same way everywhere:

- `engagement.stamp(obj)` returns a **copy** of any engagement-scoped object
  (`Asset`, `Finding`, `Alert`, …) linked to the engagement, without mutating the
  original. The concrete type is preserved (a stamped `Finding` is a `Finding`).
- `engagement.stamp_all(objects)` stamps an iterable in one call.
- `engagement.covers(host)` forwards to `EngagementScope.covers`, so a producer
  can scope-check a host against the engagement without reaching into `scope`.

```python
from olympus.engagements.store import SqliteEngagementStore

store = SqliteEngagementStore(Path("./workspace/engagements.db"))
engagement = store.require("ENG-2026-00001")  # raises if the id is unknown

if engagement.covers("api.example.com"):
    findings = engagement.stamp_all(raw_findings)  # each linked to ENG-2026-00001
```

`SqliteEngagementStore.require(engagement_id)` resolves an engagement or raises
`EngagementStoreError`, so an unknown id fails loudly at the source instead of
silently stamping objects with a dangling reference.

## Status

The shared contract, the store, the CLI (slice 1), the optional `engagement_id`
on the core scoped contracts and the association primitives (`stamp`/`stamp_all`/
`covers`, `store.require`) for slice 2 are in place. Wiring Athena assessments
and Themis jobs to **call** these primitives against the shared store at produce
time, and exposing engagements through the API and Web UI, are the remaining
slices — all on this one model and store.

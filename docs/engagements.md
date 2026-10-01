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

## Status

This is the first slice of `WEB-B`: the shared contract, the store and the CLI.
Linking Athena assessments and Themis jobs/findings to an `engagement_id`, and
exposing engagements through the API and Web UI, are the next slices — all on
this one model and store.

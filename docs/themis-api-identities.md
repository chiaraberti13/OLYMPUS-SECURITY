# THEMIS API identities, scopes and accountability

The native THEMIS API authenticates a **named identity**, checks that identity's
**scopes** and **rate limit**, and records the request with an id that is echoed
back to the caller. One shared key with implicit full access is still supported
for a single-operator deployment, but it is no longer the only option.

Implemented in `src/olympus/themis/identity.py` and `src/olympus/themis/api.py`;
operated with `olympus themis identities …`; tested in
`tests/unit/test_themis_identity.py`.

## Scopes

| Scope | Grants |
| --- | --- |
| `capabilities:read` | `GET /ready`, `GET /api/v1/capabilities` |
| `jobs:read` | `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}` |
| `jobs:write` | `POST /api/v1/jobs` |
| `jobs:cancel` | `POST /api/v1/jobs/{id}/cancel` |
| `engagements:read` | `GET /api/v1/engagements`, `GET /api/v1/engagements/{id}` |

A credential without the scope a route requires gets **403**, and the response
names the missing scope. An unknown scope in the register is refused when the
register is loaded, so a typo cannot silently grant nothing — or everything.

## The identity register

`olympus.themis-api-identities` (`1.0.0`) is written atomically and owner-only
(`0600`). It stores, per identity: the id, the **SHA-256 of the secret**, the
scope set, creation/rotation timestamps, an optional expiry, a revocation flag,
and a per-identity rate limit.

Secrets themselves are never stored and never logged. `add` and `rotate` print
the credential once; if it is lost, rotate again.

```bash
olympus themis identities add ops-console --scopes jobs:read,jobs:write
olympus themis identities add dashboard --scopes jobs:read --rate-limit 30 \
  --expires-in-days 90
olympus themis identities list
olympus themis identities rotate ops-console --overlap-seconds 300
olympus themis identities revoke dashboard
```

The register is re-read when the file changes, so **rotation and revocation take
effect without restarting the server**. A register that cannot be read or
validated authenticates *nobody*: a file that may carry a revocation is not
something to keep guessing about.

### Rotation with an overlap

`rotate` issues a new secret and keeps the previous one valid for
`--overlap-seconds` (default 300, max 7 days), so clients can be updated without
an outage. The old secret then stops working on its own — no second command is
needed. `--overlap-seconds 0` invalidates it immediately.

Revocation is stronger than expiry: it also drops any secret still inside its
rotation window.

### Expiry

`--expires-in-days` sets `not_after`. After that moment the identity
authenticates nothing, with no cleanup step required.

## Rate limiting

Each identity has its own sliding 60-second window
(`rate_limit_per_minute`, default 120). Exceeding it returns **429** with a
`Retry-After` header.

The limiter is **in-process**: it bounds one server's exposure to a runaway or
stolen credential. It is not a distributed quota — several replicas each enforce
the limit separately — and a deployment that needs a shared quota should put one
in front of the API rather than assume this provides it.

## Request, correlation and audit ids

Every response carries:

- `X-Request-ID` — this request. A caller-supplied value is echoed when it is
  inert text (`[A-Za-z0-9._-]{1,64}`); anything else is replaced with a
  generated `req-<hex>`, so a header cannot inject text into the audit log.
- `X-Correlation-ID` — the caller's trace across services, validated the same
  way and defaulted to `cor-<hex>`.

With `--audit` (default: the state directory's audit log), each request appends
one redacted `StructuredAuditRecord`: the request id as `execution_id`, the
method and path as the action, the status code as the outcome, and the
authenticated identity (`anonymous` for a rejected request) plus the correlation
id in the metadata. Credentials never appear: only the identity's name does.

## Transport

Non-loopback binds require both `--ssl-certfile` and `--ssl-keyfile`; the API
refuses to start otherwise. The single-key secret is read from an environment
variable (`--api-key-env`, default `OLYMPUS_THEMIS_API_KEY`) and is never
accepted as a command-line argument.

```bash
OLYMPUS_THEMIS_API_KEY=… olympus themis api            # loopback, single key
olympus themis api --identities ~/.local/state/olympus/themis-api-identities.json \
  --host 10.0.0.5 --ssl-certfile server.crt --ssl-keyfile server.key
```

## Log retention

The per-request audit log grows for as long as the API serves traffic. Bound it
with `olympus themis retention rotate-log`; see [`retention.md`](retention.md).

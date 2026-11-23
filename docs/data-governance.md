# System data retention and privacy policy (DATA-3)

This is the single policy of record for how long Olympus keeps each class of
sensitive material, how that material is classified for privacy, and — for
evidence — how its lifecycle is made verifiable. It unifies mechanisms that
already exist: bounded retention and secure deletion
(`olympus.core.retention`, see [retention.md](retention.md)), the signed,
hash-chained custody ledger (`olympus.minerva.custody`), and the transactional
store's own pruning (`ThemisJobStore.prune`). The policy itself lives in
`olympus.minerva.governance` (`SYSTEM_POLICY`), so it is executable, not only
prose.

## Data classes

Every sensitive class is registered with a **bounded** retention rule (age, count
or size — never "keep everything"), a **privacy classification**, how retention is
**enforced**, and whether it is tracked in the **verifiable custody chain**.

| Class | Keeps | Enforcement | Targets | Identities | Redact on egress | Custody-tracked |
| --- | --- | --- | --- | --- | --- | --- |
| `engine-evidence` | ≤365 days / ≤10000 files | prune dir | yes | no | no | **yes** |
| `finding-history` | ≤365 days / ≤10000 files | prune dir | yes | no | yes | no |
| `scanner-output` | ≤30 days / ≤5000 files | prune dir | yes | no | yes | no |
| `job-records` | ≤180 days | store-managed | yes | yes | yes | no |
| `audit-trail` | ≤365 days | rotate log | no | yes | yes | no |

The windows are conservative documented defaults — the **mechanism**, not the exact
number of days, is the contract; an operator tightens them per engagement. Raw
scanner output (least summarised, most sensitive) is kept the shortest; signed
evidence and finding history the longest.

## Evidence historicisation with a verifiable custody chain

Signed engine-run evidence (`TOOLS-4.5`) is the `custody-tracked` class. Its
lifecycle is recorded in the Minerva custody ledger: each entry anchors the
evidence SHA-256, is hash-chained to the previous entry, and — when a key is
configured — is Ed25519-signed so a third party can verify that the chain was not
truncated or rewritten (`SEC-E`). `governance.verify_custody` reuses
`custody.inspect_ledger` with the environment's key to confirm the chain is
evidence-anchored and, if signed, valid. Retention never deletes an evidence
artefact without that history remaining verifiable in the ledger.

## Operating it

```bash
# Show the whole policy as JSON.
olympus minerva governance-policy

# Apply a class's retention to a directory (dry-run first).
olympus minerva governance-apply engine-evidence ./.olympus/out --dry-run
olympus minerva governance-apply scanner-output ./.olympus/out

# Verify the custody chain that historicises evidence.
olympus minerva governance-verify-custody ./.olympus/minerva-custody.json
```

Classes enforced elsewhere refuse a directory pass with a pointer to the right
tool: `job-records` → `olympus themis jobs prune`; `audit-trail` →
`olympus themis retention rotate` (log rotation). This keeps one authority per
class rather than two mechanisms deleting the same data.

## Privacy

`contains_identities` / `contains_targets` mark the classes that name people or
authorized targets; `redact on egress` marks the classes that must be redacted
before leaving the perimeter (the same discipline the SIEM/CTI connectors already
apply). This policy is the reference the AI egress gate (`AI-2`, ADR-011) and any
export path check against.

## Scope and limits

Retention here bounds **files on disk** and **store rows**; as
[retention.md](retention.md) states, dependable erasure of data at rest is
full-disk/filesystem encryption, and this is defence in depth on top of it, not a
replacement. The concrete Postgres backend for `job-records` is out of the offline
perimeter (`DATA-2`), but the same policy windows apply once it exists.

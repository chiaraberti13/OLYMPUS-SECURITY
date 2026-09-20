# Minerva bounded incident and custody workflows

Minerva consumes versioned Apollo alerts offline and maintains local evidence
custody. Offline work does not invent a network authorization requirement; the
shared execution policy still enforces deadlines and cooperative cancellation.

## Alert triage

`minerva triage` accepts only a bounded, non-symlink regular file using the
`olympus.apollo-alerts` `1.0.0` envelope. It validates the envelope and every
nested `olympus.alert`, caps bytes and alert count, removes exact repeated alert
IDs, and rejects conflicting duplicates. It never invents or silently repairs
an alert.

The incident severity is the highest input severity, and alert/evidence links
are retained. Its stable incident ID is derived from title, owner and alert IDs;
the earliest/latest alert timestamps become the incident timeline. Repeating
the same triage therefore preserves identity. Incident output is unique,
fsynced, atomic, owner-only (`0600` on POSIX), and cannot overwrite its input.

## Evidence-anchored custody 2.0

The current `olympus.custody` contract is `2.0.0`. Every hash-linked entry now
includes both `evidence_id` and the evidence document's lowercase SHA-256. The
complete verification checks:

- contiguous sequence and previous-entry hash;
- each recomputed entry hash;
- timezone-aware monotonic timestamps;
- an immutable digest for each evidence ID;
- `collected` as the first and only collection action;
- no transition after `archived`.

Before appending, Minerva locks a private sibling lock file, re-reads and
verifies the complete chain under that lock, enforces entry/byte limits, then
uses a unique fsynced atomic replacement with mode `0600`. This prevents lost
updates between cooperating processes. The lock file intentionally remains so
concurrent processes continue to coordinate on the same inode.

Legacy `1.0.0` ledgers can be verified and rendered, but are read-only because
their entries did not contain an evidence digest. Verify/timeline exit `1` and
state that limitation; append requires preserving the old ledger and starting
a `2.0.0` ledger. A missing ledger exits `2` and is never described as verified.

```bash
olympus minerva triage apollo-alerts.json --title "Endpoint incident" \
  --output incident.json
olympus minerva record evidence.json custody.json \
  --actor responder --action collected
olympus minerva verify custody.json
olympus minerva timeline custody.json --format json
# portable, third-party-verifiable timeline:
olympus minerva timeline custody.json --export timeline.json --sign-key case.key.pem
olympus core verify timeline.json timeline.json.sig --pubkey case.pub.pem
```

`--export` writes the verified timeline as a deterministic
`olympus.minerva-timeline` JSON artifact; `--sign-key` additionally emits an
Ed25519 signature envelope over the exact exported bytes (reusing `core.signing`),
so a recipient with the trusted public key can confirm the timeline's provenance
and detect any tampering with `olympus core verify`. `--sign-key` requires
`--export`.

Defaults cap alert input at 50 MB/100,000 alerts, evidence at 1 MB, and custody
at 50 MB/100,000 entries. The corresponding `--max-*` and `--deadline` options
can tighten them. An unkeyed local hash chain detects accidental or
non-recomputed changes but is not an authenticity signature: preserve the
verified terminal hash in an independently access-controlled case system when
protection from an attacker able to rewrite the entire ledger is required.

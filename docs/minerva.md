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

## Evidence-anchored and attributed custody 3.x

The current `olympus.custody` family is `3.0.0` (unsigned), `3.1.0` (HMAC) and
`3.2.0` (Ed25519). Every first `collected` event must carry a strict acquisition
document through `--provenance`. It records tool/version, SHA-256 digests of the
effective policy and authorized scope, a redacted argv template, coverage status,
and a mandatory reason for `partial`/`failed`/`cancelled`. Verification checks:

- contiguous sequence and previous-entry hash;
- each recomputed entry hash;
- timezone-aware monotonic timestamps;
- an immutable digest for each evidence ID;
- `collected` as the first and only collection action;
- no transition after `archived`.
- acquisition context only on the first event for each evidence ID;
- complete acquisition context on every 3.x evidence chain;
- acquisition context inside the entry hash and ledger signature.

Before appending, Minerva locks a private sibling lock file, re-reads and
verifies the complete chain under that lock, enforces entry/byte limits, then
uses a unique fsynced atomic replacement with mode `0600`. This prevents lost
updates between cooperating processes. The lock file intentionally remains so
concurrent processes continue to coordinate on the same inode.

Legacy `1.0.0` ledgers can be verified and rendered, but are read-only because
their entries did not contain an evidence digest. Verify/timeline exit `1` and
state that limitation. Existing 2.x ledgers remain readable and verifiable; they
may continue existing evidence transitions, but cannot claim attribution they
never captured. A new collection starts a 3.x ledger. A missing ledger exits `2`
and is never described as verified.

```bash
olympus minerva triage apollo-alerts.json --title "Endpoint incident" \
  --output incident.json
cat > acquisition.json <<'JSON'
{
  "tool": "nmap",
  "tool_version": "7.95",
  "policy_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "scope_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "command_template": ["nmap", "-sV", "{target}"],
  "coverage_status": "clean",
  "partial_reason": null
}
JSON
olympus minerva record evidence.json custody.json \
  --actor responder --action collected --provenance acquisition.json
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

### Signed ledgers: HMAC 3.1.0 and Ed25519 3.2.0 (`SEC-E`)

Beyond the unsigned `3.0.0` ledger, the append path can sign the chain head
(`entry_count` + `head_hash`) so a truncation or a full rewrite is caught, not
just an accidental edit. The mechanism is chosen by the strongest key present:

| Env var | Ledger | Signature | Who can verify |
| --- | --- | --- | --- |
| `OLYMPUS_CUSTODY_ED25519_PRIVATE_KEY` | `3.2.0` | Ed25519 (asymmetric) | any third party, with the **public** key only |
| `OLYMPUS_CUSTODY_HMAC_KEY` | `3.1.0` | HMAC-SHA256 (symmetric) | only a holder of the shared secret |
| *(none)* | `3.0.0` | — | hash chain only |

The Ed25519 private key is a hex-encoded raw 32-byte seed, resolved through the
`SecretProvider` seam (`SEC-D`); the public key (`OLYMPUS_CUSTODY_ED25519_PUBLIC_KEY`,
hex) is read plainly. The `3.2.0` signature embeds the signer's public key, and
`verify` checks it against the operator-supplied public key (the trust anchor),
so an attacker cannot re-sign a rewritten ledger under their own key. Ed25519 is
what makes the chain **verifiable by a third party** — the completion criterion
for `SEC-E` — because, unlike HMAC, no secret is needed to verify.

```bash
# Generate a raw Ed25519 key pair as hex (private seed + public key)
python - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = Ed25519PrivateKey.generate()
print("private:", k.private_bytes_raw().hex())
print("public :", k.public_key().public_bytes_raw().hex())
PY

export OLYMPUS_CUSTODY_ED25519_PRIVATE_KEY=<private-hex>
olympus minerva record evidence.json custody.json --actor responder \
  --action collected --provenance acquisition.json
# ledger is now 3.2.0; a third party verifies with the public key alone:
OLYMPUS_CUSTODY_ED25519_PUBLIC_KEY=<public-hex> olympus minerva verify custody.json
```

Appending to a signed ledger requires the matching key: without it `verify`
exits non-zero (chain checked, signature unconfirmed) and `record` refuses rather
than silently stripping the signature.

### Nota operativa italiana

Per una nuova acquisizione, `--provenance` è obbligatorio. Il JSON deve contenere
versione dello strumento, digest SHA-256 di policy e scope, template argv con
placeholder e stato di copertura. Per `partial`, `failed` o `cancelled` serve
anche `partial_reason`; valori che sembrano segreti e caratteri di controllo
vengono rifiutati. La provenienza entra nell'hash della voce e quindi nella firma
del ledger: una modifica successiva viene rilevata da `verify`.

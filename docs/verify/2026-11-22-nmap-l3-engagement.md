# TOOLS-4.2 L3 — `nmap` live-tested, engagement-signed evidence

Formal L3 promotion of `nmap`: a real `nmap` scan executed **live** inside the
hardened scanner container, authorized by a **signed engagement manifest**
(approver Ed25519 key, not a throw-away lab policy), producing **signed evidence**
that a third party can pin-verify. This is the committed, verifiable record the
L3 promotion required.

## How it was produced

Runner: [`labs/l3/run_engagement.sh`](../../labs/l3/run_engagement.sh), against an
authorized private lab target on an isolated Docker network:

```bash
bash labs/l3/run_engagement.sh 172.18.0.2
```

The run was authorized by a signed engagement manifest (engagement
`ENG-2026-00001`, technique `nmap`, host scope), executed in the hardened
container that satisfies `require_scanner_isolation()` (read-only root, empty
capabilities, no-new-privileges, non-root uid, pinned image attestation), and
signed the evidence with a run-time Ed25519 key. No private key is committed —
only the signed evidence, its signature, and the **public** verification key.

## Committed artifacts

- [`nmap-engagement-evidence.json`](2026-11-22-nmap-l3-engagement/nmap-engagement-evidence.json)
  — the `olympus.engine-run-evidence` 1.0.0 manifest.
- [`nmap-engagement-evidence.json.sig`](2026-11-22-nmap-l3-engagement/nmap-engagement-evidence.json.sig)
  — the Ed25519 signature envelope (`olympus.sig.v1`).
- [`evidence_pub.pem`](2026-11-22-nmap-l3-engagement/evidence_pub.pem)
  — the public key to **pin** when verifying.

## What the evidence records

| Field | Value |
| --- | --- |
| Engine | `nmap`, detected `Nmap version 7.992`, pinned `v7.992` @ `0ee5616` |
| Execution state | `live`, exit `0`, `partial = false` |
| Target / kind | `172.18.0.2` / `host` |
| Authorization | signed engagement manifest `588c1dee8fb8…` (`lab_policy_sha256 = null`) |
| Findings | 1 (TCP 80 open, `http` / nginx 1.31.9) |
| Raw output digest | `stdout_sha256 = e5fd0ff2becb5ce8…` |

## Verify (pinned)

Verification goes through `olympus.engines.evidence.verify_signed`, which reads
the manifest and its `.sig` and returns the evidence only when the signature is
valid **and** the envelope's embedded public key matches the key you pin:

```python
from pathlib import Path

from olympus.engines.evidence import verify_signed

base = Path("docs/verify/2026-11-22-nmap-l3-engagement")
evidence = verify_signed(
    base / "nmap-engagement-evidence.json",
    public_pem=(base / "evidence_pub.pem").read_text(),
)
print(evidence.engine.name, evidence.outcome.state, evidence.outcome.exit_code)
```

Verification is **pinned**: the signature envelope embeds a public key, but it is
trusted only when it matches the committed `evidence_pub.pem`. Verified on
2026-11-22: the signature is valid for the manifest bytes and the embedded key
matches the pinned key (`nmap live 0`).

## Result

`nmap` is formally live-tested at **L3** with committed, engagement-signed,
pin-verifiable evidence. `httpx`/`nuclei` scan URLs, which the host-scoped
engagement manifest does not cover; their L3 runs stay on the lab-policy path
([`labs/l3/run.sh`](../../labs/l3/run.sh)) already demonstrated end-to-end.

# Security report — ENG-GOLDEN

_Generated 2026-01-02 03:04 UTC by Olympus Vulcan._

## Summary
- Assets: 1
- Findings: 1
- Alerts: 1

| Severity | Count |
| --- | --- |
| critical | 0 |
| high | 1 |
| medium | 0 |
| low | 0 |
| info | 0 |

## Assets
- AST-GOLDEN-1 — example.test (domain, argus)

## Findings (ranked)

### [HIGH] Reflected script injection
- ID: FND-GOLDEN-1
- Source: artemis
- Asset: AST-GOLDEN-1
- CVSS: 8.2
- Untrusted input is reflected into an HTML response.
- **Remediation:** Apply contextual output encoding.

## Alerts
- [MEDIUM] Suspicious login sequence (ALT-GOLDEN-1; rule APL-GOLDEN-1; MITRE T1110)

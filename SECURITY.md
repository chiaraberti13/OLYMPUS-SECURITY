# Security Policy

## Supported versions
Security fixes target the latest revision on the default branch unless a release is explicitly documented as supported.

## Scope
All native Olympus modules, shared data contracts, CLI/TUI entry points, scope enforcement, sandbox/tool execution, evidence handling, reporting, external integrations and build/CI configuration.

## Reporting
Do not open a public issue for an unpatched vulnerability. Report privately through the repository's **Security → Advisories → Report a vulnerability** (GitHub Private Vulnerability Reporting); if that is unavailable, request a private channel by opening a minimal issue that asks a maintainer to enable it, without disclosing details. Include the affected commit/version, impact, minimal reproducible proof, environment assumptions and possible mitigations. Remove unrelated sensitive data.

## Response targets
These are good-faith targets for this project, measured from a triaged, reproducible report; they are commitments of process, not of calendar guarantees, and do not assert production readiness.

| Severity | Acknowledge | Triage decision | Target fix |
| --- | --- | --- | --- |
| Critical (scope bypass, RCE/command execution, sandbox escape, secret leakage, auth failure) | 48 hours | 48 hours | 7 days |
| High | 72 hours | 5 days | 30 days |
| Medium | 7 days | 14 days | 90 days |
| Low / informational | 14 days | 30 days | next scheduled release |

If a fix cannot meet the target, the reporter is told the reason, the interim mitigation and the revised date. Coordinated disclosure follows the **Disclosure** section below. For compromise of signing keys, CI tokens or AEGIS/Themis API keys, follow the [incident-response runbook](docs/incident-response.md).

## Responsible testing
Test only systems, data, devices and networks you own or are explicitly authorized to assess. No denial of service, destructive actions, persistence, social engineering, unauthorized interception or third-party access.

## Security requirements
Keep secrets outside source control; validate untrusted input; preserve authorization/scope checks; review dependency and CI changes; prefer reproducible builds; never present partial or unverified evidence as a confirmed fact. Reports involving scope bypass, SSRF, command execution, sandbox escape, secret leakage, evidence tampering or authorization failure are especially important.

## Dependency & supply-chain updates
A vulnerability that `pip-audit` (`make audit`) reports against the runtime closure is treated as a security issue and fixed within the **Response targets** above, by severity. There is no permanent allowlist: a vulnerability may be waived only through the time-boxed registry at [`.github/audit-exceptions.toml`](.github/audit-exceptions.toml), where each entry records a motivation, an owner, the date added and an expiry. `scripts/check_audit_exceptions.py` (`make audit-exceptions`, chained into `make check`) fails when any waiver is expired or malformed, so an exception cannot silently become permanent. **Note:** the GitHub Actions workflow that ran `pip-audit`, the waiver gate and Dependabot automatically was removed from the repository (commit `58ba209`); until it is restored these supply-chain gates run on demand via `make`, not automatically on push/PR.

## Disclosure
Allow reasonable remediation time and coordinate publication of exploit-enabling details.

## Private reporting process

Use **Report a vulnerability** in the repository Security tab if private reporting is available. Otherwise use a verified private contact published by the repository owner. If no private contact is available, open a public issue asking only for a private contact, without vulnerability details. Do not publish exploit details, credentials, personal data or sensitive logs in public issues.

Include the affected revision, environment, impact and minimal synthetic reproduction. Coordinate disclosure with the maintainer. Acknowledgement and remediation depend on availability and severity; no fixed response deadline is guaranteed.

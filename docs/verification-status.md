# Verification status — 2026-10-29

Baseline audit: `b5cc491ac466fc5875a40266151e3aa55730c82e`. The tested merge
`bca1daa` includes remote `e177498` and the SEC-E-01 audit fix `e8dea67`.
[Machine-readable checks](verify/audit-2026-10-29-checks.json) record commands,
counts, source digests and limitations. [Ecosystem audit](ecosystem-audit.md) and
[ROADMAP](../ROADMAP.md) define coverage and follow-up work.

## What actually ran

Linux, Python 3.12.14. Fresh editable install with dev/api/report/observability;
separate clean wheel install with api/report. No scanner execution against a real
or third-party target. The native smoke used only loopback with live scans off.

| Check | Outcome | Meaning / limitation |
|---|---|---|
| Four new SEC-E-01 regressions before fix | 4 failed as expected (28 October) | Proved old implementation loses history / accepts replacement |
| Targeted Athena tests after merge | **51 passed** | Duplicate rejection, competing connections, reopen/recover/cancel, existing Athena flows |
| Ruff lint / format | **Passed** | Full checkout |
| Mypy strict | **Passed**, 214 source files | First-party source |
| Schema catalog / audit exceptions | **Passed**, 24 versioned contracts | No active exception |
| `make test-coverage` | **Failed: 2468 passed, 17 failed, 67 deselected** | Same 17 sandbox failures observed before the fix; host cannot chown scratch to the sandbox user (EINVAL) |
| Standalone branch gate | **81.02%, passed** (minimum 75%) | Numeric coverage only; does not override failing tests |
| `make test-mutation` | **Passed**, 1231/1991 targeted mutants killed (61.8%) | Configured security functions only, not all application paths |
| Wheel / clean install / entry point / pip check | **Passed**, version 0.2.0 | Linux/Python 3.12 only |
| Native runtime smoke from wheel | **Passed** | Migration/idempotency, unauthenticated API rejection, disabled worker remains partial, HTTPS login/CSS |
| `make audit` | **Passed with local-package skip** after pip update | pip-audit cannot audit local Olympus 0.2.0 against PyPI |
| CycloneDX SBOM generator | **Generated** | Schema/conformance and PEP 508 closure correctness not established (SEC-F-02) |
| Hash lock generation | **Timed out after 120 s** | No lock produced; no hash-locked install claimed |
| `make secrets-scan` | **Unavailable**, executable missing | No Gitleaks working-tree/history/canary pass claimed |
| Quick benchmark | **Completed** | [Synthetic measurements](verify/audit-2026-10-29-benchmark.json); budgets not enforced |
| Internal documentation links / diff whitespace | **Passed** | External links not checked |

Initial `pip-audit` found 12 advisory entries (6 unique identifiers) in the fresh
venv's bootstrap pip 25.0.1. Upgrading that environment to pip 26.2.2 resolved
those findings without project dependency waivers. This is an environment fix,
not a claim that all possible Olympus vulnerabilities are excluded.

The failed full-suite cases are listed individually in the checks JSON. They
fail while preparing the isolated scratch directory, before their intended
subprocess assertions. No tests were disabled, no sandbox policy was weakened,
and no passing full `make check` is claimed. The earlier baseline on 28 October
reported 2435 passed / the same 17 failed / 67 deselected. Added upstream tests
and the new regression cases explain the changed final passing count.

## Remaining verifications and release limits

- Container/kernel egress, scanner lab/version compatibility: SEC-B-01, D1/D2/D11.
- Hash-locked rebuild and release signing/attestations: SEC-F-01/02. The CI
  workflow (ci.yml: gate, tests, coverage, mutation, gitleaks, pip-audit, SBOM)
  and a CodeQL SAST workflow (codeql.yml) are restored/added and run on GitHub;
  making their checks *required* via branch protection is an owner action.
- Real-browser SSE and accessibility, keyboard/screen-reader and IT/EN parity:
  WEB-A-01, UX-E-01. TestClient/Textual pilot tests are not a manual accessibility review.
- Supported Python/OS matrix: only Linux 3.12 was executed here; D12 remains open.
- Full backup/restore, state/audit atomicity and performance under a declared
  production workload: WEB-J-01, DEV-E-01/02/03.

The authorized-lab opt-in is never silently enabled by an automated audit. Use
`tests/live_lab/README.md` and `labs/mars/README.md` only after verifying the
isolated environment and signed scope. Mock/fixture success never promotes an
adapter to lab-verified or release-ready. No adapter was promoted in this audit.

## CI and publication

The GitHub branch response read on 29 October reported `protected=false`, with
no required status checks. No repository policy was changed. Quality workflows
are absent, so local success must not be described as a green remote CI run.
Final push/ref and workflow status are verified separately in the delivery
message; an empty run list is not a passed pipeline.

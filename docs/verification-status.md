# Verification status — baseline 2026-10-29; follow-up 2026-10-31

Baseline audit: `b5cc491ac466fc5875a40266151e3aa55730c82e`. The tested merge
`bca1daa` includes remote `e177498` and the SEC-E-01 audit fix `e8dea67`.
[Machine-readable checks](verify/audit-2026-10-29-checks.json) record commands,
counts, source digests and limitations. [Ecosystem audit](ecosystem-audit.md) and
[ROADMAP](../ROADMAP.md) define coverage and follow-up work.

## Follow-up snapshot — 2026-10-31

Since the baseline below, commits on `main` added and verified the following
offline changes: Metis backup integrity/foreign-key checks and atomic snapshot/
restore publication (`WEB-J-01`, partial),
purple telemetry schema/rejection accounting (`OPS-PURPLE-01`), corrected CI
claims (`DEV-G-01`, partial), exact dashboard aggregates for 205 jobs
(`WEB-G-01`), and explicit unavailable-state warnings for findings/incident
dashboard stores (`WEB-B-01`, partial). The focused Themis Web test module passed
after the last change; Ruff and strict Mypy passed for the edited source. A
broader focused jobs+Web run had one unrelated environment failure while
creating the sandbox scratch directory (`EINVAL`); the remaining tests passed.

On commit `bf3e22d`, GitHub Actions `ci` run
[41225520765](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41225520765)
and CodeQL run
[41225520745](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41225520745)
were observed. On commit `50d7496`, CI run
[41226041648](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226041648)
exposed a Python 3.11 TUI shutdown regression. On commit `0911d0b`, CI run
[41226565373](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226565373)
and CodeQL run
[41226565375](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41226565375)
passed: pytest Python 3.11–3.14, branch coverage, mutation, POSIX sandbox,
Windows/macOS smoke, Ruff/format/Mypy, wheel, container, Gitleaks, pip-audit and
CodeQL. The fix awaits process-tree cleanup in Textual's actual
`CommandScreen.on_unmount` hook. The `/incidents` parity inventory mismatch from
the earlier run is corrected. On commit `5dae81a1829d4ed0893c6730b3b713308ec5f0c3`, GitHub Actions CI run
[41227141336](https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/41227141336)
completed with all 14 jobs successful: pytest Python 3.11–3.14, branch coverage,
mutation, POSIX sandbox, Windows/macOS smoke (including Windows process-tree
cancellation), native container, wheel/clean install/API/Web/worker smoke,
SBOM, Ruff/format/Mypy, pip-audit and Gitleaks. The run follows the generated
Metis CLI reference refresh that corrected the earlier stale-reference failure.
The connector did not expose a CodeQL run result for this commit. The combined
commit status reports a Vercel deployment failure, separate from the successful
GitHub Actions CI run. Branch-protection inspection was denied by GitHub
integration (403), so required-check enforcement remains unverified. See the
current [ecosystem audit](ecosystem-audit.md) and
[roadmap](../ROADMAP.md) for scope-specific status.

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
  workflow (`ci.yml`: quality, tests, coverage, mutation, gitleaks, pip-audit,
  SBOM) and CodeQL workflow (`codeql.yml`) are present and configured. A green
  run for the current commit and required branch-protection checks are not
  verified here; do not infer them from workflow-file presence.
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
no required status checks at that time. No repository policy was changed. The
quality workflow was restored on 30 October; current branch protection and
workflow run outcomes remain unverified. Final push/ref and workflow status are
verified separately in the delivery message; an empty run list is not a passed
pipeline.

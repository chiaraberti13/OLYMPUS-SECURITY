# Test suite boundaries

Olympus separates tests by the kind of boundary they exercise. The directory
layout assigns the corresponding strict pytest marker. The Makefile exposes
separate local suites. `.github/workflows/ci.yml` currently invokes the unit,
contract, offline-integration and coverage suites on pushes to `main` and pull
requests. The workflow file and its triggers are present; a successful remote run
and required-check branch policy have not been verified for every commit
(`DEV-C-01`).

The required `quality` job also checks Ruff lint/format, internal Markdown links
(`python scripts/check_doc_links.py`) and strict Mypy over `src/olympus`.
`coverage` enforces a 75% first-party branch-coverage floor. Mutation,
container, package, sandbox, portable-smoke, dependency-audit and secret-scan
checks are separate workflow jobs; see the run itself for results.

| Suite | Location | Purpose | Execution |
| --- | --- | --- | --- |
| Unit | `tests/unit/` | One component at a time; no uncontrolled external effects | Local; CI Python 3.11–3.14 on Ubuntu (POSIX-only tests excluded from matrix) |
| Contract | `tests/contract/` | Versioned schemas, compatibility, manifests, and adapter policies | Local; CI Python 3.11–3.14 on Ubuntu (POSIX-only tests excluded from matrix) |
| Integration | `tests/integration/` | Offline CLI and workflows across components, using fixtures or fakes | Local; CI Python 3.11–3.14 on Ubuntu (POSIX-only tests excluded from matrix) |
| Container | `tests/container/` | Behavior requiring Docker/Podman or a container kernel boundary | No; explicit opt-in |
| Live lab | `tests/live_lab/` | Network-active validation against a declared, authorized, isolated lab | No; explicit opt-in and authorization acknowledgement |

Run the regular suites individually with `make test-unit`, `make test-contract`,
and `make test-integration`. `make test` collects the regular and
platform-marked tests supported by the current host; it cannot silently execute
container or live-lab cases without their explicit opt-in.

Container tests require `OLYMPUS_RUN_CONTAINER_TESTS=1`; use
`make test-container` to opt in. Live-lab tests require both
`OLYMPUS_RUN_LIVE_LAB_TESTS=1` and
`OLYMPUS_LIVE_LAB_AUTHORIZATION=I_HAVE_AUTHORIZATION`; use `make test-live-lab`
only after verifying the lab scope and authorization. Tests in these suites are
not collected by a regular unit, contract, or integration CI job. An explicit
suite command with no matching tests exits non-zero (pytest's “no tests
collected” status); an empty future suite therefore cannot be reported as
validated.

Container and live-lab test files are present; their execution is explicitly
opt-in and was not performed by the 2026-10-28/29 audit. The CI workflow also
defines separate POSIX sandbox, portable smoke, wheel/SBOM package, native
container, dependency-audit, and secret-scan jobs; their outcomes depend on the
individual workflow run. API/Web TestClient and
Textual pilot tests are offline integration checks, not real browser or screen
reader validation. See [verification status](verification-status.md) for actual
commands, outcomes and environment limitations. Never infer a passed suite from
its presence or from an older run on a different commit.

## Automated development environments

The Ubuntu Python 3.11 job installs the `browser-test` extra and Chromium and
runs the real-browser module against a loopback web server with temporary stores.
To reproduce it, install `.[dev,api,browser-test]`, run
`npm ci --prefix tests/browser --ignore-scripts --no-audit --no-fund` and
`python -m playwright install --with-deps chromium`, then run
`OLYMPUS_REQUIRE_BROWSER=1 python -m pytest tests/integration/test_web_store_states_browser.py`.
An existing Chromium binary can be selected with `OLYMPUS_CHROMIUM`.

The same job runs the standard performance profile with five measured samples
after warm-up. It measures ingestion of 10,000 records, deduplication of 20,000
findings, HTML report generation and a 250-job queue lifecycle. It also runs
the original four-writer cold-start check and three load trials. Each load trial
uses a fresh, migrated temporary database, matching the Compose deployment.
Eight concurrent processes submit 250 jobs apiece. An independent cold-start
experiment with eight writers and no initial migration on Linux reproduced a
SQLite journal-mode lock in a fresh database (1,999 of 2,000 jobs persisted). A write error or a
mismatch between requested and persisted jobs fails the job. Download
`offline-benchmarks` for the timings, peak traced allocations and per-trial
write counts and latency percentiles. Timing values are descriptive on shared
runners. See [performance baselines](performance.md) for workload definitions.

Each macOS and Windows runner exercises shared version compatibility, the JSON
schema catalog and PDF rendering and private export on Python 3.11, 3.12, 3.13
and 3.14. Both required portable wheel checks also require all eight contract
environments to succeed. The Ubuntu matrix continues to run the regular suites
on all four Python versions.

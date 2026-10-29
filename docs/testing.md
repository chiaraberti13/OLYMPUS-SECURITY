# Test suite boundaries

Olympus separates tests by the kind of boundary they exercise. The directory
layout assigns the corresponding strict pytest marker. The Makefile exposes
separate local suites. No quality CI workflow currently invokes them automatically
(DEV-C-01); the only workflow in this checkout synchronizes labels.

| Suite | Location | Purpose | Execution |
| --- | --- | --- | --- |
| Unit | `tests/unit/` | One component at a time; no uncontrolled external effects | Local; CI matrix pending |
| Contract | `tests/contract/` | Versioned schemas, compatibility, manifests, and adapter policies | Local; CI matrix pending |
| Integration | `tests/integration/` | Offline CLI and workflows across components, using fixtures or fakes | Local; CI matrix pending |
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
opt-in and was not performed by the 2026-10-28/29 audit. API/Web TestClient and
Textual pilot tests are offline integration checks, not real browser or screen
reader validation. See [verification status](verification-status.md) for actual
commands, outcomes and environment limitations. Never infer a passed suite from
its presence or from an older run on a different commit.

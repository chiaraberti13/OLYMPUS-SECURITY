# Test suite boundaries

Olympus separates tests by the kind of boundary they exercise. The directory
layout assigns the corresponding strict pytest marker; CI invokes the regular
suites independently so a failure is attributed to the right boundary.

| Suite | Location | Purpose | Default CI |
| --- | --- | --- | --- |
| Unit | `tests/unit/` | One component at a time; no uncontrolled external effects | Yes, Python 3.11–3.14 |
| Contract | `tests/contract/` | Versioned schemas, compatibility, manifests, and adapter policies | Yes, Python 3.11–3.14 |
| Integration | `tests/integration/` | Offline CLI and workflows across components, using fixtures or fakes | Yes, Python 3.11–3.14 |
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

At the time of this split, container and live-lab directories intentionally
contain no test cases. The CI status makes no claim about container isolation or
scanner behavior against live targets. Those claims require dedicated tests and,
for network-active behavior, evidence from an authorized lab.

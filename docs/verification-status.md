# Verification status

This page records **which verifications Olympus can run without any live target
or external infrastructure** (the offline gates, run in CI and locally via
`make check`) and **which verifications require an authorized, isolated lab or
external infrastructure** — and the legitimate way to run those, too.

The project's rule is: *never declare a check passed that was not executed, and
never simulate results, authorizations or live scans.* That rule does not make
live verification impossible — it makes it **operator-driven and auditable**. The
sections below say exactly how.

## Offline verifications (no network, no lab)

These are deterministic and run on every change, in CI and locally with
`make check`. They cover parsing of hostile input, data contracts, the scope and
SSRF/pinning boundaries, secret redaction, and output escaping — i.e. the
offline-verifiable core of every feature, including the ones whose *live*
promotion is lab-gated.

| Check | Command | What it proves |
| --- | --- | --- |
| Lint | `make lint` (Ruff) | style/correctness lint is clean |
| Format | `make format-check` | formatting is canonical |
| Types | `make type` (mypy `--strict`) | strict typing across `src/olympus` |
| Schemas | `make schemas-check` | the published JSON-Schema catalogue matches the models |
| Tests + coverage | `make test-coverage` | unit/contract/integration/posix suites pass; first-party **branch coverage ≥ 75 %** |
| Mutation | `make test-mutation` | scope/redaction/parser/status/job security boundaries kill the configured mutants |
| Secret scan | `gitleaks detect --no-git --config .gitleaks.toml` | no secret in the working tree; the planted canary is still detected |
| Benchmarks | `python scripts/benchmark_hot_paths.py --profile quick` | deterministic hot-path baselines |
| Entry point | `olympus --version` | the CLI entry point imports and runs |

### Last recorded offline run

Snapshot, offline, on the commit noted below. Re-run `make check` to refresh it.

- **Commit:** `f0a5ec0` · **Date:** 2026-10-26
- `make lint` — **passed** (All checks passed)
- `make format-check` — **passed** (466 files already formatted)
- `make type` — **passed** (no issues found in 207 source files)
- `make schemas-check` — **passed** (24 versioned contracts current)
- `make test-coverage` — **passed** (2343 passed, 65 deselected; first-party branch coverage **80.93 %**, min 75 %)
- `make test-mutation` — **passed** (mutation gate 1149/1865 targeted mutants killed, 61.6 %)
- gitleaks working-tree scan (image `zricethezav/gitleaks:v8.28.0`) — **passed** (no leaks; canary secret still detected)
- POSIX sandbox suite (`pytest -m "posix_only and not root_only"`) — **passed**
- `olympus --version` — **passed** (`0.2.0`)

The live checks deferred to the authorized lab are tracked as an explicit
checklist in [`ROADMAP.md`](../ROADMAP.md) under "Verifiche dal vivo (live) — da
eseguire in un secondo momento".

Not executable in a plain offline checkout, covered by CI instead (no result is
claimed here for them): the native-container test (needs a Docker daemon), the
CycloneDX SBOM generation and `pip-audit` (tools installed by the CI job; the
advisory DB fetch is network-bound), and the macOS/Windows CLI smoke matrix.

## Verifications that require an authorized lab (not faked)

Promoting a scanner adapter from `live-tested` to `production-ready`, and every
`[⏸]` item in [`ROADMAP.md`](../ROADMAP.md) (recon/OSINT adapters, exploitation
orchestration, the detection loop, SIEM/EDR and CTI connectors, scheduled
monitoring), needs **real execution against real targets**. Olympus never fakes
that. Instead it ships the legitimate environment to produce **real** evidence:

### The authorized local lab

1. **Disposable, isolated targets you own.** `labs/mars/docker-compose.yml`
   brings up throwaway target services on an internal `dmz` network — nothing
   reaches a third party. Add your own intentionally-vulnerable services here.
2. **An explicit, signed authorization scope.** The engagement manifest must
   cover exactly those lab hosts; the scope gate rejects anything else, in depth.
3. **A deliberate double opt-in**, so a live run can never happen by accident:

   ```bash
   docker compose -f labs/mars/docker-compose.yml up -d        # your lab, your hosts
   export OLYMPUS_RUN_LIVE_LAB_TESTS=1
   export OLYMPUS_LIVE_LAB_AUTHORIZATION=I_HAVE_AUTHORIZATION   # set only after validating scope
   make test-live-lab                                          # pytest -m live_lab
   ```

The result is a **real** scan through the scope gate, producing a real evidence
manifest, digest, SBOM and version matrix — the `D1`/`D2` unblock prerequisites
in [`ROADMAP.md`](../ROADMAP.md) — with no simulation and no third-party contact.

**Who runs it.** The lab opt-in is the operator's to set, on infrastructure they
own and have authorized; an automated agent must not self-authorize a live run.
The agent keeps the lab harness correct and turnkey and verifies everything
around it offline (argv construction, `simulate` mode, parsers, scope gate), so
that standing up the lab is the only remaining step.

## Verifications that require external/CI infrastructure

Part of `SEC-F` (supply chain) is gated on GitHub / release infrastructure, not
on code, so it is validated where that infrastructure lives, not in a local
checkout: CodeQL/SAST (GitHub code scanning), SLSA provenance and signed release
attestations, Cosign container signing against a registry, and `main` branch
protection (a repository-owner setting). Their workflow/config can still be
lint-checked offline; their execution cannot.

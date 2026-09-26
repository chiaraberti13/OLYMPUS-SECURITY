# Contributing to Olympus Security

## Where work is planned

- [`ROADMAP.md`](ROADMAP.md) is the single source of truth for planned work. Every
  intervention has a stable ID — `SEC-*` (cybersecurity), `DEV-*` (development),
  `UX-*` (design), `OPS-*` (Red/Blue/Purple backlog) — and a priority `P0`–`P3`.
- [`upgrade.md`](upgrade.md) is the append-only historical record of the ARGUS/VAP
  integration cycles. Do not plan new work there.
- Structural decisions are recorded as numbered ADRs in
  [`docs/architecture/`](docs/architecture/README.md).

## Workflow: ID → issue → PR → commit → evidence

1. **Issue.** Open it with the *Roadmap item* or *Bug report* template and name the
   roadmap ID (for example `DEV-C`). Work that fits no ID first gets one in
   `ROADMAP.md`.
2. **Branch and commits.** Cite the ID in the commit subject, for example
   `docs: fix broken internal links (DEV-G)`.
3. **Pull request.** The PR template carries the Definition of Done checklist. Tick
   only what is true; explain every unchecked item.
4. **Roadmap.** Update the checkbox, the progress dashboard and, where relevant, the
   indicators in `ROADMAP.md` **in the same PR** that changes the status.
5. **Evidence.** Link the reproducible proof (test, CI run, committed evidence).
   Nothing is marked more mature than its evidence.

**Security vulnerabilities never go into public issues**: follow
[`SECURITY.md`](SECURITY.md).

### Labels

| Label | Meaning |
| --- | --- |
| `area:security`, `area:dev`, `area:ux`, `area:ops` | the roadmap perspective (`SEC-*`, `DEV-*`, `UX-*`, `OPS-*`) |
| `P0`, `P1`, `P2`, `P3` | the priority defined in `ROADMAP.md` |
| `roadmap` | the issue tracks a roadmap intervention |
| `bug` | behaviour differs from what is documented |

The managed definitions live in [`.github/labels.json`](.github/labels.json).
The `repository labels` workflow creates missing labels and updates their color
or description on `main`; it deliberately never deletes unmanaged labels.

## Architecture stays open

Olympus does not restrict *what* you build. Web interfaces, HTTP APIs,
databases, background workers, containers, plugins, new scanners, new modules and
new dependencies are all welcome. There are no limits on file, module or function
size. ADRs under `docs/architecture/` are **non-binding guidelines**, except for
the security invariants they list.

## What CI enforces today

These checks run on every pull request in `.github/workflows/ci.yml` and **block
the merge** when they fail:

| Check | Why it blocks |
| --- | --- |
| `ruff check .` | catches real defects (unused/undefined names, unsafe patterns) |
| `ruff format --check .` | prevents unreviewed style-only drift |
| `mypy --strict src/olympus` | rejects type inconsistencies in first-party code |
| portable `pytest` suite on Python 3.11–3.14 | offline unit, contract and guardrail tests without POSIX kernel assumptions |
| dedicated POSIX sandbox suite on Ubuntu/Python 3.11 | real privilege-drop, `setrlimit`, signal and process-group guarantees |
| macOS/Windows wheel + CLI smoke | portable surfaces must import and execute outside Linux |
| wheel build, clean install and CLI smoke test | the package must work outside the checkout |
| `pip-audit` on the runtime closure | no dependency with a known advisory ships |
| `gitleaks` (with a canary proving it works) | no secret enters the repository |

Planned, **not yet enforced**: a coverage threshold, CodeQL and a link checker —
tracked as `DEV-C`, `DEV-G` and `SEC-F` in `ROADMAP.md`.

## Local helpers

```bash
make lint      # ruff
make format-check
make type      # strict Mypy over first-party code
make test      # all tests supported by the current host
make test-portable
make test-posix # POSIX kernel-isolation suite
make check     # all four blocking first-party checks
```

The sandbox's real-kernel tests live under `tests/platform/posix/`; related
subprocess integration tests carry the same registered `posix_only` marker at
their source. Narrower requirements use `linux_only` and `root_only`;
`tests/conftest.py` skips them when the host cannot provide the required kernel
or privilege boundary. Pytest runs with `--strict-markers`, so an unregistered
or misspelled platform marker fails collection instead of silently weakening
coverage.

`pre-commit` is opt-in. Bypassing it locally with `git commit --no-verify` is
possible, but CI still runs the blocking checks above.

## What always holds

These requirements concern **security**, **real functionality** and
**licences**:

- **Real, fully-functional tools.** No demos, stubs, mocks, placeholders, or
  partial implementations presented as complete.
- **Secure runtime defaults.** Do not weaken authorization boundaries, scope
  enforcement, input validation, SSRF protection, secret handling, or
  safeguards against destructive operations.
- **Untrusted target data.** Output coming from a scanned target (banners,
  titles, reports) is hostile input: parse it safely and escape it in every
  output format (`ROADMAP.md`, `SEC-H`).
- **No committed secrets.** Never commit, log, or print real credentials.
- **Licences & provenance.** Preserve upstream licences and record provenance
  for vendored/imported components (see `docs/provenance.md`).
- **Compatibility & dependencies.** Keep dependency declarations and
  compatibility information accurate.

A change is complete when it meets the
[Definition of Done](ROADMAP.md#definition-of-done-trasversale) in `ROADMAP.md`.

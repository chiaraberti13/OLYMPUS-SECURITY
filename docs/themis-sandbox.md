# Themis scanner isolation

A scanner is untrusted code processing untrusted remote output. Themis therefore
never runs one as "just another subprocess": every child started by
`olympus.themis.runner.run_command` is confined by the policy in
`olympus.themis.sandbox` before it reaches `exec`, and every child that stops is
described by a structured reason rather than a bare exit status.

Implemented in `src/olympus/themis/sandbox.py` and `src/olympus/themis/runner.py`;
tested in `tests/unit/test_themis_sandbox.py` against the real kernel behaviour
(real `setrlimit` violations, a real ignored `SIGTERM`, a real process group).

## What the runner guarantees

| Guarantee | Mechanism |
| --- | --- |
| Unprivileged execution | `subprocess`'s own C-level `setgroups`/`setgid`/`setuid` to `THEMIS_SANDBOX_USER` when the parent is root |
| No shell, no argument injection | Fixed argument vector, executable resolved on `PATH`, `stdin` from `/dev/null` |
| Bounded CPU time | `RLIMIT_CPU` (soft `THEMIS_SANDBOX_CPU_SECONDS`, hard +5s so `SIGXCPU` is deliverable) |
| Bounded memory | `RLIMIT_AS` |
| Bounded process count | `RLIMIT_NPROC` |
| Bounded file descriptors | `RLIMIT_NOFILE` |
| Bounded temporary space | `RLIMIT_FSIZE` plus a private per-run scratch directory |
| No core dumps of scanned data | `RLIMIT_CORE = 0` |
| No inherited secrets | Allowlisted environment (`PATH`, `LANG`, `LC_ALL`, `TZ`, `SSL_CERT_*`) only |
| Isolated scratch space | Fresh `0700` directory used as the child's `cwd`, `TMPDIR`, `TMP`, `TEMP` and `HOME`, removed when the run ends |
| Bounded output | Incremental capped reads of `stdout`/`stderr` (`max_output_bytes`) |
| Whole-tree termination | Own session and process group; `SIGTERM` to the group, then `SIGKILL` after the grace window |
| Explainable outcome | A `TerminationReport` recorded on the result document |

Privileges are dropped **before** the limits are applied: `setuid` is itself
subject to `RLIMIT_NPROC`, and lowering a limit afterwards needs no privilege.
The drop, the `umask` and the new session are done by `subprocess` in C, so no
Python runs between `fork` and the privilege drop; the only post-`fork` Python
is the `setrlimit` loop, which has no `Popen` parameter.

## Running as root is refused, not assumed

When the parent process is root, the child drops to `THEMIS_SANDBOX_USER`
(`nobody` by default). If that account does not exist — or resolves to uid 0 —
the run is **refused** with `TerminationCause.SANDBOX_DENIED` and nothing is
executed. Accepting the risk is explicit and auditable:

```bash
THEMIS_SANDBOX_ALLOW_ROOT=true olympus themis run ...
```

When the parent is already unprivileged, no drop is attempted and the scanner
inherits that account.

## Termination causes

`TerminationReport.cause` is one of:

| Cause | Meaning |
| --- | --- |
| `completed` | The process set its own exit status |
| `timeout` | The per-command timeout elapsed; the group was terminated |
| `cancelled` | The caller requested cooperative cancellation |
| `output_limit` | Combined `stdout`/`stderr` passed `max_output_bytes` |
| `resource_limit` | The kernel enforced a limit (`SIGXCPU` → `cpu_seconds`, `SIGXFSZ` → `file_size_bytes`) |
| `signalled` | The process died from a signal Olympus did not send |
| `start_failed` | Missing binary, invalid argv, or a failed `exec` |
| `sandbox_denied` | The required isolation could not be established; nothing ran |

The report also records `escalated_to_kill` (the scanner ignored `SIGTERM`),
`process_group_signalled` (the whole group was signalled, not just the leader),
the limit that was crossed, the signal name, and the unprivileged account used.
It is persisted as the optional `termination` object of the
`olympus.themis-result` contract. Schema `1.2.0` also carries optional `job_id`
and `manifest_sha256` authorization provenance; consumers pinned to `1.1.0`
must negotiate or upgrade before accepting the newer document.

Note that CPython ignores `SIGXFSZ` and surfaces `EFBIG` instead, so a
Python-based scanner that crosses `file_size_bytes` fails with a write error
rather than a signal. The limit holds either way; only the recorded cause
differs.

## Configuration

All variables follow the `THEMIS_*` → legacy `VAP_*` → default precedence
described in [`themis-config.md`](themis-config.md).

| Variable | Purpose | Default | Accepted range |
| --- | --- | --- | --- |
| `THEMIS_SANDBOX_USER` | Account the scanner drops to when the parent is root | `nobody` | 1–64 characters |
| `THEMIS_SANDBOX_ALLOW_ROOT` | Explicitly accept running scanners as root | `false` | `true`/`false` |
| `THEMIS_SANDBOX_CPU_SECONDS` | `RLIMIT_CPU` soft limit | `900` | 1–86400 |
| `THEMIS_SANDBOX_MEMORY_BYTES` | `RLIMIT_AS` | 2 GiB | 64 MiB–64 GiB |
| `THEMIS_SANDBOX_MAX_PROCESSES` | `RLIMIT_NPROC` | `256` | 1–4096 |
| `THEMIS_SANDBOX_OPEN_FILES` | `RLIMIT_NOFILE` | `512` | 16–65536 |
| `THEMIS_SANDBOX_FILE_SIZE_BYTES` | `RLIMIT_FSIZE` | 512 MiB | 1 MiB–64 GiB |
| `THEMIS_SANDBOX_GRACE_SECONDS` | `SIGTERM` → `SIGKILL` escalation window | `5` | 0.05–60 |

An unparsable or out-of-range value is a startup error for that run, never a
silently disabled limit.

## What this layer deliberately does not do

Live execution is additionally fail-closed at the application boundary. Before
scope resolution or adapter construction, Olympus verifies a root-owned OCI
runtime marker, a pinned image-attestation digest, read-only `/`, zero effective
capabilities, `NoNewPrivs=1` and active seccomp filter mode from `/proc`. These
properties cannot be enabled by a CLI flag or environment variable. Direct host
`themis run`, `workers` and `jobs work` invocations may still simulate or process
disabled work, but cannot start a live scanner.

The following remain **open** on the hardening roadmap. Do not read the
guarantees above as covering them:

- **Egress allowlisting for scanner processes.** DNS rebinding is closed inside
  Olympus by address pinning (`olympus.core.pinning`), but an external scanner
  binary resolves and connects on its own; only a network policy can bound
  where it goes.

Compose does separate the planes: API and Web are attached only to the internal
`control` network, while the worker and optional engines are attached only to
`scan-egress`; migration has no network and no service is dual-homed. The shared
SQLite volume transfers jobs without opening a control-plane network path. This
topology is a boundary, not an egress allowlist: `scan-egress` remains externally
routable until a per-job policy restricts it to validated scope addresses and
ports.

The container test starts the native runtime under the repository profile and
probes a denied `process_vm_readv` call. It also runs a bounded, offline escape
probe with a 32-PID cgroup limit: the probe checks the read-only root, writable
scratch, absence of a host-only canary, protected kernel memory, zero effective
capabilities, `no-new-privileges`, seccomp filter mode and denied user-namespace
creation. A real child that ignores `SIGTERM` is also run through the production
runner with a 0.5-second timeout and grace period: the probe requires signalling
the whole process group, `SIGKILL` escalation, a structured timeout report and a
10-second outer deadline. All spawned children are reaped even on failure. This
demonstrates profile loading, mandatory live-runtime attestation and selected
kernel controls in CI; it does not demonstrate egress containment or close SEC-B
by itself.

### Optional AppArmor enforcement

On Linux hosts with AppArmor enabled, load the repository policy before starting
the worker overlay:

```bash
python scripts/manage_scanner_apparmor.py status
sudo python scripts/manage_scanner_apparmor.py install
docker compose -f docker-compose.yml -f docker-compose.apparmor.yml up --build
```

The provisioner validates the policy identity, version, regular-file type and
digest, never invokes a shell, and loads it idempotently with
`apparmor_parser -r -W`. It fails without AppArmor, the parser or root
privileges and never installs packages implicitly. Preserve its JSON output as
deployment evidence; the container test then verifies both the effective
profile and the denied canary.

The profile is named `olympus-themis-scanner`, remains in enforce mode and
complements rather than replaces the read-only root, dropped capabilities,
`no-new-privileges` and seccomp controls. Do not silently fall back to
`apparmor=unconfined`; omit the overlay only on a host where AppArmor is not an
available LSM and record the residual risk.

## Operational notes

- `cwd` defaults to the run's private scratch directory. A caller that passes
  its own `cwd` is responsible for making it reachable by the unprivileged
  account.
- The scratch directory is removed when the run ends, including after a timeout
  or a kill. Anything a scanner must keep has to be written to the evidence
  path, not to `TMPDIR`.
- `RLIMIT_AS` bounds *address space*, not resident memory. A runtime that
  reserves large virtual mappings (JVM-based scanners, for example) may need
  `THEMIS_SANDBOX_MEMORY_BYTES` raised above the default.

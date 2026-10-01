# THEMIS scanner isolation

A scanner is untrusted code processing untrusted remote output. THEMIS therefore
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
`olympus.themis-result` contract (schema `1.1.0`; every `1.0.0` field is
unchanged, so a `1.0.0` reader still understands the document).

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

These remain **open** on the hardening roadmap and are deployment concerns, not
process-level ones. Do not read the guarantees above as covering them:

- **seccomp / AppArmor confinement and a read-only root filesystem.** Provided
  by the container runtime around the process, not by the runner.
- **Egress allowlisting for scanner processes.** DNS rebinding is closed inside
  Olympus by address pinning (`olympus.core.pinning`), but an external scanner
  binary resolves and connects on its own; only a network policy can bound
  where it goes.
- **Separate control and scanning networks.** A Compose/orchestrator topology
  concern.

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

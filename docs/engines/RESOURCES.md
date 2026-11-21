# Engine resource budgets

The engine manifest states a runtime request. The deployment sandbox remains
the security ceiling. Olympus never raises `RLIMIT_AS`, a container limit, or a
policy bound to satisfy a manifest. A reviewed requirement above the configured
ceiling is refused before target resolution and names the setting that must be
reviewed by the operator.

When an interface omits timeout and deadline, `ThemisApplicationService` uses
the reviewed engine timeout through one shared resolver. This covers direct
CLI execution, jobs submitted by API or Web, and workers. An explicit CLI value
remains explicit. Estimated values do not change runtime defaults.

## Current profiles

| Engine | Profile | Timeout | Confidence | Minimum address space |
| --- | --- | ---: | --- | ---: |
| arjun | network-heavy | 300 s | estimated | — |
| commix | network-heavy | 300 s | estimated | — |
| dalfox | network-heavy | 300 s | estimated | — |
| dirsearch | network-heavy | 600 s | estimated | — |
| httpx | light | 300 s | estimated | — |
| katana | network-heavy | 300 s | estimated | — |
| nikto | network-heavy | 600 s | estimated | — |
| nmap | network-heavy | 600 s | estimated | — |
| nuclei | network-heavy | 1200 s | measured | 4 GiB `RLIMIT_AS` |
| sqlmap | network-heavy | 600 s | estimated | — |
| testssl | light | 600 s | estimated | — |
| wafw00f | light | 300 s | estimated | — |
| wapiti | network-heavy | 600 s | estimated | — |
| whatweb | light | 300 s | estimated | — |
| wpscan | network-heavy | 600 s | estimated | — |
| xsstrike | network-heavy | 300 s | estimated | — |

API-only engines have no local process profile. Estimated values remain
planning data and keep the legacy runtime default of 300 seconds until a
measurement is reviewed.

## Nuclei measurement

The manifest carries the machine-readable measurement metadata. The reviewed
run used nuclei `v3.11.1`, nuclei-templates commit
`95131c8dd920db77a5e86e72fe2d2a3e5ca37d2d`, Linux x86_64, 4 vCPU and 15 GiB
RAM on 2026-11-03. It exercised the full pinned set of 14,104 templates against
a loopback HTTP target as the unprivileged sandbox user.

The three memory quantities have different meanings:

- `RLIMIT_AS` limits virtual address space. At 2 GiB the Go runtime failed in
  about five seconds. At 4 GiB and 8 GiB the run completed.
- Peak resident memory was about 0.9 GiB. RSS does not replace the virtual
  address-space check because the Go runtime reserves substantially more memory
  than it keeps resident.
- The container or cgroup memory limit is an independent outer ceiling. It must
  be at least as restrictive as the deployment policy intends and high enough
  for the measured workload. Olympus does not infer it from RSS or change it.

The sandboxed wall time was 415–422 seconds, compared with about 365 seconds
without the sandbox. The 1200-second timeout leaves bounded headroom for network
latency. These measurements describe one environment and are not universal
performance guarantees.

Remeasure whenever the engine pin, data pin, operating system, architecture,
CPU allocation, RAM allocation, sandbox, template selection, or target profile
changes. Record the new environment in `[adapter.measurement]` and set
`reviewed = true` only after the evidence has been checked.

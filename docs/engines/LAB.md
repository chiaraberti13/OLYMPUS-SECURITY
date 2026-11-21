# Protected engine lab

A self-contained, **offline, authorized-by-construction** lab for exercising the
mandatory scanner engines against a host-local target. Nothing here reaches a real
network host: the target is bound to a documentation address (TEST-NET-1,
`192.0.2.0/24`) that never routes off the machine, and the Olympus lab policy is
bounded to that same CIDR.

Provisioner: [`scripts/lab/provision_lab.sh`](../../scripts/lab/provision_lab.sh)
(pins mirror the engine manifests; `tests/unit/test_lab_provision.py` fails if they
drift). The `olympus-lab` cloud environment runs the same recipe at session start.

## What it installs

| Engine | Pin | Source |
| --- | --- | --- |
| `nmap` | `v7.992` (commit `0ee5616…`) | built from source, same recipe as `docker/Dockerfile.scanners` |
| `nuclei` | `v3.11.1` | `go install` |
| `httpx` | `v1.11.0` | `go install` (ProjectDiscovery's, not the PyPI `httpx` CLI) |
| `nuclei-templates` | `v10.5.1` (commit `79fb682…`) | `git` checkout at `/opt/nuclei-templates` |

Plus a loopback target with files that trigger real `http/exposures` detections
(an exposed `.env`, a `.git/config`), and a `scope.json` + `lab.toml` bounded to
`192.0.2.0/24`.

## What it validates today (L1 + L2)

With the engines on `PATH` and their data at the manifest paths:

```console
$ olympus engines doctor      # exit 0: nmap/nuclei/httpx all "present"
```

That is **L1** (presence, version, pinned commit) and **L2** (the presence probe
executed in the real runtime sandbox) for the three mandatory engines. A direct
engine run then produces real findings:

```console
$ python3 -m http.server 8080 --bind 192.0.2.2 --directory /opt/olympus-lab/target &
$ nuclei -u http://192.0.2.2:8080 -t /opt/nuclei-templates/http/exposures/
[laravel-env]      [http] [high]   http://192.0.2.2:8080/.env
[codeigniter-env]  [http] [high]   http://192.0.2.2:8080/.env
[git-config]       [http] [medium] http://192.0.2.2:8080/.git/config
```

## What it deliberately does NOT grant (L3)

A full `olympus themis run` live scan with **signed evidence** enforces, in order,
a chain of fail-closed gates: a versioned `--scope`, `THEMIS_ENABLE_LIVE_SCANS`, a
signed **lab policy** (`--lab-policy`, which rejects loopback/public and accepts
only owned private/documentation ranges), `--i-am-authorized`, an Ed25519 evidence
key in `OLYMPUS_EVIDENCE_SIGNING_KEY_FILE`, and finally **scanner isolation**:

> live scanner execution requires the hardened Olympus worker container: OCI
> runtime marker, pinned scanner image attestation, read-only root filesystem,
> empty effective capability set, no-new-privileges, seccomp filter.

That last gate (`require_scanner_isolation()`) is satisfied **only** inside the
hardened image `docker/Dockerfile.scanners` plus the compose overlay — never in a
plain shell, and not in a general cloud sandbox without a Docker/OCI host. L3
(the signed-evidence "live-tested" promotion in `docs/engines/INVENTORY.md`) is
therefore gated on a container execution host (`ROADMAP.md` `DEPLOY-2`), not on
having the engines installed. This lab provides L1/L2 and direct engine runs; it
does not — and must not — bypass the isolation attestation.

## Running a live L3 scan (inside the hardened container)

Build and run the scanner image, then issue the run from inside it:

```console
$ docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
# inside the hardened worker, with OLYMPUS_POLICY_LAB_KEY and the evidence key set:
$ olympus themis run httpx --target http://192.0.2.2:8080 --kind url \
    --scope scope.json --lab-policy lab.toml --i-am-authorized \
    --evidence evidence/httpx.json --output result-httpx.json
```

Secrets (`OLYMPUS_POLICY_LAB_KEY`, the Ed25519 evidence key) are provided at run
time and are never committed.

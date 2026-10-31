# Themis 24-scanner classification, dependency & execution matrix

_Generated from `olympus.integrations.scanners` (registry) and `olympus.themis.registry` (native execution adapters) by `olympus themis matrix`. Do not edit by hand — run the command. See `docs/themis-execution-evidence.md` for the real captured evidence._

> **Correction:** OWASP **ZAP** and **OpenVAS/GVM** are open-source (Apache-2.0 / GPL-2.0) and are classified as `containerised-oss-service`, NOT commercial. Only Nessus, Burp, and Acunetix are proprietary.

> **Beware the `httpx` name collision.** The Python HTTP-client library ships a
> console script also called `httpx`, so a PATH lookup cannot tell it from the
> ProjectDiscovery probe. The adapter refuses non-probe output with an error
> naming the collision rather than reporting a clean scan.

> **Simulation is opt-in.** `olympus themis run` never fabricates findings: a missing binary → `unavailable`, live-off → `disabled`, explicit `--simulate` → `simulation`. When live is enabled, direct execution requires either a signed engagement manifest with pinned public key and revocation store, or the separate explicit HMAC-signed lab policy whose exact CIDRs intersect the Themis scope. Queued workers always require the manifest path.

| Scanner | Category | Kind | Risk | Binary / API | Licence | Auto-install | In image | Native adapter | Live-verified here |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openvas | vuln | containerised-oss-service | active | `API/daemon` | GPL-2.0 | yes | no | — pending | n/a |
| zap | web | containerised-oss-service | active | `API/daemon` | Apache-2.0 | yes | no | — pending | n/a |
| arjun | web | local-oss-binary | active | `arjun` | AGPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| commix | web | local-oss-binary | intrusive | `commix` | GPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| dalfox | web | local-oss-binary | intrusive | `dalfox` | MIT | yes | yes | ✅ implemented | ✅ yes |
| dirsearch | web | local-oss-binary | active | `dirsearch` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| httpx | web | local-oss-binary | active | `httpx` | MIT | yes | yes | ✅ implemented | ✅ yes |
| katana | web | local-oss-binary | active | `katana` | MIT | yes | yes | ✅ implemented | ✅ yes |
| nikto | web | local-oss-binary | active | `nikto` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| nmap | network | local-oss-binary | active | `nmap` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| nosqlmap | web | local-oss-binary | intrusive | `nosqlmap` | GPL-3.0 | yes | yes | — pending | n/a |
| nuclei | web | local-oss-binary | active | `nuclei` | MIT | yes | yes | ✅ implemented | ✅ yes |
| sqlmap | web | local-oss-binary | intrusive | `sqlmap` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| subfinder | dns | local-oss-binary | passive | `subfinder` | MIT | yes | yes | — pending | n/a |
| testssl | tls | local-oss-binary | active | `testssl.sh` | GPL-2.0 | yes | yes | ✅ implemented | parser only |
| theharvester | dns | local-oss-binary | passive | `theHarvester` | GPL-2.0 | yes | yes | — pending | n/a |
| wafw00f | web | local-oss-binary | active | `wafw00f` | BSD-3-Clause | yes | yes | ✅ implemented | ✅ yes |
| wapiti | web | local-oss-binary | active | `wapiti` | GPL-2.0 | yes | yes | ✅ implemented | parser only |
| whatweb | web | local-oss-binary | active | `whatweb` | GPL-3.0 | yes | yes | ✅ implemented | parser only |
| wpscan | web | local-oss-binary | active | `wpscan` | WPScan Public Source (non-OSI) | no | yes | — pending | n/a |
| xsstrike | web | local-oss-binary | intrusive | `xsstrike` | GPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| burp | web | proprietary-local | active | `API/daemon` | Commercial (PortSwigger) | no | no | — pending | n/a |
| acunetix | web | proprietary-remote-api | active | `API/daemon` | Commercial (Invicti) | no | no | — pending | n/a |
| nessus | vuln | proprietary-remote-api | active | `API/daemon` | Commercial (Tenable) | no | no | — pending | n/a |

## Recalculated totals

- **Open source** (local-oss-binary + containerised-oss-service): **21/24**
  - `containerised-oss-service`: 2
  - `local-oss-binary`: 19
  - `proprietary-local`: 1
  - `proprietary-remote-api`: 2
- **Auto-installable / redistributable**: 20/24
- **Bundled in `docker/Dockerfile.scanners`**: 19/24
- **Proprietary (commercial licence)**: 3/24 (acunetix, burp, nessus)
- **Native Themis execution adapters implemented**: 15/24 (arjun, commix, dalfox, dirsearch, httpx, katana, nikto, nmap, nuclei, sqlmap, testssl, wafw00f, wapiti, whatweb, xsstrike)
- **Live end-to-end verified in this environment**: 12/24 (arjun, commix, dalfox, dirsearch, httpx, katana, nikto, nmap, nuclei, sqlmap, wafw00f, xsstrike) — see evidence doc
- **Production-ready**: **0/24** — no adapter meets the full Definition of Done
  (per-adapter evidence manifest with digests, SBOM, vulnerability scan,
  documented version compatibility)

## Risk class

The **Risk** column is the reviewed worst-case intrusiveness of each scanner,
from `olympus.integrations.activity` and shown before every launch in the guided
flow, the TUI and `olympus themis preview`:

- `passive` — observes public information, little or no traffic to the target;
- `active` — sends requests to enumerate and probe, non-destructive but visible;
- `intrusive` — attempts injection/exploitation; needs explicit written authorization.

An unmapped scanner is treated as `active`, never `passive` — understating risk is
never the safe default. One further class, **`destructive-prohibited`**, is a
*declared product boundary* rather than a launchable class: denial of service,
persistence, real credential harvesting and defensive evasion are out of scope and
never executed, so no catalogued scanner carries it.

## Maturity, not just presence

The "Native adapter" and "Live-verified" columns above are derived from the
maturity ladder in `olympus.integrations.maturity` — `catalog-only` →
`adapter-ready` → `offline-tested` → `live-tested` → `production-ready` —
reported per engine by `olympus themis capabilities` and cross-checked against
the repository on every test run. See [`docs/scanner-maturity.md`](scanner-maturity.md).

Readiness and maturity are different questions: readiness is about *this host*
(is the binary installed, is the API configured), maturity is about *the project*
(does an adapter exist, is its parser tested, was it ever run live). An engine
installed on your machine that Olympus has no adapter for stays `catalog-only`.

## Per-scanner service/licence notes

- **OWASP ZAP** (Apache-2.0, OSS): run as a daemon/container (`zaproxy/zaproxy`), driven via its API — see the `zap` Compose profile.
- **OpenVAS/GVM** (GPL-2.0, OSS): the Greenbone GVM service stack (feed + scanner + gvmd), heavy; run via the `gvm` Compose profile or an external service.
- **Burp Suite** — Community (free, limited, no automation API) vs **Professional** (licensed, REST API for automation). Proprietary; manual install + licence.
- **Nessus** (Tenable) — proprietary; external service + API + licence/activation code.
- **Acunetix** (Invicti) — proprietary; external service + API + commercial licence.
- **wpscan** — source-available (WPScan Public Source, non-OSI); free, but the vulnerability database needs a free API token.

## Unavailable-tool policy

`olympus themis run <scanner>` returns an explicit state and never fabricates findings: `unavailable` (missing binary/API, with install instructions + `olympus themis deps` diagnostic), `disabled` (live off), `failed` (real error), or `live`. A direct live invocation also requires verified signed authorization; commercial/service engines return `unavailable` until configured. Nothing is silently skipped.

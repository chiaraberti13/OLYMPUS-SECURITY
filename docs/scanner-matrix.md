# AEGIS 24-scanner classification, dependency & execution matrix

_Generated from `olympus.integrations.scanners` (registry) and `olympus.aegis.registry` (native execution adapters). See `docs/aegis-execution-evidence.md` for the real captured evidence._

> **Correction:** OWASP **ZAP** and **OpenVAS/GVM** are open-source (Apache-2.0 / GPL-2.0) and are classified as `containerised-oss-service`, NOT commercial. Only Nessus, Burp, and Acunetix are proprietary.

> **Beware the `httpx` name collision.** The Python HTTP-client library ships a
> console script also called `httpx`, so a PATH lookup cannot tell it from the
> ProjectDiscovery probe. The adapter refuses non-probe output with an error
> naming the collision rather than reporting a clean scan.

> **Simulation is opt-in.** `olympus aegis run` never fabricates findings: a missing binary → `unavailable`, live-off → `disabled`, explicit `--simulate` → `simulation`.

| Scanner | Category | Kind | Binary / API | Licence | Auto-install | In image | Native adapter | Live-verified here |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openvas | vuln | containerised-oss-service | `API/daemon` | GPL-2.0 | yes | no | — pending | n/a |
| zap | web | containerised-oss-service | `API/daemon` | Apache-2.0 | yes | no | — pending | n/a |
| arjun | web | local-oss-binary | `arjun` | AGPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| commix | web | local-oss-binary | `commix` | GPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| dalfox | web | local-oss-binary | `dalfox` | MIT | yes | yes | ✅ implemented | ✅ yes |
| dirsearch | web | local-oss-binary | `dirsearch` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| httpx | web | local-oss-binary | `httpx` | MIT | yes | yes | ✅ implemented | ✅ yes |
| katana | web | local-oss-binary | `katana` | MIT | yes | yes | ✅ implemented | ✅ yes |
| nikto | web | local-oss-binary | `nikto` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| nmap | network | local-oss-binary | `nmap` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| nosqlmap | web | local-oss-binary | `nosqlmap` | GPL-3.0 | yes | yes | — pending | n/a |
| nuclei | web | local-oss-binary | `nuclei` | MIT | yes | yes | ✅ implemented | ✅ yes |
| sqlmap | web | local-oss-binary | `sqlmap` | GPL-2.0 | yes | yes | ✅ implemented | ✅ yes |
| subfinder | dns | local-oss-binary | `subfinder` | MIT | yes | yes | — pending | n/a |
| testssl | tls | local-oss-binary | `testssl.sh` | GPL-2.0 | yes | yes | ✅ implemented | parser only |
| theharvester | dns | local-oss-binary | `theHarvester` | GPL-2.0 | yes | yes | — pending | n/a |
| wafw00f | web | local-oss-binary | `wafw00f` | BSD-3-Clause | yes | yes | ✅ implemented | ✅ yes |
| wapiti | web | local-oss-binary | `wapiti` | GPL-2.0 | yes | yes | — pending | n/a |
| whatweb | web | local-oss-binary | `whatweb` | GPL-3.0 | yes | yes | ✅ implemented | parser only |
| wpscan | web | local-oss-binary | `wpscan` | WPScan Public Source (non-OSI) | no | yes | — pending | n/a |
| xsstrike | web | local-oss-binary | `xsstrike` | GPL-3.0 | yes | yes | ✅ implemented | ✅ yes |
| burp | web | proprietary-local | `API/daemon` | Commercial (PortSwigger) | no | no | — pending | n/a |
| acunetix | web | proprietary-remote-api | `API/daemon` | Commercial (Invicti) | no | no | — pending | n/a |
| nessus | vuln | proprietary-remote-api | `API/daemon` | Commercial (Tenable) | no | no | — pending | n/a |

## Recalculated totals

- **Open source** (local-oss-binary + containerised-oss-service): **21/24**
  - `containerised-oss-service`: 2
  - `local-oss-binary`: 19
  - `proprietary-local`: 1
  - `proprietary-remote-api`: 2
- **Auto-installable / redistributable**: 20/24
- **Bundled in `docker/Dockerfile.scanners`**: 19/24
- **Proprietary (commercial licence)**: 3/24 (nessus, acunetix, burp)
- **Native AEGIS execution adapters implemented**: 14/24 (arjun, commix, dalfox, dirsearch, httpx, katana, nikto, nmap, nuclei, sqlmap, testssl, wafw00f, whatweb, xsstrike)
- **Live end-to-end verified in this environment**: 12/24 (arjun, commix, dalfox, dirsearch, httpx, katana, nikto, nmap, nuclei, sqlmap, wafw00f, xsstrike) — see evidence doc
- **Production-ready**: **0/24** — no adapter meets the full Definition of Done
  (per-adapter evidence manifest with digests, SBOM, vulnerability scan,
  documented version compatibility)

## Maturity, not just presence

The "Native adapter" and "Live-verified" columns above are a snapshot maintained
by hand. The machine-readable, self-checking version is the maturity ladder in
`olympus.integrations.maturity` — `catalog-only` → `adapter-ready` →
`offline-tested` → `live-tested` → `production-ready` — reported per engine by
`olympus aegis capabilities` and cross-checked against the repository on every
test run. See [`docs/scanner-maturity.md`](scanner-maturity.md).

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

`olympus aegis run <scanner>` returns an explicit state and never fabricates findings: `unavailable` (missing binary/API, with install instructions + `olympus aegis deps` diagnostic), `disabled` (live off), `failed` (real error), or `live`. Commercial/service engines return `unavailable` until configured. Nothing is silently skipped.


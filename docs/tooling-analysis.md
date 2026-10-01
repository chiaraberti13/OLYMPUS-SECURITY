# Additional external-tool analysis (recommendations only)

_This is an analysis for review. **No tool below is implemented yet** — per the
project rule, additions that materially expand scope are proposed here first._

## Method

For each capability area we state whether the **current** Olympus/THEMIS set
already covers it, and only propose an addition when it fills a genuine gap with
complementary (not redundant) detection or validation. Each proposal lists
maintenance, licence, install complexity, resource cost, output, integration
design, risks, and a recommendation: **default**, **optional profile**, or
**reject**.

## Current coverage snapshot

| Capability | Already covered by |
| --- | --- |
| Network discovery / service enumeration | nmap (THEMIS) |
| Web vulnerability assessment | nikto, nuclei, wapiti, sqlmap, dalfox, xsstrike, commix, arjun, whatweb, wafw00f, ZAP, Burp/Acunetix (THEMIS); Artemis (native) |
| TLS / crypto configuration | testssl.sh (THEMIS) |
| DNS / subdomain analysis | subfinder, theHarvester (THEMIS); Argus dns/whois/fronting (native) |
| Vulnerability correlation / dedup | Vulcan (native) |
| Reporting / evidence export | Vulcan + THEMIS report_generator |
| Secrets detection (repo) | gitleaks + Hermes (native, SARIF) |

## Gaps and proposals

### 1. Dependency / software-composition analysis (SCA) — **GAP**
- No SCA today. **Propose: OSV-Scanner** (Go, Apache-2.0, Google-maintained).
- Install: single static binary. Cost: low. Output: JSON/SARIF (maps cleanly to
  `core.Finding`). Integration: new THEMIS adapter `osv` + optional Hermes mode.
- Risks: reads dependency manifests only (no exec). **Recommendation: optional
  profile** (default-on in the scanner image is reasonable given low cost).

### 2. SBOM generation — **GAP**
- **Propose: Syft** (Go, Apache-2.0, Anchore). Emits CycloneDX/SPDX.
- Pairs with OSV-Scanner (SBOM → vuln match) and Grype. Cost low.
- **Recommendation: optional profile.**

### 3. Container / image scanning — **GAP**
- **Propose: Trivy** (Go, Apache-2.0, Aqua) — images, filesystems, IaC, secrets,
  SBOM in one. Overlaps slightly with OSV/Syft but is broader and well
  maintained. Cost: medium (DB download). Output: JSON/SARIF.
- **Recommendation: optional profile** (heavier; not default).

### 4. Infrastructure-as-code analysis — **GAP**
- **Propose: Checkov** (Python, Apache-2.0, Prisma) or **KICS**. Checkov is pip-
  installable and integrates trivially. Output: JSON/SARIF.
- **Recommendation: optional profile.**

### 5. Cloud configuration assessment — **GAP (out of current scope)**
- **Propose: ScoutSuite** or **Prowler** (multi-cloud). Requires cloud creds and
  careful authorization — significant scope expansion.
- **Recommendation: reject for now** (revisit behind an explicit cloud-auth
  design; credentials + broad read access are a real operational risk).

### 6. CVE/CVSS enrichment — **PARTIAL**
- THEMIS already parses CVE IDs; there is no authoritative enrichment.
- **Propose: NVD API client** (data licence-free) or **cvss** (PyPI) for scoring.
  Low cost, no new binary. Integration: enrichment step in Vulcan/THEMIS.
- **Recommendation: optional** (rate-limited API; cache results).

### 7. Reporting / evidence export — **COVERED**
- Vulcan (JSON/Markdown/HTML) + THEMIS report_generator (+ reportlab PDF).
- **Recommendation: reject additions** — no gap.

### 8. Secrets detection (runtime/target) — **PARTIAL**
- gitleaks/Hermes cover repos. **Propose: TruffleHog** for verified live-secret
  detection (Go, AGPL-3.0). Licence (AGPL) warrants an optional profile, not
  default. **Recommendation: optional profile.**

## Summary recommendation

Add, as an **optional `sca` profile** (not default, low risk, complementary):
OSV-Scanner + Syft + Grype + Trivy + Checkov. Add NVD/CVSS enrichment as an
optional enrichment step. Reject cloud-config scanning for now (auth/scope
risk). Everything else is already covered — do not add redundant web/network
scanners.

These are proposals; implementing them will be a separate, reviewed change.

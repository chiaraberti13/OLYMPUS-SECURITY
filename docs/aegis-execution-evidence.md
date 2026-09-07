# AEGIS native execution — real evidence

_Captured on 2026-08-25 against a **local authorized lab** (a Python HTTP
server on 127.0.0.1:8000). No public/third-party system was scanned. Scope
file authorizes only 127.0.0.1; AEGIS_ENABLE_LIVE_SCANS=true._

Binaries present in this environment: nmap 7.94, nikto 2.5, wafw00f 2.x,
sqlmap 1.10.8, testssl.sh 3.x, whatweb (apt binary — broken Ruby env).

## Per-state / per-scanner results (actual JSON, trimmed)

### nmap (live=true)
```json
{
  "scanner": "nmap",
  "state": "live",
  "version": "Nmap version 7.94SVN ( https://nmap.org )",
  "finding_count": 1,
  "exit_code": 0,
  "error": null
}
```

### nikto (live=true)
```json
{
  "scanner": "nikto",
  "state": "live",
  "version": "-config+            Use this config file",
  "finding_count": 2,
  "exit_code": 0,
  "error": null
}
```

### wafw00f (live=true)
```json
{
  "scanner": "wafw00f",
  "state": "live",
  "version": "\u001b[1;97m______",
  "finding_count": 0,
  "exit_code": 0,
  "error": null
}
```

### sqlmap (live=true)
```json
{
  "scanner": "sqlmap",
  "state": "live",
  "version": "1.10.8#pip",
  "finding_count": 0,
  "exit_code": 0,
  "error": null
}
```

### whatweb (live=true)
```json
{
  "scanner": "whatweb",
  "state": "failed",
  "version": "<internal:/opt/rbenv/versions/3.3.6/lib/ruby/3.3.0/rubygems/core_ext/kernel_require.rb>:136:in `require': cannot load such file -- whatweb (LoadError)",
  "finding_count": 0,
  "exit_code": 1,
  "error": "parse failed: whatweb produced no fingerprint line"
}
```

### state matrix (same nmap adapter, different conditions)
```
condition      state        exit
live-disabled  disabled     0
--simulate     simulation   0
out-of-scope   (refused)    3
unauthorized   (refused)    4
```

---

## 2026-09-05 — ProjectDiscovery family + dalfox (native adapters)

_Captured against a **local authorized lab**: a Python `http.server` on
`127.0.0.1:8099` serving a small page with an `/admin/panel` link, plus a
deliberately broken server on `127.0.0.1:8098` that always answers 500. Scope
file authorizes `127.0.0.1` and `127.0.0.0/8` only; no public or third-party
system was contacted. `AEGIS_ENABLE_LIVE_SCANS=true`._

Engine versions: httpx (ProjectDiscovery) 1.x, katana 1.x, nuclei v3.11.1,
dalfox v2.13.0 — all built with `go install` and placed in `/opt/scanners`.

Run through Olympus, not by hand:
`olympus aegis run <scanner> --target http://127.0.0.1:8099 --kind url --scope scope.json --i-am-authorized`

| Scanner | State | Findings | Exit | Notes |
| --- | --- | --- | --- | --- |
| httpx | `live` | 4 | 0 | reachability + web server + 2 technologies |
| katana | `live` | 3 | 0 | 3 endpoints; `/admin/panel` elevated to MEDIUM |
| nuclei | `live` | 1 | 0 | one LOW match from a lab-local template |
| dalfox | `live` | 0 | 0 | clean target; `[{}]` correctly read as no findings |

```json
{"scanner": "httpx", "state": "live", "finding_count": 4, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "katana", "state": "live", "finding_count": 3, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "nuclei", "state": "live", "finding_count": 1, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "dalfox", "state": "live", "finding_count": 0, "exit_code": 0,
 "error": null, "real_execution": true}
```

### Three things the live runs taught us

**The sandbox is real.** The first attempt ran the binaries from `/root/go/bin`
and every scan returned `failed` with
`start_failed: [Errno 13] Permission denied`, `unprivileged_user: nobody`. The
sandbox had dropped privileges exactly as designed and `nobody` cannot read
`/root`. The binaries were moved to a world-readable `/opt/scanners`; the
refusal was correct behaviour, not a bug.

**nuclei cannot find its templates under the sandbox.** nuclei locates
`nuclei-templates` through `$HOME`, and the sandbox user's home is not the
operator's, so the engine exited 1 with "no templates provided for scan". The
adapter now takes `AEGIS_NUCLEI_TEMPLATES` and passes `-templates` explicitly.

**A bare host target is not a URL target.** `httpx --target 127.0.0.1` probes
80/443, which are closed on the lab host, and exits 2. Targeting
`http://127.0.0.1:8099` with `--kind url` returns `live` with 4 findings.


---

## 2026-09-05 — dirsearch + commix (native adapters)

_Captured against a **local authorized lab**: the content-discovery target is a
Python `http.server` on `127.0.0.1:8099` serving `/index.html`, `/admin/panel`
and `/private/.env`; the command-injection target on `127.0.0.1:8094` shells out
to `ping` with an unsanitised `addr` parameter. Scope authorizes `127.0.0.1` and
`127.0.0.0/8` only. `AEGIS_ENABLE_LIVE_SCANS=true`._

Engine versions: dirsearch v0.5.0, commix 4.x. Run through Olympus:
`olympus aegis run <scanner> --target <url> --kind url --scope scope.json --i-am-authorized`

| Scanner | State | Findings | Exit | Notes |
| --- | --- | --- | --- | --- |
| dirsearch | `live` | 4 | 0 | `/admin` and `/admin/` elevated to MEDIUM |
| commix | `live` | 3 | 0 | one CRITICAL per confirmed technique (classic / time-based / file-based) |

```json
{"scanner": "dirsearch", "state": "live", "finding_count": 4, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "commix", "state": "live", "finding_count": 3, "exit_code": 0,
 "error": null, "real_execution": true}
```

### What the live runs taught us

**A Python scanner's dependencies must be visible to the sandbox user.**
dirsearch first returned `failed` with `ModuleNotFoundError: No module named
'requests'`: the tool and its dependencies had been installed into root's
per-user site (`/root/.local`), which the unprivileged sandbox user cannot read,
and the sandbox does not pass `PYTHONPATH` through. Installing dirsearch's
dependencies into the system `dist-packages` — where a real deployment would put
them — resolved it. The refusal was the sandbox working, not the adapter.

**Both tools write structured reports only to a file, never to stdout.**
dirsearch's `-o` JSON and commix's `--report-json` both target a path, and
`-o /dev/stdout` hangs. Rather than give every adapter a writable scratch path
and a temp-file lifecycle for one tool each, both adapters parse the stable
result lines the tools already print (`[HH:MM:SS] <status> - <size> - <url>` for
dirsearch, `[info] ... appears to be injectable via <technique> technique` for
commix).

**commix repeats its verdict per confirming request.** The adapter deduplicates
on `(parameter, technique)`, so three confirmed techniques against one parameter
produce three findings, not one per HTTP request. The technique payloads commix
prints are deliberately omitted from evidence: they carry the injected commands,
and "parameter X is injectable" does not need a working exploit string attached.

---

## 2026-09-05 — arjun (native adapter)

_Captured against a **local authorized lab**: a server on `127.0.0.1:8092` whose
response changes for the hidden parameters `id` and `debug` (and ignores all
others), and one on `127.0.0.1:8091` that honours no parameter. Scope authorizes
`127.0.0.1` and `127.0.0.0/8` only. `AEGIS_ENABLE_LIVE_SCANS=true`._

arjun 2.x, run through Olympus:
`olympus aegis run arjun --target http://127.0.0.1:8092/ --kind url --scope scope.json --i-am-authorized`

| Target | State | Findings | Notes |
| --- | --- | --- | --- |
| 8092 (`id`, `debug` honoured) | `live` | 2 | both hidden parameters found, at INFO |
| 8091 (no hidden parameters) | `live` | 0 | a real empty result, not a failure |

```json
{"scanner": "arjun", "state": "live", "finding_count": 2, "exit_code": 0,
 "error": null, "real_execution": true}
```

Confirmed captured result lines (through Olympus, so `NO_COLOR=1` — no ANSI):

```text
[✓] parameter detected: debug, based on: body length
[✓] parameter detected: id, based on: body length
[+] Parameters found: debug, id
```

Like dirsearch and commix, arjun writes its JSON only to a file (`-o`), so the
adapter parses the per-parameter `[✓]` lines — which carry the detection reason
the summary line drops. A hidden parameter is attack surface, not a
vulnerability, so each is INFO. arjun needed the same treatment as the other
Python scanners: its dependencies (`dicttoxml`, `ratelimit`) had to be installed
into the system `dist-packages` to be visible to the unprivileged sandbox user.

---

## 2026-09-05 — xsstrike (native adapter)

_Captured against a **matched pair** of local authorized lab targets: one on
`127.0.0.1:8096` that reflects the `q` parameter unescaped (vulnerable), and one
on `127.0.0.1:8095` that HTML-escapes it (safe). Scope authorizes `127.0.0.1`
and `127.0.0.0/8` only. `AEGIS_ENABLE_LIVE_SCANS=true`._

XSStrike 3.1.5, run through Olympus:
`olympus aegis run xsstrike --target http://127.0.0.1:8096/?q=1 --kind url --scope scope.json --i-am-authorized`

| Target | State | Findings | Notes |
| --- | --- | --- | --- |
| 8096 (reflects unescaped) | `live` | 1 | one HIGH, reflected XSS in `q` |
| 8095 (HTML-escapes) | `live` | 0 | reflections and payloads appear, but none confirmed |

```json
{"scanner": "xsstrike", "state": "live", "finding_count": 1, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "xsstrike", "state": "live", "finding_count": 0, "exit_code": 0,
 "error": null, "real_execution": true}
```

### Why efficiency, and nothing else

XSStrike has no machine-readable output, so this adapter was the most carefully
guarded of the set — and the guarding was chosen empirically, not guessed. The
tempting signals are traps: against the **safe** target XSStrike still printed
`Reflections found: 1` and a long stream of `[+] Payload:` candidates, so neither
is proof of a vulnerability.

The one signal that separated the two targets is **efficiency** — the fraction
of a payload that survived into the response unmodified. Measured directly:

```text
safe target  (8095):  max Efficiency 94   → 0 findings
vuln target  (8096):      Efficiency 100  → 1 finding
```

So the adapter raises a finding only for a payload whose very next efficiency
reading is exactly 100 (byte-for-byte reflection, no escaping), pairs each
efficiency with the payload just printed, deduplicates per parameter, and
truncates the confirmed payload — reflected attacker-controlled markup — into
evidence rather than a title.

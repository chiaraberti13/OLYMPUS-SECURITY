# Malicious input corpus (SEC-H)

A versioned set of attacker-controlled inputs. Each file encodes one hostile
pattern that a scanned target or an untrusted feed could emit; the defense it
exercises is asserted by `tests/unit/test_malicious_fixtures.py`, which runs in
the ordinary unit suite on every CI run. A regression in any guardrail fails the
build.

| Fixture | Hostile pattern | Defense proven |
| --- | --- | --- |
| `nmap_entity_bomb.xml` | XML entity-expansion ("billion laughs") | `defusedxml` forbids entity expansion → `ParseError` |
| `nmap_deep_nesting.xml` | XML nested beyond the depth bound | Nmap depth limit → `ParseError` |
| `nuclei_deep_nesting.jsonl` | JSON nested beyond the depth bound | shared `check_json_depth` → `ParseError` |
| `ansi_osc_banner.txt` | ANSI/OSC and C0/C1 terminal-control bytes | report exports strip controls via `safe_terminal_text` |
| `xss_title.txt` | `<script>`/`onerror` payload in a finding title | HTML export escapes it and ships a restrictive CSP |
| `path_traversal_filenames.txt` | `../`, absolute and separator filenames | `output_path` rejects each with `ValueError` |

These are synthetic, non-executable samples. Do not "fix" a fixture to make a
test pass: the inputs are intentionally hostile, and the assertions describe how
Olympus must contain them.

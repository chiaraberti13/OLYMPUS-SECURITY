# Independent feature review and implementation map

_Review date: 2026-08-26._

The repositories below were reviewed at immutable revisions to identify useful
product patterns. Olympus does not clone, import, execute, depend on, or link to
them at runtime. Native code was written against Olympus contracts and safety
boundaries. This matters especially for AGPL projects and for GhostTrack, which
does not publish a licence file.

The machine-readable contract is
[`docs/parity/reference-implementations.json`](parity/reference-implementations.json).

| Reference | Reviewed revision | Licence observed | Useful pattern | Independent Olympus implementation |
| --- | --- | --- | --- | --- |
| `0xSteph/pentest-ai-agents` | `e5d7aa02c4c0c29a90e4789034b45e0cb7488e89` | MIT | specialist catalog, task routing, engagement planning, findings memory, scope guard | Metis capability catalog/router/planner and case store; shared `ExecutionPolicy` |
| `7onez/cti-expert` | `c8e051aeb5d68f3b66009b8cdc61bf1db4840710` | MIT + ethical-use statement | case workspaces, IOC intake, confidence, pivot/correlation, reporting | Metis strict case document, SQLite case store, local IOC extraction, finding links and Markdown/JSON reports |
| `mukul975/Anthropic-Cybersecurity-Skills` | `1b3f6b2286981381a5cc0566551ef3bb6bc38383` | Apache-2.0 | searchable cyber capability index and schema validation | native typed `CapabilityProfile` catalog and explainable deterministic scorer; no prompt files copied |
| `CarterPerez-dev/Cybersecurity-Projects` | `614b4c7e9351c76f09a2496eccae29b798982a23` | AGPL-3.0 | levelled project catalog and evidence-oriented learning paths | `olympus metis labs`, restricted to safe Olympus-native fixtures and commands |
| `blacklanternsecurity/bbot` | `a6fb827bb144cdb85b52e142a4d6e14ed5f94b69` | AGPL-3.0 | event-driven modules, presets, recursion, deduplication, blacklist and scan bounds | native `olympus.argus.pipeline` engine and strict preset/result contracts; no BBOT module/source is present |
| `HunxByts/GhostTrack` | `a5cb8ad4c08acd803f166fb067b7dac724d6cb3d` | no licence file | unified IP, public-IP, phone and username OSINT menu | existing scoped Argus `ip`, `myip`, `phone`, `accounts`; the new pipeline unifies offline intake without copying GhostTrack |

## Review decisions

- AI-provider-specific prompt packs were converted into a deterministic local
  capability catalog. Metis does not claim autonomous exploitation and does
  not require an LLM or API key.
- Findings and CTI cases use a dedicated schema instead of storing plaintext
  credentials. Secret values are never a supported Metis field.
- The event pipeline ships only offline transforms. Its extension contract has
  an explicit `active` flag; active modules require both authorization and an
  injected per-event scope gate.
- AGPL source was not copied into the MIT-native package. The AGPL-licensed
  Vulnerability Assessment Platform already vendored by Olympus remains a
  separately identified GPL component as documented in
  `THIRD_PARTY_NOTICES.md`.
- GhostTrack's HTTP calls lacked HTTPS, timeouts, scope gates, concurrency
  limits and a licence grant. Olympus retains its own safer Argus
  implementations and does not vendor that source.

## Native files

- `src/olympus/metis/`: catalog, plan, CTI cases, reports and lab catalog.
- `src/olympus/argus/pipeline.py`: event/preset pipeline.
- `examples/input/argus-pipeline.json`: synthetic offline fixture.
- `tests/unit/test_metis.py` and `tests/unit/test_argus_pipeline.py`: offline
  contract, safety, persistence and CLI verification.

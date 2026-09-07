"""Generate ``docs/scanner-matrix.md`` from the registry — never by hand.

The scanner matrix was maintained by hand: its header claimed it was "generated
from ``olympus.integrations.scanners``" while a person actually edited the table,
the two derived columns, and the totals on every adapter change. That is exactly
the kind of document that drifts. This module makes the claim true — the whole
file is rendered from the registry (:mod:`olympus.integrations.scanners`) plus
the maturity ledger (:mod:`olympus.integrations.maturity`) — and a unit test
asserts the committed file equals the rendered output, so it cannot drift again.

Two columns are *derived*, not stored, and this is where hand-maintenance used
to go wrong:

* **Native adapter** — whether a real execution adapter is registered.
* **Live-verified here** — the maturity stage: ``live-tested`` shows "yes",
  ``offline-tested`` shows "parser only", anything lower shows "n/a".

The prose sections (the ZAP/OpenVAS correction, the ``httpx`` collision note,
the per-engine licence notes) are stable editorial text kept here as constants;
editing them means editing this generator, which keeps generation the single
source of truth.
"""

from __future__ import annotations

from olympus.aegis.registry import implemented
from olympus.integrations.maturity import Maturity, record_for
from olympus.integrations.scanners import REGISTRY, ScannerSpec

#: Grouping order for the table: OSS services, local binaries, then proprietary.
_KIND_ORDER = {
    "containerised-oss-service": 0,
    "local-oss-binary": 1,
    "proprietary-local": 2,
    "proprietary-remote-api": 3,
}

_HEADER = """# AEGIS 24-scanner classification, dependency & execution matrix

_Generated from `olympus.integrations.scanners` (registry) and \
`olympus.aegis.registry` (native execution adapters) by \
`olympus aegis matrix`. Do not edit by hand — run the command. See \
`docs/aegis-execution-evidence.md` for the real captured evidence._

> **Correction:** OWASP **ZAP** and **OpenVAS/GVM** are open-source \
(Apache-2.0 / GPL-2.0) and are classified as `containerised-oss-service`, NOT \
commercial. Only Nessus, Burp, and Acunetix are proprietary.

> **Beware the `httpx` name collision.** The Python HTTP-client library ships a
> console script also called `httpx`, so a PATH lookup cannot tell it from the
> ProjectDiscovery probe. The adapter refuses non-probe output with an error
> naming the collision rather than reporting a clean scan.

> **Simulation is opt-in.** `olympus aegis run` never fabricates findings: a \
missing binary → `unavailable`, live-off → `disabled`, explicit `--simulate` → \
`simulation`.
"""

_TABLE_HEAD = (
    "| Scanner | Category | Kind | Binary / API | Licence | Auto-install "
    "| In image | Native adapter | Live-verified here |\n"
    "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"
)

_MATURITY_SECTION = """## Maturity, not just presence

The "Native adapter" and "Live-verified" columns above are derived from the
maturity ladder in `olympus.integrations.maturity` — `catalog-only` →
`adapter-ready` → `offline-tested` → `live-tested` → `production-ready` —
reported per engine by `olympus aegis capabilities` and cross-checked against
the repository on every test run. See [`docs/scanner-maturity.md`](scanner-maturity.md).

Readiness and maturity are different questions: readiness is about *this host*
(is the binary installed, is the API configured), maturity is about *the project*
(does an adapter exist, is its parser tested, was it ever run live). An engine
installed on your machine that Olympus has no adapter for stays `catalog-only`.
"""

_NOTES_SECTION = """## Per-scanner service/licence notes

- **OWASP ZAP** (Apache-2.0, OSS): run as a daemon/container (`zaproxy/zaproxy`), \
driven via its API — see the `zap` Compose profile.
- **OpenVAS/GVM** (GPL-2.0, OSS): the Greenbone GVM service stack (feed + scanner \
+ gvmd), heavy; run via the `gvm` Compose profile or an external service.
- **Burp Suite** — Community (free, limited, no automation API) vs \
**Professional** (licensed, REST API for automation). Proprietary; manual \
install + licence.
- **Nessus** (Tenable) — proprietary; external service + API + licence/activation \
code.
- **Acunetix** (Invicti) — proprietary; external service + API + commercial licence.
- **wpscan** — source-available (WPScan Public Source, non-OSI); free, but the \
vulnerability database needs a free API token.

## Unavailable-tool policy

`olympus aegis run <scanner>` returns an explicit state and never fabricates \
findings: `unavailable` (missing binary/API, with install instructions + \
`olympus aegis deps` diagnostic), `disabled` (live off), `failed` (real error), \
or `live`. Commercial/service engines return `unavailable` until configured. \
Nothing is silently skipped.
"""


def _sorted_specs() -> list[ScannerSpec]:
    return sorted(REGISTRY, key=lambda spec: (_KIND_ORDER[spec.kind], spec.name))


def _native_adapter_cell(name: str, adapters: set[str]) -> str:
    return "✅ implemented" if name in adapters else "— pending"


def _live_cell(name: str) -> str:
    stage = record_for(name).stage
    if stage is Maturity.LIVE_TESTED:
        return "✅ yes"
    if stage is Maturity.OFFLINE_TESTED:
        return "parser only"
    return "n/a"


def _row(spec: ScannerSpec, adapters: set[str]) -> str:
    binary = f"`{spec.binary}`" if spec.binary is not None else "`API/daemon`"
    return (
        f"| {spec.name} | {spec.category} | {spec.kind} | {binary} | {spec.licence} "
        f"| {'yes' if spec.redistributable else 'no'} "
        f"| {'yes' if spec.in_scanner_image else 'no'} "
        f"| {_native_adapter_cell(spec.name, adapters)} "
        f"| {_live_cell(spec.name)} |"
    )


def _totals() -> str:
    specs = list(REGISTRY)
    total = len(specs)
    by_kind = {kind: sum(1 for s in specs if s.kind == kind) for kind in _KIND_ORDER}
    oss = by_kind["containerised-oss-service"] + by_kind["local-oss-binary"]
    redistributable = sum(1 for s in specs if s.redistributable)
    in_image = sum(1 for s in specs if s.in_scanner_image)
    proprietary = sorted(
        s.name for s in specs if s.kind in {"proprietary-local", "proprietary-remote-api"}
    )
    adapters = sorted(implemented())
    live = sorted(
        s.name for s in specs if record_for(s.name).stage is Maturity.LIVE_TESTED
    )
    production = sum(
        1 for s in specs if record_for(s.name).stage is Maturity.PRODUCTION_READY
    )
    production_line = (
        f"- **Production-ready**: **{production}/{total}** — no adapter meets the full "
        "Definition of Done"
        if production == 0
        else f"- **Production-ready**: **{production}/{total}** — meets the full "
        "Definition of Done"
    )
    return "\n".join(
        [
            "## Recalculated totals",
            "",
            f"- **Open source** (local-oss-binary + containerised-oss-service): "
            f"**{oss}/{total}**",
            f"  - `containerised-oss-service`: {by_kind['containerised-oss-service']}",
            f"  - `local-oss-binary`: {by_kind['local-oss-binary']}",
            f"  - `proprietary-local`: {by_kind['proprietary-local']}",
            f"  - `proprietary-remote-api`: {by_kind['proprietary-remote-api']}",
            f"- **Auto-installable / redistributable**: {redistributable}/{total}",
            f"- **Bundled in `docker/Dockerfile.scanners`**: {in_image}/{total}",
            f"- **Proprietary (commercial licence)**: {len(proprietary)}/{total} "
            f"({', '.join(proprietary)})",
            f"- **Native AEGIS execution adapters implemented**: {len(adapters)}/{total} "
            f"({', '.join(adapters)})",
            f"- **Live end-to-end verified in this environment**: {len(live)}/{total} "
            f"({', '.join(live)}) — see evidence doc",
            production_line,
            "  (per-adapter evidence manifest with digests, SBOM, vulnerability scan,",
            "  documented version compatibility)",
        ]
    )


def render() -> str:
    """Return the complete ``docs/scanner-matrix.md`` document."""
    adapters = set(implemented())
    rows = "\n".join(_row(spec, adapters) for spec in _sorted_specs())
    blocks = [
        _HEADER.rstrip(),
        _TABLE_HEAD + "\n" + rows,
        _totals(),
        _MATURITY_SECTION.rstrip(),
        _NOTES_SECTION.rstrip(),
    ]
    return "\n\n".join(blocks) + "\n"

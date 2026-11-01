#!/usr/bin/env python3
"""Generate the static, Vercel-publishable preview of the Olympus tools (WEB-K-a).

The live Olympus web control plane is a stateful ASGI server (SQLite, a background
worker, SSE streaming and scanner subprocesses) and cannot run on Vercel's static
+ ephemeral-serverless model. This generator removes that blocker for the
*preview* use case: it renders a handful of **self-contained static HTML pages**
from the real data model, using only **synthetic** data and performing **no
execution**, so Vercel can serve them with no server, no database and no build
dependency at deploy time.

Output goes to ``public/`` at the repository root, which ``vercel.json`` serves
verbatim. Run ``python scripts/build_preview.py`` to (re)generate it, or
``--check`` to verify the committed output is current (a drift gate, like the CLI
reference and scanner matrix).

Nothing here is a live result: every page carries an explicit preview banner, and
the data is fictitious.
"""

from __future__ import annotations

import argparse
import html
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from olympus.apollo.application import ApolloApplicationService
from olympus.argus.ct import parse_crtsh_response
from olympus.core.enums import AssetType, FindingStatus, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.integrations.scanners import REGISTRY
from olympus.integrations.suite_catalog import catalog_document
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput
from olympus.vulcan.attack import ATTACK_MAP_VERSION, associate_all, technique_counts
from olympus.vulcan.report import build_report_model, render_report_html

_ROOT = Path(__file__).resolve().parents[1]
_PUBLIC = _ROOT / "public"
_FIXTURES = _ROOT / "tests" / "fixtures"

#: One deterministic timestamp so regenerating without changes is a no-op (the
#: drift gate would otherwise fail on the clock alone).
_GENERATED = datetime(2026, 1, 1, tzinfo=UTC)

_BANNER = (
    "Anteprima statica · uso didattico e test autorizzati · nessuna esecuzione, "
    "nessun target reale · dati sintetici. Le scansioni reali girano solo nel "
    "backend Olympus, contro target autorizzati, mai su questo sito."
)

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:64rem;margin:0 auto;padding:0 1rem 3rem;"
    "color:#111;line-height:1.5}"
    "header{padding:2rem 0 1rem}h1{margin:.2rem 0}h2{margin-top:2rem}"
    "a{color:#1d4ed8}.banner{background:#fef3c7;border:1px solid #f59e0b;border-radius:.5rem;"
    "padding:.6rem .9rem;margin:1rem 0;font-size:.9rem}"
    "nav{display:flex;gap:1rem;flex-wrap:wrap;margin:.5rem 0 1rem}"
    "table{border-collapse:collapse;width:100%;margin:.5rem 0}"
    "td,th{border:1px solid #ddd;padding:.35rem .6rem;text-align:left;vertical-align:top;"
    "font-size:.9rem}th{background:#f3f4f6}"
    ".pill{display:inline-block;padding:.05rem .5rem;border-radius:.4rem;color:#fff;"
    "font-size:.8rem}"
    ".present{background:#3f6212}.simulated{background:#a16207}.missing{background:#6b7280}"
    "footer{margin-top:3rem;color:#666;font-size:.85rem;border-top:1px solid #eee;padding-top:1rem}"
    "@media (prefers-color-scheme:dark){body{background:#0b0f19;color:#e5e7eb}"
    "th{background:#1f2937}td,th{border-color:#374151}.banner{background:#422006;border-color:#a16207}"
    "a{color:#93c5fd}}"
)

# Restrictive CSP: self-contained pages, inline style only, no scripts, no remote
# assets. Mirrors the Vulcan report CSP so the preview holds the same guarantee.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)


def _page(title: str, body: str) -> str:
    """Wrap a body fragment in a complete, escaped, CSP-constrained HTML document."""
    return (
        "<!doctype html><html lang='it'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head><body>"
        "<header><h1>🏛️ OLYMPUS-SECURITY</h1>"
        "<nav><a href='index.html'>Panoramica</a><a href='tools.html'>Strumenti</a>"
        "<a href='demo.html'>Demo guidata</a><a href='report.html'>Report di esempio</a>"
        "<a href='apollo.html'>Apollo</a>"
        "<a href='attack.html'>Associazioni ATT&amp;CK</a>"
        "<a href='https://github.com/chiaraberti13/OLYMPUS-SECURITY'>Codice</a></nav>"
        f"<div class='banner'>{html.escape(_BANNER)}</div></header>"
        f"{body}"
        "<footer>Anteprima generata da <code>scripts/build_preview.py</code> · "
        f"{_GENERATED.strftime('%Y-%m-%d')} · contenuti sintetici, nessun dato reale.</footer>"
        "</body></html>"
    )


def _index_html() -> str:
    catalog = catalog_document()
    coverage = cast("dict[str, int]", catalog["coverage"])
    rows = "".join(
        f"<tr><td><span class='pill {html.escape(state)}'>{html.escape(state)}</span></td>"
        f"<td>{count}</td></tr>"
        for state, count in sorted(coverage.items())
    )
    body = (
        "<p>Olympus è una piattaforma Red/Blue/Purple Team sicura e verificabile. "
        "Questa è un'<strong>anteprima statica</strong> degli strumenti e del formato "
        "dei risultati: utile per vedere cosa fa la suite, senza eseguire nulla.</p>"
        "<h2>Copertura delle capability della suite</h2>"
        "<p>Stato dichiarato in modo onesto e derivato dal codice "
        "(<code>olympus catalog</code>), non asserito.</p>"
        f"<table><tr><th>Stato</th><th>Capability</th></tr>{rows}</table>"
        "<p><a href='tools.html'>Vedi il dettaglio degli strumenti →</a></p>"
        "<h2>Cosa gira, e dove</h2>"
        "<p>Le scansioni reali (orchestrazione job, SSE live, subprocess degli scanner) "
        "girano esclusivamente nel <strong>backend Olympus</strong> su un host con disco "
        "persistente; questo sito statico mostra solo le anteprime e il formato dei "
        "deliverable.</p>"
    )
    return _page("OLYMPUS-SECURITY — Anteprima", body)


def _tools_html() -> str:
    catalog = catalog_document()
    capabilities = cast("list[dict[str, object]]", catalog["capabilities"])
    cap_rows = []
    for cap in capabilities:
        state = str(cap["coverage"])
        engines = ", ".join(str(e) for e in cap.get("engines", [])) or "—"
        modules = ", ".join(str(m) for m in cap.get("modules", [])) or "—"
        note = html.escape(str(cap.get("note") or ""))
        cap_rows.append(
            f"<tr><td><strong>{html.escape(str(cap['title']))}</strong><br>"
            f"<small>{html.escape(str(cap['summary']))}</small>"
            + (f"<br><small>{note}</small>" if note else "")
            + f"</td><td><span class='pill {html.escape(state)}'>{html.escape(state)}</span></td>"
            f"<td>{html.escape(modules)}</td><td>{html.escape(engines)}</td></tr>"
        )
    scanner_rows = "".join(
        f"<tr><td>{html.escape(spec.name)}</td><td>{html.escape(spec.category)}</td>"
        f"<td>{html.escape(spec.purpose)}</td><td>{html.escape(spec.licence)}</td></tr>"
        for spec in sorted(REGISTRY, key=lambda s: (s.category, s.name))
    )
    body = (
        "<h2>Capability della suite</h2>"
        "<p>Ogni capacità è mappata sui moduli ed engine Olympus che la realizzano, "
        "con lo stato di copertura (<span class='pill present'>present</span> = "
        "fornita e provata, <span class='pill simulated'>simulated</span> = adapter "
        "non ancora provato, <span class='pill missing'>missing</span> = non coperta).</p>"
        "<table><tr><th>Capability</th><th>Stato</th><th>Moduli</th><th>Engine</th></tr>"
        f"{''.join(cap_rows)}</table>"
        f"<h2>Catalogo scanner ({len(REGISTRY)})</h2>"
        "<p>Gli engine integrabili e la loro finalità. Catalogato non significa "
        "pronto: la maturità reale è nel ledger del progetto.</p>"
        "<table><tr><th>Nome</th><th>Categoria</th><th>Finalità</th><th>Licenza</th></tr>"
        f"{scanner_rows}</table>"
    )
    return _page("OLYMPUS-SECURITY — Strumenti", body)


def _sample_findings() -> tuple[list[Asset], list[Finding]]:
    """Return fictitious assets/findings for the sample report (never real data)."""
    asset = Asset(
        asset_id="AST-DEMO-1",
        asset_type=AssetType.HOST,
        hostname="demo.lab.invalid",
        source=Source.THEMIS,
    )
    findings = [
        Finding(
            finding_id="FND-DEMO-1",
            asset_id="AST-DEMO-1",
            source=Source.THEMIS,
            title="TLS: deprecated protocol enabled (demo)",
            severity=Severity.HIGH,
            description="The demo host accepts a deprecated TLS protocol version.",
            remediation="Disable legacy TLS versions and prefer TLS 1.3.",
            status=FindingStatus.NEW,
        ),
        Finding(
            finding_id="FND-DEMO-2",
            asset_id="AST-DEMO-1",
            source=Source.ARTEMIS,
            title="Missing security headers (demo)",
            severity=Severity.LOW,
            description="Content-Security-Policy and HSTS are not set on the demo app.",
            remediation="Add a restrictive CSP and enable HSTS.",
            status=FindingStatus.NEW,
        ),
    ]
    return [asset], findings


def _report_html() -> str:
    assets, findings = _sample_findings()
    report = build_report_model(
        "Demo engagement (synthetic)", assets, findings, [], generated_at=_GENERATED
    )
    # render_report_html already produces a complete, escaped, CSP-constrained
    # document; it is the real report format, shown here on fictitious data.
    return render_report_html(report)


# --------------------------------------------------------------------------- #
# WEB-K-c: fixture-driven interactive demo. Nothing is executed: every stage shows
# output recorded in repository fixtures, parsed by the *real* parsers/renderer.
# --------------------------------------------------------------------------- #

_DEMO_DOMAIN = "olympusdemocorp.example"
_DEMO_HOST = "127.0.0.1"
_DEMO_BANNER = "DEMO — nessuna esecuzione, dati sintetici"

# Same-origin script only on the demo page; the data is inline JSON (never executed).
_DEMO_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; img-src data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_DEMO_JS = """\
"use strict";
(function () {
  var root = document.getElementById("demo");
  if (!root) { return; }
  var start = document.getElementById("demo-start");
  var stages = Array.prototype.slice.call(root.querySelectorAll(".stage"));
  var STEP_MS = 700;
  root.classList.add("js");
  function setState(stage, state) {
    stage.setAttribute("data-state", state);
    stage.querySelector(".state").textContent = state;
  }
  function reset() {
    stages.forEach(function (s) { setState(s, "queued"); });
  }
  reset();
  var running = false;
  start.addEventListener("click", function () {
    if (running) { return; }
    running = true;
    start.disabled = true;
    reset();
    var i = 0;
    function next() {
      if (i > 0) { setState(stages[i - 1], "succeeded"); }
      if (i >= stages.length) {
        running = false; start.disabled = false;
        document.getElementById("demo-done").hidden = false;
        return;
      }
      setState(stages[i], "running");
      i += 1;
      window.setTimeout(next, STEP_MS);
    }
    document.getElementById("demo-done").hidden = true;
    next();
  });
})();
"""

_DEMO_STYLE = (
    ".stage{border:1px solid #ddd;border-radius:.5rem;padding:.6rem .9rem;margin:.8rem 0}"
    ".stage h3{margin:.1rem 0}pre{overflow:auto;background:#f3f4f6;padding:.6rem;"
    "border-radius:.4rem;font-size:.8rem}"
    ".state{font-weight:600}"
    "#demo.js .stage[data-state=queued] .out,#demo.js .stage[data-state=running] .out{display:none}"
    "#demo.js .stage[data-state=running]{border-color:#f59e0b}"
    "#demo.js .stage[data-state=succeeded]{border-color:#3f6212}"
    "button{font:inherit;padding:.4rem .9rem}"
    "@media (prefers-color-scheme:dark){pre{background:#1f2937}.stage{border-color:#374151}}"
)


def _demo_stages() -> tuple[list[tuple[str, str, str, str]], list[Finding], list[Asset]]:
    """Run the real parsers over recorded fixtures; return stage rows + findings."""
    crt = (_FIXTURES / "argus" / "crtsh.json").read_text(encoding="utf-8")
    names = parse_crtsh_response(_DEMO_DOMAIN, crt)
    nmap_xml = (_FIXTURES / "themis" / "live" / "nmap_open.xml").read_text(encoding="utf-8")
    request = ScanRequest(scanner="nmap", target=_DEMO_HOST)
    parsed = NmapAdapter().parse(CommandOutput(0, nmap_xml, ""), _DEMO_HOST, request)
    asset = Asset(
        asset_id="AST-DEMO-LAB",
        asset_type=AssetType.HOST,
        hostname="mars.lab.invalid",
        source=Source.THEMIS,
    )
    findings = [f.model_copy(update={"asset_id": asset.asset_id}) for f in parsed]
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
    enrich = "\\n".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) or "nessun finding"
    nmap_spec = next(spec for spec in REGISTRY if spec.name == "nmap")
    rows = [
        (
            "recon",
            f"Argus · CT passiva · {_DEMO_DOMAIN}",
            f"fixture tests/fixtures/argus/crtsh.json → {len(names)} nomi in scope\\n"
            + "\\n".join(names),
            "Fixture registrata; nessuna query a crt.sh.",
        ),
        (
            "scan",
            f"Themis · nmap · lab Mars locale ({_DEMO_HOST}:9090)",
            "fixture tests/fixtures/themis/live/nmap_open.xml → "
            + "\\n".join(f"[{f.severity.value}] {f.title}" for f in findings),
            "Output registrato da un lab autorizzato; nessun processo avviato.",
        ),
        (
            "enrich",
            f"Core · classificazione ({nmap_spec.name}: {nmap_spec.purpose})",
            "Finding per severità:\\n" + enrich,
            "Maturità reale delle capability: vedi pagina Strumenti.",
        ),
        (
            "report",
            "Vulcan · report HTML reale",
            f"{len(findings)} finding renderizzati dal renderer reale.",
            "Apri il report generato: demo-report.html",
        ),
    ]
    return rows, findings, [asset]


def _demo_html() -> str:
    rows, _, _ = _demo_stages()
    stages = "".join(
        f"<section class='stage' data-state='succeeded'><h3>{i}. {html.escape(name)} — "
        f"<span class='state'>succeeded</span></h3><p>{html.escape(label)}</p>"
        f"<div class='out'><pre>{html.escape(out)}</pre><small>{html.escape(note)}</small>"
        + ("<p><a href='demo-report.html'>Apri il report →</a></p>" if name == "report" else "")
        + "</div></section>"
        for i, (name, label, out, note) in enumerate(rows, 1)
    )
    body = (
        f"<style>{_DEMO_STYLE}</style>"
        f"<div class='banner' role='status'><strong>{html.escape(_DEMO_BANNER)}</strong></div>"
        "<h2>Demo guidata: recon → scan → enrich → report</h2>"
        "<p>Premi il pulsante per vedere un job <em>simulato</em> avanzare "
        "(<code>queued → running → succeeded</code>). Gli output sono "
        "<strong>pre-registrati</strong> dalle fixture del repository e analizzati dai "
        "parser reali; non viene eseguito nulla e non esistono target reali. Senza "
        "JavaScript la pagina mostra direttamente tutti gli esiti.</p>"
        f"<p>Target d'esempio: <code>{_DEMO_DOMAIN}</code> (dominio riservato) e il lab "
        "locale Mars (<code>labs/mars/</code>).</p>"
        "<button id='demo-start' type='button'>Avvia scan demo</button>"
        "<p id='demo-done' hidden role='status'>Job demo completato (simulato).</p>"
        f"<div id='demo'>{stages}</div>"
    )
    return (
        _page("OLYMPUS-SECURITY — Demo guidata", body)
        .replace(f'content="{_CSP}"', f'content="{_DEMO_CSP}"')
        .replace("</body>", "<script src='demo.js'></script></body>")
    )


def _demo_report_html() -> str:
    _, findings, assets = _demo_stages()
    report = build_report_model(
        "Demo engagement (fixture)", assets, findings, [], generated_at=_GENERATED
    )
    return render_report_html(report)


def _attack_html() -> str:
    finding = Finding(
        finding_id="FND-2026-00001",
        title="SQL injection — esempio sintetico",
        asset_id="AST-2026-00001",
        severity=Severity.HIGH,
        source=Source.ARTEMIS,
        cwe=["CWE-89"],
    )
    overlays = associate_all([finding])
    counts = technique_counts(overlays)
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.technique)}</td><td>{html.escape(item.name)}</td>"
        f"<td>{html.escape(item.tactic)}</td><td>{html.escape(item.confidence.value)}</td>"
        f"<td>{html.escape(item.rationale)}</td></tr>"
        for overlay in overlays
        for item in overlay.associations
    )
    return _page(
        "OLYMPUS-SECURITY — Associazioni ATT&CK",
        "<h2>Associazioni ATT&amp;CK dei finding</h2>"
        f"<p>DEMO · dati sintetici · mappa CWE versione {ATTACK_MAP_VERSION}. "
        "La Web UI operativa espone questa analisi in <code>/findings/attack</code>, "
        "con accesso autenticato, evidenze e download ATT&amp;CK Navigator.</p>"
        "<p>Le associazioni automatiche non dimostrano attacchi avvenuti né copertura "
        "difensiva. L'assenza di una mappatura non implica assenza di rischio.</p>"
        f"<p>Esempio: {html.escape(finding.title)} · {len(counts)} tecnica distinta.</p>"
        "<table><caption>Esempio derivato dal motore Vulcan, senza esecuzioni di rete</caption>"
        "<tr><th>Tecnica</th><th>Nome</th><th>Tattica</th><th>Confidenza</th>"
        f"<th>Provenienza automatica</th></tr>{rows}</table>",
    )


def _apollo_html() -> str:
    """Render the bundled Sysmon rule pack as an honest static preview."""
    rules = ApolloApplicationService().list_rules(_ROOT / "examples" / "input" / "apollo-sysmon")
    rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(rule.rule_id)}</code></td>"
        f"<td>{html.escape(rule.title)}</td>"
        f"<td><code>{html.escape(rule.event_type)}</code></td>"
        f"<td>{html.escape(rule.severity.value)}</td>"
        f"<td>{html.escape(', '.join(rule.mitre_attack) or '—')}</td></tr>"
        for rule in rules
    )
    return _page(
        "OLYMPUS-SECURITY — Apollo",
        "<h2>Apollo detection workbench</h2>"
        "<p>Questa pagina statica mostra il rule pack Sysmon incluso nel repository. "
        "La Web UI operativa espone <code>/apollo</code>: accetta eventi "
        "<code>olympus.event</code> normalizzati, applica davvero le regole sul backend "
        "e restituisce alert deterministici. Qui non è possibile inviare dati e non "
        "viene eseguita alcuna raccolta o chiamata di rete.</p>"
        f"<table><caption>{len(rules)} regole validate dal loader Apollo reale</caption>"
        "<tr><th>ID</th><th>Titolo</th><th>Tipo evento</th><th>Severità</th>"
        f"<th>ATT&amp;CK</th></tr>{rows}</table>",
    )


def _demo_js() -> str:
    return _DEMO_JS


_PAGES = {
    "index.html": _index_html,
    "tools.html": _tools_html,
    "report.html": _report_html,
    "demo.html": _demo_html,
    "demo-report.html": _demo_report_html,
    "demo.js": _demo_js,
    "attack.html": _attack_html,
    "apollo.html": _apollo_html,
}


def _render_all() -> dict[str, str]:
    return {name: build() for name, build in _PAGES.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the static Vercel preview.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed public/ output is current instead of writing it.",
    )
    args = parser.parse_args(argv)
    pages = _render_all()

    if args.check:
        stale: list[str] = []
        for name, content in pages.items():
            target = _PUBLIC / name
            if not target.exists() or target.read_text(encoding="utf-8") != content:
                stale.append(name)
        if stale:
            print(
                "public/ is stale; run `python scripts/build_preview.py`: "
                + ", ".join(sorted(stale)),
                file=sys.stderr,
            )
            return 1
        print(f"public/ is current ({len(pages)} pages).")
        return 0

    _PUBLIC.mkdir(parents=True, exist_ok=True)
    for name, content in pages.items():
        (_PUBLIC / name).write_text(content, encoding="utf-8")
    print(f"Wrote {len(pages)} page(s) to {_PUBLIC}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

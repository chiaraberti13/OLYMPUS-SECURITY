"""Render the engine inventory tables from the manifests, the registry and the ledger.

``docs/engines/INVENTORY.md`` is documentation people read, so it must never drift
from what the repository can prove. The tables between the generated markers are
rendered here from three sources of truth - ``engine.toml`` (pins, upstream,
distribution), the scanner registry (category, licence, shipped-in-image) and the
maturity ledger (stage) - and a test fails when the committed file differs.
"""

from __future__ import annotations

from olympus.engines.loader import load_all
from olympus.engines.schema import EngineManifest
from olympus.integrations.maturity import record_for
from olympus.integrations.scanners import by_name

BLOCK_BEGIN = "<!-- GENERATED:engine-inventory START -->"
BLOCK_END = "<!-- GENERATED:engine-inventory END -->"


def _normal(version: str) -> str:
    return version.lower().removeprefix("v")


def pin_vs_evidence(pinned: str | None, evidence: str | None) -> str:
    """Compare the pin with the version the maturity evidence was captured on.

    ``match``: identical. ``compatible``: the evidence only records a major line
    (``2.x``) and the pin sits inside it. ``RECONFIRM``: they differ, so the stage
    must be re-proven on the pin before it can be trusted. ``-``: no evidence.
    """
    if evidence is None:
        return "-"
    if pinned is None:
        return "RECONFIRM"
    pin, seen = _normal(pinned), _normal(evidence)
    if pin == seen:
        return "match"
    if seen.endswith(".x") and pin.startswith(seen[:-1]):
        return "compatible"
    return "RECONFIRM"


def _pin_text(manifest: EngineManifest) -> str:
    engine = manifest.engine
    version = f"`{engine.pinned_version}`"
    commit = engine.source.commit
    text = f"{version} @ `{commit[:7]}`" if commit else version
    if engine.reported_version:
        text += f" (l'engine stampa `{engine.reported_version}`: pin = commit)"
    return text


def _adapter_text(manifest: EngineManifest) -> str:
    if manifest.adapter is None:
        return "no"
    return "sì" if manifest.adapter.reviewed else "sì (timeout/profilo non rivisti)"


def _row_local(name: str, manifest: EngineManifest) -> str:
    engine = manifest.engine
    spec = by_name(name)
    if spec is None:
        raise ValueError(f"{name}: manifest for an engine absent from the scanner catalogue")
    verdict = pin_vs_evidence(engine.pinned_version, engine.evidence_version)
    cells = [
        f"`{name}`",
        engine.category,
        record_for(name).stage.value,
        _adapter_text(manifest),
        "sì" if engine.mandatory else "-",
        engine.upstream,
        "sì" if engine.upstream_verified else "no",
        engine.license,
        engine.language,
        engine.distribution,
        _pin_text(manifest),
        f"{engine.evidence_version or '-'} ({verdict})",
        "sì" if spec.in_scanner_image else "no",
    ]
    return "| " + " | ".join(cells) + " |"


def _row_api(name: str, manifest: EngineManifest) -> str:
    engine, source = manifest.engine, manifest.engine.source
    cells = [
        f"`{name}`",
        engine.category,
        record_for(name).stage.value,
        engine.upstream,
        engine.license,
        source.requires_product or "",
        ", ".join(f"`{item}`" for item in source.env_vars),
    ]
    return "| " + " | ".join(cells) + " |"


def render_inventory_block() -> str:
    """Return the deterministic, marker-delimited tables."""
    manifests = load_all()
    local = [(n, m) for n, m in sorted(manifests.items()) if m.engine.distribution != "api"]
    api = [(n, m) for n, m in sorted(manifests.items()) if m.engine.distribution == "api"]
    lines = [
        BLOCK_BEGIN,
        "",
        "### Engine locali (installabili)",
        "",
        "| Engine | Categoria | Stato | Adapter | Mandatory | Upstream | Upstream verificato | "
        "Licenza | Linguaggio | Distribuzione | Pin | Evidenza (esito pin) | In immagine |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        *(_row_local(name, manifest) for name, manifest in local),
        "",
        "### Engine che richiedono un prodotto esterno (solo manifest, `catalog-only`)",
        "",
        "Nessun adapter, nessun pin, `mandatory = false`: Olympus non li ha mai eseguiti. "
        "Nessus, Burp e Acunetix richiedono un prodotto commerciale; ZAP e OpenVAS sono "
        "open source ma vanno eseguiti come servizio separato.",
        "",
        "| Engine | Categoria | Stato | Upstream | Licenza | Prodotto richiesto | "
        "Variabili d'ambiente (solo nomi) |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *(_row_api(name, manifest) for name, manifest in api),
        "",
        BLOCK_END,
    ]
    return "\n".join(lines)

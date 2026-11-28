"""Render the engine inventory tables from the manifests, the registry and the ledger.

``docs/engines/INVENTORY.md`` is documentation people read, so it must never drift
from what the repository can prove. The tables between the generated markers are
rendered here from three sources of truth - ``engine.toml`` (pins, upstream,
distribution), the scanner registry (category, licence, shipped-in-image) and the
maturity ledger (stage) - and a test fails when the committed file differs.
"""

from __future__ import annotations

import re

from olympus.engines.loader import load_all, load_all_data
from olympus.engines.schema import DataManifest, EngineManifest
from olympus.integrations.maturity import record_for
from olympus.integrations.scanners import by_name

BLOCK_BEGIN = "<!-- GENERATED:engine-inventory START -->"
BLOCK_END = "<!-- GENERATED:engine-inventory END -->"

# --- Scanner-image supply-chain closure (TOOLS-4.2, reverse direction) -------- #
# ``tests/unit/test_engine_dockerfile_pins.py`` proves the forward direction: every
# governed pin reaches ``docker/Dockerfile.scanners``. These helpers prove the
# converse — nothing reaches the image ungoverned — so a scanner baked into the
# image without a manifest (or a catalogue ``in_scanner_image`` flag that drifted
# from what the image installs) fails a deterministic, offline check instead of
# shipping silently. Each regex matches one install idiom the Dockerfile uses.
_GO_INSTALL = re.compile(r"\bgo install\s+(\S+?)@")
_GIT_PIN = re.compile(r"\bgit_pin\s+(\S+)\s")
_PIP_ENGINE = re.compile(r"\bpip_engine\s+(\S+)\s")
_GEM_INSTALL = re.compile(r"\bgem install\s+(?:--no-document\s+)?(\S+)\s+-v")


def _governed_install_tokens() -> tuple[dict[tuple[str, str], str], set[str]]:
    """Resolve every install token the scanner image may legitimately carry.

    Returns ``(engine_tokens, support_packages)``. ``engine_tokens`` maps a
    ``(kind, key)`` install token to the governed engine or data dependency that owns
    it; ``support_packages`` is the set of runtime gem/pip package names a shipped
    engine declares (e.g. whatweb's ``addressable``), which the forward pin test
    already binds to the manifest.
    """
    manifests = load_all()
    tokens: dict[tuple[str, str], str] = {}
    support: set[str] = set()
    for name, manifest in manifests.items():
        spec = by_name(name)
        if spec is None or not spec.in_scanner_image:
            continue
        source = manifest.engine.source
        match manifest.engine.distribution:
            case "go" if source.module is not None:
                tokens[("go", source.module)] = name
            case "git" if source.repo is not None:
                tokens[("git", source.repo)] = name
            case "pip":
                # The ``pip_engine`` helper is called with the engine name, one venv each.
                tokens[("pip", name)] = name
            case "gem" if source.package is not None:
                tokens[("gem", source.package)] = name
        for item in source.runtime_packages:
            support.add(item.split("==", 1)[0])
    for name, data_manifest in load_all_data().items():
        repo = data_manifest.data.source.repo
        if repo is not None:
            tokens[("git", repo)] = f"data:{name}"
    return tokens, support


def installed_engine_tokens(dockerfile_text: str) -> list[tuple[str, str]]:
    """Every engine, data and gem install token the scanner Dockerfile carries."""
    found: list[tuple[str, str]] = []
    found += [("pip", match.group(1)) for match in _PIP_ENGINE.finditer(dockerfile_text)]
    found += [("go", match.group(1)) for match in _GO_INSTALL.finditer(dockerfile_text)]
    found += [("git", match.group(1)) for match in _GIT_PIN.finditer(dockerfile_text)]
    found += [("gem", match.group(1)) for match in _GEM_INSTALL.finditer(dockerfile_text)]
    return found


def scanner_image_drift(dockerfile_text: str) -> tuple[list[str], list[str]]:
    """Reverse-direction supply-chain closure for the scanner image (TOOLS-4.2).

    Returns ``(ungoverned, shipped_missing)``: install tokens in the Dockerfile that
    map to no manifest (ungoverned), and engines the catalogue marks shipped yet the
    Dockerfile never installs. Both empty means the image and the manifests agree.
    """
    tokens, support = _governed_install_tokens()
    found = installed_engine_tokens(dockerfile_text)
    ungoverned = sorted(
        f"{kind}:{key}"
        for kind, key in found
        if (kind, key) not in tokens and not (kind == "gem" and key in support)
    )
    installed_owners = {tokens[token] for token in found if token in tokens}
    shipped = {
        name
        for name in load_all()
        if (spec := by_name(name)) is not None and spec.in_scanner_image
    }
    shipped_missing = sorted(shipped - installed_owners)
    return ungoverned, shipped_missing


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


def _data_pin_text(manifest: DataManifest) -> str:
    commit = manifest.data.source.commit or ""
    return f"`{manifest.data.pinned_version}` @ `{commit[:7]}`"


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
        "### Dipendenze dati (pinnate come gli engine)",
        "",
        "Non sono codice ma decidono cosa trova l'engine: un insieme di template mobile "
        "cambierebbe i risultati senza che Olympus cambi.",
        "",
        "| Dipendenza | Usata da | Upstream | Verificato | Licenza | Pin |",
        "| --- | --- | --- | --- | --- | --- |",
        *(
            "| "
            + " | ".join(
                [
                    f"`{name}`",
                    ", ".join(f"`{item}`" for item in manifest.data.used_by),
                    manifest.data.upstream,
                    "sì" if manifest.data.upstream_verified else "no",
                    manifest.data.license,
                    _data_pin_text(manifest),
                ]
            )
            + " |"
            for name, manifest in sorted(load_all_data().items())
        ),
        "",
        BLOCK_END,
    ]
    return "\n".join(lines)

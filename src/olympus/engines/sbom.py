"""CycloneDX components for the external engines and their pinned data dependencies.

``olympus.core.sbom`` describes the Python packages Olympus imports. The engines it
*drives* are separate programs with their own versions, and the data they read (nuclei's
templates) decides what they find, so they belong in the same bill of materials. The
components are derived from the manifests, so the SBOM can never list a version the
repository does not pin.
"""

from __future__ import annotations

from typing import Any

from olympus.engines.loader import load_all, load_all_data
from olympus.engines.schema import DataManifest, EngineManifest
from olympus.integrations.maturity import record_for


def _github_path(url: str) -> str | None:
    prefix = "https://github.com/"
    return url.removeprefix(prefix).strip("/") if url.startswith(prefix) else None


def _purl(manifest: EngineManifest) -> str:
    engine, source = manifest.engine, manifest.engine.source
    version = engine.pinned_version or ""
    match engine.distribution:
        case "go":
            module = (source.module or "").split("/cmd/")[0]
            return f"pkg:golang/{module}@{version}"
        case "pip":
            return f"pkg:pypi/{(source.package or engine.name).lower()}@{version}"
        case "gem":
            return f"pkg:gem/{source.package}@{version}"
        case "npm":
            return f"pkg:npm/{source.package}@{version}"
        case "git":
            path = _github_path(source.repo or "")
            if path is not None:
                return f"pkg:github/{path.lower()}@{source.commit}"
            return f"pkg:generic/{engine.name}@{version}?vcs_url={source.repo}"
        case _:
            suffix = f"@{version}" if version else ""
            return f"pkg:generic/{engine.name}{suffix}"


def _engine_component(name: str, manifest: EngineManifest) -> dict[str, Any]:
    engine, source = manifest.engine, manifest.engine.source
    properties = [
        {"name": "olympus:distribution", "value": engine.distribution},
        {"name": "olympus:mandatory", "value": str(engine.mandatory).lower()},
        {"name": "olympus:maturity", "value": record_for(name).stage.value},
        {"name": "olympus:upstream-verified", "value": str(engine.upstream_verified).lower()},
    ]
    if source.commit:
        properties.append({"name": "olympus:commit", "value": source.commit})
    if source.requires_product:
        properties.append({"name": "olympus:requires-product", "value": source.requires_product})
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": f"engine:{name}",
        "name": name,
        "purl": _purl(manifest),
        "licenses": [{"license": {"name": engine.license}}],
        "externalReferences": [{"type": "vcs", "url": engine.upstream}],
        "properties": properties,
    }
    if engine.pinned_version:
        component["version"] = engine.pinned_version
    return component


def _data_component(name: str, manifest: DataManifest) -> dict[str, Any]:
    data = manifest.data
    path = _github_path(data.upstream)
    purl = (
        f"pkg:github/{path.lower()}@{data.source.commit}"
        if path is not None
        else f"pkg:generic/{name}@{data.pinned_version}"
    )
    return {
        "type": "data",
        "bom-ref": f"data:{name}",
        "name": name,
        "version": data.pinned_version,
        "purl": purl,
        "licenses": [{"license": {"name": data.license}}],
        "externalReferences": [{"type": "vcs", "url": data.upstream}],
        "properties": [
            {"name": "olympus:commit", "value": str(data.source.commit)},
            {"name": "olympus:upstream-verified", "value": str(data.upstream_verified).lower()},
        ],
    }


def engine_components() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return ``(components, dependencies)`` for every engine and data dependency.

    Sorted by ``bom-ref`` so two runs produce identical bytes. ``dependencies`` records
    which engine reads which data dependency.
    """
    engines = load_all()
    data = load_all_data()
    components = [_engine_component(name, manifest) for name, manifest in engines.items()]
    components += [_data_component(name, manifest) for name, manifest in data.items()]
    components.sort(key=lambda component: str(component["bom-ref"]))
    dependencies = [
        {
            "ref": f"engine:{name}",
            "dependsOn": [f"data:{item}" for item in manifest.engine.requires_data],
        }
        for name, manifest in sorted(engines.items())
        if manifest.engine.requires_data
    ]
    return components, dependencies

"""Generate a CycloneDX SBOM from the installed distribution metadata.

Roadmap §1.3 asks for an SBOM in CI. The common answer is to run Syft over the
built image, and that stays valuable for the *container*. But it makes the SBOM
depend on a third-party binary being installed, and it describes the image
rather than what Olympus actually imports. This module produces a SBOM of the
Python runtime closure directly, from :mod:`importlib.metadata` — pure standard
library, no external tool — so ``olympus core sbom`` works anywhere Olympus runs
and always describes the packages this interpreter would load.

The output is CycloneDX 1.5 JSON: ``bomFormat``/``specVersion``, an optional
``metadata`` block naming the Olympus application, and one ``component`` per
resolved dependency with its version, PURL and licence. Components are sorted by
name so the document is deterministic; the timestamp and serial number are
injected by the caller (the CLI supplies real ones, ``--reproducible`` omits
them, and tests pin them), so a byte-for-byte comparison is possible.

The dependency closure is walked from the root distribution's own
``Requires-Dist``. A requirement gated on ``extra == 'E'`` is followed only when
``E`` is active for the distribution that declares it — the root's extras come
from ``--extra``, a dependency's from the extras its requester asked for on it
(``textual`` → ``markdown-it-py[linkify]`` → ``linkify-it-py``). So a default
SBOM covers the runtime a plain install pulls, ``--extra themis`` widens it, and
extras a dependency activates on its own targets are not silently dropped.

Environment markers other than ``extra`` (``python_version``, ``sys_platform``,
``platform_python_implementation`` …) are resolved by the *installed set*: the
closure only yields a package that ``importlib.metadata`` can actually find, so a
requirement whose marker excludes this interpreter/platform was never installed
and never appears. That keeps the SBOM matched to what this environment would
load without re-implementing a PEP 508 marker evaluator in the hot path.
"""

from __future__ import annotations

import re
from importlib.metadata import Distribution, PackageNotFoundError, distribution
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.5"
ROOT_DISTRIBUTION = "olympus-security"

#: Leading distribution name in a ``Requires-Dist`` string (before any extras,
#: version specifier, or environment marker).
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

#: Extras a requirement activates on its own target, e.g. the ``linkify`` in
#: ``markdown-it-py[linkify]>=2.1.0``.
_REQUIREMENT_EXTRAS = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*\[([^\]]*)\]")

#: The ``extra == 'name'`` gate inside a requirement's environment marker.
_EXTRA_MARKER = re.compile(r"extra\s*==\s*['\"]([^'\"]+)['\"]")


def normalize(name: str) -> str:
    """Return the PEP 503 normalized distribution name (lowercase, dash-joined)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement_name(requirement: str) -> str | None:
    match = _REQUIREMENT_NAME.match(requirement)
    return match.group(1) if match else None


def _requirement_extras(requirement: str) -> frozenset[str]:
    """Return the extras a requirement activates on its target, PEP 503 normalized.

    ``markdown-it-py[linkify]>=2.1.0`` activates markdown-it-py's ``linkify``
    extra; that extra's own requirements must then be followed into the closure.
    """
    match = _REQUIREMENT_EXTRAS.match(requirement)
    if match is None:
        return frozenset()
    return frozenset(normalize(part) for part in match.group(1).split(",") if part.strip())


def _required_extra(requirement: str) -> str | None:
    """Return the extra a requirement is gated on, or ``None`` if unconditional."""
    marker = requirement.split(";", 1)
    if len(marker) < 2:
        return None
    found = _EXTRA_MARKER.search(marker[1])
    return found.group(1) if found else None


def _direct_dependencies(
    dist: Distribution, extras: frozenset[str]
) -> list[tuple[str, frozenset[str]]]:
    """Return ``(name, requested_extras)`` for requirements active under ``extras``.

    A requirement gated on ``extra == 'E'`` is included only when ``E`` is in
    ``extras`` (the extras active for *this* distribution). The extras returned
    alongside each name are the ones the requirement activates on its target, so
    the caller can widen that target's surface when it recurses into it.
    """
    dependencies: list[tuple[str, frozenset[str]]] = []
    for requirement in dist.requires or ():
        gate = _required_extra(requirement)
        if gate is not None and normalize(gate) not in extras:
            continue  # gated on an extra not active for this distribution
        name = _requirement_name(requirement)
        if name is not None:
            dependencies.append((normalize(name), _requirement_extras(requirement)))
    return dependencies


def _metadata_field(dist: Distribution, field: str) -> str | None:
    """Return one metadata header, tolerating the untyped ``PackageMetadata``."""
    # ``Distribution.metadata`` is an ``email.message.Message`` at runtime, whose
    # ``get`` the typeshed stub does not expose; ``Any`` keeps mypy and ruff happy.
    metadata: Any = dist.metadata
    value = metadata.get(field)
    return value if isinstance(value, str) else None


def _licences(dist: Distribution) -> list[dict[str, dict[str, str]]]:
    """Return CycloneDX licence entries, from metadata or license classifiers."""
    declared = (_metadata_field(dist, "License") or "").strip()
    if declared and declared.upper() not in {"UNKNOWN", "NONE"} and "\n" not in declared:
        return [{"license": {"name": declared}}]
    licences: list[dict[str, dict[str, str]]] = []
    for classifier in dist.metadata.get_all("Classifier") or ():
        if classifier.startswith("License :: "):
            licences.append({"license": {"name": classifier.split(" :: ")[-1].strip()}})
    return licences


def component_for(name: str) -> dict[str, Any] | None:
    """Return the CycloneDX component for an installed distribution, or ``None``."""
    try:
        dist = distribution(name)
    except PackageNotFoundError:
        return None
    canonical = normalize(_metadata_field(dist, "Name") or name)
    version = dist.version
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"pkg:pypi/{canonical}@{version}",
        "name": canonical,
        "version": version,
        "purl": f"pkg:pypi/{canonical}@{version}",
    }
    licences = _licences(dist)
    if licences:
        component["licenses"] = licences
    return component


def dependency_closure(
    root: str = ROOT_DISTRIBUTION, extras: frozenset[str] = frozenset()
) -> list[str]:
    """Return every installed distribution reachable from ``root`` under ``extras``.

    The root is excluded (it is the SBOM's ``metadata.component``, not a
    dependency). The walk tracks which extras are active for each distribution,
    so extras a dependency activates on its own targets (``textual`` →
    ``markdown-it-py[linkify]`` → ``linkify-it-py``) are followed — matching what
    pip actually installs. Uninstalled requirements are simply not traversed.
    """
    root_name = normalize(root)
    # Extras active for each distribution reached so far: the root starts with
    # the explicitly requested extras, a dependency with whatever its requesters
    # asked for via ``dep[extra]``. A package is re-expanded if its active extras
    # grow, so an extra discovered late still pulls that extra's requirements.
    active: dict[str, set[str]] = {}
    pending: list[str] = []

    def _activate(name: str, wanted: frozenset[str]) -> None:
        current = active.get(name)
        if current is None:
            active[name] = set(wanted)
            pending.append(name)
        elif not wanted <= current:
            current |= wanted
            pending.append(name)

    _activate(root_name, frozenset(normalize(extra) for extra in extras))
    seen: set[str] = set()
    order: list[str] = []
    while pending:
        name = pending.pop()
        try:
            dist = distribution(name)
        except PackageNotFoundError:
            continue  # declared but not installed here
        if name != root_name and name not in seen:
            seen.add(name)
            order.append(name)
        for dependency, requested in _direct_dependencies(dist, frozenset(active[name])):
            _activate(dependency, requested)
    return sorted(order)


def render_sbom(
    root: str = ROOT_DISTRIBUTION,
    extras: frozenset[str] = frozenset(),
    *,
    timestamp: str | None = None,
    serial_number: str | None = None,
) -> dict[str, Any]:
    """Return the CycloneDX 1.5 document for ``root`` and the requested extras.

    ``timestamp`` and ``serial_number`` are injected so the document can be made
    reproducible (omit both) or stamped (the CLI supplies real values). The
    component list is sorted, so two runs with the same inputs are identical.
    """
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
    }
    if serial_number is not None:
        document["serialNumber"] = serial_number

    metadata: dict[str, Any] = {}
    if timestamp is not None:
        metadata["timestamp"] = timestamp
    root_component = component_for(root)
    if root_component is not None:
        root_component = dict(root_component)
        root_component["type"] = "application"
        metadata["component"] = root_component
    if extras:
        metadata["properties"] = [
            {"name": "olympus:extra", "value": extra} for extra in sorted(extras)
        ]
    if metadata:
        document["metadata"] = metadata

    components = [
        component
        for name in dependency_closure(root, extras)
        if (component := component_for(name)) is not None
    ]
    document["components"] = components
    return document


def requirements_lines(
    root: str = ROOT_DISTRIBUTION, extras: frozenset[str] = frozenset()
) -> list[str]:
    """Return the runtime closure as pinned ``name==version`` requirement lines.

    This is the scoped input a vulnerability scanner should audit: exactly the
    packages Olympus pulls, at their installed versions, and nothing else — not
    the interpreter's ``pip``/``setuptools``/``wheel`` bootstrap, which belong to
    the environment rather than to Olympus. ``pip-audit -r`` consumes it directly.
    """
    lines: list[str] = []
    for name in dependency_closure(root, extras):
        component = component_for(name)
        if component is not None:
            lines.append(f"{component['name']}=={component['version']}")
    return lines

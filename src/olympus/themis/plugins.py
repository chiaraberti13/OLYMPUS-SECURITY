"""Optional adapter discovery via Python entry points (ROADMAP ``DEV-B``).

A professional installation may ship extra scanner adapters as separate packages.
This module discovers them through the ``olympus.scanner_adapters`` entry-point
group, but **never loads one implicitly**: discovery is *default-deny*. Only a
plugin whose name is on the operator's approved allowlist is imported, and even
then it must prove it is a concrete :class:`~olympus.themis.base.ScannerAdapter`
subclass before it is registered. A present-but-unapproved plugin is reported as
skipped, and an approved-but-invalid one as rejected — never silently dropped and
never silently trusted.

This keeps the supply-chain surface explicit: an attacker who gets a malicious
``olympus.scanner_adapters`` entry point onto the system still cannot make Olympus
execute it without the operator adding its name to the allowlist. Discovery is
offline and side-effect-free apart from importing the approved plugin modules.

Cryptographic *signing* of plugins (as opposed to the name allowlist here) builds
on the release-signing work and is tracked separately in ``ROADMAP.md``.
"""

from __future__ import annotations

import inspect
import os
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points

from olympus.themis.base import ScannerAdapter

#: Entry-point group third-party packages expose a scanner adapter under.
SCANNER_ADAPTER_GROUP = "olympus.scanner_adapters"

#: Environment variable carrying the comma-separated approved plugin names.
PLUGIN_ALLOWLIST_ENV = "OLYMPUS_SCANNER_PLUGIN_ALLOWLIST"

EntryPointLoader = Callable[[], Iterable[EntryPoint]]
_ENTRY_POINT_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class PluginError(RuntimeError):
    """Raised for an unrecoverable plugin-discovery misconfiguration."""


@dataclass(frozen=True)
class PluginMetadata:
    """Distribution provenance reported for one approved adapter."""

    distribution: str
    version: str


@dataclass(frozen=True)
class PluginDiscovery:
    """The outcome of a discovery pass — explicit about every entry point seen."""

    #: Approved, verified concrete adapters, keyed by entry-point name (sorted).
    adapters: dict[str, type[ScannerAdapter]]
    #: Entry points present but not on the allowlist (default-deny, not loaded).
    skipped: tuple[str, ...]
    #: Approved entry points that failed to load or were not valid adapters.
    rejected: tuple[tuple[str, str], ...]
    #: Distribution provenance for approved, concrete adapters.
    metadata: dict[str, PluginMetadata]


def load_plugin_allowlist(env: Mapping[str, str] | None = None) -> frozenset[str]:
    """Return the approved plugin names from the environment (empty = none approved)."""
    source = os.environ if env is None else env
    raw = source.get(PLUGIN_ALLOWLIST_ENV, "")
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


def _default_loader() -> Iterable[EntryPoint]:
    return entry_points(group=SCANNER_ADAPTER_GROUP)


def _safe_metadata(value: object, *, limit: int) -> str:
    """Bound and normalize untrusted distribution metadata before display."""
    candidate = str(value)
    if len(candidate) > limit or re.fullmatch(r"[A-Za-z0-9._+-]+", candidate) is None:
        return "unknown"
    return candidate


def discover_adapters(
    allowlist: frozenset[str],
    *,
    loader: EntryPointLoader | None = None,
    reserved_names: frozenset[str] | None = None,
) -> PluginDiscovery:
    """Discover approved entry-point adapters, default-deny and fully audited.

    Only names in ``allowlist`` are loaded; each must resolve to a concrete
    :class:`ScannerAdapter` subclass or it is rejected with a reason.
    """
    resolve = loader or _default_loader
    if reserved_names is None:
        from olympus.themis.registry import adapter_classes

        reserved_names = frozenset(adapter_classes())
    discovered = list(resolve())
    by_name: dict[str, list[EntryPoint]] = {}
    for item in discovered:
        by_name.setdefault(item.name, []).append(item)
    adapters: dict[str, type[ScannerAdapter]] = {}
    metadata: dict[str, PluginMetadata] = {}
    skipped: list[str] = []
    rejected: list[tuple[str, str]] = []
    for name, entries in sorted(by_name.items()):
        if name not in allowlist:
            skipped.append(name)  # default-deny: never load the unapproved
            continue
        if len(entries) != 1:
            rejected.append((name, "duplicate entry-point name"))
            continue
        if name in reserved_names:
            rejected.append((name, "reserved first-party adapter name"))
            continue
        if _ENTRY_POINT_NAME.fullmatch(name) is None:
            rejected.append((name, "invalid adapter name"))
            continue
        entry_point = entries[0]
        try:
            loaded = entry_point.load()
        except Exception as exc:
            # Importing third-party plugin code can raise anything; one bad plugin
            # must be rejected with a reason, never abort discovery of the rest.
            rejected.append((entry_point.name, f"failed to load ({type(exc).__name__})"))
            continue
        if not inspect.isclass(loaded) or not issubclass(loaded, ScannerAdapter):
            rejected.append((entry_point.name, "not a ScannerAdapter subclass"))
            continue
        if inspect.isabstract(loaded):
            rejected.append((entry_point.name, "abstract base, not a concrete adapter"))
            continue
        if loaded.name != entry_point.name:
            rejected.append((entry_point.name, "adapter name does not match entry-point name"))
            continue
        if (
            not isinstance(loaded.binary, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", loaded.binary) is None
        ):
            rejected.append((entry_point.name, "adapter binary must be a simple executable name"))
            continue
        if loaded.run is not ScannerAdapter.run or loaded.resolve is not ScannerAdapter.resolve:
            rejected.append(
                (entry_point.name, "adapter overrides the scope-safe execution boundary")
            )
            continue
        adapters[entry_point.name] = loaded
        distribution = getattr(entry_point, "dist", None)
        distribution_name = _safe_metadata(getattr(distribution, "name", "unknown"), limit=128)
        distribution_version = _safe_metadata(getattr(distribution, "version", "unknown"), limit=64)
        metadata[entry_point.name] = PluginMetadata(distribution_name, distribution_version)
    return PluginDiscovery(
        dict(sorted(adapters.items())),
        tuple(sorted(skipped)),
        tuple(sorted(rejected)),
        dict(sorted(metadata.items())),
    )


def available_adapters(
    allowlist: frozenset[str] | None = None, *, loader: EntryPointLoader | None = None
) -> dict[str, type[ScannerAdapter]]:
    """Return first-party adapters plus approved plugins (first-party always wins).

    The native registry is authoritative: a plugin may extend the set but can
    never shadow a built-in adapter, so an approved plugin cannot silently
    replace, e.g., the audited ``nmap`` adapter.
    """
    from olympus.themis.registry import adapter_classes

    merged = adapter_classes()
    resolved_allowlist = load_plugin_allowlist() if allowlist is None else allowlist
    for name, adapter in discover_adapters(
        resolved_allowlist, loader=loader, reserved_names=frozenset(merged)
    ).adapters.items():
        merged.setdefault(name, adapter)
    return merged


def resolve_adapter(
    name: str,
    *,
    allowlist: frozenset[str] | None = None,
    loader: EntryPointLoader | None = None,
) -> ScannerAdapter:
    """Instantiate one registered native or explicitly allowlisted plugin adapter."""
    from olympus.themis.registry import UnknownScannerError, adapter_classes, get_adapter

    native = adapter_classes()
    if name in native:
        return get_adapter(name)
    resolved_allowlist = load_plugin_allowlist() if allowlist is None else allowlist
    discovery = discover_adapters(
        resolved_allowlist, loader=loader, reserved_names=frozenset(native)
    )
    adapter_class = discovery.adapters.get(name)
    if adapter_class is None:
        raise UnknownScannerError(
            f"scanner {name!r} is not registered or allowlisted; "
            f"available: {sorted((*native, *discovery.adapters))}"
        )
    try:
        return adapter_class()
    except Exception as exc:
        raise PluginError(f"approved adapter {name!r} could not be constructed") from exc


__all__ = [
    "PLUGIN_ALLOWLIST_ENV",
    "SCANNER_ADAPTER_GROUP",
    "PluginDiscovery",
    "PluginError",
    "PluginMetadata",
    "available_adapters",
    "discover_adapters",
    "load_plugin_allowlist",
    "resolve_adapter",
]

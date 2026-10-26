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

import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points

from olympus.themis.base import ScannerAdapter

#: Entry-point group third-party packages expose a scanner adapter under.
SCANNER_ADAPTER_GROUP = "olympus.scanner_adapters"

#: Environment variable carrying the comma-separated approved plugin names.
PLUGIN_ALLOWLIST_ENV = "OLYMPUS_SCANNER_PLUGIN_ALLOWLIST"

EntryPointLoader = Callable[[], Iterable[EntryPoint]]


class PluginError(RuntimeError):
    """Raised for an unrecoverable plugin-discovery misconfiguration."""


@dataclass(frozen=True)
class PluginDiscovery:
    """The outcome of a discovery pass — explicit about every entry point seen."""

    #: Approved, verified concrete adapters, keyed by entry-point name (sorted).
    adapters: dict[str, type[ScannerAdapter]]
    #: Entry points present but not on the allowlist (default-deny, not loaded).
    skipped: tuple[str, ...]
    #: Approved entry points that failed to load or were not valid adapters.
    rejected: tuple[tuple[str, str], ...]


def load_plugin_allowlist(env: Mapping[str, str] | None = None) -> frozenset[str]:
    """Return the approved plugin names from the environment (empty = none approved)."""
    source = os.environ if env is None else env
    raw = source.get(PLUGIN_ALLOWLIST_ENV, "")
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


def _default_loader() -> Iterable[EntryPoint]:
    return entry_points(group=SCANNER_ADAPTER_GROUP)


def discover_adapters(
    allowlist: frozenset[str], *, loader: EntryPointLoader | None = None
) -> PluginDiscovery:
    """Discover approved entry-point adapters, default-deny and fully audited.

    Only names in ``allowlist`` are loaded; each must resolve to a concrete
    :class:`ScannerAdapter` subclass or it is rejected with a reason.
    """
    resolve = loader or _default_loader
    adapters: dict[str, type[ScannerAdapter]] = {}
    skipped: list[str] = []
    rejected: list[tuple[str, str]] = []
    for entry_point in resolve():
        if entry_point.name not in allowlist:
            skipped.append(entry_point.name)  # default-deny: never load the unapproved
            continue
        try:
            loaded = entry_point.load()
        except Exception as exc:
            # Importing third-party plugin code can raise anything; one bad plugin
            # must be rejected with a reason, never abort discovery of the rest.
            rejected.append((entry_point.name, f"failed to load: {exc}"))
            continue
        if not isinstance(loaded, type) or not issubclass(loaded, ScannerAdapter):
            rejected.append((entry_point.name, "not a ScannerAdapter subclass"))
            continue
        if loaded is ScannerAdapter:
            rejected.append((entry_point.name, "abstract base, not a concrete adapter"))
            continue
        adapters[entry_point.name] = loaded
    return PluginDiscovery(
        dict(sorted(adapters.items())), tuple(sorted(skipped)), tuple(sorted(rejected))
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
    for name, adapter in discover_adapters(resolved_allowlist, loader=loader).adapters.items():
        merged.setdefault(name, adapter)
    return merged


__all__ = [
    "PLUGIN_ALLOWLIST_ENV",
    "SCANNER_ADAPTER_GROUP",
    "PluginDiscovery",
    "PluginError",
    "available_adapters",
    "discover_adapters",
    "load_plugin_allowlist",
]

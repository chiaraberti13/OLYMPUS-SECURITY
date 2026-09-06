"""Registry of AEGIS-native scanner adapters (real execution layer).

Only scanners with a genuine, implemented execution adapter (real command +
real parser) are registered here. The full 24-scanner *catalogue* metadata
lives in :mod:`olympus.integrations.scanners`; this registry is the subset that
Olympus can run and parse natively today. Requesting an unimplemented scanner
returns a clear error, never a fabricated result.
"""

from __future__ import annotations

from olympus.aegis.adapters.arjun import ArjunAdapter
from olympus.aegis.adapters.commix import CommixAdapter
from olympus.aegis.adapters.dalfox import DalfoxAdapter
from olympus.aegis.adapters.dirsearch import DirsearchAdapter
from olympus.aegis.adapters.httpx import HttpxAdapter
from olympus.aegis.adapters.katana import KatanaAdapter
from olympus.aegis.adapters.nikto import NiktoAdapter
from olympus.aegis.adapters.nmap import NmapAdapter
from olympus.aegis.adapters.nuclei import NucleiAdapter
from olympus.aegis.adapters.sqlmap import SqlmapAdapter
from olympus.aegis.adapters.testssl import TestsslAdapter
from olympus.aegis.adapters.wafw00f import Wafw00fAdapter
from olympus.aegis.adapters.whatweb import WhatwebAdapter
from olympus.aegis.base import ScannerAdapter

_ADAPTERS: dict[str, type[ScannerAdapter]] = {
    "nmap": NmapAdapter,
    "nikto": NiktoAdapter,
    "wafw00f": Wafw00fAdapter,
    "sqlmap": SqlmapAdapter,
    "whatweb": WhatwebAdapter,
    "testssl": TestsslAdapter,
    "httpx": HttpxAdapter,
    "nuclei": NucleiAdapter,
    "katana": KatanaAdapter,
    "dalfox": DalfoxAdapter,
    "dirsearch": DirsearchAdapter,
    "commix": CommixAdapter,
    "arjun": ArjunAdapter,
}


class UnknownScannerError(ValueError):
    """Raised when a scanner has no AEGIS-native execution adapter yet."""


def implemented() -> list[str]:
    """Return the sorted names of scanners with a native execution adapter."""
    return sorted(_ADAPTERS)


def get_adapter(name: str) -> ScannerAdapter:
    """Return a fresh adapter instance for ``name``, or raise if unimplemented."""
    factory = _ADAPTERS.get(name)
    if factory is None:
        raise UnknownScannerError(
            f"no native execution adapter for {name!r}; implemented: {implemented()}"
        )
    return factory()

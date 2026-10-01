"""Registry of THEMIS-native scanner adapters (real execution layer).

Only scanners with a genuine, implemented execution adapter (real command +
real parser) are registered here. The full 24-scanner *catalogue* metadata
lives in :mod:`olympus.integrations.scanners`; this registry is the subset that
Olympus can run and parse natively today. Requesting an unimplemented scanner
returns a clear error, never a fabricated result.
"""

from __future__ import annotations

from olympus.themis.adapters.arjun import ArjunAdapter
from olympus.themis.adapters.commix import CommixAdapter
from olympus.themis.adapters.dalfox import DalfoxAdapter
from olympus.themis.adapters.dirsearch import DirsearchAdapter
from olympus.themis.adapters.httpx import HttpxAdapter
from olympus.themis.adapters.katana import KatanaAdapter
from olympus.themis.adapters.nikto import NiktoAdapter
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.adapters.sqlmap import SqlmapAdapter
from olympus.themis.adapters.testssl import TestsslAdapter
from olympus.themis.adapters.wafw00f import Wafw00fAdapter
from olympus.themis.adapters.wapiti import WapitiAdapter
from olympus.themis.adapters.whatweb import WhatwebAdapter
from olympus.themis.adapters.xsstrike import XsstrikeAdapter
from olympus.themis.base import ScannerAdapter

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
    "xsstrike": XsstrikeAdapter,
    "wapiti": WapitiAdapter,
}


class UnknownScannerError(ValueError):
    """Raised when a scanner has no THEMIS-native execution adapter yet."""


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

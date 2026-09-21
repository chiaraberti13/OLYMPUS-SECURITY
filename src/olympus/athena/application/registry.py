"""Closed in-process adapter registry for Athena.

Adapter names in a plan are resolved here against a fixed set of factories.
Unknown names are rejected before an assessment is ever persisted, so a plan
can never reference an adapter that does not exist in this repository.

Adapters fall into two groups, and they must not share one HTTP client:

* *target* adapters connect to the engagement's own hosts, so their transport
  is pinned to the plan's authorized scope; and
* *service* adapters (DoH, RDAP) connect to fixed third-party lookup services
  that are never in the engagement scope, so their transport is pinned to
  exactly those service hosts.

Handing a service adapter the scoped client would break every lookup; handing a
target adapter the service client would let it reach outside the engagement.
"""

from __future__ import annotations

from collections.abc import Callable

from olympus.argus.dns_records import RESOLVER_HOSTS
from olympus.argus.whois import RDAP_HOSTS
from olympus.athena.adapters.aegis_scan import AegisScanAdapter
from olympus.athena.adapters.tools.dns_records import DnsRecordsAdapter
from olympus.athena.adapters.tools.web_headers import WebHeadersAdapter
from olympus.athena.adapters.tools.whois import WhoisAdapter
from olympus.athena.ports import ToolRunner
from olympus.core.http import HttpClient


def _aegis_scan_factory(_http: HttpClient) -> ToolRunner:
    """Build the AEGIS scan step. It ignores the HTTP client: AEGIS scanners run
    as their own scope-gated subprocess engine, not over Athena's HTTP transport."""
    return AegisScanAdapter("nmap")


#: The fixed set of adapter factories, keyed by their stable name.
_FACTORIES: dict[str, Callable[[HttpClient], ToolRunner]] = {
    "web-headers": WebHeadersAdapter,
    "dns": DnsRecordsAdapter,
    "whois": WhoisAdapter,
    "aegis": _aegis_scan_factory,
}

#: Adapters that connect to the engagement's own targets.
_TARGET_ADAPTERS = frozenset({"web-headers", "aegis"})

#: Every host the service adapters are allowed to reach.
SERVICE_HOSTS: tuple[str, ...] = tuple(sorted({*RESOLVER_HOSTS, *RDAP_HOSTS}))


class UnknownAdapterError(ValueError):
    """Raised when a plan references an adapter name outside the registry."""


def available_adapters() -> tuple[str, ...]:
    """Return the sorted names of every registered adapter."""
    return tuple(sorted(_FACTORIES))


def resolve_adapters(
    names: tuple[str, ...],
    http: HttpClient,
    *,
    service_http: HttpClient | None = None,
) -> dict[str, ToolRunner]:
    """Instantiate every named adapter, or raise on the first unknown name.

    ``http`` is the target-scoped transport; ``service_http`` is the one pinned
    to :data:`SERVICE_HOSTS`. It defaults to ``http`` so a caller with a single
    unrestricted client (tests, in-process use) still works.
    """
    unknown = [name for name in names if name not in _FACTORIES]
    if unknown:
        raise UnknownAdapterError(
            f"unknown adapter(s): {sorted(unknown)}; available: {list(available_adapters())}"
        )
    service = service_http if service_http is not None else http
    return {
        name: _FACTORIES[name](http if name in _TARGET_ADAPTERS else service) for name in names
    }

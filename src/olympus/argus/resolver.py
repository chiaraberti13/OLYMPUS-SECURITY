"""DNS resolver abstraction.

Passive recon needs to run against real DNS in production and against
canned, offline data in tests. Every consumer in this module talks to the
:class:`DnsResolver` protocol, never to ``dns.resolver`` directly, so a
:class:`DnspythonResolver` (production) and a fake in-memory resolver
(tests) are interchangeable.
"""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.rdata
import dns.resolver


class DnsResolver(Protocol):
    """Anything able to answer a passive DNS query by record type."""

    def resolve(self, name: str, record_type: str) -> list[str]:
        """Return the text values for ``name``/``record_type``, or ``[]`` if absent."""
        ...


class DnsResolutionError(RuntimeError):
    """Raised when a DNS query fails for a reason other than NXDOMAIN/NoAnswer."""


def _rdata_to_text(rdata: dns.rdata.Rdata, record_type: str) -> str:
    """Render one answer record as a stable, human-readable string."""
    if record_type == "MX":
        exchange = str(rdata.exchange).rstrip(".")  # type: ignore[attr-defined]
        return f"{rdata.preference} {exchange}"  # type: ignore[attr-defined]
    if record_type == "TXT":
        strings: list[bytes] = rdata.strings  # type: ignore[attr-defined]
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(rdata).rstrip(".")


class DnspythonResolver:
    """Production :class:`DnsResolver` backed by ``dnspython``, doing real lookups."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def resolve(self, name: str, record_type: str) -> list[str]:
        """Resolve ``name`` for ``record_type``, returning ``[]`` on NXDOMAIN/NoAnswer."""
        try:
            answer = self._resolver.resolve(name, record_type)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsResolutionError(f"DNS query failed for {name} ({record_type}): {exc}") from exc
        return [_rdata_to_text(rdata, record_type) for rdata in answer]

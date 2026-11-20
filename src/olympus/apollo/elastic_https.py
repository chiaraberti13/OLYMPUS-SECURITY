"""Compatibility entry point for Elasticsearch's IP-literal, single-attempt transport."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from olympus.apollo.dispatch import SiemDestination, SiemProvider
from olympus.apollo.siem_https import SiemHttpsTransport


class ElasticHttpsTransport(SiemHttpsTransport):
    """Deliver to one IP-literal /_bulk endpoint whose certificate covers that IP."""

    def __init__(self, address: IPv4Address | IPv6Address, port: int, *, ca_file: Path) -> None:
        if not isinstance(address, (IPv4Address, IPv6Address)) or not 1 <= port <= 65535:
            raise ValueError("Expected an IP address and a valid TCP port")
        host = f"[{address}]" if isinstance(address, IPv6Address) else str(address)
        super().__init__(
            SiemDestination(SiemProvider.ELASTIC, f"https://{host}:{port}/_bulk", ""),
            address,
            ca_file=ca_file,
        )

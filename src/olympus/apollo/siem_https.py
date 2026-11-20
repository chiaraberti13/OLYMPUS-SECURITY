"""One HTTPS request to an approved SIEM endpoint and a pinned socket address."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Mapping
from http.client import HTTPSConnection
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from urllib.parse import urlsplit

from olympus.apollo.dispatch import (
    MAX_RESPONSE_BYTES,
    SiemDestination,
    SiemProvider,
    SiemResponse,
    validate_endpoint,
)
from olympus.core.execution import ExecutionPolicyError


class SiemHttpsTransport:
    """Use the approved hostname for HTTP and TLS, and only the approved IP for TCP."""

    def __init__(
        self,
        destination: SiemDestination,
        address: IPv4Address | IPv6Address,
        *,
        ca_file: Path | None = None,
    ) -> None:
        validate_endpoint(destination)
        if not isinstance(address, (IPv4Address, IPv6Address)):
            raise ValueError("Expected a pinned IP address")
        url = urlsplit(destination.endpoint)
        if url.hostname is None:
            raise ValueError("Missing SIEM hostname")
        self.endpoint = destination.endpoint
        self._hostname = url.hostname
        self._port = url.port or 443
        self._ip = str(address)
        self._path = url.path
        if destination.provider is SiemProvider.SENTINEL:
            self._path += "?api-version=2023-01-01"
        self._tls = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)

    def post(
        self, endpoint: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> SiemResponse:
        if endpoint != self.endpoint:
            raise ExecutionPolicyError("SIEM destination is outside pinned egress scope")
        conn = HTTPSConnection(self._hostname, self._port, context=self._tls, timeout=timeout)
        try:
            # Supplying the connected TLS socket keeps HTTP Host and SNI independent
            # of the pinned TCP address. No DNS lookup of the destination hostname.
            with socket.create_connection((self._ip, self._port), timeout) as tcp:
                conn.sock = self._tls.wrap_socket(tcp, server_hostname=self._hostname)
                conn.request("POST", self._path, body, dict(headers))
                response = conn.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise ExecutionPolicyError("SIEM response exceeds bounded response limit")
                return SiemResponse(response.status, payload)
        finally:
            conn.close()

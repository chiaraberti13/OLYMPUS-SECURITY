"""Single-attempt Elasticsearch transport pinned to one explicitly approved IP and port."""

from __future__ import annotations

import ssl
from collections.abc import Mapping
from http.client import HTTPSConnection
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from olympus.apollo.dispatch import MAX_RESPONSE_BYTES, SiemResponse
from olympus.core.execution import ExecutionPolicyError


class ElasticHttpsTransport:
    """Deliver to one IP-literal /_bulk endpoint whose certificate covers that IP."""

    def __init__(self, address: IPv4Address | IPv6Address, port: int, *, ca_file: Path) -> None:
        if not isinstance(address, (IPv4Address, IPv6Address)) or not 1 <= port <= 65535:
            raise ValueError("Expected an IP address and a valid TCP port")
        self._ip = str(address)
        self._port = port
        host = f"[{address}]" if isinstance(address, IPv6Address) else self._ip
        self.endpoint = f"https://{host}:{port}/_bulk"
        self._tls = ssl.create_default_context(cafile=str(ca_file))

    def post(
        self, endpoint: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> SiemResponse:
        if endpoint != self.endpoint:
            raise ExecutionPolicyError("Elasticsearch destination is outside pinned egress scope")
        connection = HTTPSConnection(self._ip, self._port, context=self._tls, timeout=timeout)
        try:
            connection.request("POST", "/_bulk", body, dict(headers))
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ExecutionPolicyError("Elasticsearch response exceeds bounded response limit")
            return SiemResponse(response.status, payload)
        finally:
            connection.close()

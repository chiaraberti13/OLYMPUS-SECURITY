"""The Elastic adapter enforces its exact socket destination and one bounded request."""

from ipaddress import IPv4Address
from pathlib import Path
from unittest.mock import patch

import pytest

from olympus.apollo.dispatch import MAX_RESPONSE_BYTES
from olympus.apollo.elastic_https import ElasticHttpsTransport
from olympus.core.execution import ExecutionPolicyError


def test_pinned_delivery_rejects_other_destinations_and_never_follows_redirects() -> None:
    with (
        patch("olympus.apollo.elastic_https.ssl.create_default_context") as tls,
        patch("olympus.apollo.elastic_https.HTTPSConnection") as connect,
    ):
        transport = ElasticHttpsTransport(IPv4Address("127.0.0.1"), 19200, ca_file=Path("ca.pem"))
        tls.assert_called_once_with(cafile="ca.pem")
        with pytest.raises(ExecutionPolicyError, match="scope"):
            transport.post("https://127.0.0.2:19200/_bulk", b"", {}, timeout=2)
        connect.assert_not_called()
        response = connect.return_value.getresponse.return_value
        response.status = 307
        response.read.return_value = b""
        result = transport.post(transport.endpoint, b"batch", {}, timeout=2)
        assert result.status_code == 307
        connect.assert_called_once_with("127.0.0.1", 19200, context=tls.return_value, timeout=2)
        connect.return_value.request.assert_called_once_with("POST", "/_bulk", b"batch", {})
        response.read.assert_called_once_with(MAX_RESPONSE_BYTES + 1)
        connect.return_value.close.assert_called_once()
        response.read.return_value = b"x" * (MAX_RESPONSE_BYTES + 1)
        with pytest.raises(ExecutionPolicyError, match="bounded"):
            transport.post(transport.endpoint, b"batch", {}, timeout=2)
        assert connect.return_value.close.call_count == 2

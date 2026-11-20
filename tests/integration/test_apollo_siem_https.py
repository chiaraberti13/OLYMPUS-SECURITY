"""Contract tests on loopback TLS using the captured Windows batch, without vendor accounts."""

import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from olympus.apollo.dispatch import SiemDestination, SiemProvider, deliver_alerts
from olympus.apollo.ecs import alert_to_ecs
from olympus.apollo.sentinel import alert_to_sentinel
from olympus.apollo.siem_https import SiemHttpsTransport
from olympus.core.execution import ExecutionPolicy, ExecutionPolicyError
from olympus.core.models import Alert


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL CLI required to generate the ephemeral test certificate")
    directory = tmp_path_factory.mktemp("siem-tls")
    pem, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=siem.test",
            "-addext",
            "subjectAltName=DNS:siem.test",
            "-keyout",
            str(key),
            "-out",
            str(pem),
        ],
        check=True,
        capture_output=True,
    )
    return pem, key


@pytest.mark.parametrize("provider", [SiemProvider.SPLUNK, SiemProvider.SENTINEL])
def test_windows_alert_delivery_over_pinned_tls(cert, provider):
    observed = []
    hec = provider is SiemProvider.SPLUNK
    ingest_path = (
        "/services/collector/event"
        if hec
        else "/dataCollectionRules/dcr-abc/streams/Custom-Olympus"
    )
    code = 200 if hec else 204

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            observed.append(
                (self.path, self.headers, self.rfile.read(int(self.headers["Content-Length"])))
            )
            self.send_response(code)
            self.end_headers()
            if hec:
                self.wfile.write(b'{"code":0}')

        def log_message(self, *args):
            pass

    pem, key = cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem, key)
    with HTTPServer(("127.0.0.1", 0), Receiver) as server:
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            destination = SiemDestination(
                provider,
                f"https://siem.test:{server.server_port}{ingest_path}",
                "OLYMPUS_SIEM_TEST",
            )
            transport = SiemHttpsTransport(destination, IPv4Address("127.0.0.1"), ca_file=pem)
            batch = Path(__file__).resolve().parents[2] / "labs/apollo/elasticsearch/alerts.json"
            alerts = [Alert.model_validate(row) for row in json.loads(batch.read_bytes())["alerts"]]
            scopes = []
            options = {
                "policy": ExecutionPolicy(authorized=True, approval_reference="loopback-test"),
                "authorize_endpoint": scopes.append,
                "transport": transport,
                "environ": {"OLYMPUS_SIEM_TEST": "local-only"},
            }
            result = deliver_alerts(alerts, destination, **options)
            assert (result.status_code, result.alert_count) == (code, 3)
            assert scopes == [destination.endpoint]
            [(path, headers, payload)] = observed
            assert path == ingest_path + ("" if hec else "?api-version=2023-01-01")
            assert headers["Host"] == f"siem.test:{server.server_port}"
            assert headers["Authorization"] == ("Splunk " if hec else "Bearer ") + "local-only"
            assert headers["Content-Type"] == "application/json"
            if hec:
                assert [json.loads(line)["event"] for line in payload.splitlines()] == [
                    alert_to_ecs(a) for a in alerts
                ]
            else:
                assert json.loads(payload) == [alert_to_sentinel(a) for a in alerts]
            # The address stays in scope, but the certificate is valid only for siem.test.
            wrong_name = SiemDestination(
                provider,
                destination.endpoint.replace("siem.test", "wrong.test"),
                "OLYMPUS_SIEM_TEST",
            )
            with pytest.raises(ssl.SSLCertVerificationError):
                SiemHttpsTransport(wrong_name, IPv4Address("127.0.0.1"), ca_file=pem).post(
                    wrong_name.endpoint, b"", {}, timeout=2
                )
            assert len(observed) == 1
            code = 307
            with pytest.raises(ExecutionPolicyError, match="HTTP status"):
                deliver_alerts(alerts, destination, **options)
            assert len(observed) == 2
        finally:
            server.shutdown()
            thread.join()

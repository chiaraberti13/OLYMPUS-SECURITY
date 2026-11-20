"""Send the verified BLUE-1 alerts to the disposable node and read back every ECS field."""

import base64
import hashlib
import json
import os
import ssl
import sys
from collections.abc import Mapping
from http.client import HTTPSConnection
from ipaddress import IPv4Address
from pathlib import Path

from olympus.apollo.dispatch import SiemDestination, SiemProvider, SiemResponse, deliver_alerts
from olympus.apollo.ecs import alert_to_ecs
from olympus.apollo.elastic_https import ElasticHttpsTransport
from olympus.core.execution import ExecutionPolicy, ExecutionPolicyError
from olympus.core.models import Alert

INDEX = "olympus-blue2"
IP = "127.0.0.1"
PORT = 19200
ENDPOINT = f"https://{IP}:{PORT}/_bulk"


def authorize(endpoint: str) -> None:
    if endpoint != ENDPOINT:
        raise ExecutionPolicyError("Destination outside this loopback lab")


class LabTransport(ElasticHttpsTransport):
    """Keep just the item receipts from the actual server response."""

    receipts: dict[str, int]

    def post(
        self, endpoint: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> SiemResponse:
        response = super().post(endpoint, body, headers, timeout=timeout)
        items = [item["create"] for item in json.loads(response.body)["items"]]
        self.receipts = {item["_id"]: item["status"] for item in items}
        return response


def main() -> None:
    ca_file = Path(sys.argv[1])
    tls = ssl.create_default_context(cafile=str(ca_file))
    password = os.environ["BLUE2_BOOTSTRAP_PASSWORD"]
    basic = base64.b64encode(f"elastic:{password}".encode()).decode()

    def admin(method: str, path: str, data: object = None) -> dict:
        conn = HTTPSConnection(IP, PORT, context=tls, timeout=20)
        try:
            conn.request(
                method,
                path,
                None if data is None else json.dumps(data).encode(),
                {"Authorization": f"Basic {basic}", "Content-Type": "application/json"},
            )
            response = conn.getresponse()
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Lab setup/read-back failed: {method} {path} {response.status}")
            return json.loads(response.read())
        finally:
            conn.close()

    fixture = Path(__file__).with_name("alerts.json").read_bytes()
    if (
        hashlib.sha256(fixture).hexdigest()
        != "7784ab3ec24a8daca53bc91c979ae36f0440caf1e22f065d546eb1b6afa2cd03"
    ):
        raise RuntimeError("BLUE-1 alert fixture has changed")
    alerts = [Alert.model_validate(a) for a in json.loads(fixture)["alerts"]]
    expected = {a.alert_id: alert_to_ecs(a) for a in alerts}
    version = admin("GET", "/")["version"]["number"]
    # Pre-map identifiers so the create-only key needs no mapping privileges.
    keyword = {"type": "keyword"}
    admin(
        "PUT",
        f"/{INDEX}",
        {
            "settings": {"number_of_replicas": 0},
            "mappings": {
                "dynamic": False,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event": {"properties": {"id": keyword}},
                    "rule": {"properties": {"id": keyword}},
                    "olympus": {"properties": {"event_id": keyword}},
                },
            },
        },
    )
    key = admin(
        "POST",
        "/_security/api_key",
        {
            "name": "blue2-create-only",
            "expiration": "15m",
            "role_descriptors": {
                "writer": {"indices": [{"names": [INDEX], "privileges": ["create_doc"]}]}
            },
        },
    )
    transport = LabTransport(IPv4Address(IP), PORT, ca_file=ca_file)
    destination = SiemDestination(SiemProvider.ELASTIC, ENDPOINT, "OLYMPUS_SIEM_LAB", INDEX)

    def send():
        return deliver_alerts(
            alerts,
            destination,
            policy=ExecutionPolicy(authorized=True, approval_reference="BLUE-2-loopback-lab"),
            authorize_endpoint=authorize,
            transport=transport,
            environ={"OLYMPUS_SIEM_LAB": key["encoded"]},
        )

    first = send()
    if transport.receipts != dict.fromkeys(expected, 201):
        raise RuntimeError("Expected three create receipts with status 201")
    try:
        send()
    except ExecutionPolicyError as exc:
        if "bulk response" not in str(exc) or transport.receipts != dict.fromkeys(expected, 409):
            raise
    else:
        raise RuntimeError("Duplicate batch unexpectedly accepted")
    docs = admin("POST", f"/{INDEX}/_mget", {"ids": list(expected)})["docs"]
    actual = {d["_id"]: d["_source"] for d in docs if d["found"] and d["_index"] == INDEX}
    admin("POST", f"/{INDEX}/_refresh")
    count = admin("GET", f"/{INDEX}/_count")["count"]
    if actual != expected or count != 3:
        raise RuntimeError("Read-back differs from the three original alerts")
    print(
        json.dumps(
            {
                "elasticsearch": version,
                "http_status": first.status_code,
                "count": count,
                "ids": sorted(actual),
                "duplicate_batch_rejected": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

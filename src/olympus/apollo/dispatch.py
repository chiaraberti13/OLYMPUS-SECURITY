"""Authorization-gated, transport-injected SIEM delivery boundary (BLUE-2).

No HTTP client is provided. A caller must inject a transport after verifying
the engagement's approved egress destination; offline tests inject a fake.
This layer never logs tokens, request bodies or raw SIEM responses.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import urlsplit

from olympus.apollo.elastic import DEFAULT_ELASTIC_INDEX, alerts_to_elastic_bulk
from olympus.apollo.hec import alerts_to_hec
from olympus.apollo.sentinel import alerts_to_sentinel_json
from olympus.core.execution import ExecutionPolicy, ExecutionPolicyError
from olympus.core.models import Alert

MAX_DELIVERY_BYTES = 8_000_000
MAX_RESPONSE_BYTES = 65_536
_ENV_NAME = re.compile(r"OLYMPUS_SIEM_[A-Z0-9_]{1,80}\Z")


class SiemProvider(Enum):
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"


@dataclass(frozen=True)
class SiemResponse:
    status_code: int
    body: bytes = b""


class SiemTransport(Protocol):
    """Injected, single-attempt HTTP adapter. No redirects or retries allowed."""

    def post(
        self, endpoint: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> SiemResponse: ...


@dataclass(frozen=True)
class SiemDestination:
    provider: SiemProvider
    endpoint: str
    credential_env: str
    elastic_index: str = DEFAULT_ELASTIC_INDEX


@dataclass(frozen=True)
class SiemDeliveryResult:
    provider: SiemProvider
    status_code: int
    alert_count: int
    bytes_sent: int


def _validate_endpoint(destination: SiemDestination) -> None:
    raw = destination.endpoint
    if any(ord(char) <= 32 or ord(char) == 127 for char in raw):
        raise ExecutionPolicyError("SIEM endpoint contains forbidden characters")
    try:
        url = urlsplit(raw)
        hostname = url.hostname
        port = url.port
    except ValueError as exc:
        raise ExecutionPolicyError("SIEM endpoint has an invalid URL authority") from exc
    if (
        url.scheme != "https"
        or not hostname
        or not url.netloc
        or url.username is not None
        or url.password is not None
        or url.fragment
        or url.query
        or port == 0
    ):
        raise ExecutionPolicyError(
            "SIEM endpoint must be an HTTPS URL without credentials, query or fragment"
        )
    if destination.provider is SiemProvider.SPLUNK and url.path != "/services/collector/event":
        raise ExecutionPolicyError("Splunk destination must use /services/collector/event")
    if destination.provider is SiemProvider.ELASTIC and url.path != "/_bulk":
        raise ExecutionPolicyError("Elasticsearch destination must use /_bulk")
    if destination.provider is SiemProvider.SENTINEL and not re.fullmatch(
        r"/dataCollectionRules/[^/]+/streams/[^/]+", url.path
    ):
        raise ExecutionPolicyError("Sentinel destination must identify a DCR and stream")


def deliver_alerts(
    alerts: Sequence[Alert],
    destination: SiemDestination,
    *,
    policy: ExecutionPolicy,
    authorize_endpoint: Callable[[str], object],
    transport: SiemTransport,
    environ: Mapping[str, str] | None = None,
) -> SiemDeliveryResult:
    """Dispatch one bounded, explicitly authorized SIEM batch through a port.

    The supplied authorization callback must validate the destination against
    the signed engagement's approved egress scope; the callback is mandatory.
    Authentication comes only from an OLYMPUS_SIEM_* environment variable.
    Provider-specific rejection (including Elastic partial bulk errors) fails.
    """
    policy.require_authorization("SIEM delivery")
    if not policy.approval_reference:
        raise ExecutionPolicyError("SIEM delivery requires an approval reference")
    _validate_endpoint(destination)
    policy.authorize_target("SIEM delivery", destination.endpoint, authorize_endpoint)
    if not _ENV_NAME.fullmatch(destination.credential_env):
        raise ExecutionPolicyError("credential_env must name an OLYMPUS_SIEM_* variable")
    secret = (os.environ if environ is None else environ).get(destination.credential_env)
    if not secret or any(c in secret for c in "\r\n"):
        raise ExecutionPolicyError("SIEM credential is missing or invalid")
    if not alerts:
        raise ExecutionPolicyError("refusing to deliver an empty SIEM batch")
    if destination.provider is SiemProvider.SPLUNK:
        payload = alerts_to_hec(alerts)
        auth = "Splunk " + secret
        content_type = "application/json"
    elif destination.provider is SiemProvider.ELASTIC:
        payload = alerts_to_elastic_bulk(alerts, index=destination.elastic_index)
        auth = "ApiKey " + secret
        content_type = "application/x-ndjson"
    elif destination.provider is SiemProvider.SENTINEL:
        payload = alerts_to_sentinel_json(alerts)
        auth = "Bearer " + secret
        content_type = "application/json"
    else:
        raise ExecutionPolicyError("unsupported SIEM provider")
    body = payload.encode("utf-8")
    if len(body) > MAX_DELIVERY_BYTES:
        raise ExecutionPolicyError("SIEM batch exceeds the bounded delivery limit")
    response = transport.post(
        destination.endpoint,
        body,
        {"Authorization": auth, "Content-Type": content_type},
        timeout=policy.timeout_seconds,
    )
    if not 200 <= response.status_code < 300:
        raise ExecutionPolicyError("SIEM destination rejected delivery (HTTP status not successful)")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise ExecutionPolicyError("SIEM response exceeds bounded response limit")
    if destination.provider is SiemProvider.ELASTIC:
        try:
            parsed = json.loads(response.body)
            if not isinstance(parsed, dict) or parsed.get("errors") is not False:
                raise ValueError("partial or malformed response")
        except (ValueError, UnicodeError) as exc:
            raise ExecutionPolicyError(
                "Elasticsearch bulk response is incomplete or contains errors"
            ) from exc
    elif destination.provider is SiemProvider.SPLUNK:
        try:
            parsed = json.loads(response.body)
            if not isinstance(parsed, dict) or parsed.get("code") != 0:
                raise ValueError("non-successful HEC response")
        except (ValueError, UnicodeError) as exc:
            raise ExecutionPolicyError("Splunk HEC response is incomplete or unsuccessful") from exc
    return SiemDeliveryResult(
        destination.provider, response.status_code, len(alerts), len(body)
    )

"""Offline contract tests for injected SIEM transport and authorization (BLUE-2)."""

from __future__ import annotations

import json

import pytest

from olympus.apollo.dispatch import (
    SiemDestination,
    SiemProvider,
    SiemResponse,
    deliver_alerts,
)
from olympus.core.enums import Severity, Source
from olympus.core.execution import (
    AuthorizationRequiredError,
    ExecutionPolicy,
    ExecutionPolicyError,
)
from olympus.core.models import Alert


class FakeTransport:
    def __init__(self, response: SiemResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, bytes, dict[str, str], float]] = []

    def post(
        self, endpoint: str, body: bytes, headers: dict[str, str], *, timeout: float
    ) -> SiemResponse:
        self.calls.append((endpoint, body, dict(headers), timeout))
        return self.response


DESTINATIONS = [
    (
        SiemProvider.SPLUNK,
        "https://siem.example/services/collector/event",
        SiemResponse(200, b'{"code":0}'),
    ),
    (
        SiemProvider.ELASTIC,
        "https://siem.example/_bulk",
        SiemResponse(200, b'{"errors":false}'),
    ),
    (
        SiemProvider.SENTINEL,
        "https://siem.example/dataCollectionRules/dcr/streams/Custom-Olympus",
        SiemResponse(204),
    ),
]


def _alert() -> Alert:
    return Alert(event_id="EVT-1", title="Example", source=Source.APOLLO, severity=Severity.HIGH)


def _policy(*, authorized: bool = True) -> ExecutionPolicy:
    return ExecutionPolicy(authorized=authorized, approval_reference="LAB-APPROVED")


@pytest.mark.parametrize(("provider", "url", "response"), DESTINATIONS)
def test_delivery_uses_injected_port_and_env_only(provider: SiemProvider, url: str, response: SiemResponse) -> None:
    transport = FakeTransport(response)
    seen: list[str] = []
    result = deliver_alerts(
        [_alert()],
        SiemDestination(provider, url, "OLYMPUS_SIEM_TEST"),
        policy=_policy(),
        authorize_endpoint=seen.append,
        transport=transport,
        environ={"OLYMPUS_SIEM_TEST": "fake-secret"},
    )
    assert seen == [url]
    assert len(transport.calls) == 1
    endpoint, body, headers, timeout = transport.calls[0]
    assert endpoint == url
    assert b"fake-secret" not in body
    assert headers["Authorization"].endswith("fake-secret")
    assert timeout == _policy().timeout_seconds
    assert result.alert_count == 1
    assert result.bytes_sent == len(body)
    assert result.status_code == response.status_code
    if provider is SiemProvider.SENTINEL:
        assert isinstance(json.loads(body), list)
    elif provider is SiemProvider.ELASTIC:
        assert body.endswith(b"\n") and len(body.splitlines()) == 2


def test_fail_closed_before_transport_without_authorization() -> None:
    transport = FakeTransport(SiemResponse(200, b'{"code":0}'))
    with pytest.raises(AuthorizationRequiredError):
        deliver_alerts(
            [_alert()], SiemDestination(SiemProvider.SPLUNK, DESTINATIONS[0][1], "OLYMPUS_SIEM_TEST"),
            policy=_policy(authorized=False), authorize_endpoint=lambda _: None,
            transport=transport, environ={"OLYMPUS_SIEM_TEST": "secret"},
        )
    assert not transport.calls


@pytest.mark.parametrize("url", [
    "http://siem.example/_bulk",
    "https://user:pass@siem.example/_bulk",
    "https://siem.example/_bulk?token=secret",
    "https://siem.example/other",
    "https://siem.example/_bulk#fragment",
    "https://siem.example:invalid/_bulk",
    "https://[broken/_bulk",
])
def test_invalid_endpoints_do_not_reach_transport(url: str) -> None:
    transport = FakeTransport(SiemResponse(200, b'{"errors":false}'))
    with pytest.raises(ExecutionPolicyError):
        deliver_alerts(
            [_alert()], SiemDestination(SiemProvider.ELASTIC, url, "OLYMPUS_SIEM_TEST"),
            policy=_policy(), authorize_endpoint=lambda _: None, transport=transport,
            environ={"OLYMPUS_SIEM_TEST": "secret"},
        )
    assert not transport.calls


def test_scope_denial_prevents_delivery() -> None:
    transport = FakeTransport(SiemResponse(204))
    def deny(_: str) -> None:
        raise AuthorizationRequiredError("out of scope")
    with pytest.raises(AuthorizationRequiredError):
        deliver_alerts(
            [_alert()], SiemDestination(SiemProvider.SENTINEL, DESTINATIONS[2][1], "OLYMPUS_SIEM_TEST"),
            policy=_policy(), authorize_endpoint=deny, transport=transport,
            environ={"OLYMPUS_SIEM_TEST": "secret"},
        )
    assert not transport.calls


@pytest.mark.parametrize("response", [
    SiemResponse(403, b"unauthorized secret"),
    SiemResponse(200, b'{"errors":true}'),
    SiemResponse(200, b"not json"),
])
def test_elastic_failure_or_partial_bulk_cannot_be_reported_as_success(response: SiemResponse) -> None:
    transport = FakeTransport(response)
    with pytest.raises(ExecutionPolicyError, match="SIEM destination|Elasticsearch bulk"):
        deliver_alerts(
            [_alert()], SiemDestination(SiemProvider.ELASTIC, DESTINATIONS[1][1], "OLYMPUS_SIEM_TEST"),
            policy=_policy(), authorize_endpoint=lambda _: None, transport=transport,
            environ={"OLYMPUS_SIEM_TEST": "secret"},
        )


def test_missing_credential_and_empty_batch_fail_closed() -> None:
    transport = FakeTransport(SiemResponse(200, b'{"code":0}'))
    base = dict(
        destination=SiemDestination(SiemProvider.SPLUNK, DESTINATIONS[0][1], "OLYMPUS_SIEM_TEST"),
        policy=_policy(), authorize_endpoint=lambda _: None, transport=transport,
    )
    with pytest.raises(ExecutionPolicyError, match="credential"):
        deliver_alerts([_alert()], environ={}, **base)
    with pytest.raises(ExecutionPolicyError, match="empty"):
        deliver_alerts([], environ={"OLYMPUS_SIEM_TEST": "secret"}, **base)
    assert not transport.calls

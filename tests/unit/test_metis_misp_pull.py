"""Live MISP event pulling, exercised entirely offline (BLUE-3).

The network edge is a :class:`~olympus.metis.misp_pull.MispTransport` ``Protocol``,
so these tests drive the whole pull — pagination, the incremental ``timestamp``
cursor, the event/page bounds, the fail-closed auth header and the egress guard
— against a canned in-memory server, with no sockets. The MISP normalization is
the already-tested offline core; here we prove the *pull* around it is correct
and safe. It mirrors ``test_metis_taxii.py``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from olympus.metis.misp_pull import (
    MAX_MISP_ATTRIBUTES,
    MAX_MISP_EVENTS,
    MispConfigError,
    MispPullError,
    MispResponse,
    MispServer,
    PinnedMispTransport,
    pull_events,
)
from olympus.metis.models import IndicatorType

pytestmark = pytest.mark.unit

# The API-key *env var name*, not a secret.
TOKEN_ENV = "OLYMPUS_MISP_KEY"  # noqa: S105 - an env var name, not a credential


# --- a canned, socket-free MISP server -------------------------------------- #


class FakeTransport:
    """Serve queued responses and record every request made."""

    def __init__(self, responses: list[MispResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

    def post(
        self, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> MispResponse:
        self.requests.append((url, json.loads(body.decode("utf-8")), dict(headers)))
        if not self._responses:  # pragma: no cover - a test queued too few pages
            raise AssertionError("FakeTransport ran out of queued responses")
        return self._responses.pop(0)


def _attr(misp_type: str, value: str) -> dict[str, object]:
    return {"type": misp_type, "value": value, "to_ids": True}


def _event(
    attributes: list[dict[str, object]], *, timestamp: str | None = None
) -> dict[str, object]:
    body: dict[str, object] = {"info": "evt", "Attribute": attributes}
    if timestamp is not None:
        body["timestamp"] = timestamp
    return {"Event": body}


def _response(events: list[dict[str, object]], *, status: int = 200) -> MispResponse:
    return MispResponse(status, json.dumps({"response": events}).encode("utf-8"), {})


def _server() -> MispServer:
    return MispServer(base_url="https://misp.example", token_env=TOKEN_ENV)


# --- server configuration --------------------------------------------------- #


def test_server_requires_https_and_token_env() -> None:
    with pytest.raises(MispConfigError, match="https"):
        MispServer(base_url="http://misp.example", token_env=TOKEN_ENV)
    with pytest.raises(MispConfigError, match="query or fragment"):
        MispServer(base_url="https://misp.example/?x=1", token_env=TOKEN_ENV)
    with pytest.raises(MispConfigError, match="token_env"):
        MispServer(base_url="https://misp.example", token_env="   ")  # noqa: S106 - blank, not a key


def test_server_url_and_label_carry_no_secret() -> None:
    server = MispServer(base_url="https://misp.example/", token_env=TOKEN_ENV)
    assert server.search_url == "https://misp.example/events/restSearch"
    assert server.source_label == "misp://misp.example"


def test_auth_header_is_fail_closed_and_uses_raw_key() -> None:
    server = _server()
    with pytest.raises(MispConfigError, match="is not set"):
        server.auth_headers(environ={})
    headers = server.auth_headers(environ={TOKEN_ENV: "k3y"})
    # MISP uses the raw key in Authorization, with no "Bearer" prefix.
    assert headers["Authorization"] == "k3y"
    assert headers["Accept"] == "application/json"
    assert headers["Content-Type"] == "application/json"


# --- pulling: normalization, pagination, incremental cursor ----------------- #


def test_single_page_normalizes_attributes_to_iocs() -> None:
    events = [
        _event(
            [
                _attr("domain", "evil.tld"),
                _attr("ip-dst", "203.0.113.7"),
                _attr("vulnerability", "CVE-2024-1234"),
                _attr("comment", "not an ioc"),
            ],
            timestamp="1700000000",
        )
    ]
    transport = FakeTransport([_response(events)])
    pull = pull_events(transport, _server(), environ={TOKEN_ENV: "k"})

    kinds = {(i.indicator_type, i.value) for i in pull.result.indicators}
    assert (IndicatorType.DOMAIN, "evil.tld") in kinds
    assert (IndicatorType.IPV4, "203.0.113.7") in kinds
    assert (IndicatorType.CVE, "CVE-2024-1234") in kinds
    assert pull.indicator_count == 3
    assert len(pull.result.skipped) == 1  # the 'comment' attribute is unmapped
    assert pull.events_fetched == 1
    assert pull.pages_fetched == 1
    # Cursor advances past the newest event timestamp seen.
    assert pull.next_since == "1700000001"
    assert pull.more_available is False
    assert pull.source == "misp://misp.example"


def test_pagination_pages_until_short_page() -> None:
    full = [_event([_attr("domain", f"d{n}.tld")], timestamp=str(1700000000 + n)) for n in range(2)]
    page1 = _response(full)  # exactly page_limit -> keep paging
    page2 = _response(
        [_event([_attr("domain", "last.tld")], timestamp="1700000100")]
    )  # short -> stop
    transport = FakeTransport([page1, page2])
    pull = pull_events(transport, _server(), page_limit=2, environ={TOKEN_ENV: "k"})

    assert pull.pages_fetched == 2
    assert pull.events_fetched == 3
    assert {i.value for i in pull.result.indicators} == {"d0.tld", "d1.tld", "last.tld"}
    assert transport.requests[1][1]["page"] == 2
    assert pull.next_since == "1700000101"
    assert pull.more_available is False


def test_since_tags_and_published_reach_the_request() -> None:
    transport = FakeTransport([_response([])])
    pull_events(
        transport,
        _server(),
        since="1d",
        tags=["tlp:white", "apt"],
        published_only=True,
        environ={TOKEN_ENV: "k"},
    )
    body = transport.requests[0][1]
    assert body["timestamp"] == "1d"
    assert body["tags"] == ["tlp:white", "apt"]
    assert body["published"] is True
    assert body["returnFormat"] == "json"


def test_event_bound_truncates_and_flags_more() -> None:
    events = [
        _event([_attr("domain", f"h{n}.tld")], timestamp=str(1700000000 + n)) for n in range(5)
    ]
    transport = FakeTransport([_response(events)])
    pull = pull_events(transport, _server(), max_events=2, page_limit=5, environ={TOKEN_ENV: "k"})
    assert pull.events_fetched == 2
    assert pull.more_available is True
    assert pull.pages_fetched == 1


def test_page_bound_stops_runaway_pagination() -> None:
    # Every page is full (== page_limit), so the loop must stop at max_pages.
    pages = [_response([_event([_attr("domain", f"p{n}.tld")])]) for n in range(5)]
    transport = FakeTransport(pages)
    pull = pull_events(transport, _server(), page_limit=1, max_pages=3, environ={TOKEN_ENV: "k"})
    assert pull.pages_fetched == 3
    assert pull.more_available is True


def test_auth_header_reaches_the_transport() -> None:
    transport = FakeTransport([_response([])])
    pull_events(transport, _server(), environ={TOKEN_ENV: "unit-key"})
    assert transport.requests[0][2]["Authorization"] == "unit-key"


# --- protocol and transport failures ---------------------------------------- #


@pytest.mark.parametrize("status", [401, 403])
def test_authorization_refusal_raises(status: int) -> None:
    transport = FakeTransport([MispResponse(status, b"{}", {})])
    with pytest.raises(MispPullError, match="refused authorization"):
        pull_events(transport, _server(), environ={TOKEN_ENV: "k"})


def test_server_error_status_raises() -> None:
    transport = FakeTransport([MispResponse(500, b"oops", {})])
    with pytest.raises(MispPullError, match="HTTP 500"):
        pull_events(transport, _server(), environ={TOKEN_ENV: "k"})


def test_invalid_json_and_shape_raise() -> None:
    bad_json = FakeTransport([MispResponse(200, b"not json", {})])
    with pytest.raises(MispPullError, match="not valid JSON"):
        pull_events(bad_json, _server(), environ={TOKEN_ENV: "k"})

    bad_shape = FakeTransport([MispResponse(200, json.dumps({"response": {}}).encode(), {})])
    with pytest.raises(MispPullError, match="not an array"):
        pull_events(bad_shape, _server(), environ={TOKEN_ENV: "k"})


def test_bounds_are_validated() -> None:
    server = _server()
    transport = FakeTransport([_response([])])
    for kwargs in (
        {"page_limit": 0},
        {"max_events": MAX_MISP_EVENTS + 1},
        {"max_pages": 0},
        {"timeout": 0.0},
    ):
        with pytest.raises(MispConfigError):
            pull_events(transport, server, environ={TOKEN_ENV: "k"}, **kwargs)  # type: ignore[arg-type]


def test_merged_attribute_count_is_bounded() -> None:
    # One event with more attributes than the cap must be refused, not normalized.
    attrs = [_attr("domain", f"d{n}.tld") for n in range(MAX_MISP_ATTRIBUTES + 1)]
    transport = FakeTransport([_response([_event(attrs)])])
    with pytest.raises(MispPullError, match="attribute count exceeds"):
        pull_events(transport, _server(), environ={TOKEN_ENV: "k"})


def test_pinned_transport_refuses_non_https() -> None:
    transport = PinnedMispTransport()
    with pytest.raises(MispPullError, match="only speaks https"):
        transport.post("http://misp.example/x", b"{}", {}, timeout=1.0)

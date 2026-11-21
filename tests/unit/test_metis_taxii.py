"""Live TAXII 2.1 polling, exercised entirely offline (BLUE-3).

The network edge is a :class:`~olympus.metis.taxii.TaxiiTransport` ``Protocol``,
so these tests drive the whole poll — pagination, the incremental ``added_after``
cursor, the object/page bounds, the fail-closed auth header and the egress guard
— against a canned in-memory server, with no sockets. The STIX normalization is
the already-tested offline core; here we prove the *fetch* around it is correct
and safe.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from olympus.metis.models import IndicatorType
from olympus.metis.taxii import (
    MAX_TAXII_OBJECTS,
    PinnedTaxiiTransport,
    TaxiiCollection,
    TaxiiConfigError,
    TaxiiError,
    TaxiiResponse,
    poll_collection,
)

pytestmark = pytest.mark.unit


# --- a canned, socket-free TAXII server ------------------------------------ #


class FakeTransport:
    """Serve queued responses and record every request made."""

    def __init__(self, responses: list[TaxiiResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, headers: Mapping[str, str], *, timeout: float) -> TaxiiResponse:
        self.requests.append((url, dict(headers)))
        if not self._responses:  # pragma: no cover - a test queued too few pages
            raise AssertionError("FakeTransport ran out of queued responses")
        return self._responses.pop(0)


def _indicator_obj(pattern: str) -> dict[str, object]:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{abs(hash(pattern)) % (10**8):08d}-0000-0000-0000-000000000000",
        "pattern": pattern,
        "pattern_type": "stix",
    }


def _envelope(
    objects: list[dict[str, object]],
    *,
    more: bool = False,
    next_cursor: str | None = None,
    date_added_last: str | None = None,
    status: int = 200,
) -> TaxiiResponse:
    body: dict[str, object] = {"objects": objects, "more": more}
    if next_cursor is not None:
        body["next"] = next_cursor
    headers = {"Content-Type": "application/taxii+json;version=2.1"}
    if date_added_last is not None:
        headers["X-TAXII-Date-Added-Last"] = date_added_last
    return TaxiiResponse(status, json.dumps(body).encode("utf-8"), headers)


# The token *env var name*, not a secret — it names where the token would live.
TOKEN_ENV = "OLYMPUS_TAXII_TOKEN"  # noqa: S105 - an env var name, not a credential


def _collection(token_env: str | None = None) -> TaxiiCollection:
    return TaxiiCollection(
        api_root_url="https://feed.example/taxii2/api1",
        collection_id="91a7b528-80eb-42ed",
        token_env=token_env,
    )


# --- collection configuration ---------------------------------------------- #


def test_collection_requires_https_and_wellformed_id() -> None:
    with pytest.raises(TaxiiConfigError, match="https"):
        TaxiiCollection(api_root_url="http://feed.example/api1", collection_id="abc")
    with pytest.raises(TaxiiConfigError, match="character"):
        TaxiiCollection(api_root_url="https://feed.example/api1", collection_id="../secret")
    with pytest.raises(TaxiiConfigError, match="query or fragment"):
        TaxiiCollection(api_root_url="https://feed.example/api1?x=1", collection_id="abc")


def test_collection_urls_and_label_carry_no_secret() -> None:
    collection = TaxiiCollection(
        api_root_url="https://feed.example/taxii2/api1/",
        collection_id="col-1",
        token_env=TOKEN_ENV,
    )
    assert collection.objects_url == "https://feed.example/taxii2/api1/collections/col-1/objects/"
    assert collection.source_label == "taxii://feed.example/col-1"


def test_auth_header_is_fail_closed_on_missing_token() -> None:
    collection = _collection(token_env=TOKEN_ENV)
    with pytest.raises(TaxiiConfigError, match="is not set"):
        collection.auth_headers(environ={})
    headers = collection.auth_headers(environ={TOKEN_ENV: "s3cr3t"})
    assert headers == {"Authorization": "Bearer s3cr3t"}
    # No token_env configured: anonymous, no header.
    assert _collection().auth_headers(environ={}) == {}


# --- polling: normalization, pagination, incremental cursor ---------------- #


def test_single_page_normalizes_stix_to_iocs() -> None:
    objects = [
        _indicator_obj("[domain-name:value = 'evil.tld']"),
        _indicator_obj("[ipv4-addr:value = '203.0.113.7']"),
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": "vulnerability--x",
            "name": "CVE-2024-1234",
        },
        _indicator_obj("[domain-name:value = 'a.tld' OR domain-name:value = 'b.tld']"),
    ]
    transport = FakeTransport([_envelope(objects, date_added_last="2026-11-21T10:00:00Z")])
    poll = poll_collection(transport, _collection())

    kinds = {(i.indicator_type, i.value) for i in poll.result.indicators}
    assert (IndicatorType.DOMAIN, "evil.tld") in kinds
    assert (IndicatorType.IPV4, "203.0.113.7") in kinds
    assert (IndicatorType.CVE, "CVE-2024-1234") in kinds
    # The compound pattern is skipped, never mangled into a wrong IOC.
    assert poll.indicator_count == 3
    assert len(poll.result.skipped) == 1
    assert poll.objects_fetched == 4
    assert poll.pages_fetched == 1
    assert poll.next_added_after == "2026-11-21T10:00:00Z"
    assert poll.more_available is False
    assert poll.source == "taxii://feed.example/91a7b528-80eb-42ed"


def test_pagination_follows_next_and_accumulates() -> None:
    page1 = _envelope(
        [_indicator_obj("[domain-name:value = 'one.tld']")],
        more=True,
        next_cursor="CURSOR-2",
        date_added_last="2026-11-21T09:00:00Z",
    )
    page2 = _envelope(
        [_indicator_obj("[domain-name:value = 'two.tld']")],
        more=False,
        date_added_last="2026-11-21T09:05:00Z",
    )
    transport = FakeTransport([page1, page2])
    poll = poll_collection(transport, _collection(), page_limit=1)

    assert poll.pages_fetched == 2
    assert poll.objects_fetched == 2
    assert {i.value for i in poll.result.indicators} == {"one.tld", "two.tld"}
    # The second request carried the server's pagination cursor.
    assert "next=CURSOR-2" in transport.requests[1][0]
    # The cursor advances to the last page's date-added.
    assert poll.next_added_after == "2026-11-21T09:05:00Z"
    assert poll.more_available is False


def test_added_after_is_sent_and_defaults_forward() -> None:
    transport = FakeTransport([_envelope([_indicator_obj("[domain-name:value = 'x.tld']")])])
    poll = poll_collection(transport, _collection(), added_after="2026-11-20T00:00:00Z")
    assert "added_after=2026-11-20T00%3A00%3A00Z" in transport.requests[0][0]
    # No X-TAXII header on the page: the cursor falls back to the input added_after.
    assert poll.next_added_after == "2026-11-20T00:00:00Z"


def test_object_bound_truncates_and_flags_more() -> None:
    objects = [_indicator_obj(f"[domain-name:value = 'h{n}.tld']") for n in range(5)]
    transport = FakeTransport([_envelope(objects, more=True, next_cursor="C")])
    poll = poll_collection(transport, _collection(), max_objects=2)
    assert poll.objects_fetched == 2
    assert poll.more_available is True
    assert poll.pages_fetched == 1


def test_page_bound_stops_runaway_pagination() -> None:
    # Every page claims more objects; the page cap must stop the loop.
    pages = [
        _envelope(
            [_indicator_obj(f"[domain-name:value = 'p{n}.tld']")], more=True, next_cursor=f"C{n}"
        )
        for n in range(5)
    ]
    transport = FakeTransport(pages)
    poll = poll_collection(transport, _collection(), page_limit=1, max_pages=3)
    assert poll.pages_fetched == 3
    assert poll.more_available is True


def test_auth_header_reaches_the_transport() -> None:
    transport = FakeTransport([_envelope([])])
    collection = _collection(token_env=TOKEN_ENV)
    import os

    os.environ[TOKEN_ENV] = "unit-token"
    try:
        poll_collection(transport, collection)
    finally:
        del os.environ[TOKEN_ENV]
    assert transport.requests[0][1]["Authorization"] == "Bearer unit-token"
    assert transport.requests[0][1]["Accept"] == "application/taxii+json;version=2.1"


# --- protocol and transport failures --------------------------------------- #


@pytest.mark.parametrize("status", [401, 403])
def test_authorization_refusal_raises(status: int) -> None:
    transport = FakeTransport([TaxiiResponse(status, b"{}", {})])
    with pytest.raises(TaxiiError, match="refused authorization"):
        poll_collection(transport, _collection())


def test_server_error_status_raises() -> None:
    transport = FakeTransport([TaxiiResponse(500, b"oops", {})])
    with pytest.raises(TaxiiError, match="HTTP 500"):
        poll_collection(transport, _collection())


def test_invalid_json_and_shape_raise() -> None:
    bad_json = FakeTransport([TaxiiResponse(200, b"not json", {})])
    with pytest.raises(TaxiiError, match="not valid JSON"):
        poll_collection(bad_json, _collection())

    bad_shape = FakeTransport([TaxiiResponse(200, json.dumps({"objects": {}}).encode(), {})])
    with pytest.raises(TaxiiError, match="not an array"):
        poll_collection(bad_shape, _collection())


def test_range_not_satisfiable_is_an_empty_page() -> None:
    transport = FakeTransport([TaxiiResponse(416, b"", {})])
    poll = poll_collection(transport, _collection())
    assert poll.objects_fetched == 0
    assert poll.indicator_count == 0
    assert poll.more_available is False


def test_bounds_are_validated() -> None:
    collection = _collection()
    transport = FakeTransport([_envelope([])])
    for kwargs in (
        {"page_limit": 0},
        {"max_objects": MAX_TAXII_OBJECTS + 1},
        {"max_pages": 0},
        {"timeout": 0.0},
    ):
        with pytest.raises(TaxiiConfigError):
            poll_collection(transport, collection, **kwargs)  # type: ignore[arg-type]


def test_pinned_transport_refuses_non_https() -> None:
    transport = PinnedTaxiiTransport()
    with pytest.raises(TaxiiError, match="only speaks https"):
        transport.get("http://feed.example/x", {}, timeout=1.0)

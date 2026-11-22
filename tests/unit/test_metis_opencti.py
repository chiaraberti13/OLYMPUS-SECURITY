"""Live OpenCTI indicator pulling, exercised entirely offline (BLUE-3).

The network edge is an :class:`~olympus.metis.opencti.OpenCtiTransport`
``Protocol``, so these tests drive the whole pull — Relay pagination, the
incremental ``since`` cursor, the indicator/page bounds, the fail-closed auth
header, revoked-indicator exclusion and GraphQL errors — against a canned
in-memory server, with no sockets. It mirrors ``test_metis_taxii.py`` and
``test_metis_misp_pull.py``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from olympus.metis.models import IndicatorType
from olympus.metis.opencti import (
    MAX_OPENCTI_INDICATORS,
    OpenCtiConfigError,
    OpenCtiError,
    OpenCtiResponse,
    OpenCtiServer,
    PinnedOpenCtiTransport,
    pull_indicators,
)

pytestmark = pytest.mark.unit

# The API-token *env var name*, not a secret.
TOKEN_ENV = "OLYMPUS_OPENCTI_TOKEN"  # noqa: S105 - an env var name, not a credential


# --- a canned, socket-free OpenCTI server ----------------------------------- #


class FakeTransport:
    """Serve queued responses and record every request made."""

    def __init__(self, responses: list[OpenCtiResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

    def post(
        self, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> OpenCtiResponse:
        self.requests.append((url, json.loads(body.decode("utf-8")), dict(headers)))
        if not self._responses:  # pragma: no cover - a test queued too few pages
            raise AssertionError("FakeTransport ran out of queued responses")
        return self._responses.pop(0)


def _node(pattern: str, *, revoked: bool = False, updated: str = "2026-11-21T10:00:00Z") -> dict:
    return {"pattern": pattern, "pattern_type": "stix", "revoked": revoked, "updated_at": updated}


def _page(
    nodes: list[dict], *, has_next: bool = False, cursor: str | None = None, status: int = 200
) -> OpenCtiResponse:
    body = {
        "data": {
            "indicators": {
                "edges": [{"node": n} for n in nodes],
                "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
            }
        }
    }
    return OpenCtiResponse(status, json.dumps(body).encode("utf-8"), {})


def _server() -> OpenCtiServer:
    return OpenCtiServer(base_url="https://opencti.example", token_env=TOKEN_ENV)


# --- server configuration --------------------------------------------------- #


def test_server_requires_https_and_token_env() -> None:
    with pytest.raises(OpenCtiConfigError, match="https"):
        OpenCtiServer(base_url="http://opencti.example", token_env=TOKEN_ENV)
    with pytest.raises(OpenCtiConfigError, match="query or fragment"):
        OpenCtiServer(base_url="https://opencti.example/?x=1", token_env=TOKEN_ENV)
    with pytest.raises(OpenCtiConfigError, match="token_env"):
        OpenCtiServer(base_url="https://opencti.example", token_env="   ")  # noqa: S106 - blank


def test_server_url_and_label_carry_no_secret() -> None:
    server = OpenCtiServer(base_url="https://opencti.example/", token_env=TOKEN_ENV)
    assert server.graphql_url == "https://opencti.example/graphql"
    assert server.source_label == "opencti://opencti.example"


def test_auth_header_is_fail_closed_and_uses_bearer() -> None:
    server = _server()
    with pytest.raises(OpenCtiConfigError, match="is not set"):
        server.auth_headers(environ={})
    headers = server.auth_headers(environ={TOKEN_ENV: "t0k"})
    assert headers["Authorization"] == "Bearer t0k"
    assert headers["Content-Type"] == "application/json"


# --- pulling: normalization, pagination, incremental cursor, revoked --------- #


def test_single_page_normalizes_indicators_and_excludes_revoked() -> None:
    nodes = [
        _node("[domain-name:value = 'evil.tld']", updated="2026-11-21T10:00:00Z"),
        _node("[ipv4-addr:value = '203.0.113.7']", updated="2026-11-21T11:00:00Z"),
        _node("[domain-name:value = 'revoked.tld']", revoked=True, updated="2026-11-21T12:00:00Z"),
        _node("[domain-name:value = 'a.tld' OR domain-name:value = 'b.tld']"),
    ]
    transport = FakeTransport([_page(nodes)])
    pull = pull_indicators(transport, _server(), environ={TOKEN_ENV: "k"})

    kinds = {(i.indicator_type, i.value) for i in pull.result.indicators}
    assert (IndicatorType.DOMAIN, "evil.tld") in kinds
    assert (IndicatorType.IPV4, "203.0.113.7") in kinds
    # Revoked indicator is excluded from the bundle entirely.
    assert all(v != "revoked.tld" for _, v in kinds)
    # The compound pattern is skipped, never mangled.
    assert pull.indicator_count == 2
    assert len(pull.result.skipped) == 1
    # fetched counts nodes (revoked included); cursor tracks newest updated_at seen.
    assert pull.indicators_fetched == 4
    assert pull.next_since == "2026-11-21T12:00:00Z"
    assert pull.more_available is False
    assert pull.source == "opencti://opencti.example"


def test_pagination_follows_cursor_and_accumulates() -> None:
    page1 = _page([_node("[domain-name:value = 'one.tld']")], has_next=True, cursor="CUR2")
    page2 = _page([_node("[domain-name:value = 'two.tld']")], has_next=False)
    transport = FakeTransport([page1, page2])
    pull = pull_indicators(transport, _server(), page_size=1, environ={TOKEN_ENV: "k"})

    assert pull.pages_fetched == 2
    assert {i.value for i in pull.result.indicators} == {"one.tld", "two.tld"}
    # The second request carried the Relay cursor as `after`.
    assert transport.requests[1][1]["variables"]["after"] == "CUR2"
    assert pull.more_available is False


def test_since_builds_a_filter_and_defaults_forward() -> None:
    transport = FakeTransport([_page([])])
    pull = pull_indicators(
        transport, _server(), since="2026-11-20T00:00:00Z", environ={TOKEN_ENV: "k"}
    )
    filters = transport.requests[0][1]["variables"]["filters"]
    assert filters["filters"][0]["key"] == "updated_at"
    assert filters["filters"][0]["operator"] == "gte"
    assert filters["filters"][0]["values"] == ["2026-11-20T00:00:00Z"]
    # Empty page: cursor falls back to the input since.
    assert pull.next_since == "2026-11-20T00:00:00Z"


def test_indicator_bound_truncates_and_flags_more() -> None:
    nodes = [_node(f"[domain-name:value = 'h{n}.tld']") for n in range(5)]
    transport = FakeTransport([_page(nodes, has_next=True, cursor="C")])
    pull = pull_indicators(transport, _server(), max_indicators=2, environ={TOKEN_ENV: "k"})
    assert pull.indicators_fetched == 2
    assert pull.more_available is True
    assert pull.pages_fetched == 1


def test_page_bound_stops_runaway_pagination() -> None:
    pages = [
        _page([_node(f"[domain-name:value = 'p{n}.tld']")], has_next=True, cursor=f"C{n}")
        for n in range(5)
    ]
    transport = FakeTransport(pages)
    pull = pull_indicators(transport, _server(), page_size=1, max_pages=3, environ={TOKEN_ENV: "k"})
    assert pull.pages_fetched == 3
    assert pull.more_available is True


def test_auth_header_reaches_the_transport() -> None:
    transport = FakeTransport([_page([])])
    pull_indicators(transport, _server(), environ={TOKEN_ENV: "unit-token"})
    assert transport.requests[0][2]["Authorization"] == "Bearer unit-token"


# --- protocol and transport failures ---------------------------------------- #


@pytest.mark.parametrize("status", [401, 403])
def test_authorization_refusal_raises(status: int) -> None:
    transport = FakeTransport([OpenCtiResponse(status, b"{}", {})])
    with pytest.raises(OpenCtiError, match="refused authorization"):
        pull_indicators(transport, _server(), environ={TOKEN_ENV: "k"})


def test_server_error_status_raises() -> None:
    transport = FakeTransport([OpenCtiResponse(500, b"oops", {})])
    with pytest.raises(OpenCtiError, match="HTTP 500"):
        pull_indicators(transport, _server(), environ={TOKEN_ENV: "k"})


def test_graphql_errors_raise() -> None:
    body = json.dumps({"errors": [{"message": "not authorized to query indicators"}]}).encode()
    transport = FakeTransport([OpenCtiResponse(200, body, {})])
    with pytest.raises(OpenCtiError, match="GraphQL error: not authorized"):
        pull_indicators(transport, _server(), environ={TOKEN_ENV: "k"})


def test_invalid_json_and_shape_raise() -> None:
    bad_json = FakeTransport([OpenCtiResponse(200, b"not json", {})])
    with pytest.raises(OpenCtiError, match="not valid JSON"):
        pull_indicators(bad_json, _server(), environ={TOKEN_ENV: "k"})

    no_conn = FakeTransport([OpenCtiResponse(200, json.dumps({"data": {}}).encode(), {})])
    with pytest.raises(OpenCtiError, match="no 'indicators' connection"):
        pull_indicators(no_conn, _server(), environ={TOKEN_ENV: "k"})


def test_bounds_are_validated() -> None:
    server = _server()
    transport = FakeTransport([_page([])])
    for kwargs in (
        {"page_size": 0},
        {"max_indicators": MAX_OPENCTI_INDICATORS + 1},
        {"max_pages": 0},
        {"timeout": 0.0},
    ):
        with pytest.raises(OpenCtiConfigError):
            pull_indicators(transport, server, environ={TOKEN_ENV: "k"}, **kwargs)  # type: ignore[arg-type]


def test_pinned_transport_refuses_non_https() -> None:
    transport = PinnedOpenCtiTransport()
    with pytest.raises(OpenCtiError, match="only speaks https"):
        transport.post("http://opencti.example/graphql", b"{}", {}, timeout=1.0)

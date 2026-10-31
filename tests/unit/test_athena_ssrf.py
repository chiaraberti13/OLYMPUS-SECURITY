"""SSRF regression tests for the Athena web path.

Covers the four attacks the hardening roadmap calls out: DNS rebinding, a
mixed answer set, an out-of-scope redirect, and IPv4 smuggled inside an IPv6
wrapper.
"""

from __future__ import annotations

from typing import Any

import pytest

from olympus.argus.web import WebPolicyBlockedError, WebReconError, fetch_web
from olympus.athena.adapters.tools.web_headers import WebHeadersAdapter
from olympus.athena.ports import ToolRequest
from olympus.athena.scope import (
    SsrfBlockedError,
    TargetOutOfScopeError,
    ensure_web_target_allowed,
    scoped_address_policy,
)
from olympus.core.http import HttpAddressPolicyError, HttpRequestError, HttpResponse

ALLOWED = ("example.com",)


class _NeverCancelled:
    def is_cancelled(self) -> bool:
        return False


def _answers(*addresses: str) -> list[tuple[Any, ...]]:
    return [(2, 1, 6, "", (address, 0)) for address in addresses]


def _request(target: str = "https://example.com") -> ToolRequest:
    return ToolRequest(
        target_kind="url",
        target_value=target,
        allowed_domains=ALLOWED,
        timeout_seconds=5,
    )


class _Http:
    """HTTP client stub whose ``get`` consults an address policy, like urllib."""

    def __init__(self, policy: object, *, response: HttpResponse | None = None) -> None:
        self._policy = policy
        self._response = response or HttpResponse(status_code=200, headers={"Server": "nginx"})

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        from urllib.parse import urlsplit

        host = urlsplit(url).hostname or ""
        try:
            self._policy(host)
        except Exception as exc:  # the pinned handler turns this into an OSError
            raise HttpAddressPolicyError(
                f"HTTP GET for {url} was refused by the address policy: {exc}"
            ) from exc
        return self._response


# --------------------------------------------------------------------------- #
# DNS rebinding
# --------------------------------------------------------------------------- #


def test_rebinding_between_validation_and_connect_is_refused() -> None:
    lookups = 0

    def rebinding(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        nonlocal lookups
        lookups += 1
        return _answers("93.184.216.34") if lookups == 1 else _answers("127.0.0.1")

    # Plan-time validation sees the honest answer...
    assert ensure_web_target_allowed("url", "https://example.com", ALLOWED, resolver=rebinding)

    # ...and the connect-time policy, which is what actually opens the socket,
    # sees the rebound one and refuses.
    policy = scoped_address_policy(ALLOWED, resolver=rebinding)
    with pytest.raises(SsrfBlockedError, match=r"127\.0\.0\.1"):
        policy("example.com")


def test_adapter_reports_a_rebinding_block_as_ssrf_not_as_unreachable() -> None:
    lookups = 0

    def rebinding(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        nonlocal lookups
        lookups += 1
        return _answers("93.184.216.34") if lookups == 1 else _answers("127.0.0.1")

    policy = scoped_address_policy(ALLOWED, resolver=rebinding)
    adapter = WebHeadersAdapter(_Http(policy), resolver=rebinding)

    result = adapter.run(_request(), _NeverCancelled())

    assert (result.ok, result.error_code) == (False, "ssrf_blocked")


# --------------------------------------------------------------------------- #
# Mixed record sets
# --------------------------------------------------------------------------- #


def test_mixed_public_and_private_answers_are_refused_as_a_whole() -> None:
    def mixed(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return _answers("93.184.216.34", "10.0.0.5")

    with pytest.raises(SsrfBlockedError, match=r"10\.0\.0\.5"):
        scoped_address_policy(ALLOWED, resolver=mixed)("example.com")


def test_mixed_ipv4_and_ipv6_answers_are_refused_when_either_is_private() -> None:
    def mixed(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return _answers("93.184.216.34", "fe80::1")

    with pytest.raises(SsrfBlockedError, match="fe80::1"):
        scoped_address_policy(ALLOWED, resolver=mixed)("example.com")


# --------------------------------------------------------------------------- #
# IPv4 smuggled inside IPv6
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",  # IPv4-mapped metadata service
        "::127.0.0.1",  # deprecated IPv4-compatible form
        "64:ff9b::7f00:1",  # NAT64-wrapped loopback
        "2002:7f00:1::",  # 6to4-wrapped loopback
    ],
)
def test_ipv4_smuggled_in_an_ipv6_answer_is_refused(address: str) -> None:
    def wrapped(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return _answers(address)

    with pytest.raises(SsrfBlockedError):
        scoped_address_policy(ALLOWED, resolver=wrapped)("example.com")

    with pytest.raises(SsrfBlockedError):
        ensure_web_target_allowed("url", "https://example.com", ALLOWED, resolver=wrapped)


@pytest.mark.parametrize("literal", ["::ffff:127.0.0.1", "64:ff9b::7f00:1", "::127.0.0.1"])
def test_ipv4_smuggled_in_a_literal_target_is_refused(literal: str) -> None:
    with pytest.raises(SsrfBlockedError):
        scoped_address_policy((literal,))(literal)


# --------------------------------------------------------------------------- #
# Redirects
# --------------------------------------------------------------------------- #


def test_redirect_to_a_private_host_is_refused_at_connect_time() -> None:
    def resolver(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return _answers("127.0.0.1" if host == "internal.example.com" else "93.184.216.34")

    policy = scoped_address_policy(ALLOWED, resolver=resolver)

    assert policy("example.com") == ("93.184.216.34",)
    with pytest.raises(SsrfBlockedError, match=r"127\.0\.0\.1"):
        policy("internal.example.com")


def test_redirect_out_of_scope_is_refused_even_when_it_is_public() -> None:
    def resolver(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return _answers("93.184.216.34")

    with pytest.raises(TargetOutOfScopeError, match="out of scope"):
        scoped_address_policy(ALLOWED, resolver=resolver)("attacker.test")


def test_fetch_web_distinguishes_a_policy_block_from_an_unreachable_host() -> None:
    class _Refusing:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            raise HttpAddressPolicyError("refused by the address policy")

    class _Broken:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            raise HttpRequestError("connection reset")

    with pytest.raises(WebPolicyBlockedError):
        fetch_web("https://example.com", _Refusing())

    with pytest.raises(WebReconError) as unreachable:
        fetch_web("https://example.com", _Broken())
    assert not isinstance(unreachable.value, WebPolicyBlockedError)

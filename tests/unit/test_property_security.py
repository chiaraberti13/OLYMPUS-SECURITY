"""Property-based (fuzz) tests for the security-critical guards (§2, roadmap).

Example-based tests prove the cases we thought of; these prove an *invariant*
holds across thousands of machine-generated inputs, which is where SSRF and
redaction bypasses hide. Two controls are fuzzed here:

* the SSRF address guard (:mod:`olympus.core.addresses`): it must never accept a
  non-global destination, including one smuggled inside an IPv6 wrapper;
* the audit/evidence redaction (:mod:`olympus.core.execution`): a secret placed
  anywhere a redaction pass claims to reach must never survive into the output.

The strategies do no network or disk I/O, so the suite stays offline and fast.
Reference: Hypothesis — https://hypothesis.readthedocs.io/
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.core.addresses import (
    embedded_ipv4,
    is_globally_routable,
    parse_address,
)
from olympus.core.execution import _SENSITIVE_KEY_PARTS, redact_mapping, redact_url

#: Either IP address flavour, aliased to keep the fuzz signatures readable.
_IP = ipaddress.IPv4Address | ipaddress.IPv6Address

# --------------------------------------------------------------------------- #
# SSRF address guard
# --------------------------------------------------------------------------- #

#: Ranges a request must never be allowed to reach. Membership here is the
#: independent ground truth the guard is checked against — it is derived from
#: the addressing RFCs, not from the module under test.
_FORBIDDEN_V4 = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this host"
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local (cloud metadata lives here)
        "172.16.0.0/12",  # private
        # NB: 192.0.0.0/24 (IETF protocol assignments) is deliberately excluded
        # here — it is a *mixed* block: 192.0.0.9 (PCP) and 192.0.0.10 (TURN) are
        # allocated as globally routable anycast, so the block is not uniformly
        # forbidden. Its correctness is covered by the is_global cross-check test.
        "192.0.2.0/24",  # TEST-NET-1
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved
    )
]
_FORBIDDEN_V6 = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "::1/128",  # loopback
        "::/128",  # unspecified
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
]


@st.composite
def _address_in(draw: st.DrawFn, networks: list[Any]) -> _IP:
    """Draw a concrete address that lies inside one of ``networks``."""
    network = draw(st.sampled_from(networks))
    offset = draw(st.integers(min_value=0, max_value=int(network.num_addresses) - 1))
    return ipaddress.ip_address(int(network.network_address) + offset)


@given(_address_in(_FORBIDDEN_V4 + _FORBIDDEN_V6))
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_ssrf_guard_never_accepts_a_forbidden_address(
    address: _IP,
) -> None:
    # Any address drawn from a reserved/private/loopback/metadata range must be
    # refused outright — this is the core SSRF invariant.
    assert is_globally_routable(address) is False


@given(_address_in(_FORBIDDEN_V4))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_ssrf_guard_never_accepts_a_forbidden_ipv4_mapped_into_ipv6(
    v4: ipaddress.IPv4Address,
) -> None:
    # The same forbidden IPv4, smuggled inside an ::ffff:0:0/96 mapped wrapper,
    # must still be refused: the guard has to judge the address a packet reaches,
    # not the envelope it arrives in.
    mapped = ipaddress.ip_address("::ffff:" + str(v4))
    assert is_globally_routable(mapped) is False


@given(st.ip_addresses())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_ssrf_acceptance_implies_the_reached_address_is_global(
    address: _IP,
) -> None:
    # If the guard accepts an address, the address a request would actually
    # reach (after unwrapping any IPv6 tunnel) must be globally routable by the
    # standard library's own classification — no false accepts.
    if not is_globally_routable(address):
        return
    reached: _IP = address
    for _ in range(4):
        nested = embedded_ipv4(reached)
        if nested is None:
            break
        reached = nested
    assert reached.is_global is True


@given(st.text(max_size=64))
@settings(max_examples=300)
def test_parse_address_is_total(raw: str) -> None:
    # parse_address either returns an IP address or raises its own typed error;
    # arbitrary text must never leak a different exception to the caller.
    try:
        result = parse_address(raw)
    except ValueError:
        return
    assert isinstance(result, ipaddress.IPv4Address | ipaddress.IPv6Address)


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: A concrete sensitive key for each declared secret-bearing key fragment.
_SENSITIVE_KEYS = list(_SENSITIVE_KEY_PARTS)
#: URL-safe secret material with a distinctive marker so a match is never a
#: coincidence with unrelated output.
_secrets = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    min_size=6,
    max_size=32,
).map(lambda token: "SEKRET" + token)


@given(key=st.sampled_from(_SENSITIVE_KEYS), secret=_secrets)
@settings(max_examples=300)
def test_a_secret_key_value_never_survives_redaction(key: str, secret: str) -> None:
    assert redact_mapping({key: secret})[key] == "[REDACTED]"


@given(
    secret=_secrets,
    depth=st.integers(min_value=0, max_value=3),
    param=st.sampled_from(["token", "api_key", "access_key", "password"]),
)
@settings(max_examples=300)
def test_a_url_query_secret_never_survives_however_deeply_nested(
    secret: str, depth: int, param: str
) -> None:
    # Build a URL carrying the secret in a sensitive query parameter, then bury
    # it under ``depth`` levels of list nesting under a non-sensitive key.
    url = f"https://host.example/path?{param}={secret}&keep=1"
    value: Any = url
    for _ in range(depth):
        value = [value]
    redacted = redact_mapping({"payload": value})
    serialized = json.dumps(redacted)
    assert secret not in serialized
    assert "keep=1" in serialized  # non-secret data is preserved


@given(st.text(max_size=128))
@settings(max_examples=200)
def test_redact_url_is_total_and_idempotent(raw: str) -> None:
    once = redact_url(raw)
    # Redaction must never raise on arbitrary text and must be stable: running
    # it again changes nothing (no half-redacted state a second pass would fix).
    assert redact_url(once) == once

"""Target values must never become scanner flags or shell words (SEC-H).

A scanned target is attacker-chosen. If a hostname like ``-oG`` or a URL with an
embedded space reached a scanner's argument vector unchecked, the target could
smuggle extra flags (argument injection) or, under a shell, extra commands. Two
design invariants prevent this and are asserted here so a regression fails CI:

* ``host_of`` normalizes and rejects any host whose labels are flag-like
  (leading ``-``), carry URL/shell metacharacters or whitespace, and accepts
  only ``http``/``https`` URLs with a valid host — so the token that reaches a
  scanner can never be option-like.
* every adapter builds a ``list[str]`` argument vector (never a shell string),
  so a target token is always one argument, never word-split into flags.

No scanner is executed: only pure argv construction and validation run.
"""

from __future__ import annotations

import pytest

from olympus.themis.model import ScanRequest
from olympus.themis.registry import get_adapter, implemented
from olympus.themis.scope import TargetValidationError, host_of

_FLAG_LIKE_HOSTS = [
    "-oG",
    "-x",
    "--script=http-evil",
    "-lead.example.com",
    "foo;rm -rf /",
    "a b",
    "e/vil",
    "host$(whoami)",
    "name`id`",
]

_BAD_URLS = [
    "http://-evil.example.com",
    "ftp://example.com",
    "javascript:alert(1)",
    "http://example.com --script=evil",
    "http://user:pass@example.com",
]


@pytest.mark.parametrize("value", _FLAG_LIKE_HOSTS)
def test_host_of_rejects_flag_like_and_metachar_hosts(value: str) -> None:
    with pytest.raises(TargetValidationError):
        host_of("host", value)


@pytest.mark.parametrize("value", _BAD_URLS)
def test_host_of_rejects_unsafe_urls(value: str) -> None:
    with pytest.raises(TargetValidationError):
        host_of("url", value)


def test_normalized_host_is_never_flag_like() -> None:
    # A legitimate host passes and, crucially, never starts with '-'.
    normalized = host_of("host", "Scanme.Example.COM")
    assert normalized == "scanme.example.com"
    assert not normalized.startswith("-")


@pytest.mark.parametrize("name", implemented())
def test_adapter_argv_is_a_safe_list_for_host_targets(name: str) -> None:
    host = "scanme.example.com"
    request = ScanRequest(scanner=name, target=host, target_kind="host", allowed=(host,))
    argv = get_adapter(name).build_argv(host, request)
    assert isinstance(argv, list) and all(isinstance(token, str) for token in argv)
    assert any(host in token for token in argv)  # the target is actually passed
    # No token that carries the target is option-like: the host can never be
    # interpreted as a flag by the scanner.
    assert not any(token.startswith("-") and host in token for token in argv)


@pytest.mark.parametrize("name", implemented())
def test_adapter_argv_is_a_safe_list_for_url_targets(name: str) -> None:
    host = "scanme.example.com"
    url = f"http://{host}/path"
    request = ScanRequest(scanner=name, target=url, target_kind="url", allowed=(host,))
    argv = get_adapter(name).build_argv(host, request)
    assert isinstance(argv, list) and all(isinstance(token, str) for token in argv)
    # Whatever target token the adapter emits (raw URL or http://host), it starts
    # with the scheme, never with '-'.
    target_tokens = [token for token in argv if host in token]
    assert target_tokens
    assert not any(token.startswith("-") for token in target_tokens)

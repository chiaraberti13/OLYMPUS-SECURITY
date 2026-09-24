"""Unit tests for the DnspythonResolver DNS adapter."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.rdata
import dns.resolver
import pytest

from olympus.argus.resolver import DnspythonResolver, DnsResolutionError


class _FakeRdata:
    """Minimal stand-in for dnspython's Rdata used to exercise text rendering."""

    def __init__(self, text: str, *, preference: int | None = None, exchange: str = "") -> None:
        self._text = text
        self.preference = preference
        self.exchange = exchange

    def __str__(self) -> str:
        return self._text


class _FakeTxtRdata:
    """Minimal stand-in for a TXT Rdata (chunked byte strings)."""

    def __init__(self, strings: list[bytes]) -> None:
        self.strings = strings


def _patch_resolve(monkeypatch: pytest.MonkeyPatch, result: Any) -> None:
    def _fake_resolve(self: dns.resolver.Resolver, name: str, record_type: str) -> Any:
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve)


def test_resolve_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [_FakeRdata("203.0.113.10")])
    resolver = DnspythonResolver()
    assert resolver.resolve("olympusdemocorp.example", "A") == ["203.0.113.10"]


def test_resolve_mx_record_renders_preference_and_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(
        monkeypatch,
        [_FakeRdata("unused", preference=10, exchange="mail.olympusdemocorp.example.")],
    )
    resolver = DnspythonResolver()
    assert resolver.resolve("olympusdemocorp.example", "MX") == ["10 mail.olympusdemocorp.example"]


def test_resolve_txt_record_joins_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [_FakeTxtRdata([b"v=spf1 ", b"~all"])])
    resolver = DnspythonResolver()
    assert resolver.resolve("olympusdemocorp.example", "TXT") == ["v=spf1 ~all"]


def test_nxdomain_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, dns.resolver.NXDOMAIN())  # type: ignore[no-untyped-call]
    resolver = DnspythonResolver()
    assert resolver.resolve("does-not-exist.example", "A") == []


def test_no_answer_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, dns.resolver.NoAnswer())  # type: ignore[no-untyped-call]
    resolver = DnspythonResolver()
    assert resolver.resolve("olympusdemocorp.example", "AAAA") == []


def test_dns_exception_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, dns.exception.Timeout())  # type: ignore[no-untyped-call]
    resolver = DnspythonResolver()
    with pytest.raises(DnsResolutionError, match="DNS query failed"):
        resolver.resolve("olympusdemocorp.example", "A")

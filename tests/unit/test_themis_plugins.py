"""Entry-point adapter discovery is default-deny and audited (ROADMAP ``DEV-B``).

Pin the supply-chain invariants: a plugin is loaded only when its name is on the
operator allowlist, an approved plugin must be a concrete ``ScannerAdapter`` or it
is rejected with a reason, present-but-unapproved plugins are reported (never
silently dropped), and a plugin can never shadow a first-party adapter. No real
entry points or packages are involved — fakes stand in for them.
"""

from __future__ import annotations

from collections.abc import Iterable

from olympus.themis.base import ScannerAdapter
from olympus.themis.plugins import (
    PLUGIN_ALLOWLIST_ENV,
    available_adapters,
    discover_adapters,
    load_plugin_allowlist,
)
from olympus.themis.registry import adapter_classes


class _GoodAdapter(ScannerAdapter):
    name = "demo-plugin"
    binary = "demo"

    def build_argv(self, host, request):  # type: ignore[no-untyped-def]
        return [self.binary, host]

    def parse(self, output, host, request):  # type: ignore[no-untyped-def]
        return []


class _NotAnAdapter:
    """A plausible-looking class that is deliberately not a ScannerAdapter."""


class _FakeEntryPoint:
    def __init__(self, name: str, target: object, *, error: Exception | None = None) -> None:
        self.name = name
        self._target = target
        self._error = error

    def load(self) -> object:
        if self._error is not None:
            raise self._error
        return self._target


def _loader(*entry_points: _FakeEntryPoint):
    def load() -> Iterable[_FakeEntryPoint]:
        return entry_points

    return load


def test_unapproved_plugin_is_skipped_not_loaded() -> None:
    loaded_marker: list[str] = []

    class _Tripwire:
        name = "evil"

        def load(self) -> object:
            loaded_marker.append("loaded")  # must never run
            return _GoodAdapter

    result = discover_adapters(frozenset(), loader=lambda: [_Tripwire()])
    assert result.adapters == {}
    assert result.skipped == ("evil",)
    assert loaded_marker == []  # default-deny: .load() was never called


def test_approved_valid_plugin_is_registered() -> None:
    result = discover_adapters(
        frozenset({"demo-plugin"}), loader=_loader(_FakeEntryPoint("demo-plugin", _GoodAdapter))
    )
    assert result.adapters == {"demo-plugin": _GoodAdapter}
    assert result.skipped == () and result.rejected == ()


def test_approved_non_adapter_is_rejected_with_reason() -> None:
    result = discover_adapters(
        frozenset({"bad"}), loader=_loader(_FakeEntryPoint("bad", _NotAnAdapter))
    )
    assert result.adapters == {}
    assert result.rejected == (("bad", "not a ScannerAdapter subclass"),)


def test_approved_abstract_base_is_rejected() -> None:
    result = discover_adapters(
        frozenset({"base"}), loader=_loader(_FakeEntryPoint("base", ScannerAdapter))
    )
    assert result.rejected == (("base", "abstract base, not a concrete adapter"),)


def test_approved_plugin_that_fails_to_load_is_rejected_not_fatal() -> None:
    boom = _FakeEntryPoint("boom", None, error=ImportError("missing dep"))
    good = _FakeEntryPoint("demo-plugin", _GoodAdapter)
    result = discover_adapters(frozenset({"boom", "demo-plugin"}), loader=_loader(boom, good))
    # One bad plugin never aborts discovery of the rest.
    assert result.adapters == {"demo-plugin": _GoodAdapter}
    assert result.rejected[0][0] == "boom" and "failed to load" in result.rejected[0][1]


def test_allowlist_parsing_ignores_blanks() -> None:
    assert load_plugin_allowlist({PLUGIN_ALLOWLIST_ENV: " a , b ,, c "}) == frozenset(
        {"a", "b", "c"}
    )
    assert load_plugin_allowlist({}) == frozenset()


def test_available_adapters_includes_first_party_and_cannot_be_shadowed() -> None:
    first_party = adapter_classes()
    assert "nmap" in first_party

    # A plugin approved under the reserved name "nmap" must not replace the built-in.
    merged = available_adapters(
        frozenset({"nmap", "demo-plugin"}),
        loader=_loader(
            _FakeEntryPoint("nmap", _GoodAdapter),
            _FakeEntryPoint("demo-plugin", _GoodAdapter),
        ),
    )
    assert merged["nmap"] is first_party["nmap"]  # first-party wins
    assert merged["demo-plugin"] is _GoodAdapter  # new capability added


def test_available_adapters_defaults_to_no_plugins() -> None:
    # With no allowlist and no entry points, the view equals the first-party set.
    assert available_adapters(frozenset(), loader=_loader()) == adapter_classes()

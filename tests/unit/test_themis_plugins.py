"""Entry-point adapter discovery is default-deny and audited (ROADMAP ``DEV-B``).

Pin the supply-chain invariants: a plugin is loaded only when its name is on the
operator allowlist, an approved plugin must be a concrete ``ScannerAdapter`` or it
is rejected with a reason, present-but-unapproved plugins are reported (never
silently dropped), and a plugin can never shadow a first-party adapter. No real
entry points or packages are involved — fakes stand in for them.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace

from olympus.themis.base import ScannerAdapter
from olympus.themis.plugins import (
    PLUGIN_ALLOWLIST_ENV,
    available_adapters,
    discover_adapters,
    load_plugin_allowlist,
    resolve_adapter,
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
    def __init__(
        self,
        name: str,
        target: object,
        *,
        error: Exception | None = None,
        distribution: str = "olympus-demo-plugin",
        version: str = "1.2.3",
    ) -> None:
        self.name = name
        self._target = target
        self._error = error
        self.dist = SimpleNamespace(name=distribution, version=version)

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


def test_approved_abstract_subclass_is_rejected() -> None:
    class _AbstractAdapter(_GoodAdapter):
        @abc.abstractmethod
        def additional_contract(self) -> None: ...

    result = discover_adapters(
        frozenset({"demo-plugin"}),
        loader=_loader(_FakeEntryPoint("demo-plugin", _AbstractAdapter)),
    )
    assert result.adapters == {}
    assert result.rejected == (("demo-plugin", "abstract base, not a concrete adapter"),)


def test_plugin_with_path_like_binary_is_rejected() -> None:
    class _PathAdapter(_GoodAdapter):
        binary = "../demo"

    result = discover_adapters(
        frozenset({"demo-plugin"}),
        loader=_loader(_FakeEntryPoint("demo-plugin", _PathAdapter)),
    )
    assert result.adapters == {}
    assert result.rejected == (("demo-plugin", "adapter binary must be a simple executable name"),)


def test_duplicate_approved_names_are_rejected_before_import() -> None:
    loaded: list[str] = []

    class _Tripwire(_FakeEntryPoint):
        def load(self) -> object:
            loaded.append(self.name)
            return super().load()

    result = discover_adapters(
        frozenset({"demo-plugin"}),
        loader=_loader(
            _Tripwire("demo-plugin", _GoodAdapter),
            _Tripwire("demo-plugin", _GoodAdapter),
        ),
    )
    assert result.adapters == {}
    assert result.rejected == (("demo-plugin", "duplicate entry-point name"),)
    assert loaded == []


def test_native_name_collision_is_rejected_before_import() -> None:
    loaded: list[str] = []

    class _Tripwire(_FakeEntryPoint):
        def load(self) -> object:
            loaded.append(self.name)
            return super().load()

    result = discover_adapters(frozenset({"nmap"}), loader=_loader(_Tripwire("nmap", _GoodAdapter)))
    assert result.adapters == {}
    assert result.rejected == (("nmap", "reserved first-party adapter name"),)
    assert loaded == []


def test_approved_plugin_that_fails_to_load_is_rejected_not_fatal() -> None:
    boom = _FakeEntryPoint("boom", None, error=ImportError("missing dep"))
    good = _FakeEntryPoint("demo-plugin", _GoodAdapter)
    result = discover_adapters(frozenset({"boom", "demo-plugin"}), loader=_loader(boom, good))
    # One bad plugin never aborts discovery of the rest.
    assert result.adapters == {"demo-plugin": _GoodAdapter}
    assert result.rejected[0] == ("boom", "failed to load (ImportError)")


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


def test_discovery_reports_distribution_provenance() -> None:
    result = discover_adapters(
        frozenset({"demo-plugin"}),
        loader=_loader(
            _FakeEntryPoint("demo-plugin", _GoodAdapter, distribution="demo_dist", version="2.1.0")
        ),
    )
    assert result.metadata["demo-plugin"].distribution == "demo_dist"
    assert result.metadata["demo-plugin"].version == "2.1.0"


def test_approved_plugin_runs_through_preview_runtime_and_capabilities(tmp_path: Path) -> None:
    from olympus.integrations.capabilities import inventory
    from olympus.themis.application import ThemisApplicationService, ThemisRunRequest, ThemisScope
    from olympus.themis.preview import planned_command, preview_run

    allowlist = frozenset({"demo-plugin"})
    loader = _loader(_FakeEntryPoint("demo-plugin", _GoodAdapter))

    def factory(name: str) -> ScannerAdapter:
        return resolve_adapter(name, allowlist=allowlist, loader=loader)

    scope = ThemisScope(allowed_domains=("example.test",))
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(scope.model_dump_json(), encoding="utf-8")
    request = ThemisRunRequest(
        scanner="demo-plugin",
        target="example.test",
        target_kind="domain",
        scope_path=scope_path,
        authorized=False,
        live_enabled=False,
        simulate=True,
    )

    command = planned_command(
        "demo-plugin", "example.test", "domain", scope, adapter_factory=factory
    )
    preview = preview_run(request, scope, adapter_factory=factory)
    result = ThemisApplicationService(adapter_factory=factory).run(request)
    caps = inventory(
        {PLUGIN_ALLOWLIST_ENV: "demo-plugin"},
        plugin_loader=loader,
    )
    plugin_cap = next(item for item in caps if item.name == "demo-plugin")

    assert command == ("demo", "example.test")
    assert preview.planned_command == command
    assert result.state.value == "simulation"
    assert result.findings[0].title.startswith("[SIMULATION]")
    assert plugin_cap.kind == "external-plugin"
    assert plugin_cap.distribution == "olympus-demo-plugin"
    assert plugin_cap.version == "1.2.3"
    assert plugin_cap.maturity.value == "catalog-only"
    assert "validation evidence" in (plugin_cap.blocker or "")


def test_available_adapters_defaults_to_no_plugins() -> None:
    # With no allowlist and no entry points, the view equals the first-party set.
    assert available_adapters(frozenset(), loader=_loader()) == adapter_classes()

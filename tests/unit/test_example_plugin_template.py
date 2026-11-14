"""The documented plugin SDK template is a valid, discoverable adapter (ROADMAP ``INT-2``).

``examples/plugins/example_scanner_adapter.py`` is the copy-me skeleton for a
third-party scanner adapter, and ``docs/plugins.md`` documents the contract. These
tests pin that the committed template actually satisfies that contract end to end:
it is approved by the real discovery engine, parses output, and fails closed on a
corrupt result line — so the SDK the docs promise is the SDK the code enforces.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.plugins import discover_adapters
from olympus.themis.runner import CommandOutput

_TEMPLATE = (
    Path(__file__).resolve().parents[2] / "examples" / "plugins" / "example_scanner_adapter.py"
)


def _load_template() -> type[ScannerAdapter]:
    spec = importlib.util.spec_from_file_location("_olympus_example_plugin", _TEMPLATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    adapter: type[ScannerAdapter] = module.ExampleScannerAdapter
    return adapter


class _FakeEntryPoint:
    def __init__(self, name: str, target: object) -> None:
        self.name = name
        self._target = target
        self.dist = SimpleNamespace(name="olympus-example-plugin", version="1.0.0")

    def load(self) -> object:
        return self._target


def _request() -> ScanRequest:
    return ScanRequest(scanner="example-scanner", target="host.example", target_kind="host")


def test_template_is_a_concrete_scanner_adapter() -> None:
    adapter = _load_template()
    assert issubclass(adapter, ScannerAdapter)
    assert adapter.name == "example-scanner"
    # The scope-safe execution boundary is never overridden by a plugin.
    assert adapter.run is ScannerAdapter.run
    assert adapter.resolve is ScannerAdapter.resolve


def test_template_is_approved_by_the_real_discovery_engine() -> None:
    adapter = _load_template()
    result = discover_adapters(
        frozenset({"example-scanner"}),
        loader=lambda: [_FakeEntryPoint("example-scanner", adapter)],
        reserved_names=frozenset(),
    )
    assert list(result.adapters) == ["example-scanner"]
    assert result.skipped == ()
    assert result.rejected == ()
    assert result.metadata["example-scanner"].distribution == "olympus-example-plugin"


def test_template_without_the_allowlist_is_skipped_not_loaded() -> None:
    adapter = _load_template()
    # Default-deny: an un-allowlisted plugin is never imported/registered.
    result = discover_adapters(
        frozenset(),
        loader=lambda: [_FakeEntryPoint("example-scanner", adapter)],
        reserved_names=frozenset(),
    )
    assert result.adapters == {}
    assert result.skipped == ("example-scanner",)


def test_template_parses_findings_and_deduplicates() -> None:
    adapter = _load_template()()
    output = CommandOutput(
        exit_code=0,
        stdout='{"title":"Weak TLS","detail":"TLS1.0"}\n\n{"title":"Weak TLS"}\n',
        stderr="",
    )
    findings = adapter.parse(output, "host.example", _request())
    assert [f.title for f in findings] == ["Weak TLS"]  # the duplicate is folded


def test_template_build_argv_is_a_fixed_vector() -> None:
    adapter = _load_template()()
    argv = adapter.build_argv("host.example", _request())
    assert argv == ["example-scanner", "--json", "--target", "host.example"]


def test_template_fails_closed_on_a_corrupt_result_line() -> None:
    adapter = _load_template()()
    # A corrupt result line must never read as a clean "nothing found".
    for bad in ("not json\n", '{"detail":"no title"}\n', "[1,2,3]\n"):
        output = CommandOutput(exit_code=0, stdout=bad, stderr="")
        try:
            adapter.parse(output, "host.example", _request())
        except ParseError:
            continue
        raise AssertionError(f"expected ParseError for corrupt output: {bad!r}")


def test_template_empty_output_is_a_real_empty_result() -> None:
    adapter = _load_template()()
    assert (
        adapter.parse(CommandOutput(exit_code=0, stdout="\n  \n", stderr=""), "h", _request()) == []
    )

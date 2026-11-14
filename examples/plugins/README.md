# Example scanner adapter plugin

`example_scanner_adapter.py` is a copy-me skeleton for an external Olympus scanner
adapter. See [`docs/plugins.md`](../../docs/plugins.md) for the full SDK: the
adapter contract, the default-deny security model, packaging via the
`olympus.scanner_adapters` entry point, and how an operator approves a plugin with
`OLYMPUS_SCANNER_PLUGIN_ALLOWLIST`.

The template is a complete, valid adapter: `tests/unit/test_example_plugin_template.py`
feeds it through the real discovery engine and asserts it is approved, parses
findings, and fails closed on corrupt output.

# Scanner adapter plugin SDK

Olympus ships its scanners as first-party adapters, but a professional
installation can add more as **separate packages** — without forking Olympus.
This page is the stable SDK for writing one. The copy-me skeleton lives at
[`examples/plugins/example_scanner_adapter.py`](../examples/plugins/example_scanner_adapter.py)
and is exercised end-to-end by `tests/unit/test_example_plugin_template.py`, so
the contract documented here is the contract the code enforces.

## Security model: default-deny, scope-safe, audited

Discovery (`olympus.themis.plugins.discover_adapters`) is **default-deny**. A
plugin is found through the `olympus.scanner_adapters` entry-point group but is
**never loaded implicitly**:

- only a plugin whose name is on the operator's allowlist
  (`OLYMPUS_SCANNER_PLUGIN_ALLOWLIST`, comma-separated) is imported;
- it must then prove it is a **concrete** `ScannerAdapter` subclass, or it is
  *rejected with a reason* — never silently trusted and never silently dropped;
- a first-party adapter name can never be shadowed (reserved names are rejected),
  and the native registry always wins;
- the plugin **may not override the execution boundary** (`run`/`resolve`): DNS
  resolution, scope/authorization enforcement, resource caps, redaction and the
  output-grammar/state handling stay with Olympus. A plugin only *describes* the
  command and *interprets* its output.

So an attacker who plants a malicious `olympus.scanner_adapters` entry point still
cannot make Olympus execute it: the operator must add its name to the allowlist,
and even then the scope-safe boundary is not reachable from plugin code.

## The adapter contract

Subclass `olympus.themis.base.ScannerAdapter` and provide:

| Member | Requirement |
|---|---|
| `name` | lowercase, hyphenated id (`^[a-z0-9][a-z0-9-]{0,63}$`) that **equals the entry-point name** |
| `binary` | a **simple executable name** resolved on `PATH` — no path, no shell metacharacters |
| `version_expected` | the expected tool version string (or `"any"`) |
| `build_argv(host, request)` | return a **fixed argument vector**, never a string assembled from input |
| `parse(output, host, request)` | turn real output into `core.Finding` objects; **fail closed** |
| `build_asset(host, request)` | optional; the default attaches findings to the scanned target |

Do **not** override `run` or `resolve`. Leave `success_exit_codes` at its default
unless your tool signals success with other codes.

**Parsing is fail-closed.** An empty output is a real empty result, but a result
record you cannot parse must raise `olympus.themis.base.ParseError` (so a corrupt
or truncated run is reported as *failed*, never as a clean "nothing found"). Treat
every byte the tool emits as hostile input: carry target-controlled text as data
only — Olympus escapes it in every output format.

```python
from olympus.themis.base import ParseError, ScannerAdapter


class ExampleScannerAdapter(ScannerAdapter):
    name = "example-scanner"
    binary = "example-scanner"
    version_expected = "1.x"

    def build_argv(self, host, request):
        target = request.target if request.target_kind == "url" else host
        return [self.binary, "--json", "--target", target]

    def parse(self, output, host, request):
        ...  # see examples/plugins/example_scanner_adapter.py for the full skeleton
```

## Packaging

Register the adapter under the entry-point group in your package's
`pyproject.toml`:

```toml
[project.entry-points."olympus.scanner_adapters"]
example-scanner = "olympus_example_plugin.adapter:ExampleScannerAdapter"
```

The entry-point **name** (`example-scanner`) must equal the adapter's `name`.

## Enabling a plugin

Discovery is default-deny, so installing the package is not enough — the operator
approves it by name:

```bash
export OLYMPUS_SCANNER_PLUGIN_ALLOWLIST="example-scanner"
```

An approved, valid plugin then appears alongside the first-party adapters; an
installed-but-unapproved one is reported as *skipped*, and an approved-but-invalid
one as *rejected* with the reason.

"""Template third-party scanner adapter for Olympus (ROADMAP ``INT-2``).

This is a **copy-me skeleton** for packaging an external scanner as an Olympus
plugin. It is a complete, valid :class:`~olympus.themis.base.ScannerAdapter`: feed
it to :func:`olympus.themis.plugins.discover_adapters` with its name on the
operator allowlist and it is approved and registered. See ``docs/plugins.md`` for
the packaging (``pyproject.toml`` entry point) and the security model.

The contract every plugin adapter must honour — all of it enforced by discovery,
so a plugin that breaks one of these is *rejected with a reason*, never silently
trusted:

* subclass ``ScannerAdapter`` and be **concrete** (no abstract methods left);
* set ``name`` to a lowercase, hyphenated identifier that **matches the
  entry-point name**, and ``binary`` to a **simple executable name** (no path, no
  shell metacharacters);
* implement ``build_argv`` (a **fixed argument vector** — never a string assembled
  from input) and ``parse`` (turn real output into ``core.Finding`` objects);
* **never override ``run`` or ``resolve``** — that is the scope-safe execution
  boundary Olympus owns (DNS resolution, scope/authorization checks, resource
  caps, redaction, output-grammar handling). A plugin only *describes* the command
  and *interprets* its output.

The adapter is pure in the sense that matters: it assembles argv and parses bytes;
it performs no I/O itself. Olympus runs the command, under its sandbox and scope.
"""

from __future__ import annotations

import json

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


class ExampleScannerAdapter(ScannerAdapter):
    """Parse an example tool that prints one JSON finding object per line (JSONL).

    Replace the binary, argv and parsing with your tool's. The shape here is the
    one to copy: a fixed argv, and a parser that is **fail-closed** — a result
    record it cannot parse raises :class:`ParseError` (so a corrupt run is reported
    as failed, never as a clean "nothing found"), while a genuinely empty output is
    a real empty result.
    """

    #: Must equal the entry-point name the package registers under.
    name = "example-scanner"
    #: A simple executable name resolved on PATH — never a path or a shell string.
    binary = "example-scanner"
    version_expected = "1.x"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        """Return the fixed argument vector for a real scan of ``host``.

        A fixed vector (never a shell string built from input) is mandatory: it is
        how Olympus guarantees no argument injection. Use ``request.target`` for a
        URL target, the resolved ``host`` otherwise.
        """
        target = request.target if request.target_kind == "url" else host
        return [self.binary, "--json", "--target", target]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        """Turn the tool's JSONL output into findings; fail closed on a corrupt line.

        Each non-empty line is expected to be a JSON object carrying a string
        ``title``. A blank line is ignored; a line that is not a valid finding
        record raises :class:`ParseError`, so a mangled or truncated run is never
        mistaken for a clean result. The target-controlled ``title``/``detail`` are
        carried as data only — Olympus escapes them in every output format.
        """
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in output.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ParseError(f"example-scanner emitted a non-JSON result line: {exc}") from exc
            if not isinstance(record, dict) or not isinstance(record.get("title"), str):
                raise ParseError("example-scanner result line is missing a string 'title'")
            title = record["title"].strip()
            if not title or title in seen:
                continue
            seen.add(title)
            detail = record.get("detail")
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=title,
                    description=detail
                    if isinstance(detail, str)
                    else "Reported by example-scanner.",
                    severity=Severity.INFO,
                    evidence=[f"reported_by={self.name}"],
                ),
                request,
            )
        return findings

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        """Return the shared asset the findings attach to (override optional)."""
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.URL if request.target_kind == "url" else AssetType.HOST,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

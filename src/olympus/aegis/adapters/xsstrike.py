"""Real xsstrike adapter: parses XSStrike's reflected-XSS confirmation stream.

XSStrike has no machine-readable output at all — it is a coloured, progress-bar
console tool — so this adapter is the most carefully guarded of the set. The
naive signals are traps: XSStrike prints ``Reflections found`` and a stream of
``[+] Payload:`` candidates even against a target that safely escapes its input,
so neither is proof of anything.

The one reliable signal, established by running XSStrike against a matched pair
of lab targets, is **efficiency**. For each candidate XSStrike prints::

    [+] Payload: <svg onload=...>
    [!] Efficiency: 100
    [!] Confidence: 10

Efficiency is the fraction of the payload that survived into the response
unmodified. Against a server that HTML-escapes its output, efficiency tops out
in the low 90s; a payload only reaches **100** when it is reflected byte-for-byte
with no escaping or filtering — i.e. a genuinely exploitable reflected XSS. So a
finding is raised only for a ``Payload`` whose very next efficiency reading is
100, and never on the ``Reflections found`` or ``Payload`` lines alone.

The confirmed payload is reflected attacker-controlled markup: it is truncated
and carried as evidence, never interpolated into a title.
"""

from __future__ import annotations

import re

from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TESTING = re.compile(r"Testing parameter:\s*(?P<param>[^\s]+)")
_PAYLOAD = re.compile(r"\[\+\]\s*Payload:\s*(?P<payload>.+?)\s*$")
_EFFICIENCY = re.compile(r"Efficiency:\s*(?P<value>\d+)")

#: Efficiency at which a payload is reflected byte-for-byte: confirmed XSS.
_CONFIRMED_EFFICIENCY = 100
#: How much of a confirmed payload to keep as evidence.
_MAX_PAYLOAD = 300


class XsstrikeAdapter(ScannerAdapter):
    name = "xsstrike"
    binary = "xsstrike"
    version_expected = "3.x"
    install = "git clone s0md3v/XSStrike"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        target = request.target if request.target_kind == "url" else f"http://{host}"
        return [
            self.binary,
            "-u", target,
            "--skip",         # never prompt to continue; the sandbox has no user
            "--skip-dom",     # DOM XSS needs a real browser the sandbox lacks
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        confirmed: set[str] = set()
        current_param = "unknown"
        pending_payload: str | None = None

        for raw in output.stdout.splitlines():
            line = _ANSI.sub("", raw).strip()
            if not line:
                continue

            testing = _TESTING.search(line)
            if testing is not None:
                current_param = testing.group("param")
                pending_payload = None
                continue

            payload = _PAYLOAD.search(line)
            if payload is not None:
                pending_payload = payload.group("payload").strip()
                continue

            efficiency = _EFFICIENCY.search(line)
            if efficiency is None or pending_payload is None:
                continue
            # An efficiency reading belongs to the payload just printed. Only a
            # byte-for-byte reflection (100) is a confirmed, exploitable vector.
            if int(efficiency.group("value")) < _CONFIRMED_EFFICIENCY:
                pending_payload = None
                continue
            if current_param in confirmed:
                pending_payload = None
                continue
            confirmed.add(current_param)

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"Reflected XSS in parameter {current_param}",
                    description=(
                        f"XSStrike confirmed a reflected cross-site scripting vector in "
                        f"parameter {current_param!r}: a payload was reflected into the "
                        "response with no escaping (efficiency 100)."
                    ),
                    severity=Severity.HIGH,
                    evidence=[
                        f"parameter={current_param}",
                        f"payload={pending_payload[:_MAX_PAYLOAD]}",
                        "efficiency=100",
                    ],
                ),
                request,
            )
            pending_payload = None

        # No confirmed vector is a real clean result: XSStrike streams candidates
        # and reflections against safe targets too, so their absence is expected.
        return findings

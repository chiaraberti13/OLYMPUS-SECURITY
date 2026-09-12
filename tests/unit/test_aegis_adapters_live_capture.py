"""Parser validation against REAL captured scanner output (§1.1 / §3.1).

The roadmap's discipline is "nessuna fixture inventata": every adapter parser
must be exercised against output a real tool actually produced. The three
fixtures under ``tests/fixtures/aegis/live/`` were captured on 2026-09-12 by
running the installed tools against a local authorized target — a throwaway
``python -m http.server`` bound to ``127.0.0.1`` — and saved verbatim:

* ``whatweb.txt`` — ``whatweb --color=never http://127.0.0.1:PORT``
  (run under the system Ruby; the fingerprint line is byte-for-byte real).
* ``wafw00f.json`` — ``wafw00f -o - -f json http://127.0.0.1:PORT`` on a target
  with no WAF, so the parser's negative path is what a real "None" result gives.
* ``nmap_open.xml`` — ``nmap -Pn -sV --version-light -p 9090 -oX - 127.0.0.1``
  with the local server listening, so an open port with a probed service banner
  is real, not synthesised.
* ``testssl.json`` — ``testssl --quiet --color 0 --jsonfile <f> --severity LOW
  127.0.0.1:9443`` against a local HTTPS server using a freshly generated
  self-signed certificate, so the TLS findings (self-signed chain, missing SAN,
  URI mismatch) are what testssl really reports for that endpoint.

These prove the parsers handle the real tools' actual grammar, not an idealised
sample. The live *execution* path (scope gating, sandbox) is covered separately;
here the concern is faithful parsing of genuine output.
"""

from __future__ import annotations

from pathlib import Path

from olympus.aegis.adapters.nmap import NmapAdapter
from olympus.aegis.adapters.testssl import TestsslAdapter
from olympus.aegis.adapters.wafw00f import Wafw00fAdapter
from olympus.aegis.adapters.whatweb import WhatwebAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import Severity

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "aegis" / "live"


def _out(stdout: str = "", stderr: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr=stderr)


def _req(**kw: object) -> ScanRequest:
    base: dict[str, object] = {"scanner": "x", "target": "127.0.0.1", "allowed": ("127.0.0.1",)}
    base.update(kw)
    return ScanRequest(**base)  # type: ignore[arg-type]


def test_whatweb_parser_reads_a_real_fingerprint_line() -> None:
    captured = (_FIXTURES / "whatweb.txt").read_text(encoding="utf-8")
    findings = WhatwebAdapter().parse(_out(captured), "127.0.0.1", _req())
    # The real line discloses HTTPServer[SimpleHTTP/0.6 Python/3.11.15]; that is
    # the one _INTERESTING plugin carrying a detail, so exactly one finding.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.INFO
    assert finding.title.startswith("Technology disclosed: HTTPServer")
    assert any("SimpleHTTP" in item for item in finding.evidence)


def test_wafw00f_parser_reports_nothing_when_no_waf_is_present() -> None:
    captured = (_FIXTURES / "wafw00f.json").read_text(encoding="utf-8")
    # A real "detected: false" result must parse cleanly and yield zero findings
    # (absence of a WAF is not itself a finding), never raise.
    findings = Wafw00fAdapter().parse(_out(captured), "127.0.0.1", _req())
    assert findings == []


def test_nmap_parser_reads_a_real_open_port_and_service_banner() -> None:
    captured = (_FIXTURES / "nmap_open.xml").read_text(encoding="utf-8")
    findings = NmapAdapter().parse(_out(captured), "127.0.0.1", _req())
    assert len(findings) == 1
    finding = findings[0]
    assert "9090/tcp" in finding.title or "9090" in finding.title
    assert any(item == "port=9090/tcp" for item in finding.evidence)
    # nmap -sV probed the real service: SimpleHTTPServer 0.6.
    assert any("SimpleHTTPServer" in item for item in finding.evidence)


def test_testssl_parser_reads_real_tls_findings_for_a_self_signed_endpoint() -> None:
    captured = (_FIXTURES / "testssl.json").read_text(encoding="utf-8")
    findings = TestsslAdapter().parse(_out(captured), "127.0.0.1", _req())
    # The real scan of a self-signed endpoint yields several severity-bearing
    # findings; the self-signed chain of trust is the CRITICAL one.
    assert findings, "expected testssl to report severity findings"
    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert any("self signed" in f.description.lower() for f in critical)
    # every emitted finding carries the testssl id and severity in its evidence
    assert all(
        any(item.startswith("id=") for item in f.evidence)
        and any(item.startswith("severity=") for item in f.evidence)
        for f in findings
    )

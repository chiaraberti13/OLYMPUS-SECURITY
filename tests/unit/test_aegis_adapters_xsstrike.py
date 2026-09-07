"""Parser tests for the xsstrike adapter.

Fixtures are real captured output, produced by running XSStrike through
``olympus aegis run`` against a matched pair of local authorized lab targets: a
server on ``127.0.0.1:8096`` that reflects ``q`` unescaped, and one on
``127.0.0.1:8095`` that HTML-escapes it. The escaping target returns zero
findings — reflections and payloads alone are not proof. See
``docs/aegis-execution-evidence.md``.
"""

from __future__ import annotations

from olympus.aegis.adapters.xsstrike import XsstrikeAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import Severity

# A confirmed vector: payload printed, then Efficiency 100 (byte-for-byte reflect).
XSSTRIKE_VULN = (
    "[+] WAF Status: Offline\n"
    "[!] Testing parameter: q\n"
    "[!] Reflections found: 1\n"
    "[~] Analysing reflections\n"
    "[+] Payload: <deTAils/+/oNtoGglE%0a=%0a(prompt)``%0dx//\n"
    "[!] Efficiency: 100\n"
    "[!] Confidence: 10\n"
)
# A safe target: reflections and payload candidates appear, but efficiency
# tops out below 100 because the server escapes the output.
XSSTRIKE_SAFE = (
    "[!] Testing parameter: q\n"
    "[!] Reflections found: 1\n"
    "[~] Analysing reflections\n"
    "[+] Payload: <html/+/onmOUSeOVer%0a=%0aconfirm()//\n"
    "[!] Efficiency: 92\n"
    "[!] Confidence: 10\n"
    "[+] Payload: <html/+/oNpoiNTerenteR%09=%09(prompt)``>\n"
    "[!] Efficiency: 94\n"
    "[!] Confidence: 10\n"
)


def _out(stdout: str = "", stderr: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr=stderr)


def _req(**kw: object) -> ScanRequest:
    base: dict[str, object] = {"scanner": "x", "target": "127.0.0.1", "allowed": ("127.0.0.1",)}
    base.update(kw)
    return ScanRequest(**base)  # type: ignore[arg-type]


def test_xsstrike_parser_confirms_a_reflected_xss() -> None:
    findings = XsstrikeAdapter().parse(_out(XSSTRIKE_VULN), "127.0.0.1", _req())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.title == "Reflected XSS in parameter q"
    assert "efficiency=100" in finding.evidence
    assert "parameter=q" in finding.evidence


def test_xsstrike_parser_treats_an_escaping_target_as_clean() -> None:
    """The decisive test: reflections and payloads without efficiency 100 are not a vuln."""
    assert XsstrikeAdapter().parse(_out(XSSTRIKE_SAFE), "127.0.0.1", _req()) == []


def test_xsstrike_parser_does_not_flag_on_reflections_alone() -> None:
    reflection_only = "[!] Testing parameter: q\n[!] Reflections found: 1\n"
    assert XsstrikeAdapter().parse(_out(reflection_only), "127.0.0.1", _req()) == []


def test_xsstrike_parser_reports_one_finding_per_parameter() -> None:
    doubled = XSSTRIKE_VULN + (
        "[+] Payload: <svg/onload=confirm()>\n[!] Efficiency: 100\n[!] Confidence: 10\n"
    )
    # Two confirmed payloads, same parameter q → one finding.
    assert len(XsstrikeAdapter().parse(_out(doubled), "127.0.0.1", _req())) == 1


def test_xsstrike_parser_separates_two_parameters() -> None:
    two = XSSTRIKE_VULN + (
        "[!] Testing parameter: search\n"
        "[+] Payload: <svg/onload=confirm()>\n[!] Efficiency: 100\n[!] Confidence: 10\n"
    )
    findings = XsstrikeAdapter().parse(_out(two), "127.0.0.1", _req())
    params = {item.split("=", 1)[1] for f in findings for item in f.evidence
              if item.startswith("parameter=")}
    assert params == {"q", "search"}


def test_xsstrike_parser_truncates_the_reflected_payload() -> None:
    huge = (
        "[!] Testing parameter: q\n"
        f"[+] Payload: {'A' * 5000}\n[!] Efficiency: 100\n"
    )
    finding = XsstrikeAdapter().parse(_out(huge), "127.0.0.1", _req())[0]
    payload = next(item for item in finding.evidence if item.startswith("payload="))
    assert len(payload) <= len("payload=") + 300
    assert "A" * 5000 not in finding.title


def test_xsstrike_parser_ignores_an_efficiency_without_a_payload() -> None:
    """A stray efficiency reading must not synthesize a finding."""
    stray = "[!] Testing parameter: q\n[!] Efficiency: 100\n"
    assert XsstrikeAdapter().parse(_out(stray), "127.0.0.1", _req()) == []


def test_xsstrike_argv_is_non_interactive() -> None:
    argv = XsstrikeAdapter().build_argv("127.0.0.1", _req(target="http://127.0.0.1/?q=1"))
    assert "--skip" in argv and "--skip-dom" in argv

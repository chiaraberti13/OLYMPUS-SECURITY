"""Output grammar / canonical states for the JSON-report adapters (TOOLS-4.4).

These check that wapiti, wafw00f and testssl never read unexpected or incomplete
output as a clean result. The clean-path parse of each real captured fixture
lives in ``test_themis_adapters_live_capture.py``; the synthetic inputs here
follow each tool's real JSON structure but carry the anomalies a real run can
produce (a malformed report record, a non-object finding, a FATAL scan-error
row). Informational rows a tool emits by design (testssl's OK/INFO) stay expected
noise and must never inflate a run into a false partial.
"""

from __future__ import annotations

import json
from pathlib import Path

from olympus.themis.adapters.testssl import TestsslAdapter
from olympus.themis.adapters.wafw00f import Wafw00fAdapter
from olympus.themis.adapters.wapiti import WapitiAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "themis" / "live"


def _out(stdout: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr="")


def _req() -> ScanRequest:
    return ScanRequest(  # type: ignore[arg-type]
        scanner="x", target="127.0.0.1", allowed=("127.0.0.1",)
    )


# --- wapiti ----------------------------------------------------------------- #


def test_wapiti_clean_report_is_not_partial() -> None:
    captured = (_FIXTURES / "wapiti.json").read_text(encoding="utf-8")
    adapter = WapitiAdapter()
    adapter.parse(_out(captured), "127.0.0.1", _req())
    assert adapter.coverage_loss(_out(captured), _req()) is None


def test_wapiti_a_malformed_category_makes_the_run_partial() -> None:
    # A category whose value is not a list of findings is unexpected grammar.
    report = json.dumps({"vulnerabilities": {"SQL Injection": "oops-not-a-list"}})
    adapter = WapitiAdapter()
    adapter.parse(_out(report), "127.0.0.1", _req())
    reason = adapter.coverage_loss(_out(report), _req())
    assert reason is not None
    assert "1 wapiti report record(s)" in reason


def test_wapiti_a_non_object_finding_makes_the_run_partial() -> None:
    report = json.dumps({"vulnerabilities": {"XSS": ["not-an-object"]}})
    adapter = WapitiAdapter()
    assert adapter.parse(_out(report), "127.0.0.1", _req()) == []
    reason = adapter.coverage_loss(_out(report), _req())
    assert reason is not None
    assert "1 wapiti report record(s)" in reason


# --- wafw00f ---------------------------------------------------------------- #


def test_wafw00f_no_waf_detected_is_not_partial() -> None:
    captured = (_FIXTURES / "wafw00f.json").read_text(encoding="utf-8")
    adapter = Wafw00fAdapter()
    assert adapter.parse(_out(captured), "127.0.0.1", _req()) == []
    assert adapter.coverage_loss(_out(captured), _req()) is None


def test_wafw00f_a_non_object_element_makes_the_run_partial() -> None:
    adapter = Wafw00fAdapter()
    assert adapter.parse(_out('["unexpected string element"]'), "127.0.0.1", _req()) == []
    reason = adapter.coverage_loss(_out('["unexpected string element"]'), _req())
    assert reason is not None
    assert "1 wafw00f output record(s)" in reason


# --- testssl ---------------------------------------------------------------- #


def test_testssl_real_findings_are_not_partial() -> None:
    # The real fixture (captured with --severity LOW) holds only severity-bearing
    # rows, so a genuine finding-bearing run is never turned into a false partial.
    captured = (_FIXTURES / "testssl.json").read_text(encoding="utf-8")
    adapter = TestsslAdapter()
    assert adapter.parse(_out(captured), "127.0.0.1", _req())
    assert adapter.coverage_loss(_out(captured), _req()) is None


def test_testssl_informational_rows_are_not_partial() -> None:
    # OK/INFO/DEBUG are passed-check rows testssl emits by design: expected noise,
    # never a discarded record.
    data = json.dumps(
        [
            {"id": "cipherlist", "severity": "OK", "finding": "no weak ciphers"},
            {"id": "service", "severity": "INFO", "finding": "HTTP"},
        ]
    )
    adapter = TestsslAdapter()
    assert adapter.parse(_out(data), "127.0.0.1", _req()) == []
    assert adapter.coverage_loss(_out(data), _req()) is None


def test_testssl_a_fatal_scan_error_makes_the_run_partial() -> None:
    # FATAL is a scan error, not a passed check: it must surface as partial so a
    # TLS result that is missing because the scan broke never reads as clean.
    data = json.dumps(
        [
            {"id": "cert_chain", "severity": "HIGH", "finding": "self-signed"},
            {"id": "scanProblem", "severity": "FATAL", "finding": "cannot connect"},
        ]
    )
    adapter = TestsslAdapter()
    findings = adapter.parse(_out(data), "127.0.0.1", _req())
    assert len(findings) == 1
    reason = adapter.coverage_loss(_out(data), _req())
    assert reason is not None
    assert "1 testssl output record(s)" in reason

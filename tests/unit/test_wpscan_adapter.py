"""Offline tests for the WPScan adapter (RED-2).

The JSON below is a small, **synthetic but format-faithful** WPScan
``--format json`` report (no real target or data): a core version vulnerability,
a theme vulnerability, a plugin vulnerability and an interesting finding. These
prove the parser extracts each component's vulnerabilities, preserves references
and never invents a severity. This is offline evidence only — the adapter stays
``adapter-ready`` until exercised against recorded real WPScan output.
"""

from __future__ import annotations

import json

import pytest

from olympus.core.enums import Severity
from olympus.themis.adapters import wpscan as wpscan_module
from olympus.themis.adapters.wpscan import WpscanAdapter
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_REPORT = json.dumps(
    {
        "version": {
            "number": "5.8",
            "status": "insecure",
            "vulnerabilities": [
                {
                    "title": "WordPress 5.8 - Core stored XSS",
                    "fixed_in": "5.8.1",
                    "references": {"cve": ["2021-1234"], "url": ["https://wpscan.com/vuln/x"]},
                }
            ],
        },
        "main_theme": {
            "slug": "twentytwenty",
            "vulnerabilities": [
                {
                    "title": "Theme arbitrary file read",
                    "fixed_in": "1.9",
                    "references": {"cve": ["2020-5678"]},
                }
            ],
        },
        "plugins": {
            "contact-form-7": {
                "slug": "contact-form-7",
                "vulnerabilities": [
                    {
                        "title": "CF7 unrestricted file upload",
                        "fixed_in": "5.3.2",
                        "references": {"url": ["https://wpscan.com/vuln/y"]},
                    }
                ],
            }
        },
        "interesting_findings": [
            {
                "url": "http://demo.lab.invalid/robots.txt",
                "to_s": "robots.txt available",
                "type": "robots_txt",
            }
        ],
    }
)


def _request() -> ScanRequest:
    return ScanRequest(
        scanner="wpscan", target="127.0.0.1", target_kind="host", allowed=("127.0.0.1",)
    )


def _parse(stdout: str) -> list:
    return WpscanAdapter().parse(
        CommandOutput(exit_code=0, stdout=stdout, stderr=""), "127.0.0.1", _request()
    )


def test_wpscan_parser_extracts_core_theme_plugin_and_interesting() -> None:
    findings = _parse(_REPORT)
    titles = [f.title for f in findings]
    assert any("WordPress core:" in t and "Core stored XSS" in t for t in titles)
    assert any("theme twentytwenty:" in t for t in titles)
    assert any("plugin contact-form-7:" in t for t in titles)
    assert any(f.severity is Severity.INFO for f in findings)  # the interesting finding

    core = next(f for f in findings if "WordPress core:" in f.title)
    assert core.severity is Severity.MEDIUM  # disclosed vuln, no fabricated score
    assert "CVE-2021-1234" in core.evidence
    assert "fixed_in=5.8.1" in core.evidence


def test_wpscan_parser_rejects_malformed_output() -> None:
    for bad in ("", "   ", "not json", "[]", '{"version": 5}' * 0 + "{" * 400):
        with pytest.raises((ParseError, ValueError)):
            _parse(bad)


def test_wpscan_parser_tolerates_unexpected_shape() -> None:
    # A well-formed object with no vulnerability containers yields no findings,
    # never a crash or an invented result.
    assert _parse('{"unexpected": "shape"}') == []


def test_wpscan_parser_aborted_scan_is_failed_not_clean() -> None:
    # WPScan aborts (target not WordPress, blocked, rate-limited, ...) with a valid
    # JSON object carrying scan_aborted and no vulnerability data. That is not a
    # clean "no vulnerability" verdict — the site was never assessed — so it must
    # fail closed with WPScan's own reason (TOOLS-4.4), never read as clean.
    report = json.dumps(
        {
            "target_url": "http://demo.lab.invalid/",
            "scan_aborted": "The remote website is up, but does not seem to be running WordPress.",
        }
    )
    with pytest.raises(ParseError, match="aborted the scan"):
        _parse(report)


def test_wpscan_parser_a_normal_report_is_not_treated_as_aborted() -> None:
    # The full synthetic report has no scan_aborted and must still parse cleanly,
    # so a real scan is never mistaken for an aborted one.
    assert _parse(_REPORT)


def test_build_argv_is_shell_free_and_omits_token_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wpscan_module, "get_env", lambda _key: "")
    argv = WpscanAdapter().build_argv("127.0.0.1", _request())
    assert argv[:1] == ["wpscan"]
    assert "--format" in argv and "json" in argv
    assert "--api-token" not in argv
    assert "http://127.0.0.1" in argv  # host carried as one atomic token


def test_build_argv_appends_token_only_from_the_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        wpscan_module,
        "get_env",
        lambda key: "SECRET-TOKEN" if key == "THEMIS_WPSCAN_API_TOKEN" else "",
    )
    argv = WpscanAdapter().build_argv("127.0.0.1", _request())
    assert "--api-token" in argv
    assert argv[argv.index("--api-token") + 1] == "SECRET-TOKEN"

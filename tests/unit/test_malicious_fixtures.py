"""Run the versioned adversarial fixture corpus against Olympus' defenses (SEC-H).

The files under ``tests/fixtures/malicious/`` are a committed corpus of
attacker-controlled inputs — an XML entity bomb, over-deep XML and JSONL, an
ANSI/OSC terminal-injection banner, an XSS payload used as a finding title, and
path-traversal filenames. Every assertion below is exercised by the ordinary
unit suite, so each defense is proven on every CI run and any regression fails
the build. Nothing network-active runs: only parsers, report renderers and the
output-path guard are invoked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.core.paths import output_path
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput
from olympus.vulcan.report import render_html, render_markdown

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "malicious"


def _fixture(name: str) -> str:
    return (_CORPUS / name).read_text(encoding="utf-8")


def _out(text: str) -> CommandOutput:
    return CommandOutput(exit_code=0, stdout=text, stderr="")


def _req() -> ScanRequest:
    return ScanRequest(scanner="x", target="127.0.0.1", allowed=("127.0.0.1",))


def test_corpus_is_present() -> None:
    """Guard against the corpus going missing and the suite silently passing."""
    expected = {
        "nmap_entity_bomb.xml",
        "nmap_deep_nesting.xml",
        "nuclei_deep_nesting.jsonl",
        "ansi_osc_banner.txt",
        "xss_title.txt",
        "path_traversal_filenames.txt",
    }
    assert expected <= {path.name for path in _CORPUS.iterdir()}


def test_nmap_rejects_xml_entity_bomb() -> None:
    # defusedxml forbids entity expansion, so the billion-laughs payload never
    # inflates: the parser fails closed instead.
    with pytest.raises(ParseError):
        NmapAdapter().parse(_out(_fixture("nmap_entity_bomb.xml")), "127.0.0.1", _req())


def test_nmap_rejects_over_deep_xml() -> None:
    with pytest.raises(ParseError, match="depth limit"):
        NmapAdapter().parse(_out(_fixture("nmap_deep_nesting.xml")), "127.0.0.1", _req())


def test_nmap_normalizes_unknown_declared_encoding() -> None:
    # A malformed encoding declaration makes ElementTree raise LookupError,
    # not ParseError. Keep that decoder detail inside the adapter boundary.
    hostile_xml = '<?xml version="1.0" encoding="XTF-8"?><nmaprun />'
    with pytest.raises(ParseError, match="unparseable"):
        NmapAdapter().parse(_out(hostile_xml), "127.0.0.1", _req())


def test_nuclei_rejects_over_deep_jsonl() -> None:
    with pytest.raises(ParseError, match="depth limit"):
        NucleiAdapter().parse(_out(_fixture("nuclei_deep_nesting.jsonl")), "127.0.0.1", _req())


def test_report_exports_neutralize_ansi_banner() -> None:
    banner = _fixture("ansi_osc_banner.txt")
    asset = Asset(asset_type=AssetType.HOST, hostname="host", source=Source.ARGUS)
    finding = Finding(asset_id="AST-1", source=Source.ARTEMIS, title=banner, severity=Severity.HIGH)
    for render in (render_html, render_markdown):
        rendered = render("eng", [asset], [finding], [])
        for control in ("\x1b", "\x07", "\x7f", "\x08"):
            assert control not in rendered


def test_html_report_escapes_xss_title_and_ships_csp() -> None:
    xss = _fixture("xss_title.txt")
    asset = Asset(asset_type=AssetType.HOST, hostname="host", source=Source.ARGUS)
    finding = Finding(asset_id="AST-1", source=Source.ARTEMIS, title=xss, severity=Severity.HIGH)
    html_doc = render_html("eng", [asset], [finding], [])
    assert "<script" not in html_doc.lower()  # no executable markup survives
    assert "&lt;script&gt;" in html_doc  # the payload is present only as escaped text
    assert "Content-Security-Policy" in html_doc


def test_output_path_rejects_every_traversal_filename() -> None:
    names = _fixture("path_traversal_filenames.txt").splitlines()
    assert names  # the fixture must not be empty
    for name in names:
        with pytest.raises(ValueError):
            output_path(name)

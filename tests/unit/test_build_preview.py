"""Tests for the static Vercel preview generator (WEB-K-a)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_preview.py"
PUBLIC = ROOT / "public"
PAGES = ("index.html", "tools.html", "report.html", "attack.html", "apollo.html", "metis.html")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_committed_preview_is_current() -> None:
    # Drift gate: the committed public/ must match a fresh generation, like the
    # CLI reference and scanner matrix. If this fails, run build_preview.py.
    result = _run("--check")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("name", PAGES)
def test_each_page_is_a_self_contained_document(name: str) -> None:
    text = (PUBLIC / name).read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "Content-Security-Policy" in text
    # No raw terminal control bytes reach the static output.
    assert "\x1b" not in text


def test_pages_carry_the_preview_banner_and_no_execution_claim() -> None:
    for name in ("index.html", "tools.html"):
        text = (PUBLIC / name).read_text(encoding="utf-8")
        assert "Anteprima statica" in text
        assert "nessuna esecuzione" in text


def test_tools_page_renders_the_capability_states() -> None:
    text = (PUBLIC / "tools.html").read_text(encoding="utf-8")
    # The three honest coverage states appear as pills.
    for state in ("present", "simulated", "missing"):
        assert f"pill {state}" in text
    # And the suite capabilities are named.
    for title in ("Port Scanner", "SSL/TLS Scanner", "Password Auditor"):
        assert title in text


def test_report_page_is_the_real_report_format_on_synthetic_data() -> None:
    text = (PUBLIC / "report.html").read_text(encoding="utf-8")
    assert "Security report" in text
    assert "Demo engagement (synthetic)" in text
    # Fictitious host, never a real target.
    assert "demo.lab.invalid" in text


def test_generator_writes_all_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A plain run (no --check) regenerates the pages in place and reports success.
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Wrote 9 page(s)" in result.stdout
    for name in PAGES:
        assert (PUBLIC / name).exists()


# --- WEB-K-c: fixture-driven interactive demo -------------------------------


def test_demo_page_is_fixture_driven_and_labelled_as_demo() -> None:
    text = (PUBLIC / "demo.html").read_text(encoding="utf-8")
    assert "DEMO — nessuna esecuzione, dati sintetici" in text
    # Real parsers over recorded fixtures: CT names and nmap finding appear.
    assert "portal.olympusdemocorp.example" in text
    assert "SimpleHTTPServer" in text or "9090" in text
    for stage in ("recon", "scan", "enrich", "report"):
        assert f"<h3>{['recon', 'scan', 'enrich', 'report'].index(stage) + 1}. {stage} " in text
    # Without JavaScript every outcome is shown (progressive enhancement).
    assert "queued" in (PUBLIC / "demo.js").read_text(encoding="utf-8")


def test_demo_script_is_same_origin_only_and_makes_no_network_calls() -> None:
    page = (PUBLIC / "demo.html").read_text(encoding="utf-8")
    assert "<script src='demo.js'></script>" in page
    assert "script-src 'self'" in page
    script = (PUBLIC / "demo.js").read_text(encoding="utf-8")
    for forbidden in ("fetch(", "XMLHttpRequest", "WebSocket", "eval(", "innerHTML", "http"):
        assert forbidden not in script


def test_demo_report_uses_the_real_renderer() -> None:
    text = (PUBLIC / "demo-report.html").read_text(encoding="utf-8")
    assert "Security report" in text
    assert "mars.lab.invalid" in text


def test_attack_preview_labels_automatic_synthetic_mapping() -> None:
    text = (PUBLIC / "attack.html").read_text(encoding="utf-8")
    assert "DEMO · dati sintetici" in text
    assert "T1190" in text and "derived from CWE-89" in text
    assert "non dimostrano attacchi avvenuti" in text


def test_metis_preview_uses_the_real_stix_parser() -> None:
    text = (PUBLIC / "metis.html").read_text(encoding="utf-8")
    assert "Metis CTI import workbench" in text
    # Faithful IOCs recovered by the real parser from the synthetic bundle.
    assert "malware.example" in text
    assert "CVE-2026-12345" in text
    # The compound STIX pattern is refused, not guessed.
    assert "compound or unmapped pattern" in text
    assert "non effettua alcuna chiamata di rete" in text


def test_apollo_preview_uses_the_real_bundled_rule_pack() -> None:
    text = (PUBLIC / "apollo.html").read_text(encoding="utf-8")
    assert "Apollo detection workbench" in text
    assert "APL-SYSMON-C2-DNS" in text
    assert "loader Apollo reale" in text
    assert "non è possibile inviare dati" in text


def test_vercel_headers_allow_script_only_on_the_demo_route() -> None:
    import json
    import re

    config = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    rules = {rule["source"]: rule["headers"] for rule in config["headers"]}

    def csp(source: str) -> str:
        return next(h["value"] for h in rules[source] if h["key"] == "Content-Security-Policy")

    demo = next(src for src in rules if "demo" in src and src.startswith("/demo"))
    default = next(src for src in rules if src != demo)
    assert "script-src 'self'" in csp(demo)
    assert "script-src" not in csp(default)
    # The catch-all rule must not also match the demo route (headers would merge).
    assert re.fullmatch(default, "/demo") is None
    assert re.fullmatch(default, "/demo.html") is None
    assert re.fullmatch(default, "/tools") is not None

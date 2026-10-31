"""Tests for the static Vercel preview generator (WEB-K-a)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_preview.py"
PUBLIC = ROOT / "public"
PAGES = ("index.html", "tools.html", "report.html")


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
    assert "Wrote 3 page(s)" in result.stdout
    for name in PAGES:
        assert (PUBLIC / name).exists()

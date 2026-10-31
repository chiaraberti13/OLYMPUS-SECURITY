"""Tests for the internal documentation link checker (DEV-G)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_doc_links.py"


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def test_repository_has_no_broken_internal_links() -> None:
    """The first-party Markdown tree must have no broken links or anchors."""
    result = _run(ROOT)
    assert result.returncode == 0, result.stderr
    assert "Documentation links OK" in result.stdout


def test_detects_broken_file_link(tmp_path: Path) -> None:
    doc = tmp_path / "a.md"
    doc.write_text("# Title\n\n[gone](./missing.md)\n", encoding="utf-8")
    result = _run(tmp_path, str(doc))
    assert result.returncode == 1
    assert "broken link" in result.stderr


def test_detects_missing_anchor(tmp_path: Path) -> None:
    doc = tmp_path / "a.md"
    doc.write_text("# Real Heading\n\n[nope](#not-a-heading)\n", encoding="utf-8")
    result = _run(tmp_path, str(doc))
    assert result.returncode == 1
    assert "anchor" in result.stderr


def test_accepts_valid_links_and_ignores_external(tmp_path: Path) -> None:
    target = tmp_path / "other.md"
    target.write_text("# Section One\n", encoding="utf-8")
    doc = tmp_path / "a.md"
    doc.write_text(
        "# Home\n\n"
        "[self](#home)\n"
        "[file](./other.md)\n"
        "[cross](./other.md#section-one)\n"
        "[ext](https://example.com/page)\n"
        "[mail](mailto:x@example.com)\n",
        encoding="utf-8",
    )
    result = _run(tmp_path, str(doc))
    assert result.returncode == 0, result.stderr


def test_anchor_inside_code_fence_is_not_a_heading(tmp_path: Path) -> None:
    doc = tmp_path / "a.md"
    doc.write_text(
        "# Real\n\n```\n# Fake fenced heading\n```\n\n[bad](#fake-fenced-heading)\n",
        encoding="utf-8",
    )
    result = _run(tmp_path, str(doc))
    assert result.returncode == 1
    assert "anchor" in result.stderr

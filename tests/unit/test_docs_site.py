"""The static documentation site stays in sync with docs/ and self-contained (DOCS-3).

``scripts/build_docs_site.py`` renders every ``docs/**/*.md`` into a standalone HTML
page under ``public/docs/``. These tests pin the drift gate (committed site matches a
fresh build), the completeness (every source doc has a page, the index lists them
all), the self-containment (each page is a full CSP-constrained document with an
inline stylesheet, no scripts), and the Markdown renderer's core constructs.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_docs_site.py"
DOCS = ROOT / "docs"
OUT = ROOT / "public" / "docs"


def _load_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("build_docs_site", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses needs the module registered
    spec.loader.exec_module(module)
    return module


def test_committed_site_is_current() -> None:
    # Drift gate: public/docs/ must match a fresh render of docs/.
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_doc_has_a_page_and_the_index_lists_it() -> None:
    index = (OUT / "index.html").read_text(encoding="utf-8")
    for md in sorted(DOCS.rglob("*.md")):
        rel = md.relative_to(DOCS).as_posix()
        page = OUT / (rel[: -len(".md")] + ".html")
        assert page.is_file(), f"missing generated page for {rel}"
        assert rel in index, f"index does not reference {rel}"


@pytest.mark.parametrize(
    "page",
    ["index.html", "metis.html", "engines/INVENTORY.html", "architecture/README.html"],
)
def test_pages_are_self_contained_csp_documents(page: str) -> None:
    text = (OUT / page).read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>")
    assert "Content-Security-Policy" in text
    assert "<script" not in text.lower()  # CSP forbids scripts; none must be emitted
    assert "\x1b" not in text


def test_no_internal_markdown_links_survive_in_generated_pages() -> None:
    # Every relative *.md link must have been rewritten to *.html.
    broken = re.compile(r'href="(?!https?:|mailto:|#)[^"]*\.md(?:#|")')
    for page in OUT.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        assert not broken.search(text), f"un-rewritten .md link in {page.relative_to(ROOT)}"


def test_renderer_handles_core_markdown_constructs() -> None:
    render = _load_module().render_markdown
    html_out = render(
        "# Title\n\n"
        "A paragraph with **bold**, *italic*, `code` and a [link](other.md).\n\n"
        "- one\n- two\n  - nested\n\n"
        "| A | B |\n| --- | --- |\n| 1 | 2 |\n\n"
        "```\nraw <code> & stuff\n```\n\n"
        "> a quote\n"
    )
    assert '<h1 id="title">Title</h1>' in html_out
    assert "<strong>bold</strong>" in html_out and "<em>italic</em>" in html_out
    assert "<code>code</code>" in html_out
    assert 'href="other.html"' in html_out  # .md rewritten
    assert "<ul><li>one</li>" in html_out and "<ul><li>nested</li></ul>" in html_out
    assert "<table><thead><tr><th>A</th><th>B</th>" in html_out
    assert "<td>1</td><td>2</td>" in html_out
    assert "raw &lt;code&gt; &amp; stuff" in html_out  # code fence escaped, not executed
    assert "<blockquote>" in html_out


def test_renderer_drops_html_comments() -> None:
    render = _load_module().render_markdown
    assert "SECRET" not in render("before <!-- SECRET --> after")

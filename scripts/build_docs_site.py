#!/usr/bin/env python3
"""Generate a static, self-contained documentation site from ``docs/`` (DOCS-3).

The same Markdown tree under ``docs/`` is rendered to standalone HTML pages under
``public/docs/`` so it can be served with no server and no build step — by Vercel
(``public/`` is its output directory) or by GitHub Pages
(``.github/workflows/docs-site.yml``). Every page is a complete document with an
**inline** stylesheet and the same restrictive Content-Security-Policy as the rest
of ``public/`` (``default-src 'none'; style-src 'unsafe-inline'``): no scripts, no
remote assets, so the Markdown is rendered **server-side** here, never in the
browser.

The site chrome (landing page, navigation, section labels) is **bilingual IT/EN**;
each document is rendered in whatever language it is written in — no machine
translation of the bodies. Internal ``*.md`` links are rewritten to ``*.html`` so
navigation works in the static site.

Run ``python scripts/build_docs_site.py`` to (re)generate ``public/docs/``, or
``--check`` to verify the committed output is current (a drift gate, like the CLI
reference, scanner matrix and the Vercel preview).
"""

from __future__ import annotations

import argparse
import html
import posixpath
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = ROOT / "public" / "docs"

#: One deterministic timestamp so regenerating without changes is a no-op.
_GENERATED = datetime(2026, 1, 1, tzinfo=UTC)

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:60rem;margin:0 auto;"
    "padding:0 1rem 3rem;color:#111;line-height:1.6}"
    "header{padding:1.5rem 0 .5rem}h1{margin:.2rem 0}h2{margin-top:2rem}"
    "h3{margin-top:1.5rem}a{color:#1d4ed8}"
    "nav{display:flex;gap:1rem;flex-wrap:wrap;margin:.5rem 0 1rem;font-size:.9rem}"
    "code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem;font-size:.9em}"
    "pre{background:#f3f4f6;padding:.8rem 1rem;border-radius:.5rem;overflow:auto}"
    "pre code{background:none;padding:0}"
    "blockquote{border-left:.25rem solid #d1d5db;margin:.8rem 0;padding:.2rem 1rem;color:#374151}"
    "table{border-collapse:collapse;width:100%;margin:.8rem 0;display:block;overflow:auto}"
    "td,th{border:1px solid #ddd;padding:.35rem .6rem;text-align:left;vertical-align:top;"
    "font-size:.9rem}th{background:#f3f4f6}"
    "hr{border:none;border-top:1px solid #e5e7eb;margin:2rem 0}"
    ".lead{color:#374151}.section{margin-top:1.5rem}.section h2{margin-bottom:.3rem}"
    "ul.docs{list-style:none;padding-left:0}ul.docs li{margin:.2rem 0}"
    "footer{margin-top:3rem;color:#666;font-size:.85rem;border-top:1px solid #eee;padding-top:1rem}"
    "@media (prefers-color-scheme:dark){body{background:#0b0f19;color:#e5e7eb}"
    "a{color:#93c5fd}code,pre{background:#1f2937}th{background:#1f2937}"
    "td,th{border-color:#374151}blockquote{border-color:#374151;color:#9ca3af}"
    "hr{border-color:#374151}.lead{color:#9ca3af}}"
)


# --------------------------------------------------------------------------- #
# Minimal, deterministic Markdown -> HTML renderer (no third-party dependency).
# Covers the constructs the docs actually use: ATX headings, paragraphs, fenced
# code, blockquotes, GFM tables, ordered/unordered (nested) lists, horizontal
# rules, and inline code/bold/italic/links/images. Raw HTML is escaped; HTML
# comments are dropped.
# --------------------------------------------------------------------------- #

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_LIST_ITEM = re.compile(r"^(?P<indent>\s*)(?P<marker>[-*+]|\d+\.)\s+(?P<body>.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$")
_HR = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITALIC = re.compile(r"(?<![\w*])[*_](?!\s)(.+?)(?<!\s)[*_](?![\w*])")
_CODE_SPAN = re.compile(r"`([^`]+)`")
_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _SLUG.sub("-", _strip_inline(text).lower()).strip("-")


def _strip_inline(text: str) -> str:
    text = _IMAGE.sub(r"\1", text)
    text = _LINK.sub(r"\1", text)
    text = _BOLD.sub(r"\1", text)
    text = _CODE_SPAN.sub(r"\1", text)
    return text.replace("*", "").replace("_", "").strip()


_REPO_BLOB = "https://github.com/chiaraberti13/OLYMPUS-SECURITY/blob/main/"

#: Repo-relative directory of the doc currently being rendered (e.g. "docs/engines").
#: Set per page by _build so link rewriting can resolve relative targets.
_BASE_DIR = "docs"


def _rewrite_href(href: str) -> str:
    if href.startswith(("http://", "https://", "mailto:", "#")):
        return href
    anchor = ""
    if "#" in href:
        href, anchor = href.split("#", 1)
        anchor = "#" + anchor
    # Resolve the target to a repo-relative path from the current doc's directory.
    base = href.lstrip("/") if href.startswith("/") else posixpath.join(_BASE_DIR, href)
    resolved = posixpath.normpath(base)
    # A link to another doc stays relative within the site, with .md -> .html so
    # the static navigation works; anything else (source files, labs, scripts, or a
    # doc that escapes docs/) points at the file on GitHub so it never dead-ends.
    if resolved.startswith("docs/") and href.endswith(".md"):
        return href[: -len(".md")] + ".html" + anchor
    return _REPO_BLOB + resolved + anchor


def _inline(text: str) -> str:
    # Protect code spans before escaping the rest, then restore as <code>.
    spans: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        spans.append(match.group(1))
        return f"\x00{len(spans) - 1}\x00"

    text = _CODE_SPAN.sub(_stash, text)
    text = html.escape(text, quote=False)
    text = _IMAGE.sub(
        lambda m: (
            f'<img src="{html.escape(_rewrite_href(m.group(2)), quote=True)}" '
            f'alt="{html.escape(m.group(1), quote=True)}">'
        ),
        text,
    )
    text = _LINK.sub(
        lambda m: (
            f'<a href="{html.escape(_rewrite_href(m.group(2)), quote=True)}">{m.group(1)}</a>'
        ),
        text,
    )
    text = _BOLD.sub(r"<strong>\1</strong>", text)
    text = _ITALIC.sub(r"<em>\1</em>", text)

    def _unstash(match: re.Match[str]) -> str:
        return f"<code>{html.escape(spans[int(match.group(1))], quote=False)}</code>"

    return re.sub(r"\x00(\d+)\x00", _unstash, text)


def _render_table(rows: list[str]) -> str:
    def cells(row: str) -> list[str]:
        row = row.strip()
        if row.startswith("|"):
            row = row[1:]
        if row.endswith("|"):
            row = row[:-1]
        return [c.strip() for c in row.split("|")]

    header = cells(rows[0])
    body = [cells(r) for r in rows[2:]]
    out = ["<table><thead><tr>"]
    out += [f"<th>{_inline(c)}</th>" for c in header]
    out.append("</tr></thead><tbody>")
    for line in body:
        out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in line) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _render_list(items: list[tuple[int, str, str]], start: int) -> tuple[str, int]:
    # items: (indent, marker, body). Build one list at the indent of items[start],
    # recursing into deeper-indented runs. Returns (html, next_index).
    indent = items[start][0]
    ordered = items[start][1][0].isdigit()
    tag = "ol" if ordered else "ul"
    out = [f"<{tag}>"]
    i = start
    while i < len(items):
        item_indent, _marker, body = items[i]
        if item_indent < indent:
            break
        if item_indent > indent:
            nested, i = _render_list(items, i)
            out[-1] = out[-1][:-5] + nested + "</li>"
            continue
        out.append(f"<li>{_inline(body)}</li>")
        i += 1
    out.append(f"</{tag}>")
    return "".join(out), i


def render_markdown(md: str) -> str:
    md = re.sub(r"<!--.*?-->", "", md, flags=re.DOTALL)
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.lstrip().startswith("```"):
            fence = line.lstrip()[:3]
            buf: list[str] = []
            i += 1
            while i < n and lines[i].strip() != fence:
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            out.append(f"<pre><code>{html.escape(chr(10).join(buf), quote=False)}</code></pre>")
            continue
        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            text = heading.group(2)
            out.append(f'<h{level} id="{_slug(text)}">{_inline(text)}</h{level}>')
            i += 1
            continue
        if _HR.match(line):
            out.append("<hr>")
            i += 1
            continue
        if "|" in line and i + 1 < n and _TABLE_SEP.match(lines[i + 1]):
            rows = [line, lines[i + 1]]
            i += 2
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(lines[i])
                i += 1
            out.append(_render_table(rows))
            continue
        if line.lstrip().startswith(">"):
            buf = []
            while i < n and lines[i].lstrip().startswith(">"):
                buf.append(lines[i].lstrip()[1:].lstrip())
                i += 1
            out.append(f"<blockquote>{render_markdown(chr(10).join(buf))}</blockquote>")
            continue
        if _LIST_ITEM.match(line):
            items: list[tuple[int, str, str]] = []
            while i < n and (m := _LIST_ITEM.match(lines[i])) is not None:
                items.append((len(m.group("indent")), m.group("marker"), m.group("body")))
                i += 1
            rendered, _ = _render_list(items, 0)
            out.append(rendered)
            continue
        # paragraph: gather until a blank line or a block start
        buf = [line]
        i += 1
        while i < n and lines[i].strip() and not _block_starts(lines[i], lines, i):
            buf.append(lines[i])
            i += 1
        out.append(f"<p>{_inline(' '.join(s.strip() for s in buf))}</p>")
    return "".join(out)


def _block_starts(line: str, lines: list[str], i: int) -> bool:
    if line.lstrip().startswith(("```", ">")):
        return True
    if _HEADING.match(line) or _HR.match(line) or _LIST_ITEM.match(line):
        return True
    return "|" in line and i + 1 < len(lines) and bool(_TABLE_SEP.match(lines[i + 1]))


# --------------------------------------------------------------------------- #
# Site assembly
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Doc:
    rel: str  # posix path relative to docs/, e.g. "architecture/adr-009.md"
    title: str

    @property
    def href(self) -> str:
        return self.rel[: -len(".md")] + ".html"

    @property
    def out_path(self) -> Path:
        return OUT / (self.rel[: -len(".md")] + ".html")


def _title_of(path: Path) -> str:
    for raw in path.read_text(encoding="utf-8").splitlines():
        heading = _HEADING.match(raw)
        if heading:
            return _strip_inline(heading.group(2))
    return path.stem


def _discover() -> list[Doc]:
    docs = []
    for path in sorted(DOCS.rglob("*.md")):
        rel = path.relative_to(DOCS).as_posix()
        docs.append(Doc(rel=rel, title=_title_of(path)))
    return docs


def _depth_prefix(rel: str) -> str:
    # Relative path back to public/docs/ root from a page nested under it.
    return "../" * rel.count("/")


def _page(title: str, body: str, *, up: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head><body>"
        "<header><h1>🏛️ OLYMPUS-SECURITY — Docs</h1>"
        f"<nav><a href='{up}index.html'>Index</a>"
        f"<a href='{up}../index.html'>Site home</a>"
        "<a href='https://github.com/chiaraberti13/OLYMPUS-SECURITY'>Code</a></nav>"
        "</header>"
        f"{body}"
        "<footer>Generated by <code>scripts/build_docs_site.py</code> · "
        f"{_GENERATED.strftime('%Y-%m-%d')} · source of truth: <code>docs/</code>.</footer>"
        "</body></html>"
    )


_SECTIONS = {
    "": ("General", "Generale"),
    "architecture": ("Architecture (ADRs)", "Architettura (ADR)"),
    "engines": ("Engines", "Motori"),
    "verify": ("Verification evidence", "Evidenze di verifica"),
    "apollo": ("Apollo", "Apollo"),
}


def _section_of(rel: str) -> str:
    return rel.split("/", 1)[0] if "/" in rel else ""


def _index_html(docs: Iterable[Doc]) -> str:
    groups: dict[str, list[Doc]] = {}
    for doc in docs:
        groups.setdefault(_section_of(doc.rel), []).append(doc)
    body = [
        "<p class='lead'>Static, offline documentation rendered from the "
        "<code>docs/</code> source tree. &mdash; Documentazione statica e offline "
        "generata dalla sorgente <code>docs/</code>.</p>"
    ]
    for key in sorted(groups, key=lambda k: (k != "", k)):
        en, it = _SECTIONS.get(key, (key or "General", key or "Generale"))
        label = en if en == it else f"{en} · {it}"
        body.append(f"<div class='section'><h2>{html.escape(label)}</h2><ul class='docs'>")
        for doc in sorted(groups[key], key=lambda d: d.title.lower()):
            body.append(
                f"<li><a href='{html.escape(doc.href, quote=True)}'>"
                f"{html.escape(doc.title)}</a> "
                f"<code>{html.escape(doc.rel)}</code></li>"
            )
        body.append("</ul></div>")
    return _page("OLYMPUS-SECURITY — Documentation", "".join(body), up="")


def _build() -> dict[Path, str]:
    global _BASE_DIR
    docs = _discover()
    files: dict[Path, str] = {OUT / "index.html": _index_html(docs)}
    for doc in docs:
        md = (DOCS / doc.rel).read_text(encoding="utf-8")
        up = _depth_prefix(doc.rel)
        _BASE_DIR = posixpath.dirname(f"docs/{doc.rel}")
        files[doc.out_path] = _page(doc.title, render_markdown(md), up=up)
    _BASE_DIR = "docs"
    return files


def _write(files: dict[Path, str]) -> None:
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _check(files: dict[Path, str]) -> int:
    drift: list[str] = []
    existing = set(OUT.rglob("*.html"))
    for path, text in files.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != text:
            drift.append(str(path.relative_to(ROOT)))
    stale = [str(p.relative_to(ROOT)) for p in existing - set(files)]
    if drift or stale:
        if drift:
            print("Out-of-date doc-site pages:")
            for d in sorted(drift):
                print(f"  - {d}")
        if stale:
            print("Stale doc-site pages (source removed):")
            for s in sorted(stale):
                print(f"  - {s}")
        print("Run: python scripts/build_docs_site.py")
        return 1
    print(f"Doc site is current ({len(files)} pages).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the static docs site from docs/.")
    parser.add_argument("--check", action="store_true", help="Verify committed output is current.")
    args = parser.parse_args(argv)
    files = _build()
    if args.check:
        return _check(files)
    _write(files)
    print(f"Wrote {len(files)} pages to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

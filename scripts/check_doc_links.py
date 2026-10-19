"""Fail CI on broken internal Markdown links in first-party docs (DEV-G).

Walks every first-party Markdown file (``vendor/`` and ``.git/`` excluded) and
checks each inline link ``[text](target)``:

* external links (``http``, ``https``, ``mailto``, ``tel``) and protocol-relative
  links are not followed;
* a relative file link must resolve to an existing file or directory;
* a ``#anchor`` (same file or ``path#anchor``) must match a heading in the target,
  using GitHub-style slug rules.

Autolinks and reference-style definitions are out of scope; the repository uses
inline links. Run from the repository root:

    python scripts/check_doc_links.py            # check the whole tree
    python scripts/check_doc_links.py docs/x.md  # check specific files
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_EXCLUDED_DIRS = {".git", "vendor", "node_modules", "__pycache__", ".mypy_cache"}
_EXTERNAL = ("http://", "https://", "mailto:", "tel:", "//")
# Inline links: the text in [...] then (target) where target is up to the first
# whitespace (a title) or the closing paren. Images ![...](...) are included too.
_LINK = re.compile(r"\[(?:[^\]]*)\]\(\s*([^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def iter_markdown(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*.md")):
        if any(part in _EXCLUDED_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
    return files


def _slug(heading: str) -> str:
    """GitHub-style heading slug: lowercase, drop punctuation, spaces to hyphens."""
    text = heading.strip().lower()
    # Strip Markdown emphasis/inline-code markers and links, keep link text.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").replace("*", "").replace("_", "")
    text = re.sub(r"[^\w\- ]+", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def heading_slugs(path: Path) -> set[str]:
    slugs: dict[str, int] = {}
    result: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return result
    in_fence = False
    for line in lines:
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = _HEADING.match(line)
        if not match:
            continue
        base = _slug(match.group(2))
        count = slugs.get(base, 0)
        slugs[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def check_file(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    for target in _LINK.findall(text):
        if target.startswith(_EXTERNAL) or target.startswith("data:"):
            continue
        file_part, _, anchor = target.partition("#")
        if file_part == "":
            # Pure same-file anchor.
            if anchor and _slug_missing(path, anchor):
                problems.append(f"{path}: missing anchor '#{anchor}'")
            continue
        resolved = (path.parent / file_part).resolve()
        if not resolved.exists():
            problems.append(f"{path}: broken link '{target}' -> {file_part}")
            continue
        if anchor and resolved.suffix == ".md" and _slug_missing(resolved, anchor):
            problems.append(f"{path}: '{target}' points to a missing anchor")
    return problems


def _slug_missing(path: Path, anchor: str) -> bool:
    return _slug(anchor) not in heading_slugs(path)


def main(argv: list[str]) -> int:
    root = Path.cwd()
    targets = [Path(arg) for arg in argv] if argv else iter_markdown(root)
    problems: list[str] = []
    for path in targets:
        problems.extend(check_file(path, root))
    if problems:
        print("Broken internal documentation links:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(f"Documentation links OK: checked {len(targets)} Markdown file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

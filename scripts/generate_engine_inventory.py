"""Rewrite or check the generated tables in docs/engines/INVENTORY.md.

python scripts/generate_engine_inventory.py --write
python scripts/generate_engine_inventory.py --check   # CI: exit 1 when stale
"""

from __future__ import annotations

import sys
from pathlib import Path

from olympus.engines.inventory import BLOCK_BEGIN, BLOCK_END, render_inventory_block

DOC = Path(__file__).resolve().parents[1] / "docs" / "engines" / "INVENTORY.md"


def current_document() -> str:
    return DOC.read_text(encoding="utf-8")


def rendered_document(document: str) -> str:
    start = document.index(BLOCK_BEGIN)
    end = document.index(BLOCK_END) + len(BLOCK_END)
    return document[:start] + render_inventory_block() + document[end:]


def main(argv: list[str]) -> int:
    document = current_document()
    updated = rendered_document(document)
    if "--write" in argv:
        DOC.write_text(updated, encoding="utf-8")
        return 0
    if updated != document:
        print(
            "docs/engines/INVENTORY.md is stale; run scripts/generate_engine_inventory.py --write"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

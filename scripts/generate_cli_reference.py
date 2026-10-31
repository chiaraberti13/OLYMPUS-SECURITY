"""Write (or check) docs/cli-reference.md from the Typer command tree (DEV-F).

Usage:
    python scripts/generate_cli_reference.py            # regenerate the doc
    python scripts/generate_cli_reference.py --check    # fail if the doc is stale

The ``--check`` mode is the drift gate: it exits non-zero when the committed
reference no longer matches the live command tree, so documentation stays in
step with the code instead of silently drifting.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from olympus.cli_reference import render_document

_DOC = Path(__file__).resolve().parents[1] / "docs" / "cli-reference.md"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if docs/cli-reference.md is out of date (no write).",
    )
    args = parser.parse_args()

    expected = render_document()
    if args.check:
        current = _DOC.read_text(encoding="utf-8") if _DOC.exists() else ""
        if current != expected:
            print(
                "docs/cli-reference.md is stale; run "
                "`python scripts/generate_cli_reference.py` to regenerate it.",
                file=sys.stderr,
            )
            return 1
        print("docs/cli-reference.md is current.")
        return 0

    _DOC.write_text(expected, encoding="utf-8")
    print(f"Wrote {_DOC}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Generate or verify the committed versioned JSON Schema catalog."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from olympus.schema_catalog import catalog_files, write_catalog


def _check(output: Path) -> int:
    mismatches: list[str] = []
    for relative_path, expected in catalog_files().items():
        path = output / relative_path
        if not path.is_file():
            mismatches.append(f"missing: {path}")
        elif path.read_text(encoding="utf-8") != expected:
            mismatches.append(f"stale: {path}")
    if mismatches:
        print("Schema catalog check failed:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"- {mismatch}", file=sys.stderr)
        return 1
    print(f"Schema catalog is current ({len(catalog_files()) - 2} versioned contracts).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("schemas"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        return _check(args.output)
    written = write_catalog(args.output)
    print(f"Wrote {len(written) - 2} versioned contracts and catalog to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

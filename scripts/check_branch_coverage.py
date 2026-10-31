#!/usr/bin/env python3
"""Enforce the first-party branch-coverage threshold from a coverage.py JSON report."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="coverage.py JSON report path")
    args = parser.parse_args()

    try:
        config: dict[str, Any] = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        threshold = float(config["tool"]["olympus"]["coverage"]["branch_fail_under"])
        report: dict[str, Any] = json.loads(args.report.read_text(encoding="utf-8"))
        actual = float(report["totals"]["percent_branches_covered"])
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Could not read branch coverage or threshold: {exc}", file=sys.stderr)
        return 2

    if not 0 <= threshold <= 100:
        print("Configured branch coverage threshold must be between 0 and 100", file=sys.stderr)
        return 2

    print(f"First-party branch coverage: {actual:.2f}% (minimum {threshold:.2f}%)")
    if actual < threshold:
        print("Branch coverage is below the configured threshold", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

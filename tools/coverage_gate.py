"""Run pytest with a dependency-free line coverage gate."""

from __future__ import annotations

import argparse
import os
import runpy
import sys
import trace
from pathlib import Path
from types import FrameType
from typing import Any


def _pytest_status(source_root: Path) -> tuple[int, set[tuple[str, int]]]:
    """Run pytest under tracing before pytest or application modules are imported."""
    previous_argv = sys.argv
    sys.argv = ["pytest", "-q", "-o", "addopts=-q"]
    counts: set[tuple[str, int]] = set()
    prefix = f"{source_root}{os.sep}"

    def record_line(frame: FrameType, event: str, argument: object) -> Any:
        """Trace Olympus frames while immediately ignoring dependency frames."""
        del argument
        filename = frame.f_code.co_filename
        if not filename.startswith(prefix):
            return None
        if event == "line":
            counts.add((str(Path(filename).resolve()), frame.f_lineno))
        return record_line

    status = 0
    sys.settrace(record_line)
    try:
        runpy.run_module("pytest", run_name="__main__")
    except SystemExit as exc:
        status = int(exc.code or 0)
    finally:
        sys.settrace(None)
        sys.argv = previous_argv
    return status, counts


def main() -> int:
    """Execute tests, report Olympus coverage and enforce the requested threshold."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-under", type=float, default=90.0)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    source_root = root / "src" / "olympus"
    status, counts = _pytest_status(source_root)
    executable = 0
    covered = 0
    for source in sorted(source_root.rglob("*.py")):
        lines = trace._find_executable_linenos(str(source))  # type: ignore[attr-defined]
        executable += len(lines)
        covered += sum((str(source), line) in counts for line in lines)
    percentage = 100.0 if executable == 0 else covered * 100.0 / executable
    print(f"Olympus coverage: {covered}/{executable} lines ({percentage:.1f}%)")
    if status != 0:
        return status
    if percentage < args.fail_under:
        print(f"Coverage failure: {percentage:.1f}% is below {args.fail_under:.1f}%")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

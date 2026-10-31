"""Keep the documented scanner-maturity counts in step with the ledger (DEV-G).

README.md and docs/scanner-maturity.md both publish a per-stage count of the
scanner catalogue. These are easy to let drift. The authoritative source is
``olympus.integrations.maturity.summary()``, derived from the registry and the
declarations (themselves cross-checked against the repository). These tests
parse the numbers out of the docs and assert they equal the live summary, so a
stale table fails the build instead of misleading a reader.
"""

from __future__ import annotations

import re
from pathlib import Path

from olympus.integrations.maturity import summary

ROOT = Path(__file__).resolve().parents[2]
_STAGES = ("catalog-only", "adapter-ready", "offline-tested", "live-tested", "production-ready")

# Matches a Markdown table cell `| `stage` | N |` with optional ** bold markers.
_README_ROW = re.compile(
    r"\|\s*\*{0,2}`(?P<stage>[a-z-]+)`\*{0,2}\s*\|\s*\*{0,2}(?P<count>\d+)\*{0,2}\s*\|"
)
# Matches a plain `stage   N` line in the docs/scanner-maturity.md code block.
_PLAIN_ROW = re.compile(r"^(?P<stage>[a-z-]+)\s+(?P<count>\d+)\b", re.MULTILINE)


def _counts(text: str, pattern: re.Pattern[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for match in pattern.finditer(text):
        stage = match.group("stage")
        if stage in _STAGES:
            found[stage] = int(match.group("count"))
    return found


def test_readme_maturity_counts_match_the_ledger() -> None:
    live = summary()
    documented = _counts((ROOT / "README.md").read_text(encoding="utf-8"), _README_ROW)
    # Every stage the README publishes must match; it must publish them all.
    assert documented == live, f"README drift: documented={documented} live={live}"


def test_scanner_maturity_doc_counts_match_the_ledger() -> None:
    live = summary()
    documented = _counts(
        (ROOT / "docs" / "scanner-maturity.md").read_text(encoding="utf-8"), _PLAIN_ROW
    )
    assert documented == live, f"scanner-maturity.md drift: documented={documented} live={live}"


def test_summary_totals_the_full_catalogue() -> None:
    from olympus.integrations.scanners import REGISTRY

    assert sum(summary().values()) == len(REGISTRY)

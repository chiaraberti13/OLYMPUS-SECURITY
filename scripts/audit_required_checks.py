"""Compare expected merge checks with effective GitHub rules and PR check runs."""

import argparse
import json
from pathlib import Path

EXPECTED = {
    "ruff · format · mypy (required)",
    *(f"pytest · Python 3.{minor} · Ubuntu" for minor in range(11, 15)),
    "first-party branch coverage · Python 3.11 · Ubuntu",
    "security-boundary mutation tests · Python 3.11 · Ubuntu",
    "POSIX sandbox · Python 3.11 · Ubuntu",
    "wheel · clean-install · CLI smoke",
    "native THEMIS container · no vendor · no live traffic",
    "pip-audit (blocking · runtime closure)",
    "gitleaks (blocking working-tree + history scan)",
    "CodeQL · Python · security-extended",
    "CLI smoke · Windows · Python 3.11",
    "CLI smoke · macOS · Python 3.11",
    "scanner-image gate",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha", help="Full PR head SHA")
    parser.add_argument(
        "rules", type=Path, help="JSON from GET /repos/{owner}/{repo}/rules/branches/main"
    )
    parser.add_argument(
        "checks", type=Path, help="JSON from GET /repos/{owner}/{repo}/commits/{sha}/check-runs"
    )
    args = parser.parse_args()
    rules = json.loads(args.rules.read_text(encoding="utf-8"))
    checks = json.loads(args.checks.read_text(encoding="utf-8"))
    strict = False
    required: dict[str, set[int | None]] = {}
    for rule in rules:
        if rule["type"] == "required_status_checks":
            parameters = rule["parameters"]
            strict |= parameters["strict_required_status_checks_policy"]
            for check in parameters["required_status_checks"]:
                required.setdefault(check["context"], set()).add(check.get("integration_id"))

    runs = [run for run in checks["check_runs"] if run["head_sha"] == args.sha]
    if len(checks["check_runs"]) != checks["total_count"]:
        parser.error("incomplete check-runs response; retrieve all pages")
    print(f"PR head: `{args.sha}`\n")
    print("| Check | Expected | Required | Successful on this SHA |")
    print("| --- | --- | --- | --- |")
    success = strict and required.keys() == EXPECTED
    for name in sorted(EXPECTED | required.keys()):
        sources = required.get(name, set())
        passed = bool(sources) and all(
            any(
                run["name"] == name
                and run["conclusion"] == "success"
                and (source is None or run["app"]["id"] == source)
                for run in runs
            )
            for source in sources
        )
        print(f"| {name} | {name in EXPECTED} | {bool(sources)} | {passed} |")
        success &= passed
    print(f"\nStrict branch freshness: {strict}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())

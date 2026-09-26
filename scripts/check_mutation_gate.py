"""Require every selected security-boundary mutant to be killed by tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

MUTATED_FUNCTIONS = {
    "src/olympus/athena/scope.py": ["x__reject_out_of_scope", "x_ensure_target_allowed"],
    "src/olympus/core/execution.py": [
        "x__sensitive_key",
        "x_redact_url",
        "x_redact_text",
        "x_redact_mapping",
    ],
    "src/olympus/aegis/adapters/nmap.py": ["xǁNmapAdapterǁparse"],
    "src/olympus/core/coverage.py": ["xǁCoverageǁstatus"],
    "src/olympus/athena/cli.py": ["x__exit_code_for"],
    "src/olympus/athena/domain/assessment.py": [
        "x_advance_job",
        "x_derive_terminal_state",
    ],
}


def main() -> int:
    mutants_dir = Path("mutants/src/olympus")
    errors: list[str] = []
    selected = 0
    killed = 0

    for source_path, functions in MUTATED_FUNCTIONS.items():
        metadata_path = mutants_dir / source_path.removeprefix("src/olympus/")
        metadata_path = metadata_path.with_suffix(metadata_path.suffix + ".meta")
        if not metadata_path.is_file():
            errors.append(f"mutation metadata missing: {metadata_path}")
            continue

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        statuses: dict[str, int | None] = metadata.get("exit_code_by_key", {})
        module = source_path.removeprefix("src/").removesuffix(".py").replace("/", ".")
        for function in functions:
            prefix = f"{module}.{function}__mutmut_"
            matching = {
                name: status for name, status in statuses.items() if name.startswith(prefix)
            }
            selected += len(matching)
            if not matching:
                errors.append(f"no mutants selected for {source_path}:{function}")
                continue
            unchecked = [name for name, status in matching.items() if status not in {None, 0, 1, 3}]
            if unchecked:
                errors.append(
                    f"{source_path}:{function} has {len(unchecked)} untested or invalid mutant(s): "
                    + ", ".join(unchecked[:5])
                )
            tested = {name: status for name, status in matching.items() if status in {0, 1, 3}}
            if not tested:
                errors.append(f"no executable mutants were tested for {source_path}:{function}")
                continue
            function_killed = sum(status in {1, 3} for status in tested.values())
            killed += function_killed
            score = function_killed / len(tested)
            selected += len(tested) - len(matching)
            if score < 0.35:
                errors.append(
                    f"{source_path}:{function} mutation score {score:.0%} is below the 35% floor"
                )

    if selected == 0:
        errors.append("no selected mutants were checked")
    if errors:
        print("Mutation gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Mutation gate passed: {killed}/{selected} targeted mutants killed "
        f"({killed / selected:.1%})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Plan loading and validation use cases for Athena."""

from __future__ import annotations

import json
from pathlib import Path

from olympus.athena.application.registry import UnknownAdapterError, available_adapters
from olympus.athena.domain.contracts import AssessmentPlan, PlanValidationError, load_plan


def load_plan_file(path: Path) -> AssessmentPlan:
    """Read and validate a plan JSON file into an :class:`AssessmentPlan`.

    Raises :class:`PlanValidationError` on missing/unreadable files, malformed
    JSON, contract violations, or references to adapters outside the registry.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PlanValidationError(f"plan file not found: {path}") from exc
    except OSError as exc:
        raise PlanValidationError(f"plan file could not be read: {path} ({exc})") from exc
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PlanValidationError(f"plan file is not valid JSON: {path} ({exc})") from exc

    plan = load_plan(parsed)
    unknown = [name for name in plan.adapters if name not in available_adapters()]
    if unknown:
        raise PlanValidationError(
            f"plan references unknown adapter(s) {sorted(unknown)}; "
            f"available: {list(available_adapters())}"
        )
    return plan


__all__ = ["PlanValidationError", "UnknownAdapterError", "load_plan_file"]

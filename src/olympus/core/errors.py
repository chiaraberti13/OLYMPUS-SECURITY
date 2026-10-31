"""Human- and machine-readable validation errors.

Olympus treats its data contract as a real contract: when an object fails
validation, the error must be understandable both by a person reading a
terminal and by a process parsing JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError


@dataclass(frozen=True)
class ValidationReport:
    """A structured, serializable view over a Pydantic validation failure."""

    schema: str
    errors: list[dict[str, Any]] = field(default_factory=list)
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the machine-readable form of the report."""
        return {
            "error": "schema_validation_error",
            "schema": self.schema,
            "source": self.source,
            "count": len(self.errors),
            "details": self.errors,
        }

    def to_human(self) -> str:
        """Return the human-readable form of the report."""
        header = f"Olympus Schema Validation Error ({self.schema})"
        if self.source:
            header += f"\nSource: {self.source}"
        lines = [header, f"{len(self.errors)} invalid field(s) found:"]
        for item in self.errors:
            location = ".".join(str(part) for part in item.get("loc", ()))
            message = item.get("msg", "invalid value")
            lines.append(f"  - {location or '<root>'}: {message}")
        return "\n".join(lines)


def format_validation_error(
    exc: ValidationError,
    *,
    schema: str,
    source: str | None = None,
) -> ValidationReport:
    """Convert a Pydantic ``ValidationError`` into a :class:`ValidationReport`."""
    details: list[dict[str, Any]] = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]
    return ValidationReport(schema=schema, errors=details, source=source)

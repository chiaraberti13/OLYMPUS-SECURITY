"""Validated acquisition provenance for custody records."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from olympus.core.coverage import RunStatus
from olympus.core.execution import redact_mapping, redact_text


def _validate_command_template(value: tuple[str, ...]) -> tuple[str, ...]:
    if any(
        not item or len(item) > 500 or any(character in item for character in "\r\n\x00")
        for item in value
    ):
        raise ValueError("command template arguments must be non-empty bounded single-line text")
    if tuple(redact_text(item) for item in value) != value:
        raise ValueError("command template must contain placeholders, not secret values")
    for index, item in enumerate(value):
        if not item.startswith("--"):
            continue
        key, separator, inline = item[2:].partition("=")
        if separator:
            candidate = inline
        elif index + 1 < len(value):
            candidate = value[index + 1]
        else:
            return value
        redacted = redact_mapping({key: candidate})[key]
        placeholder = candidate.startswith("{") and candidate.endswith("}")
        if redacted == "[REDACTED]" and not placeholder:
            raise ValueError("command template must contain placeholders, not secret values")
    return value


def _validate_reason_status(coverage_status: RunStatus, partial_reason: str | None) -> None:
    incomplete = coverage_status in {
        RunStatus.PARTIAL,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }
    if incomplete and partial_reason is None:
        raise ValueError("partial_reason is required for incomplete coverage")
    if not incomplete and partial_reason is not None:
        raise ValueError("partial_reason is only valid for incomplete coverage")


class AcquisitionProvenance(BaseModel):
    """Bounded, non-secret context that makes an acquired result reproducible."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(min_length=1, max_length=100)
    policy_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    command_template: tuple[str, ...] = Field(min_length=1, max_length=128)
    coverage_status: RunStatus
    partial_reason: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("tool", "tool_version")
    @classmethod
    def _safe_label(cls, value: str) -> str:
        if value != value.strip() or any(character in value for character in "\r\n\x00"):
            raise ValueError("provenance labels must be trimmed single-line text without NUL")
        return value

    @field_validator("command_template")
    @classmethod
    def _safe_command_template(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_command_template(value)

    @field_validator("partial_reason")
    @classmethod
    def _safe_partial_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or any(character in value for character in "\r\n\x00"):
            raise ValueError("partial_reason must be trimmed single-line text without NUL")
        if redact_text(value) != value:
            raise ValueError("partial_reason must not contain secret values")
        return value

    @model_validator(mode="after")
    def _reason_matches_status(self) -> AcquisitionProvenance:
        _validate_reason_status(self.coverage_status, self.partial_reason)
        return self

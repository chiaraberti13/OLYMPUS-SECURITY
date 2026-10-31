"""Shared helpers for Athena in-process tool adapters."""

from __future__ import annotations

from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.athena.scope import (
    SsrfBlockedError,
    TargetOutOfScopeError,
    TargetValidationError,
    ensure_target_allowed,
)


class CancelledBeforeStart(RuntimeError):
    """Raised internally when cancellation is observed before work begins."""


def guard_target(request: ToolRequest, cancellation: Cancellation) -> str | ToolResult:
    """Validate scope/SSRF and cancellation, returning a host or a failed result.

    Returns the validated host string on success, or a ready-made failed
    :class:`ToolResult` with a stable, redacted error code otherwise.
    """
    if cancellation.is_cancelled():
        return ToolResult(ok=False, error_code="cancelled")
    try:
        return ensure_target_allowed(
            request.target_kind, request.target_value, request.allowed_domains
        )
    except TargetValidationError:
        return ToolResult(ok=False, error_code="invalid_target")
    except TargetOutOfScopeError:
        return ToolResult(ok=False, error_code="out_of_scope")
    except SsrfBlockedError:
        return ToolResult(ok=False, error_code="ssrf_blocked")

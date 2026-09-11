"""Tests for the shared authorization, limits, cancellation, and redaction policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.core.execution import (
    MAX_BACKOFF_SECONDS,
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    Deadline,
    ExecutionPolicy,
    ExecutionPolicyError,
    NeverCancelled,
    StructuredAuditRecord,
    append_structured_audit,
    interruptible_sleep,
    redact_mapping,
)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("deadline_seconds", 0),
        ("max_concurrency", 65),
        ("retries", 6),
        ("backoff_seconds", -1),
        ("min_interval_seconds", 61),
        ("jitter_ratio", 1.5),
        ("jitter_ratio", -0.1),
    ],
)
def test_policy_rejects_unsafe_resource_values(field: str, value: object) -> None:
    with pytest.raises(ExecutionPolicyError, match=field):
        ExecutionPolicy(**{field: value})  # type: ignore[arg-type]


def test_policy_authorizes_before_invoking_scope_gate() -> None:
    calls: list[str] = []
    denied = ExecutionPolicy(authorized=False)

    with pytest.raises(AuthorizationRequiredError):
        denied.authorize_target("lookup", "example.com", calls.append)
    assert calls == []

    ExecutionPolicy(authorized=True).authorize_target("lookup", "example.com", calls.append)
    assert calls == ["example.com"]


def test_cancellation_is_thread_safe_and_observed() -> None:
    policy = ExecutionPolicy()
    policy.check_cancellation(NeverCancelled())
    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        policy.check_cancellation(token)


def test_structured_audit_redacts_nested_secrets_and_url_queries() -> None:
    raw = {
        "api_key": "top-secret",
        "request": {
            "url": "https://api.example/v1?token=abc&target=example.com",
            "password": "also-secret",
        },
    }
    redacted = redact_mapping(raw)
    assert redacted["api_key"] == "[REDACTED]"
    request = redacted["request"]
    assert isinstance(request, dict)
    assert "[REDACTED]" in request.values()
    assert "abc" not in request["url"]
    assert "target=example.com" in request["url"]

    record = StructuredAuditRecord(
        timestamp="2026-08-25T00:00:00Z",
        execution_id="EXEC-1",
        action="request",
        outcome="blocked",
        target="https://api.example/v1?token=target-secret&target=example.com",
        metadata=raw,
    )
    serialized = record.to_json()
    assert "top-secret" not in serialized
    assert "target-secret" not in serialized
    assert json.loads(serialized)["metadata"]["api_key"] == "[REDACTED]"


def test_redaction_reaches_url_secrets_inside_lists_and_nested_lists() -> None:
    # A URL query secret must be redacted wherever it sits, not only when it is
    # the immediate value of a key: a redirect chain or a list of discovered
    # endpoints is exactly the kind of value that lands in metadata as a list.
    raw = {
        "redirects": ["https://api.example/v1?token=leak-a&keep=1"],
        "nested": [["https://api.example/v2?token=leak-b"]],
        "mixed": [{"url": "https://api.example/v3?token=leak-c"}, "plain"],
    }
    redacted = redact_mapping(raw)
    serialized = json.dumps(redacted)
    assert "leak-a" not in serialized
    assert "leak-b" not in serialized
    assert "leak-c" not in serialized
    # non-secret data is preserved so the audit record stays useful
    assert redacted["redirects"][0].endswith("keep=1")
    assert redacted["mixed"][1] == "plain"


def test_structured_audit_append_writes_one_redacted_line(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.ndjson"
    append_structured_audit(
        path,
        StructuredAuditRecord(
            timestamp="2026-08-25T00:00:00Z",
            execution_id="EXEC-2",
            action="request",
            outcome="completed",
            metadata={"authorization": "Bearer synthetic-secret"},
        ),
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["metadata"]["authorization"] == "[REDACTED]"
    assert "synthetic-secret" not in lines[0]


def test_jitter_spreads_the_rate_limit_around_the_configured_interval() -> None:
    """Perfectly regular pacing is both fingerprintable and prone to lockstep."""
    policy = ExecutionPolicy(min_interval_seconds=2.0, jitter_ratio=0.5)

    assert policy.next_interval(lambda: 0.0) == pytest.approx(1.0)
    assert policy.next_interval(lambda: 1.0) == pytest.approx(3.0)
    assert policy.next_interval(lambda: 0.5) == pytest.approx(2.0)


def test_jitter_never_produces_a_negative_wait() -> None:
    policy = ExecutionPolicy(min_interval_seconds=1.0, jitter_ratio=1.0)
    assert policy.next_interval(lambda: 0.0) == 0.0


def test_interval_is_zero_when_no_rate_limit_is_configured() -> None:
    assert ExecutionPolicy(jitter_ratio=0.5).next_interval(lambda: 0.0) == 0.0


def test_backoff_grows_exponentially_and_stays_capped() -> None:
    policy = ExecutionPolicy(backoff_seconds=1.0, retries=5)

    assert policy.next_backoff(1) == 1.0
    assert policy.next_backoff(2) == 2.0
    assert policy.next_backoff(3) == 4.0
    assert policy.next_backoff(20) == MAX_BACKOFF_SECONDS
    with pytest.raises(ExecutionPolicyError):
        policy.next_backoff(0)


def test_jittered_backoff_stays_inside_the_band_and_the_cap() -> None:
    policy = ExecutionPolicy(backoff_seconds=1.0, jitter_ratio=0.5)

    assert policy.next_backoff(2, lambda: 0.0) == pytest.approx(1.0)
    assert policy.next_backoff(2, lambda: 1.0) == pytest.approx(3.0)
    capped = ExecutionPolicy(backoff_seconds=MAX_BACKOFF_SECONDS, jitter_ratio=1.0)
    assert capped.next_backoff(1, lambda: 1.0) == MAX_BACKOFF_SECONDS


def test_deadline_is_taken_once_and_reports_what_is_left() -> None:
    deadline = Deadline(5.0)

    assert 0.0 < deadline.remaining <= 5.0
    assert deadline.expired is False
    assert deadline.slice_for(30.0) <= 5.0
    assert deadline.slice_for(0.5) == pytest.approx(0.5)
    with pytest.raises(ExecutionPolicyError):
        Deadline(0.0)


def test_interruptible_sleep_returns_early_on_cancellation() -> None:
    token = CancellationToken()
    token.cancel()

    assert interruptible_sleep(30.0, token) is False
    assert interruptible_sleep(0.0, token) is True  # nothing to wait for


def test_interruptible_sleep_returns_early_on_a_spent_deadline() -> None:
    deadline = Deadline(0.05)
    assert interruptible_sleep(5.0, NeverCancelled(), deadline) is False


def test_interruptible_sleep_completes_a_short_wait() -> None:
    assert interruptible_sleep(0.06, NeverCancelled()) is True

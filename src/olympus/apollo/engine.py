"""Apollo detection engine producing shared Alert objects."""

import hashlib
import time

from olympus.apollo.rules import DetectionRule, matches
from olympus.core.enums import Source
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Alert, Event


def evaluate(rules: list[DetectionRule], event: Event) -> list[Alert]:
    """Evaluate rules against an event and return normalized alerts."""
    identifiers = [rule.rule_id for rule in rules]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("rules must have unique rule_id values")
    return [
        Alert(
            alert_id=(
                "ALT-"
                + hashlib.sha256(f"{rule.rule_id}:{event.event_id}".encode())
                .hexdigest()[:24]
                .upper()
            ),
            event_id=event.event_id,
            title=rule.title,
            source=Source.APOLLO,
            severity=rule.severity,
            rule_id=rule.rule_id,
            mitre_attack=rule.mitre_attack,
            created_at=event.observed_at,
        )
        for rule in rules
        if matches(rule, event)
    ]


def evaluate_stream(
    rules: list[DetectionRule],
    events: list[Event],
    *,
    max_evaluations: int = 1_000_000,
    max_alerts: int = 100_000,
    policy: ExecutionPolicy | None = None,
    cancellation: Cancellation | None = None,
) -> list[Alert]:
    """Bound the library-level rule/event product and cooperative cancellation."""
    if not 1 <= max_evaluations <= 100_000_000:
        raise ValueError("max_evaluations must be between 1 and 100000000")
    if not 1 <= max_alerts <= 1_000_000:
        raise ValueError("max_alerts must be between 1 and 1000000")
    if len(rules) * len(events) > max_evaluations:
        raise ValueError(f"rule/event product exceeds the {max_evaluations} evaluation limit")
    runtime_policy = policy or ExecutionPolicy()
    token = cancellation or NeverCancelled()
    deadline = time.monotonic() + runtime_policy.deadline_seconds
    alerts: list[Alert] = []
    for event in events:
        runtime_policy.check_cancellation(token)
        if time.monotonic() >= deadline:
            raise TimeoutError("Apollo stream evaluation deadline exceeded")
        fired = evaluate(rules, event)
        if len(alerts) + len(fired) > max_alerts:
            raise ValueError(f"alerts exceed the {max_alerts} result limit")
        alerts.extend(fired)
    return alerts

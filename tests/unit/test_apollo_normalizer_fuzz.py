"""Property-based fuzzing of the Apollo ECS/OCSF alert normalizers (SEC-H).

Alerts carry free text that ultimately derives from untrusted events (titles,
identifiers). The ECS and OCSF exporters must turn any such alert into a
JSON-serializable mapping and NDJSON whose every line is valid JSON with no raw
terminal-control bytes — never crashing and never emitting bytes that could
inject into a terminal or a downstream SIEM line. This suite drives the
normalizers with hostile title/event_id text (C0/C1 controls, ANSI/OSC, unicode)
and asserts those invariants, completing the parser/normalizer fuzz coverage for
the Apollo layer. Nothing network-active runs.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.apollo.ecs import alert_to_ecs
from olympus.apollo.ecs import alerts_to_ndjson as ecs_alerts_to_ndjson
from olympus.apollo.ocsf import alert_to_ocsf
from olympus.apollo.ocsf import alerts_to_ndjson as ocsf_alerts_to_ndjson
from olympus.core.enums import AlertStatus, Severity, Source
from olympus.core.models import Alert

_hostile = st.text(
    alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), min_size=1, max_size=64
)

# Alerts with attacker-influenced free text in the fields the model leaves free
# (title, event_id). rule_id/mitre_attack are schema-constrained, so they are
# held to valid shapes here rather than fuzzed.
_alerts = st.builds(
    Alert,
    event_id=_hostile,
    title=_hostile,
    source=st.sampled_from(list(Source)),
    severity=st.sampled_from(list(Severity)),
    status=st.sampled_from(list(AlertStatus)),
    rule_id=st.none(),
    mitre_attack=st.just([]),
)

_RAW_CONTROLS = ("\x1b", "\x07", "\x7f", "\x08", "\x00")


@given(alert=_alerts)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_ecs_and_ocsf_mappings_are_json_serializable(alert: Alert) -> None:
    for normalize in (alert_to_ecs, alert_to_ocsf):
        mapping = normalize(alert)
        assert isinstance(mapping, dict)
        json.dumps(mapping)  # must not raise


@given(alert=_alerts)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_ndjson_lines_are_valid_json_without_raw_controls(alert: Alert) -> None:
    for to_ndjson in (ecs_alerts_to_ndjson, ocsf_alerts_to_ndjson):
        ndjson = to_ndjson([alert])
        lines = [line for line in ndjson.splitlines() if line.strip()]
        assert lines  # one alert yields at least one record
        for line in lines:
            json.loads(line)  # each line is a standalone JSON document
            for control in _RAW_CONTROLS:
                assert control not in line  # json.dumps escapes controls to \uXXXX

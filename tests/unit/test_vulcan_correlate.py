"""Finding correlation engine and ``olympus vulcan correlate`` CLI (ROADMAP ``CORR-1``).

The engine derives deterministic relationships over the shared finding contract —
the same asset reported by two or more tool sources (asset-overlap) and the same
CVE across two or more assets (shared-cve) — each traceable, motivated and graded
with a confidence and an epistemic class. These tests pin that derivation, its
determinism, the published-contract round-trip, and the rule that a correlation is
never promoted to a stronger epistemic class than a deterministic join warrants.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import EpistemicClass, Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Event, Finding
from olympus.metis.models import Indicator, IndicatorType
from olympus.vulcan.correlate import (
    CorrelationsDocument,
    correlate_findings,
    correlate_indicators_with_events,
    correlations_document,
)

runner = CliRunner()

_WHEN = datetime(2026, 1, 1, tzinfo=UTC)


def _indicator(
    value: str,
    *,
    indicator_type: IndicatorType = IndicatorType.DOMAIN,
    source: str = "misp",
    suffix: str = "a" * 24,
) -> Indicator:
    return Indicator(
        indicator_id=f"ioc-{suffix}",
        indicator_type=indicator_type,
        value=value,
        source=source,
        confidence=80,
        first_seen=_WHEN,
    )


def _event(
    event_id: str,
    *,
    asset_id: str = "AST-1",
    source: Source = Source.APOLLO,
    attributes: dict[str, str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        event_type="dns",
        source=source,
        observed_at=_WHEN,
        asset_id=asset_id,
        attributes=attributes or {},
    )


def _finding(
    finding_id: str,
    *,
    asset_id: str = "AST-1",
    source: Source = Source.ARTEMIS,
    cve: list[str] | None = None,
    evidence: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        asset_id=asset_id,
        source=source,
        title=f"issue {finding_id}",
        severity=Severity.MEDIUM,
        cve=cve or [],
        evidence=evidence or [],
    )


def _bundle(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def test_asset_overlap_needs_two_distinct_sources() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.THEMIS),
        _finding("F3", asset_id="AST-2", source=Source.ARTEMIS),
    ]
    correlations = correlate_findings(findings)
    overlaps = [c for c in correlations if c.kind == "asset-overlap"]
    assert [c.key for c in overlaps] == ["AST-1"]
    assert overlaps[0].sources == ("argus", "themis")
    assert set(overlaps[0].members) == {"F1", "F2"}


def test_same_asset_same_source_is_not_an_overlap() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.ARGUS),
    ]
    assert [c for c in correlate_findings(findings) if c.kind == "asset-overlap"] == []


def test_shared_cve_needs_two_distinct_assets() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.THEMIS, cve=["CVE-2024-0001"]),
        _finding("F2", asset_id="AST-2", source=Source.THEMIS, cve=["CVE-2024-0001"]),
        _finding("F3", asset_id="AST-3", source=Source.THEMIS, cve=["CVE-2024-0002"]),
    ]
    shared = [c for c in correlate_findings(findings) if c.kind == "shared-cve"]
    assert [c.key for c in shared] == ["CVE-2024-0001"]
    assert shared[0].sources == ("AST-1", "AST-2")


def test_shared_evidence_needs_two_distinct_findings() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS, evidence=["EV-abc", "  "]),
        _finding("F2", asset_id="AST-2", source=Source.THEMIS, evidence=["EV-abc"]),
        _finding("F3", asset_id="AST-3", source=Source.ARTEMIS, evidence=["EV-solo"]),
    ]
    shared = [c for c in correlate_findings(findings) if c.kind == "shared-evidence"]
    # Only EV-abc is cited by >=2 distinct findings; EV-solo and the blank are not.
    assert [c.key for c in shared] == ["EV-abc"]
    assert set(shared[0].members) == {"F1", "F2"}
    assert shared[0].sources == ("argus", "themis")


def test_shared_evidence_ignores_a_lone_citation_and_blanks() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS, evidence=["EV-1", ""]),
        _finding("F2", asset_id="AST-2", source=Source.THEMIS, evidence=["  "]),
    ]
    assert [c for c in correlate_findings(findings) if c.kind == "shared-evidence"] == []


def test_correlations_are_deterministic_facts_never_hypotheses_or_compromise() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.THEMIS, cve=["CVE-2024-0001"]),
        _finding("F3", asset_id="AST-2", source=Source.ARTEMIS, cve=["CVE-2024-0001"]),
    ]
    correlations = correlate_findings(findings)
    assert correlations  # non-empty
    for correlation in correlations:
        # A join on identity is a deterministic result, never an inference/hypothesis.
        assert correlation.epistemic_class is EpistemicClass.DETERMINISTIC_RESULT
        # Traceable and motivated.
        assert correlation.members and correlation.sources and correlation.reason
        # Never asserts exploitation or compromise.
        lowered = correlation.reason.lower()
        assert "compromis" not in lowered and "exploited" not in lowered


def test_all_three_deterministic_kinds_from_one_corpus() -> None:
    # One realistic corpus that exercises every first-slice relationship kind.
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS, evidence=["EV-pcap"]),
        _finding(
            "F2",
            asset_id="AST-1",
            source=Source.THEMIS,
            cve=["CVE-2024-0001"],
            evidence=["EV-pcap"],
        ),
        _finding("F3", asset_id="AST-2", source=Source.ARTEMIS, cve=["CVE-2024-0001"]),
    ]
    kinds = {c.kind for c in correlate_findings(findings)}
    assert kinds == {"asset-overlap", "shared-cve", "shared-evidence"}


def test_no_correlation_without_overlap() -> None:
    assert correlate_findings([_finding("F1", asset_id="AST-1", source=Source.ARGUS)]) == ()


def test_result_is_deterministically_ordered() -> None:
    findings = [
        _finding("F3", asset_id="AST-2", source=Source.ARTEMIS, cve=["CVE-2024-0001"]),
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.THEMIS, cve=["CVE-2024-0001"]),
    ]
    first = correlate_findings(findings)
    assert [(c.kind, c.key) for c in first] == sorted((c.kind, c.key) for c in first)
    assert correlate_findings(findings) == first


def test_document_validates_the_published_contract() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.THEMIS),
    ]
    document = correlations_document(findings)
    assert document["schema_name"] == "olympus.correlations"
    assert CorrelationsDocument.model_validate(document).model_dump(mode="json") == document


# ---------------------------------------------------------------------------
# IOC ↔ event (cross-module, suggested_correlation)
# ---------------------------------------------------------------------------


def test_ioc_event_matches_value_observed_in_event() -> None:
    indicators = [
        _indicator("Bad.Example", indicator_type=IndicatorType.DOMAIN),
        _indicator("203.0.113.9", indicator_type=IndicatorType.IPV4, suffix="b" * 24),
        _indicator("unseen.example", indicator_type=IndicatorType.DOMAIN, suffix="c" * 24),
    ]
    events = [
        _event("E1", attributes={"query": "bad.example"}),  # case-insensitive match
        _event("E2", asset_id="203.0.113.9"),  # indicator value is the asset id
    ]
    correlations = correlate_indicators_with_events(indicators, events)
    by_key = {c.key: c for c in correlations}
    assert set(by_key) == {"domain:Bad.Example", "ipv4:203.0.113.9"}
    assert by_key["domain:Bad.Example"].members == ("E1",)
    assert by_key["ipv4:203.0.113.9"].members == ("E2",)


def test_ioc_event_is_a_suggested_lead_never_a_fact_or_compromise() -> None:
    correlations = correlate_indicators_with_events(
        [_indicator("bad.example")], [_event("E1", attributes={"query": "bad.example"})]
    )
    assert len(correlations) == 1
    only = correlations[0]
    # An IOC hit is weaker than an identity join: suggested, not deterministic.
    assert only.epistemic_class is EpistemicClass.SUGGESTED_CORRELATION
    # The reason frames the match as a lead to verify, explicitly not a compromise.
    assert "lead" in only.reason.lower()
    assert "not a proven compromise" in only.reason.lower()


def test_ioc_event_folds_indicators_sharing_an_identity() -> None:
    # Same type+value from two CTI feeds collapses into one correlation.
    indicators = [
        _indicator("bad.example", source="misp", suffix="a" * 24),
        _indicator("bad.example", source="otx", suffix="d" * 24),
    ]
    correlations = correlate_indicators_with_events(
        indicators, [_event("E1", attributes={"query": "bad.example"})]
    )
    assert [c.key for c in correlations] == ["domain:bad.example"]
    assert "misp" in correlations[0].reason and "otx" in correlations[0].reason


def test_ioc_event_absent_value_yields_nothing() -> None:
    assert (
        correlate_indicators_with_events(
            [_indicator("nowhere.example")], [_event("E1", attributes={"query": "other.example"})]
        )
        == ()
    )


def test_document_merges_finding_and_ioc_event_correlations() -> None:
    findings = [
        _finding("F1", asset_id="AST-1", source=Source.ARGUS),
        _finding("F2", asset_id="AST-1", source=Source.THEMIS),
    ]
    document = correlations_document(
        findings,
        indicators=[_indicator("bad.example")],
        events=[_event("E1", attributes={"query": "bad.example"})],
    )
    kinds = {c["kind"] for c in document["correlations"]}
    assert kinds == {"asset-overlap", "ioc-event"}
    # The merged document still validates against the published contract.
    assert CorrelationsDocument.model_validate(document).model_dump(mode="json") == document


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_correlate_json(tmp_path: Path) -> None:
    bundle = _bundle(
        tmp_path / "f.json",
        [
            _finding("F1", asset_id="AST-1", source=Source.ARGUS),
            _finding("F2", asset_id="AST-1", source=Source.THEMIS, cve=["CVE-2024-0001"]),
            _finding("F3", asset_id="AST-2", source=Source.ARTEMIS, cve=["CVE-2024-0001"]),
        ],
    )
    result = runner.invoke(
        app, ["vulcan", "correlate", "--findings", str(bundle), "--format", "json"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.stdout)
    assert payload["count"] == 2
    assert {c["kind"] for c in payload["correlations"]} == {"asset-overlap", "shared-cve"}


def test_cli_correlate_table_renders_each_relationship(tmp_path: Path) -> None:
    bundle = _bundle(
        tmp_path / "f.json",
        [
            _finding("F1", asset_id="AST-1", source=Source.ARGUS),
            _finding("F2", asset_id="AST-1", source=Source.THEMIS, cve=["CVE-2024-0001"]),
            _finding("F3", asset_id="AST-2", source=Source.ARTEMIS, cve=["CVE-2024-0001"]),
        ],
    )
    # Default (no --format) renders the human-readable table surface.
    result = runner.invoke(app, ["vulcan", "correlate", "--findings", str(bundle)])
    assert result.exit_code == ExitCode.OK, result.output
    assert "Correlations" in result.output
    # Both deterministic joins appear, keyed by asset id and CVE id.
    assert "asset-overlap" in result.output and "AST-1" in result.output
    assert "shared-cve" in result.output and "CVE-2024-0001" in result.output
    # The count is surfaced so an operator knows how many relationships were found.
    assert "2 correlation(s)" in result.output


def test_cli_correlate_no_overlap_is_an_empty_versioned_document(tmp_path: Path) -> None:
    # A singleton bundle cannot overlap: the CLI must still emit a valid,
    # zero-count olympus.correlations document rather than fail or omit the header.
    bundle = _bundle(tmp_path / "f.json", [_finding("F1", asset_id="AST-1", source=Source.ARGUS)])
    result = runner.invoke(
        app, ["vulcan", "correlate", "--findings", str(bundle), "--format", "json"]
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.stdout)
    assert payload["schema_name"] == "olympus.correlations"
    assert payload["count"] == 0 and payload["correlations"] == []
    # The emitted document still validates against the published contract.
    assert CorrelationsDocument.model_validate(payload).model_dump(mode="json") == payload


def _case_bundle(path: Path, indicators: list[Indicator]) -> Path:
    document = {
        "schema_name": "olympus.metis-case",
        "schema_version": "1.0.0",
        "case_id": "case-" + "0" * 23 + "1",
        "title": "demo",
        "status": "open",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "indicators": [json.loads(i.model_dump_json()) for i in indicators],
        "findings": [],
        "correlations": [],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _event_bundle(path: Path, events: list[Event]) -> Path:
    path.write_text(json.dumps([json.loads(e.model_dump_json()) for e in events]), encoding="utf-8")
    return path


def test_cli_correlate_ioc_event_from_case_and_events(tmp_path: Path) -> None:
    case = _case_bundle(tmp_path / "case.json", [_indicator("bad.example")])
    events = _event_bundle(
        tmp_path / "events.json", [_event("E1", attributes={"query": "bad.example"})]
    )
    result = runner.invoke(
        app,
        ["vulcan", "correlate", "--case", str(case), "--events", str(events), "--format", "json"],
    )
    assert result.exit_code == ExitCode.OK, result.output
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    only = payload["correlations"][0]
    assert only["kind"] == "ioc-event"
    assert only["epistemic_class"] == "suggested_correlation"


def test_cli_correlate_requires_both_case_and_events(tmp_path: Path) -> None:
    case = _case_bundle(tmp_path / "case.json", [_indicator("bad.example")])
    result = runner.invoke(app, ["vulcan", "correlate", "--case", str(case)])
    assert result.exit_code == ExitCode.USAGE
    assert "both --case and --events" in result.output


def test_cli_correlate_with_no_inputs_is_a_usage_error() -> None:
    result = runner.invoke(app, ["vulcan", "correlate"])
    assert result.exit_code == ExitCode.USAGE


def test_cli_correlate_reports_a_bad_bundle_as_usage_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["vulcan", "correlate", "--findings", str(bad)])
    assert result.exit_code == ExitCode.USAGE

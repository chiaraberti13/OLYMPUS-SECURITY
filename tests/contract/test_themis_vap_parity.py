"""Keep the SEC-A legacy/native runtime parity inventory tied to source routes."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from olympus.themis.jobs import JobState

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/parity/themis-vap-runtime.json"
RETIREMENT_MANIFEST = ROOT / "docs/parity/themis-vap-retirement.json"
VALID_STATUSES = {"implemented", "partial", "missing"}
VALID_RETIREMENT_DECISIONS = {
    "native_replacement",
    "intentional_exclusion",
    "future_native_capability",
}


def _read_manifest() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(MANIFEST.read_text(encoding="utf-8")))


def _read_retirement_manifest() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(RETIREMENT_MANIFEST.read_text(encoding="utf-8")))


def _routes(path: Path) -> list[dict[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    routes: list[dict[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in {"get", "post", "put", "patch", "delete", "websocket"}
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "app"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                routes.append(
                    {
                        "method": "WS"
                        if decorator.func.attr == "websocket"
                        else decorator.func.attr.upper(),
                        "path": decorator.args[0].value,
                        "handler": node.name,
                    }
                )
    return sorted(routes, key=lambda item: (item["path"], item["method"], item["handler"]))


def _route_key(route: dict[str, str]) -> tuple[str, str, str]:
    return route["method"], route["path"], route["handler"]


def _retirement_route_key(route: dict[str, str]) -> str:
    return f"{route['method']} {route['path']}"


def test_legacy_route_inventory_is_complete_and_pinned_to_reviewed_source() -> None:
    manifest = _read_manifest()
    source = ROOT / manifest["baseline"]["legacy_route_source"]
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    assert digest == manifest["baseline"]["legacy_app_sha256"]
    assert manifest["baseline"]["legacy_repository_revision"] == (
        "6c6b395d79f358372e028fe7094cc673374dd88f"
    )
    expected = {_route_key(route) for route in _routes(source)}
    recorded = {_route_key(route) for route in manifest["legacy_routes"]}
    assert recorded == expected
    assert len(recorded) == len(manifest["legacy_routes"])


def test_native_route_inventory_matches_api_and_web_routers() -> None:
    manifest = _read_manifest()
    expected: set[tuple[str, str, str, str]] = set()
    for surface, relative_path in (
        ("api", "src/olympus/themis/api.py"),
        ("web", "src/olympus/themis/web.py"),
    ):
        for route in _routes(ROOT / relative_path):
            expected.add((surface, *_route_key(route)))
    recorded = {
        (route["surface"], route["method"], route["path"], route["handler"])
        for route in manifest["native_routes"]
    }
    assert recorded == expected
    assert len(recorded) == len(manifest["native_routes"])


def test_every_legacy_route_has_an_explicit_parity_and_security_decision() -> None:
    manifest = _read_manifest()
    assert manifest["roadmap_id"] == "SEC-A"
    assert manifest["priority"] == "P0"
    assert set(manifest["status_values"]) == VALID_STATUSES
    assert {route["status"] for route in manifest["legacy_routes"]} == VALID_STATUSES
    for route in manifest["legacy_routes"]:
        assert route["decision"].strip()
        if route["status"] == "missing":
            assert route["native"] is None
        else:
            assert route["native"]


def test_every_legacy_route_has_one_non_blocking_retirement_decision() -> None:
    parity = _read_manifest()
    retirement = _read_retirement_manifest()

    assert retirement["roadmap_id"] == "SEC-A"
    assert retirement["priority"] == "P0"
    assert set(retirement["decision_values"]) == VALID_RETIREMENT_DECISIONS
    assert parity["retirement_decision_manifest"] == str(RETIREMENT_MANIFEST.relative_to(ROOT))
    assert (
        retirement["baseline"]["legacy_repository_revision"]
        == (parity["baseline"]["legacy_repository_revision"])
    )
    assert retirement["baseline"]["legacy_app_sha256"] == parity["baseline"]["legacy_app_sha256"]

    expected = {_retirement_route_key(route) for route in parity["legacy_routes"]}
    recorded: list[str] = []
    decision_by_route: dict[str, str] = {}
    for group in retirement["route_decisions"]:
        assert group["decision"] in VALID_RETIREMENT_DECISIONS
        assert group["source_removal_blocker"] is False
        assert group["rationale"].strip()
        if group["decision"] == "future_native_capability":
            assert group["follow_up"]
        recorded.extend(group["routes"])
        decision_by_route.update(dict.fromkeys(group["routes"], group["decision"]))

    assert set(recorded) == expected
    assert len(recorded) == len(set(recorded))
    implemented = {
        _retirement_route_key(route)
        for route in parity["legacy_routes"]
        if route["status"] == "implemented"
    }
    assert all(decision_by_route[route] == "native_replacement" for route in implemented)


def test_every_legacy_data_boundary_has_one_retirement_decision() -> None:
    parity = _read_manifest()
    retirement = _read_retirement_manifest()
    expected = set(parity["data_contracts"])
    decisions = retirement["data_decisions"]
    recorded = [item["boundary"] for item in decisions]

    assert set(recorded) == expected
    assert len(recorded) == len(set(recorded))
    for item in decisions:
        assert item["decision"] in VALID_RETIREMENT_DECISIONS
        assert item["source_removal_blocker"] is False
        assert item["rationale"].strip()
        if item["decision"] == "future_native_capability":
            assert item["follow_up"]

    outcome = retirement["review_outcome"]
    assert outcome["route_and_data_decisions_complete"] is True
    assert outcome["source_removal_blockers"] == []
    assert outcome["remaining_sec_a_work"]


def test_job_state_parity_does_not_collapse_non_clean_outcomes() -> None:
    states = _read_manifest()["data_contracts"]["job_states"]
    native_states = {state.value for state in JobState}
    assert set(states["native"]) == native_states
    assert states["mapping"]["completed"] == JobState.SUCCEEDED.value
    assert states["mapping"]["canceled"] == JobState.CANCELLED.value
    assert {"report_failed", "deleted", "archived"} == set(states["unmapped_legacy"])
    assert {"partial", "timed_out", "policy_denied"} == set(states["unmapped_native"])
    assert states["status"] == "partial"
    assert "Do not collapse" in states["decision"]


def test_persistence_audit_reports_and_cancellation_remain_partial() -> None:
    contracts = _read_manifest()["data_contracts"]
    for name in ("persistence", "audit", "reports", "cancellation"):
        assert contracts[name]["status"] == "partial"
        assert contracts[name]["migration"]
    migration = contracts["persistence"]["migration"]
    assert "legacy-snapshot" in migration
    assert "legacy-verify" in migration
    assert "legacy-plan" in migration
    assert "legacy-approve" in migration
    assert "legacy-import" in migration
    assert "zero executable jobs" in migration
    assert "reconstructed inventory" in migration
    assert "still rejects foreign/VAP databases" in migration
    assert "never converts active rows" in migration
    assert "not retroactively authorized" in migration
    assert "completed becomes partial" in migration
    assert "workers cannot claim" in migration

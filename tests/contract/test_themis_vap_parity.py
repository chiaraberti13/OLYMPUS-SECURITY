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
VALID_STATUSES = {"implemented", "partial", "missing"}


def _read_manifest() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(MANIFEST.read_text(encoding="utf-8")))


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
    assert "rejects foreign/VAP databases" in contracts["persistence"]["migration"]

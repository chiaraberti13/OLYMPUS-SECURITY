"""The scope registry is exactly the set of scopes the surfaces enforce.

``olympus.themis.api.SCOPES`` is the single source of truth for which scopes an
API key / Web session can be granted (``ApiSettings`` rejects an unknown scope).
Two drifts must never happen:

* a route is gated on a scope that is **not** in ``SCOPES`` — no identity could
  ever be granted it, so the route is permanently unreachable (silent 403);
* ``SCOPES`` lists a scope that **no** surface enforces — a dead grant that
  widens an identity without protecting anything.

This gate pins ``SCOPES`` to the scopes actually wired across the API
(``authenticated("…")``) and the Web control plane (``requires("…")``), plus any
scope checked inline against a ``…​.scopes`` set, so the registry and the
enforcement points can never diverge.
"""

from __future__ import annotations

import ast
from pathlib import Path

from olympus.themis.api import SCOPES

ROOT = Path(__file__).resolve().parents[2]
_SURFACES = (
    ROOT / "src/olympus/themis/api.py",
    ROOT / "src/olympus/themis/web.py",
)
_GATE_FUNCTIONS = {"authenticated", "requires"}


def _enforced_scopes() -> set[str]:
    enforced: set[str] = set()
    for path in _SURFACES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # authenticated("scope") / requires("scope")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in _GATE_FUNCTIONS
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                enforced.add(node.args[0].value)
            # "scope" in <...>.scopes
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.In)
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and isinstance(node.comparators[0], ast.Attribute)
                and node.comparators[0].attr == "scopes"
            ):
                enforced.add(node.left.value)
    return enforced


def test_scope_registry_matches_enforced_scopes() -> None:
    registry = set(SCOPES)
    enforced = _enforced_scopes()

    unknown = sorted(enforced - registry)
    assert not unknown, (
        f"these scopes are enforced by a surface but are not in SCOPES, so no identity "
        f"could ever be granted them (permanent 403): {unknown}"
    )

    dead = sorted(registry - enforced)
    assert not dead, (
        f"these scopes are in SCOPES but no surface enforces them — a dead grant that "
        f"protects nothing: {dead}"
    )


def test_scopes_are_well_formed_resource_action_pairs() -> None:
    for scope in SCOPES:
        resource, sep, action = scope.partition(":")
        assert sep == ":" and resource and action, f"malformed scope: {scope!r}"

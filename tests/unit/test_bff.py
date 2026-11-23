"""Safety properties of the split-deployment BFF forwarder (DEPLOY-3).

``api/_bff.py`` relays read requests to the one configured backend and nothing else.
These tests pin, entirely offline (an injected opener, never a real socket), that it:
never runs a scanner (no olympus/subprocess import), only forwards named routes from
the allowlist (GET/HEAD), connects solely to the ``https://`` backend from the
environment with a constant path (no request data reaches the URL — no SSRF), passes
3xx through without chasing, strips cookies/hop-by-hop headers, and fails closed
(403/405/502/503) without touching the network when it must refuse.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / "api"


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(f"olympus_bff_{name}", API / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_bff = _load("_bff")
ENV = {"OLYMPUS_BACKEND_URL": "https://backend.example.com"}


class _FakeResp:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.status = status
        self._headers = headers
        self._body = body

    @property
    def headers(self) -> Any:
        pairs = self._headers

        class _H:
            def items(self) -> list[tuple[str, str]]:
                return pairs

        return _H()

    def getcode(self) -> int:
        return self.status

    def read(self) -> bytes:
        return self._body


def _recording_opener(resp: _FakeResp) -> tuple[Any, list[Any]]:
    seen: list[Any] = []

    def opener(req: Any, timeout: float) -> Any:
        seen.append(req)
        return resp

    return opener, seen


def _never_opener(req: Any, timeout: float) -> Any:  # pragma: no cover - must never run
    raise AssertionError("opener must not be called for a refused request")


# --- backend_base validation ------------------------------------------------ #


def test_backend_base_accepts_https_and_strips_trailing_slash() -> None:
    assert _bff.backend_base({"OLYMPUS_BACKEND_URL": "https://b.example/"}) == "https://b.example"


@pytest.mark.parametrize(
    "value",
    ["", "http://b.example", "ftp://b.example", "https://", "https://b.example/?x=1"],
)
def test_backend_base_rejects_bad_urls(value: str) -> None:
    with pytest.raises(_bff.BackendError):
        _bff.backend_base({"OLYMPUS_BACKEND_URL": value})


# --- refusals never touch the network --------------------------------------- #


def test_write_method_is_405_without_calling_backend() -> None:
    assert _bff.forward("POST", "health", {}, b"", env=ENV, opener=_never_opener).status == 405


def test_unknown_route_is_403() -> None:
    assert _bff.forward("GET", "nope", {}, b"", env=ENV, opener=_never_opener).status == 403


@pytest.mark.parametrize(
    "route",
    ["/api/v1/engines/preflight", "http://evil.example/x", "../secret", "//evil.example"],
)
def test_client_cannot_supply_a_path_or_url_only_a_known_route(route: str) -> None:
    # Anything that is not an exact key in ROUTES is refused without a request.
    assert _bff.forward("GET", route, {}, b"", env=ENV, opener=_never_opener).status == 403


def test_missing_backend_is_503() -> None:
    assert _bff.forward("GET", "health", {}, b"", env={}, opener=_never_opener).status == 503


# --- the happy path forwards a constant path to the configured backend ------ #


def test_known_route_forwards_constant_path_to_configured_backend() -> None:
    resp = _FakeResp(
        200, [("Content-Type", "application/json"), ("Connection", "keep-alive")], b"[]"
    )
    opener, seen = _recording_opener(resp)
    out = _bff.forward(
        "GET",
        "engines-preflight",
        {"Accept": "application/json", "Cookie": "s=1"},
        b"",
        env=ENV,
        opener=opener,
    )
    assert out.status == 200 and out.body == b"[]"
    # The URL is the fixed backend plus the CONSTANT path for the route — no request
    # data is concatenated into it.
    assert seen[0].full_url == "https://backend.example.com" + _bff.ROUTES["engines-preflight"]
    names = {k.lower() for k, _ in out.headers}
    assert "connection" not in names and "x-content-type-options" in names
    assert not any(k.lower() == "cookie" for k in dict(seen[0].header_items()))


def test_transport_failure_is_502() -> None:
    def boom(req: Any, timeout: float) -> Any:
        raise urllib.error.URLError("refused")

    assert _bff.forward("GET", "health", {}, b"", env=ENV, opener=boom).status == 502


def test_redirect_is_passed_through_not_followed() -> None:
    resp = _FakeResp(302, [("Location", "https://elsewhere.example/")], b"")
    opener, _ = _recording_opener(resp)
    out = _bff.forward("GET", "health", {}, b"", env=ENV, opener=opener)
    assert out.status == 302  # passed through, not chased


def test_head_returns_no_body() -> None:
    resp = _FakeResp(200, [("Content-Type", "application/json")], b"should-not-appear")
    opener, _ = _recording_opener(resp)
    out = _bff.forward("HEAD", "health", {}, b"", env=ENV, opener=opener)
    assert out.status == 200 and out.body == b""


# --- it never executes anything --------------------------------------------- #


@pytest.mark.parametrize("name", ["_bff.py", "bff.py"])
def test_bff_never_imports_scanner_or_spawns_process(name: str) -> None:
    # Match code, not prose: the docstrings legitimately say "no subprocess".
    tree = ast.parse((API / name).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "olympus" not in imported, f"{name} must not import olympus (no execution on Vercel)"
    assert "subprocess" not in imported, f"{name} must not import subprocess"
    calls = {
        ast.unparse(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
    }
    for forbidden in ("os.system", "os.popen", "eval", "exec"):
        assert forbidden not in calls, f"{name} must not call {forbidden}"

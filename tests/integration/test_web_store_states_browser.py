"""Real-browser check of WEB-B-01: a failed store is not shown as an empty one.

Opt-in by dependency: skipped unless the optional ``playwright`` package and a
Chromium binary are available (set ``OLYMPUS_CHROMIUM`` to override the path).
The server binds to loopback only, on an ephemeral port, with synthetic data.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
uvicorn = pytest.importorskip("uvicorn")

from olympus.engagements.store import SqliteEngagementStore  # noqa: E402
from olympus.themis.api import ApiSettings  # noqa: E402
from olympus.themis.identity import SCOPES  # noqa: E402
from olympus.themis.web import create_web_app  # noqa: E402

pytestmark = pytest.mark.integration

API_KEY = "b" * 32


def _chromium_path() -> str | None:
    override = os.environ.get("OLYMPUS_CHROMIUM")
    if override:
        return override
    return None


def _launch_args() -> list[str]:
    # Containers commonly run as root, where Chromium refuses its sandbox.
    return ["--no-sandbox"] if os.environ.get("OLYMPUS_CHROMIUM_NO_SANDBOX") else []


def _settings(tmp_path: Path, **overrides: object) -> ApiSettings:
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    (scopes / "engagement.json").write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    base: dict[str, object] = {
        "database": tmp_path / "jobs.sqlite3",
        "scope_directory": scopes,
        "api_key": API_KEY,
        "api_key_scopes": SCOPES,
        "audit_path": tmp_path / "audit.log",
    }
    base.update(overrides)
    return ApiSettings(**base)  # type: ignore[arg-type]


class _Server:
    def __init__(self, settings: ApiSettings) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        config = uvicorn.Config(
            create_web_app(settings), host="127.0.0.1", port=self.port, log_level="error"
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("web server did not start")
            time.sleep(0.05)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def browser_page() -> Iterator[object]:
    with sync_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(
                executable_path=_chromium_path(), args=_launch_args()
            )
        except Exception as exc:  # no browser binary in this environment
            pytest.skip(f"Chromium unavailable: {type(exc).__name__}")
        context = browser.new_context()
        yield context.new_page()
        browser.close()


def _login(page: object, base: str) -> None:
    page.goto(f"{base}/login")  # type: ignore[attr-defined]
    page.fill('input[name="api_key"]', API_KEY)  # type: ignore[attr-defined]
    page.click('button[type="submit"]')  # type: ignore[attr-defined]
    page.wait_for_url(f"{base}/")  # type: ignore[attr-defined]


def test_corrupt_stores_render_unavailable_not_empty_in_a_real_browser(
    tmp_path: Path, browser_page: object
) -> None:
    engagements = tmp_path / "engagements.db"
    engagements.write_bytes(b"not a SQLite database")
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "broken.json").write_text("{", encoding="utf-8")
    settings = _settings(tmp_path, engagements_database=engagements, findings_directory=findings)
    with _Server(settings) as server:
        _login(browser_page, server.url)
        dashboard = browser_page.inner_text("body")  # type: ignore[attr-defined]
        assert "Findings unavailable" in dashboard
        assert "Findings by severity" not in dashboard

        browser_page.goto(f"{server.url}/engagements")  # type: ignore[attr-defined]
        listing = browser_page.inner_text("body")  # type: ignore[attr-defined]
        assert "configured engagement store is unavailable" in listing
        assert "No engagements yet" not in listing


def test_healthy_empty_store_is_not_reported_unavailable_in_a_real_browser(
    tmp_path: Path, browser_page: object
) -> None:
    database = tmp_path / "engagements.db"
    SqliteEngagementStore(database).close()
    with _Server(_settings(tmp_path, engagements_database=database)) as server:
        _login(browser_page, server.url)
        browser_page.goto(f"{server.url}/engagements")  # type: ignore[attr-defined]
        listing = browser_page.inner_text("body")  # type: ignore[attr-defined]
        assert "No engagements yet" in listing
        assert "store is unavailable" not in listing

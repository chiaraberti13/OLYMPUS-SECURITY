"""Real-browser checks for store status and keyboard access to the control plane.

Opt-in by dependency: skipped unless the optional ``playwright`` package and a
Chromium binary are available (set ``OLYMPUS_CHROMIUM`` to override the path).
Set ``OLYMPUS_REQUIRE_BROWSER=1`` to require both dependencies and a working browser.
The server binds to loopback only, on an ephemeral port, with synthetic data.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

if os.environ.get("OLYMPUS_REQUIRE_BROWSER") == "1":
    import playwright.sync_api as sync_api
    import uvicorn
else:
    sync_api = pytest.importorskip("playwright.sync_api")
    uvicorn = pytest.importorskip("uvicorn")

from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.store import SqliteEngagementStore
from olympus.themis.api import ApiSettings
from olympus.themis.identity import SCOPES
from olympus.themis.jobs import HistoricalJobImport, JobState, ThemisJobStore
from olympus.themis.web import create_web_app

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
        except sync_api.Error as exc:
            if os.environ.get("OLYMPUS_REQUIRE_BROWSER") == "1":
                raise
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


@pytest.mark.parametrize("width", [360, 1280], ids=["mobile", "desktop"])
def test_keyboard_sign_in_and_skip_navigation(
    tmp_path: Path, browser_page: sync_api.Page, width: int
) -> None:
    browser_page.set_viewport_size({"width": width, "height": 800})
    with _Server(_settings(tmp_path)) as server:
        browser_page.goto(f"{server.url}/login")
        assert browser_page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        credential = browser_page.get_by_label("API credential", exact=True)
        sync_api.expect(credential).to_be_focused()
        browser_page.keyboard.type(API_KEY)
        browser_page.keyboard.press("Tab")
        sync_api.expect(browser_page.get_by_role("button", name="Sign in")).to_be_focused()
        browser_page.keyboard.press("Enter")

        browser_page.wait_for_url(f"{server.url}/")
        main = browser_page.get_by_role("main")
        sync_api.expect(main.get_by_role("heading", level=1, name="Dashboard")).to_be_visible()
        browser_page.keyboard.press("Tab")
        skip_link = browser_page.get_by_role("link", name="Skip to content")
        sync_api.expect(skip_link).to_be_focused()
        sync_api.expect(skip_link).to_be_in_viewport()
        browser_page.keyboard.press("Enter")
        browser_page.wait_for_url(f"{server.url}/#main")
        browser_page.keyboard.press("Tab")
        sync_api.expect(main.locator(":focus")).to_have_count(1)


def _seed_terminal_job(settings: ApiSettings) -> str:
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    (job,) = ThemisJobStore(settings.database).import_historical_terminal(
        [
            HistoricalJobImport(
                idempotency_key="browser-history",
                scanner="fixture",
                target="127.0.0.1",
                target_kind="host",
                scope_path=settings.scope_directory / "engagement.json",
                state=JobState.PARTIAL,
                created_at=timestamp,
                finished_at=timestamp,
                result={
                    "partial": True,
                    "partial_reason": "Incomplete synthetic record",
                    "finding_count": 0,
                },
            )
        ]
    )
    return job.job_id


AUDITED_VIEWS = [
    ("/login", "Sign in"),
    ("/", "Dashboard"),
    ("/jobs", "Jobs"),
    ("/findings", "Findings"),
    ("/engagements", "Engagements"),
    ("/incidents", "Incidents"),
    ("/findings/diff", "Scan diff"),
    ("/findings/attack", "ATT&CK finding associations"),
    ("/correlations", "Correlation workbench"),
    ("/explain", "Finding explanation workbench"),
    ("/apollo", "Apollo detection workbench"),
    ("/minerva", "Minerva custody-ledger verification"),
    ("/tools", "Tools"),
    ("/advanced", "Advanced mode"),
    ("/athena", "Athena assessment planner"),
    ("/argus", "Argus Certificate Transparency workbench"),
    ("/artemis", "Artemis response fingerprint workbench"),
    ("/helios", "Helios passive service identification"),
    ("/hermes", "Hermes secret scan workbench"),
    ("/proteus", "Proteus campaign validation workbench"),
    ("/assessments/new", "New assessment"),
    ("/assessments/smart", "Smart Scan"),
    ("/metis", "Metis CTI extraction workbench"),
    ("/findings/FND-2026-00001", "TCP port 443 exposed"),
    ("/engagements/ENG-2026-00001", "Accessibility review"),
    ("/jobs/{job_id}", "Job {job_id}"),
    ("/jobs/missing", "Job not found"),
    ("/missing-page", "Not found"),
]


def test_audit_matrix_exercises_each_html_get_route(tmp_path: Path) -> None:
    from fastapi.responses import HTMLResponse
    from fastapi.routing import APIRoute

    app = create_web_app(_settings(tmp_path))
    pages = [
        route
        for route in app.routes
        if isinstance(route, APIRoute)
        and "GET" in route.methods
        and route.response_class is HTMLResponse
    ]
    audited = {path for path, _ in AUDITED_VIEWS} - {"/missing-page", "/jobs/missing"}
    # FastAPI dispatches in declaration order. A literal /findings/diff case
    # must not count as a visit to /findings/{finding_id}.
    visited = {
        next(route.path for route in pages if route.path_regex.fullmatch(path)) for path in audited
    }
    assert visited == {route.path for route in pages}


@pytest.mark.parametrize("width", [320, 1280], ids=["mobile", "desktop"])
@pytest.mark.parametrize(("route", "heading"), AUDITED_VIEWS)
def test_wcag_a_aa_and_page_reflow(
    tmp_path: Path, browser_page: sync_api.Page, route: str, heading: str, width: int
) -> None:
    root = Path(__file__).resolve().parents[2]
    script = root / "tests/browser/node_modules/axe-core/axe.min.js"
    if not script.is_file() and os.environ.get("OLYMPUS_REQUIRE_BROWSER") != "1":
        pytest.skip("Install the locked audit engine with npm ci --prefix tests/browser")

    browser_page.add_init_script(path=script)
    browser_page.set_viewport_size({"width": width, "height": 800})
    findings = tmp_path / "findings"
    findings.mkdir()
    bundle = root / "examples/output/helios-findings.json"
    (findings / "bundle.json").write_bytes(bundle.read_bytes())
    engagements = tmp_path / "engagements.db"
    store = SqliteEngagementStore(engagements)
    try:
        if route == "/engagements/ENG-2026-00001":
            store.save(
                Engagement(
                    engagement_id="ENG-2026-00001",
                    name="Accessibility review",
                    scope=EngagementScope(included=("audit.test",)),
                )
            )
    finally:
        store.close()
    incidents = tmp_path / "incidents"
    incidents.mkdir()
    incident = root / "examples/output/minerva-incident.json"
    (incidents / "incident.json").write_bytes(incident.read_bytes())
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yaml").write_bytes((root / "examples/input/apollo-rule.yaml").read_bytes())
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    settings = _settings(
        tmp_path,
        findings_directory=findings,
        findings_database=tmp_path / "finding-transitions.db",
        engagements_database=engagements,
        incidents_directory=incidents,
        baseline_findings_directory=baseline,
        apollo_rules_directory=rules,
    )
    expected_heading = heading
    if route == "/jobs/{job_id}":
        job_id = _seed_terminal_job(settings)
        route = route.format(job_id=job_id)
        expected_heading = heading.format(job_id=job_id)
    expected_status = 404 if route in {"/jobs/missing", "/missing-page"} else 200
    with _Server(settings) as server:
        if route != "/login":
            _login(browser_page, server.url)
        response = browser_page.goto(f"{server.url}{route}")
        assert response and response.status == expected_status
        sync_api.expect(
            browser_page.get_by_role("heading", name=expected_heading, level=1)
        ).to_be_visible()
        if route == "/incidents":
            sync_api.expect(browser_page.get_by_text("INC-2026-00004", exact=True)).to_be_visible()
        if route == "/apollo":
            sync_api.expect(browser_page.get_by_text("APL-DEMO-PWSH", exact=True)).to_be_visible()
        if route in {"/findings", "/findings/diff"}:
            sync_api.expect(
                browser_page.get_by_role("link", name="TCP port 443 exposed")
            ).to_be_visible()
        result = browser_page.evaluate(
            """async () => {
                const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];
                const audit = await axe.run(document, {runOnly: {type: "tag", values: tags}});
                const summarize = rule => ({
                    id: rule.id, impact: rule.impact, helpUrl: rule.helpUrl,
                    nodes: rule.nodes.map(node => ({
                        target: node.target, reason: node.failureSummary
                    }))
                });
                return {
                    version: audit.testEngine.version, tags,
                    passes: audit.passes.map(rule => rule.id),
                    violations: audit.violations.map(summarize),
                    incomplete: audit.incomplete.map(summarize),
                    pageWidth: document.documentElement.scrollWidth
                };
            }"""
        )
        result.update(route=route, viewport=width)
        output = os.environ.get("OLYMPUS_A11Y_RESULTS")
        if output:
            directory = Path(output)
            directory.mkdir(parents=True, exist_ok=True)
            slug = heading.lower().replace("{job_id}", "detail").replace(" ", "-")
            (directory / f"{slug}-{width}.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
        assert result["passes"], "No accessibility rules produced a pass"
        assert not result["violations"], json.dumps(result["violations"], indent=2)
        assert result["pageWidth"] <= width, f"Page content overflows at {width}px on {route}"

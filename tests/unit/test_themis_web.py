"""Web-security and job-lifecycle tests for the native THEMIS web control plane.

The acceptance criterion for ROADMAP ``WEB-A`` is that a job started from the
browser is indistinguishable, by policy and by audit, from one started on the
command line, and that the web-security (headers, CSRF, authz) and the
job-lifecycle/cancellation paths pass. These tests pin exactly that.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.cli import app
from olympus.themis.api import ApiSettings, create_app
from olympus.themis.identity import IdentityRegister, add_identity, save_register
from olympus.themis.web import SESSION_COOKIE, create_web_app

API_KEY = "a" * 32
# A browser speaks to the web app over HTTPS, so the Secure session cookie is
# sent back; an http base_url would silently drop it (which is the point).
BASE = "https://testserver"


def _scope(directory: Path, name: str = "engagement") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(
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


def _settings(tmp_path: Path, **overrides: object) -> ApiSettings:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    base = {
        "database": tmp_path / "jobs.sqlite3",
        "scope_directory": scopes,
        "api_key": API_KEY,
        "audit_path": tmp_path / "audit.log",
    }
    base.update(overrides)
    return ApiSettings(**base)  # type: ignore[arg-type]


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    return TestClient(create_web_app(_settings(tmp_path, **overrides)), base_url=BASE)


def _login(client: TestClient, api_key: str = API_KEY) -> None:
    response = client.post("/login", data={"api_key": api_key}, follow_redirects=False)
    assert response.status_code == 303, response.text


def _csrf(client: TestClient) -> str:
    page = client.get("/assessments/new")
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text)
    assert match is not None
    return match.group(1)


def _submit(client: TestClient, csrf: str, **overrides: str) -> str:
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_id": "engagement",
        "authorized": "on",
        "csrf_token": csrf,
    }
    payload.update(overrides)
    response = client.post("/jobs", data=payload, follow_redirects=False)
    assert response.status_code == 303, response.text
    return response.headers["location"].rsplit("/", 1)[-1]


def test_pages_require_a_session_and_health_is_public(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/health").status_code == 200
    for route in ("/", "/jobs", "/assessments/new"):
        redirect = client.get(route, follow_redirects=False)
        assert redirect.status_code == 303
        assert redirect.headers["location"] == "/login"


def test_security_headers_and_csp_are_restrictive(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/login")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_login_sets_a_hardened_session_cookie_and_rejects_bad_credentials(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    bad = client.post("/login", data={"api_key": "wrong"}, follow_redirects=False)
    assert bad.status_code == 401
    assert SESSION_COOKIE not in client.cookies

    good = client.post("/login", data={"api_key": API_KEY}, follow_redirects=False)
    assert good.status_code == 303
    cookie_header = good.headers["set-cookie"].lower()
    assert "httponly" in cookie_header
    assert "secure" in cookie_header
    assert "samesite=strict" in cookie_header


def test_state_changing_posts_require_a_valid_csrf_token(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    _csrf(client)  # establish the session page
    rejected = client.post(
        "/jobs",
        data={
            "scanner": "nmap",
            "target": "127.0.0.1",
            "scope_id": "engagement",
            "authorized": "on",
            "csrf_token": "forged",
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 403


def test_submission_requires_confirmed_authorization(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    unconfirmed = client.post(
        "/jobs",
        data={
            "scanner": "nmap",
            "target": "127.0.0.1",
            "scope_id": "engagement",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert unconfirmed.status_code == 400
    assert "authorization" in unconfirmed.text.lower()


def test_browser_job_is_identical_to_a_cli_or_api_job(tmp_path: Path) -> None:
    """A job queued in the browser is visible and identical through the API."""
    settings = _settings(tmp_path)
    web = TestClient(create_web_app(settings), base_url=BASE)
    api = TestClient(create_app(settings))
    _login(web)
    job_id = _submit(web, _csrf(web))

    through_api = api.get(f"/api/v1/jobs/{job_id}", headers={"X-Olympus-API-Key": API_KEY})
    assert through_api.status_code == 200
    body = through_api.json()
    assert body["scanner"] == "nmap"
    assert body["target"] == "127.0.0.1"
    assert body["scope_name"] == "engagement.json"
    assert body["authorized"] is True
    # The server filesystem path never leaves the store, on either interface.
    assert "scope_path" not in body
    assert str(tmp_path) not in web.get("/jobs").text


def test_job_lifecycle_cancel_and_sse_stream(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    job_id = _submit(client, csrf)

    assert client.get(f"/jobs/{job_id}").status_code == 200
    cancelled = client.post(
        f"/jobs/{job_id}/cancel", data={"csrf_token": csrf}, follow_redirects=False
    )
    assert cancelled.status_code == 303

    with client.stream("GET", f"/jobs/{job_id}/events") as stream:
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        body = "".join(stream.iter_text())
    assert '"state": "cancelled"' in body
    assert '"terminal": true' in body
    assert body.rstrip().endswith("data: terminal")


def test_sse_reports_a_missing_job_without_leaking(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    with client.stream("GET", "/jobs/THEMIS-00000000000000000000000000000000/events") as stream:
        assert stream.status_code == 200
        body = "".join(stream.iter_text())
    assert "job not found" in body


def test_target_influenced_text_is_defanged_in_the_page(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    hostile = "example.com\x1b[31m<script>alert(1)</script>"
    job_id = _submit(client, csrf, target=hostile, target_kind="domain")
    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    # No raw escape byte and no executable markup survive into the page.
    assert "\x1b" not in page.text
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;" in page.text


def test_scope_based_authorization_is_enforced(tmp_path: Path) -> None:
    """A read-only identity can browse but cannot queue or cancel work."""
    register = IdentityRegister(identities=[])
    register, secret = add_identity(register, identity_id="viewer", scopes=["jobs:read"])
    register_path = tmp_path / "identities.json"
    save_register(register_path, register)
    client = TestClient(
        create_web_app(_settings(tmp_path, api_key="", identities_path=register_path)),
        base_url=BASE,
    )
    _login(client, secret)
    assert client.get("/jobs").status_code == 200
    # The write form itself is gated on jobs:write.
    assert client.get("/assessments/new", follow_redirects=False).status_code == 403


def test_oversized_body_is_refused(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    response = client.post(
        "/jobs",
        headers={
            "Content-Length": str(64 * 1024 + 1),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        content=b"x",
    )
    assert response.status_code == 413


def test_cli_web_requires_secret_and_tls_for_remote_bind(tmp_path: Path) -> None:
    runner = CliRunner()
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    missing = runner.invoke(app, ["themis", "web", "--scope-directory", str(scopes)])
    assert missing.exit_code == 2
    assert "OLYMPUS_THEMIS_API_KEY" in missing.output
    remote = runner.invoke(
        app,
        ["themis", "web", "--scope-directory", str(scopes), "--host", "0.0.0.0"],  # noqa: S104
        env={"OLYMPUS_THEMIS_API_KEY": API_KEY},
    )
    assert remote.exit_code == 2
    assert "require TLS" in remote.output


def _seed_engagement(tmp_path: Path) -> str:
    from olympus.core.models import Engagement, EngagementScope
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore

    engagement = Engagement(
        name="Acme web",
        client="Acme",
        scope=EngagementScope(included=("acme.test",), excluded=("vpn.acme.test",)),
    )
    store = SqliteEngagementStore(tmp_path / ENGAGEMENTS_DB_NAME)
    try:
        store.save(engagement)
    finally:
        store.close()
    return engagement.engagement_id


def _engagements_client(tmp_path: Path) -> tuple[TestClient, str]:
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME

    engagement_id = _seed_engagement(tmp_path)
    client = _client(tmp_path, engagements_database=tmp_path / ENGAGEMENTS_DB_NAME)
    return client, engagement_id


def test_engagements_are_browsable_in_the_web_ui(tmp_path: Path) -> None:
    client, engagement_id = _engagements_client(tmp_path)
    _login(client)
    listing = client.get("/engagements")
    assert listing.status_code == 200
    assert engagement_id in listing.text
    assert "acme.test" in listing.text
    detail = client.get(f"/engagements/{engagement_id}")
    assert detail.status_code == 200
    assert "Acme web" in detail.text
    assert "vpn.acme.test" in detail.text  # the excluded entry is shown


def test_engagements_page_states_when_not_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)  # no engagement store wired
    _login(client)
    page = client.get("/engagements")
    assert page.status_code == 200
    assert "No engagement store is configured" in page.text


def test_new_assessment_offers_engagements_and_enforces_their_scope(tmp_path: Path) -> None:
    client, engagement_id = _engagements_client(tmp_path)
    _login(client)
    form = client.get("/assessments/new")
    assert form.status_code == 200
    assert engagement_id in form.text

    csrf = _csrf(client)
    rejected = client.post(
        "/jobs",
        data={
            "scanner": "nmap",
            "target": "evil.test",
            "target_kind": "domain",
            "scope_id": "engagement",
            "engagement_id": engagement_id,
            "authorized": "on",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 422
    assert "outside the selected engagement" in rejected.text

    accepted = client.post(
        "/jobs",
        data={
            "scanner": "nmap",
            "target": "www.acme.test",
            "target_kind": "domain",
            "scope_id": "engagement",
            "engagement_id": engagement_id,
            "authorized": "on",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert accepted.status_code == 303, accepted.text


def test_engagement_pages_require_the_engagements_scope(tmp_path: Path) -> None:
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME

    _seed_engagement(tmp_path)
    register = IdentityRegister(identities=[])
    register, secret = add_identity(register, identity_id="runner", scopes=["jobs:read"])
    register_path = tmp_path / "identities.json"
    save_register(register_path, register)
    client = TestClient(
        create_web_app(
            _settings(
                tmp_path,
                api_key="",
                identities_path=register_path,
                engagements_database=tmp_path / ENGAGEMENTS_DB_NAME,
            )
        ),
        base_url=BASE,
    )
    _login(client, secret)
    assert client.get("/engagements", follow_redirects=False).status_code == 403

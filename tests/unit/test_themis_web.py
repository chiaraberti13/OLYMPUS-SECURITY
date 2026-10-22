"""Web-security and job-lifecycle tests for the native THEMIS web control plane.

The acceptance criterion for ROADMAP ``WEB-A`` is that a job started from the
browser is indistinguishable, by policy and by audit, from one started on the
command line, and that the web-security (headers, CSRF, authz) and the
job-lifecycle/cancellation paths pass. These tests pin exactly that.
"""

from __future__ import annotations

import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest
from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore
from olympus.themis.api import ApiSettings, create_app
from olympus.themis.identity import SCOPES, IdentityRegister, add_identity, save_register
from olympus.themis.jobs import ThemisJobStore
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
        "api_key_scopes": SCOPES,
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


def test_web_rejects_and_audits_requests_over_the_concurrency_limit(
    tmp_path: Path, monkeypatch
) -> None:
    client = _client(tmp_path, max_concurrent_requests=1)
    _login(client)
    entered = threading.Event()
    release = threading.Event()
    original_list = ThemisJobStore.list

    def delayed_list(self, *, limit=100, state=None):
        entered.set()
        assert release.wait(timeout=5)
        return original_list(self, limit=limit, state=state)

    monkeypatch.setattr(ThemisJobStore, "list", delayed_list)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.get, "/jobs")
        assert entered.wait(timeout=5)
        overloaded = client.get("/jobs")
        assert overloaded.status_code == 503
        assert overloaded.headers["retry-after"] == "1"
        assert overloaded.headers["x-request-id"]
        assert "default-src 'none'" in overloaded.headers["content-security-policy"]
        release.set()
        accepted = first.result(timeout=5)

    assert accepted.status_code == 200
    audit = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()
    ]
    assert any(record["outcome"] == "503" for record in audit)


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

    missing_key = runner.invoke(
        app,
        [
            "themis",
            "web",
            "--scope-directory",
            str(scopes),
            "--engagement-storage",
            str(tmp_path),
            "--manifest-public-key",
            str(tmp_path / "missing-public-key.pem"),
        ],
        env={"OLYMPUS_THEMIS_API_KEY": API_KEY},
    )
    assert missing_key.exit_code == 2
    assert "missing-public-key.pem" in missing_key.output


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
    engagement_id = _seed_engagement(tmp_path)
    client = _client(tmp_path, engagements_database=tmp_path / ENGAGEMENTS_DB_NAME)
    return client, engagement_id


def _signed_web_client(
    tmp_path: Path,
    *,
    expires_at: datetime | None = None,
    allowed_techniques: tuple[str, ...] = ("nmap",),
) -> tuple[TestClient, SignedEngagementManifest, str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    engagement_id = _seed_engagement(tmp_path)
    private_key, public_key = generate_keypair()
    now = datetime.now(UTC)
    signed = SignedEngagementManifest.sign_manifest(
        EngagementManifest(
            engagement_id=engagement_id,
            client="Acme",
            owner="Security Owner",
            approver="Authorized Approver",
            contract_id="CONTRACT-WEB-01",
            scope=EngagementScope(included=("acme.test",), excluded=("vpn.acme.test",)),
            valid_from=now - timedelta(hours=2),
            expires_at=expires_at or now + timedelta(hours=1),
            allowed_techniques=allowed_techniques,
        ),
        private_key_pem=private_key,
    )
    client = _client(
        tmp_path,
        engagements_database=tmp_path / ENGAGEMENTS_DB_NAME,
        trusted_manifest_public_key_pem=public_key,
    )
    return client, signed, engagement_id, public_key


def test_web_requires_verifies_and_binds_signed_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"nmap"})
    client, signed, engagement_id, public_key = _signed_web_client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    form = client.get("/assessments/new")
    assert 'name="signed_manifest"' in form.text

    base = {
        "scanner": "nmap",
        "target": "www.acme.test",
        "target_kind": "domain",
        "scope_id": "engagement",
        "engagement_id": engagement_id,
        "authorized": "on",
        "csrf_token": csrf,
    }
    missing = client.post("/jobs", data=base, follow_redirects=False)
    assert missing.status_code == 403
    assert "signed engagement manifest is required" in missing.text

    document = signed.model_dump_json()
    preview = _preview(
        client,
        csrf,
        activity="network",
        scanner="nmap",
        target="www.acme.test",
        target_kind="domain",
        engagement_id=engagement_id,
        signed_manifest=document,
    )
    assert preview.status_code == 200, preview.text
    assert signed.manifest_sha256 in preview.text

    accepted = client.post(
        "/jobs", data={**base, "signed_manifest": document}, follow_redirects=False
    )
    assert accepted.status_code == 303, accepted.text
    job_id = accepted.headers["location"].rsplit("/", 1)[-1]
    assert ThemisJobStore(tmp_path / "jobs.sqlite3").get(job_id).manifest_sha256 == (
        signed.manifest_sha256
    )
    audit = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "signature_envelope" not in audit
    assert "CONTRACT-WEB-01" not in audit

    retained = SqliteEngagementStore(tmp_path / ENGAGEMENTS_DB_NAME)
    try:
        stored = retained.authorize_stored_manifest(
            signed.manifest_sha256,
            trusted_public_key_pem=public_key,
            target="www.acme.test",
            technique="nmap",
            now=datetime.now(UTC),
        )
    finally:
        retained.close()
    assert stored.manifest_id == signed.manifest.manifest_id


def test_web_manifest_gate_rejects_tampering_expiry_revocation_and_wrong_tool(
    tmp_path: Path,
) -> None:
    client, signed, engagement_id, public_key = _signed_web_client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    base = {
        "scanner": "nmap",
        "target": "www.acme.test",
        "target_kind": "domain",
        "scope_id": "engagement",
        "engagement_id": engagement_id,
        "authorized": "on",
        "csrf_token": csrf,
    }

    tampered = signed.model_dump(mode="json")
    tampered["manifest"]["client"] = "Mallory"
    rejected = client.post("/jobs", data={**base, "signed_manifest": json.dumps(tampered)})
    assert rejected.status_code == 403
    assert "digest" in rejected.text

    wrong_tool = client.post(
        "/jobs",
        data={**base, "scanner": "nuclei", "signed_manifest": signed.model_dump_json()},
    )
    assert wrong_tool.status_code == 403

    outside_scope = client.post(
        "/jobs",
        data={**base, "target": "evil.test", "signed_manifest": signed.model_dump_json()},
    )
    assert outside_scope.status_code == 422
    assert "outside the selected engagement" in outside_scope.text

    store = SqliteEngagementStore(tmp_path / ENGAGEMENTS_DB_NAME)
    try:
        store.revoke_manifest(signed, trusted_public_key_pem=public_key)
    finally:
        store.close()
    revoked = client.post("/jobs", data={**base, "signed_manifest": signed.model_dump_json()})
    assert revoked.status_code == 403
    assert "revoked" in revoked.text

    expired_client, expired, expired_engagement, _ = _signed_web_client(
        tmp_path / "expired", expires_at=datetime.now(UTC) - timedelta(minutes=1)
    )
    _login(expired_client)
    expired_response = expired_client.post(
        "/jobs",
        data={
            **base,
            "engagement_id": expired_engagement,
            "csrf_token": _csrf(expired_client),
            "signed_manifest": expired.model_dump_json(),
        },
    )
    assert expired_response.status_code == 403


def test_web_rejects_manifest_when_no_trusted_key_is_configured(tmp_path: Path) -> None:
    client, signed, engagement_id, _ = _signed_web_client(tmp_path / "signed")
    del client
    untrusted = _client(
        tmp_path,
        engagements_database=tmp_path / "signed" / ENGAGEMENTS_DB_NAME,
    )
    _login(untrusted)
    response = untrusted.post(
        "/jobs",
        data={
            "scanner": "nmap",
            "target": "www.acme.test",
            "target_kind": "domain",
            "scope_id": "engagement",
            "engagement_id": engagement_id,
            "authorized": "on",
            "csrf_token": _csrf(untrusted),
            "signed_manifest": signed.model_dump_json(),
        },
    )
    assert response.status_code == 400
    assert "no trusted approver key" in response.text


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


def test_tools_page_reflects_the_real_capability_inventory(tmp_path: Path) -> None:
    """The Tools page is a faithful projection of the capability system."""
    from olympus.integrations.capabilities import CapabilityState, inventory

    client = _client(tmp_path)
    _login(client)
    page = client.get("/tools")
    assert page.status_code == 200

    expected = inventory()
    # Every catalogued engine is rendered — the list is not hardcoded in the GUI.
    for capability in expected:
        assert capability.name in page.text

    ready = sum(1 for item in expected if item.ready)
    adapter_missing = sum(1 for item in expected if item.state is CapabilityState.ADAPTER_MISSING)
    # Exactly the ready engines carry the "runnable here: yes" flag, and every
    # non-adapted engine is labelled as such: a non-adapted scanner can never
    # appear executable (ROADMAP WEB-D acceptance criterion).
    assert page.text.count("cap-flag-yes") == ready
    assert page.text.count("No Olympus adapter") == adapter_missing
    assert ">" + str(len(expected)) + "<" in page.text  # catalogued count tile


def test_tools_page_requires_the_capabilities_scope(tmp_path: Path) -> None:
    register = IdentityRegister(identities=[])
    register, secret = add_identity(register, identity_id="runner", scopes=["jobs:read"])
    register_path = tmp_path / "identities.json"
    save_register(register_path, register)
    client = TestClient(
        create_web_app(_settings(tmp_path, api_key="", identities_path=register_path)),
        base_url=BASE,
    )
    _login(client, secret)
    assert client.get("/tools", follow_redirects=False).status_code == 403


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


# --- Guided New Assessment flow (ROADMAP WEB-E) -----------------------------


def _preview(client: TestClient, csrf: str, **overrides: str) -> httpx.Response:
    payload = {
        "activity": "network",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_id": "engagement",
        "scanner": "",
        "csrf_token": csrf,
    }
    payload.update(overrides)
    return client.post("/assessments/preview", data=payload, follow_redirects=False)


def test_new_assessment_is_a_guided_flow_with_activities_and_tools(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    page = client.get("/assessments/new")
    assert page.status_code == 200
    # Activity-first wizard, not a single scanner field.
    assert 'name="activity"' in page.text
    assert "Automatic" in page.text
    # Non-native activities are surfaced honestly with a CLI hint, not faked.
    assert "olympus hermes scan" in page.text
    assert "olympus athena run" in page.text
    # The flow previews before launching; no direct queue from this form.
    assert 'action="/assessments/preview"' in page.text


def test_preview_shows_risk_and_does_not_queue_until_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"nmap"})
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="network", scanner="")
    assert preview.status_code == 200, preview.text
    assert "Olympus is about to run" in preview.text
    assert "nmap" in preview.text
    assert "Active" in preview.text  # the risk class is shown
    # Nothing was queued by previewing.
    jobs = client.get("/jobs")
    assert "nmap" not in jobs.text or "No jobs" in jobs.text
    # The launch form on the preview submits to /jobs and actually queues.
    job_id = _submit(client, csrf, scanner="nmap", target="127.0.0.1")
    assert client.get(f"/jobs/{job_id}").status_code == 200


def test_passive_activity_completes_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"subfinder"})
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="recon", scanner="")
    assert preview.status_code == 200, preview.text
    assert "subfinder" in preview.text  # automatic picked the ready recon tool
    assert "Passive" in preview.text
    job_id = _submit(client, csrf, scanner="subfinder", target="127.0.0.1")
    assert client.get(f"/jobs/{job_id}").status_code == 200


def test_intrusive_tool_preview_demands_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"sqlmap"})
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="web", scanner="sqlmap", target="127.0.0.1")
    assert preview.status_code == 200, preview.text
    assert "Intrusive" in preview.text
    assert "documented authorization" in preview.text


def test_preview_refuses_when_no_tool_is_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: set())
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="network", scanner="")
    assert preview.status_code == 422
    assert "No scanner" in preview.text


def test_preview_rejects_a_tool_outside_the_chosen_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"nmap", "nuclei"})
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="web", scanner="nmap")
    assert preview.status_code == 422
    assert "does not belong" in preview.text


def test_preview_rejects_a_not_ready_specific_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: set())
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="network", scanner="nmap")
    assert preview.status_code == 422
    assert "not ready" in preview.text


def test_preview_rejects_a_non_native_activity(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(client, csrf, activity="secret", scanner="")
    assert preview.status_code == 422
    assert "not run from the web" in preview.text


def test_preview_requires_a_valid_csrf_token(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)
    preview = _preview(client, "deadbeef", activity="network", scanner="")
    assert preview.status_code == 403


def test_preview_enforces_engagement_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"nmap"})
    client, engagement_id = _engagements_client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    preview = _preview(
        client,
        csrf,
        activity="network",
        scanner="nmap",
        target="evil.test",
        target_kind="domain",
        engagement_id=engagement_id,
    )
    assert preview.status_code == 422
    assert "outside the selected engagement" in preview.text


def test_preview_keeps_the_raw_target_but_displays_a_redacted_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The launch form must resubmit the real target; only the display is redacted.

    A URL target carrying a query secret would scan the wrong thing if the
    redacted display value were put into the hidden field (SEC-H must not change
    the operation).
    """
    import olympus.themis.web as web

    monkeypatch.setattr(web, "_ready_scanner_names", lambda: {"nuclei"})
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf(client)
    url = "http://127.0.0.1/?token=supersecretvalue"
    preview = _preview(
        client, csrf, activity="web", scanner="nuclei", target=url, target_kind="url"
    )
    assert preview.status_code == 200, preview.text
    # The secret is redacted wherever the target is shown to the operator.
    assert "supersecretvalue" not in _visible_text(preview.text)
    assert "[REDACTED]" in preview.text
    # But the hidden field that the launch form resubmits carries the real URL.
    assert f'name="target" value="{url}"' in preview.text


def _visible_text(html: str) -> str:
    """Strip hidden input values so a redaction check tests only shown text."""
    return re.sub(r'<input[^>]*type="hidden"[^>]*>', "", html)


# ---------------------------------------------------------------------------
# Findings review and triage (ROADMAP WEB-C wired into the browser)
# ---------------------------------------------------------------------------

_FINDING = {
    "schema_name": "olympus.finding",
    "schema_version": "1.0.0",
    "finding_id": "FND-2026-00001",
    "title": "Reflected XSS in search",
    "description": "User input reflected without encoding.",
    "severity": "high",
    "source": "artemis",
    "status": "new",
    "asset_id": "AST-2026-00001",
    "first_seen": "2026-08-14T07:43:32.267724Z",
    "last_seen": "2026-08-14T07:43:32.267733Z",
    "evidence": ["EVD-2026-00001", "http://127.0.0.1/?q=<script>"],
    "references": [],
    "remediation": "",
}


def _findings_dir(tmp_path: Path, *findings: dict[str, object]) -> Path:
    directory = tmp_path / "findings"
    directory.mkdir(parents=True, exist_ok=True)
    for index, finding in enumerate(findings or (_FINDING,)):
        (directory / f"bundle-{index}.json").write_text(json.dumps(finding), encoding="utf-8")
    return directory


def _findings_client(
    tmp_path: Path, *findings: dict[str, object], **overrides: object
) -> TestClient:
    return _client(
        tmp_path,
        findings_directory=_findings_dir(tmp_path, *findings),
        findings_database=tmp_path / "finding-transitions.sqlite3",
        **overrides,
    )


def _findings_csrf(client: TestClient, finding_id: str = "FND-2026-00001") -> str:
    page = client.get(f"/findings/{finding_id}")
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text)
    assert match is not None, page.text
    return match.group(1)


def test_findings_list_requires_the_findings_read_scope(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        api_key_scopes=("jobs:read",),
        findings_directory=_findings_dir(tmp_path),
    )
    _login(client)
    assert client.get("/findings").status_code == 403


def test_findings_page_is_honest_when_no_directory_is_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)  # no findings_directory
    _login(client)
    page = client.get("/findings")
    assert page.status_code == 200
    assert "No findings directory is configured" in page.text


def test_findings_list_renders_and_filters_like_the_cli(tmp_path: Path) -> None:
    low = {**_FINDING, "finding_id": "FND-2026-00002", "title": "Info banner", "severity": "info"}
    client = _findings_client(tmp_path, _FINDING, low)
    _login(client)

    page = client.get("/findings")
    assert page.status_code == 200
    assert "Reflected XSS in search" in page.text
    assert "Info banner" in page.text
    assert "2 of 2" in page.text

    # The minimum-severity filter reuses FindingFilter; only the high stays.
    filtered = client.get("/findings", params={"severity": "high"})
    assert "Reflected XSS in search" in filtered.text
    assert "Info banner" not in filtered.text
    assert "1 of 2" in filtered.text


def test_finding_detail_shows_lifecycle_and_evidence(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    page = client.get("/findings/FND-2026-00001")
    assert page.status_code == 200
    assert "Lifecycle" in page.text
    assert "Evidence" in page.text
    # A structured reference with no ledger wired in is honestly "no custody".
    assert "no-custody" in page.text
    # The inline, non-structured reference is redacted (SEC-H), never raw script.
    assert "<script>" not in page.text


def test_finding_detail_404_for_unknown_id(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    assert client.get("/findings/FND-2026-09999").status_code == 404


def test_a_transition_is_recorded_and_updates_the_effective_status(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    csrf = _findings_csrf(client)
    moved = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "confirmed", "reason": "exploited in a lab", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert moved.status_code == 303
    assert moved.headers["location"] == "/findings/FND-2026-00001"
    # The effective status is folded from the append-only store, not the bundle.
    page = client.get("/findings/FND-2026-00001")
    assert "Confirmed" in page.text
    assert "exploited in a lab" in page.text
    # The immutable producer bundle is never rewritten.
    bundle = json.loads((tmp_path / "findings" / "bundle-0.json").read_text())
    assert bundle["status"] == "new"


def test_a_transition_requires_a_valid_csrf_token(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    response = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "confirmed", "csrf_token": "wrong"},
    )
    assert response.status_code == 403


def test_a_transition_requires_the_findings_write_scope(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        api_key_scopes=("findings:read",),
        findings_directory=_findings_dir(tmp_path),
        findings_database=tmp_path / "ft.sqlite3",
    )
    _login(client)
    response = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "confirmed", "csrf_token": "anything"},
    )
    assert response.status_code == 403


def test_an_illegal_transition_is_rejected_and_records_nothing(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    csrf = _findings_csrf(client)
    # new -> in_remediation is not a legal edge in the shared state machine.
    bad = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "in_remediation", "reason": "x", "csrf_token": csrf},
    )
    assert bad.status_code == 422
    # Nothing was recorded, so the finding is still New.
    assert "New" in client.get("/findings/FND-2026-00001").text


def test_suppressing_a_finding_requires_a_reason(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    csrf = _findings_csrf(client)
    response = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "accepted", "reason": "   ", "csrf_token": csrf},
    )
    assert response.status_code == 422
    assert "reason is required" in response.text


def test_transition_without_a_lifecycle_store_is_refused(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        api_key_scopes=SCOPES,
        findings_directory=_findings_dir(tmp_path),
    )  # findings_database is None
    _login(client)
    csrf = _csrf(client)
    response = client.post(
        "/findings/FND-2026-00001/transition",
        data={"target": "confirmed", "reason": "x", "csrf_token": csrf},
    )
    assert response.status_code == 400
    assert "lifecycle store" in response.text


# ---------------------------------------------------------------------------
# Report builder over Vulcan (ROADMAP WEB-I slice 1)
# ---------------------------------------------------------------------------

_LOW_FINDING = {
    **_FINDING,
    "finding_id": "FND-2026-00002",
    "title": "Server banner disclosed",
    "severity": "info",
}


def test_report_requires_the_findings_read_scope(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        api_key_scopes=("jobs:read",),
        findings_directory=_findings_dir(tmp_path),
    )
    _login(client)
    assert client.get("/findings/report", params={"format": "md"}).status_code == 403


def test_report_renders_in_each_format_as_a_download(tmp_path: Path) -> None:
    client = _findings_client(tmp_path, _FINDING, _LOW_FINDING)
    _login(client)
    for fmt, content_type in (
        ("md", "text/markdown"),
        ("html", "text/html"),
        ("json", "application/json"),
    ):
        response = client.get("/findings/report", params={"format": fmt, "engagement": "Demo 2026"})
        assert response.status_code == 200, response.text
        assert content_type in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]
        assert "olympus-report-Demo-2026." in response.headers["content-disposition"]
        assert "Reflected XSS in search" in response.text


def test_report_reflects_the_same_filter_as_the_table(tmp_path: Path) -> None:
    client = _findings_client(tmp_path, _FINDING, _LOW_FINDING)
    _login(client)
    report = client.get("/findings/report", params={"format": "md", "severity": "high"})
    assert report.status_code == 200
    # Only the high finding survives the min-severity filter — exactly the table.
    assert "Reflected XSS in search" in report.text
    assert "Server banner disclosed" not in report.text


def test_report_rejects_an_unknown_format(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    assert client.get("/findings/report", params={"format": "pdf"}).status_code == 422


def test_report_exports_sarif_of_the_filtered_findings(tmp_path: Path) -> None:
    client = _findings_client(tmp_path, _FINDING, _LOW_FINDING)
    _login(client)
    response = client.get("/findings/report", params={"format": "sarif", "severity": "high"})
    assert response.status_code == 200, response.text
    assert "application/sarif+json" in response.headers["content-type"]
    assert ".sarif.json" in response.headers["content-disposition"]
    document = json.loads(response.text)
    assert document["version"] == "2.1.0"
    # Only the high finding survives the min-severity filter — the SARIF reflects it.
    titles = {r["message"]["text"].splitlines()[0] for r in document["runs"][0]["results"]}
    assert "Reflected XSS in search" in titles
    assert "Server banner disclosed" not in titles


def test_report_is_honest_when_no_directory_is_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)  # no findings_directory
    _login(client)
    response = client.get("/findings/report", params={"format": "md"})
    assert response.status_code == 400


def test_report_route_does_not_shadow_a_finding_detail(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)
    _login(client)
    # 'report' is a dedicated route, and a real finding detail still resolves.
    assert client.get("/findings/FND-2026-00001").status_code == 200
    # The findings list offers the export links for the current view.
    assert "/findings/report?format=md" in client.get("/findings").text


# ---------------------------------------------------------------------------
# Scan diff in the browser (ROADMAP WEB-I slice 2)
# ---------------------------------------------------------------------------


def _baseline_dir(tmp_path: Path, *findings: dict[str, object]) -> Path:
    directory = tmp_path / "baseline"
    directory.mkdir(parents=True, exist_ok=True)
    for index, finding in enumerate(findings):
        (directory / f"base-{index}.json").write_text(json.dumps(finding), encoding="utf-8")
    return directory


def test_scan_diff_requires_the_findings_read_scope(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        api_key_scopes=("jobs:read",),
        findings_directory=_findings_dir(tmp_path),
        baseline_findings_directory=_baseline_dir(tmp_path, _FINDING),
    )
    _login(client)
    assert client.get("/findings/diff").status_code == 403


def test_scan_diff_is_honest_when_baseline_is_not_configured(tmp_path: Path) -> None:
    client = _findings_client(tmp_path)  # findings dir but no baseline
    _login(client)
    page = client.get("/findings/diff")
    assert page.status_code == 200
    assert "not set" in page.text


def test_scan_diff_classifies_new_resolved_and_persistent(tmp_path: Path) -> None:
    resolved = {
        **_FINDING,
        "finding_id": "FND-2026-00009",
        "title": "Legacy TLS",
        "asset_id": "AST-2026-00009",
    }
    # Baseline: the current XSS (same asset+title → persistent) plus a resolved one.
    baseline = {**_FINDING, "finding_id": "FND-2026-05555", "severity": "low"}
    client = _client(
        tmp_path,
        findings_directory=_findings_dir(tmp_path, _FINDING),
        baseline_findings_directory=_baseline_dir(tmp_path, baseline, resolved),
    )
    _login(client)
    page = client.get("/findings/diff")
    assert page.status_code == 200
    # XSS persists (worsened low -> high); Legacy TLS resolved; nothing new.
    assert "Reflected XSS in search" in page.text
    assert "Legacy TLS" in page.text
    assert "low → high" in page.text


def test_scan_diff_does_not_shadow_a_finding_detail(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        findings_directory=_findings_dir(tmp_path, _FINDING),
        baseline_findings_directory=_baseline_dir(tmp_path, _FINDING),
    )
    _login(client)
    assert client.get("/findings/diff").status_code == 200
    assert client.get("/findings/FND-2026-00001").status_code == 200

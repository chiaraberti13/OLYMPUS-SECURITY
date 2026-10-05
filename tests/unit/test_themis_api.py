from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore
from olympus.themis.api import ApiSettings, create_app

API_KEY = "a" * 32
AUTH = {"X-Olympus-API-Key": API_KEY}


def _seed_engagement(tmp_path: Path) -> Engagement:
    """Persist one engagement in the shared store and return it."""
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
    return engagement


def _engagements_client(tmp_path: Path) -> tuple[TestClient, Engagement]:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    engagement = _seed_engagement(tmp_path)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                engagements_database=tmp_path / ENGAGEMENTS_DB_NAME,
            )
        )
    )
    return client, engagement


def _scope(directory: Path, name: str = "engagement") -> Path:
    directory.mkdir(parents=True)
    path = directory / f"{name}.json"
    path.write_text(
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
    return path


def _client(tmp_path: Path) -> TestClient:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    return TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
            )
        )
    )


def test_health_is_public_but_operational_routes_require_auth(tmp_path: Path) -> None:
    client = _client(tmp_path)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["cache-control"] == "no-store"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert client.get("/ready").status_code == 401
    ready = client.get("/ready", headers=AUTH)
    assert ready.status_code == 200
    assert ready.json()["control_plane"] is True


def test_authenticated_job_lifecycle_uses_registered_scope(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_id": "engagement",
        "authorized": True,
    }
    submitted = client.post("/api/v1/jobs", headers=AUTH, json=payload)
    assert submitted.status_code == 201, submitted.text
    job_id = submitted.json()["job_id"]
    listed = client.get("/api/v1/jobs?state=queued", headers=AUTH)
    assert listed.status_code == 200 and listed.json()["count"] == 1
    assert client.get(f"/api/v1/jobs/{job_id}", headers=AUTH).status_code == 200
    cancelled = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=AUTH)
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"


def test_api_refuses_unconfirmed_or_unregistered_work(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "missing",
        "authorized": False,
    }
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 403
    payload["authorized"] = True
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 404
    payload["scope_id"] = "../escape"
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 422


def test_api_rejects_symlink_scope_and_oversized_body(tmp_path: Path) -> None:
    client = _client(tmp_path)
    real = _scope(tmp_path / "outside", "real")
    (tmp_path / "scopes" / "linked.json").symlink_to(real)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "linked",
        "authorized": True,
    }
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 404
    headers = {**AUTH, "Content-Length": str(64 * 1024 + 1)}
    assert client.post("/api/v1/jobs", headers=headers, json=payload).status_code == 413


def test_api_rejects_chunked_body_without_content_length(tmp_path: Path) -> None:
    client = _client(tmp_path)

    def oversized_chunks():  # type: ignore[no-untyped-def]
        for _ in range(65):
            yield b"x" * 1024

    response = client.post(
        "/api/v1/jobs",
        headers={**AUTH, "Content-Type": "application/json"},
        content=oversized_chunks(),
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "request body too large"}


def test_api_rejects_invalid_content_length(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/jobs",
        headers={**AUTH, "Content-Length": "-1", "Content-Type": "application/json"},
        content=b"{}",
    )
    assert response.status_code == 413


def test_cli_requires_secret_and_tls_for_remote_bind(tmp_path: Path) -> None:
    runner = CliRunner()
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    missing = runner.invoke(app, ["themis", "api", "--scope-directory", str(scopes)])
    assert missing.exit_code == 2
    assert "OLYMPUS_THEMIS_API_KEY" in missing.output
    assert "--identities" in missing.output
    remote = runner.invoke(
        app,
        ["themis", "api", "--scope-directory", str(scopes), "--host", "0.0.0.0"],  # noqa: S104
        env={"OLYMPUS_AEGIS_API_KEY": API_KEY},
    )
    assert remote.exit_code == 2
    assert "require TLS" in remote.output


def test_resubmitting_with_an_idempotency_key_returns_the_same_job(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "engagement",
        "authorized": True,
        "idempotency_key": "ticket-4711",
    }
    first = client.post("/api/v1/jobs", headers=AUTH, json=payload)
    second = client.post("/api/v1/jobs", headers=AUTH, json=payload)
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["job_id"] == second.json()["job_id"]
    assert client.get("/api/v1/jobs", headers=AUTH).json()["count"] == 1

    conflicting = dict(payload, target="127.0.0.2")
    assert client.post("/api/v1/jobs", headers=AUTH, json=conflicting).status_code == 409


def test_submission_validates_the_attempt_budget(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "engagement",
        "authorized": True,
        "max_attempts": 99,
    }
    assert client.post("/api/v1/jobs", headers=AUTH, json=payload).status_code == 422
    accepted = client.post("/api/v1/jobs", headers=AUTH, json=dict(payload, max_attempts=3))
    assert accepted.status_code == 201
    assert accepted.json()["max_attempts"] == 3


def test_the_api_never_publishes_server_filesystem_paths(tmp_path: Path) -> None:
    client = _client(tmp_path)
    submitted = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={
            "scanner": "nmap",
            "target": "127.0.0.1",
            "scope_id": "engagement",
            "authorized": True,
        },
    )
    assert submitted.status_code == 201
    body = submitted.json()
    assert body["scope_name"] == "engagement.json"
    assert "scope_path" not in body
    assert str(tmp_path) not in submitted.text
    listed = client.get("/api/v1/jobs", headers=AUTH)
    assert str(tmp_path) not in listed.text
    assert listed.json()["schema_version"] == "2.0.0"


def test_engagements_are_readable_over_the_api(tmp_path: Path) -> None:
    client, engagement = _engagements_client(tmp_path)
    listed = client.get("/api/v1/engagements", headers=AUTH)
    assert listed.status_code == 200
    body = listed.json()
    assert body["schema_name"] == "olympus.themis-engagement-list"
    assert body["count"] == 1
    assert body["engagements"][0]["engagement_id"] == engagement.engagement_id

    shown = client.get(f"/api/v1/engagements/{engagement.engagement_id}", headers=AUTH)
    assert shown.status_code == 200
    assert shown.json()["schema_name"] == "olympus.engagement"
    assert shown.json()["name"] == "Acme web"
    # An unknown engagement is an honest 404, never a silent empty record.
    assert client.get("/api/v1/engagements/ENG-2000-00000", headers=AUTH).status_code == 404


def test_engagement_routes_report_when_the_store_is_not_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)  # no engagements_database wired
    unavailable = client.get("/api/v1/engagements", headers=AUTH)
    assert unavailable.status_code == 503
    assert "not configured" in unavailable.json()["detail"]


def test_engagement_read_requires_its_own_scope(tmp_path: Path) -> None:
    from olympus.themis.identity import IdentityRegister, add_identity, save_register

    scopes = tmp_path / "scopes"
    _scope(scopes)
    _seed_engagement(tmp_path)
    register = IdentityRegister(identities=[])
    register, secret = add_identity(register, identity_id="runner", scopes=["jobs:write"])
    register_path = tmp_path / "identities.json"
    save_register(register_path, register)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                identities_path=register_path,
                engagements_database=tmp_path / ENGAGEMENTS_DB_NAME,
            )
        )
    )
    denied = client.get("/api/v1/engagements", headers={"X-Olympus-API-Key": secret})
    assert denied.status_code == 403
    assert "engagements:read" in denied.json()["detail"]


def test_submission_is_scope_checked_against_its_engagement(tmp_path: Path) -> None:
    client, engagement = _engagements_client(tmp_path)
    base = {
        "scanner": "nmap",
        "scope_id": "engagement",
        "authorized": True,
        "engagement_id": engagement.engagement_id,
    }
    in_scope = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**base, "target": "www.acme.test", "target_kind": "domain"},
    )
    assert in_scope.status_code == 201, in_scope.text

    out_of_scope = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**base, "target": "evil.test", "target_kind": "domain"},
    )
    assert out_of_scope.status_code == 422
    assert "outside the engagement scope" in out_of_scope.json()["detail"]

    # An explicitly excluded host is refused even though its parent is included.
    excluded = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**base, "target": "https://vpn.acme.test/login", "target_kind": "url"},
    )
    assert excluded.status_code == 422

    # An unknown engagement id is refused before any job is queued.
    unknown = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**base, "engagement_id": "ENG-2000-00000", "target": "www.acme.test"},
    )
    assert unknown.status_code == 404

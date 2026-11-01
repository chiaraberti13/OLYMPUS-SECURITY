from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Engagement, EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest
from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore
from olympus.themis.api import ApiSettings, create_app
from olympus.themis.identity import SCOPES
from olympus.themis.jobs import ThemisJobStore

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
                api_key_scopes=SCOPES,
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
                api_key_scopes=SCOPES,
            )
        )
    )


def _apollo_rules(tmp_path: Path) -> Path:
    directory = tmp_path / "apollo-rules"
    directory.mkdir(parents=True)
    (directory / "suspicious-process.yaml").write_text(
        json.dumps(
            {
                "schema_name": "olympus.apollo-rule",
                "schema_version": "1.0.0",
                "rule_id": "APL-API-TEST",
                "title": "Suspicious process",
                "event_type": "process.start",
                "conditions": {"image": "powershell.exe"},
                "severity": "high",
                "mitre_attack": ["T1059.001"],
            }
        ),
        encoding="utf-8",
    )
    return directory


def _apollo_event() -> dict[str, object]:
    return {
        "schema_name": "olympus.event",
        "schema_version": "1.0.0",
        "event_id": "EVT-2026-00001",
        "event_type": "process.start",
        "source": "apollo",
        "observed_at": "2026-11-01T09:00:00Z",
        "attributes": {"image": "powershell.exe"},
    }


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


def test_apollo_rules_and_evaluation_are_versioned_and_deterministic(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                api_key_scopes=SCOPES,
                apollo_rules_directory=_apollo_rules(tmp_path),
            )
        )
    )

    listed = client.get("/api/v1/apollo/rules", headers=AUTH)
    assert listed.status_code == 200
    assert listed.json()["schema_name"] == "olympus.apollo-rule-list"
    assert listed.json()["schema_version"] == "1.0.0"
    assert listed.json()["rules"][0]["rule_id"] == "APL-API-TEST"

    evaluated = client.post(
        "/api/v1/apollo/evaluate", headers=AUTH, json={"events": [_apollo_event()]}
    )
    assert evaluated.status_code == 200, evaluated.text
    body = evaluated.json()
    assert body["schema_name"] == "olympus.apollo-evaluation"
    assert body["schema_version"] == "1.0.0"
    assert (body["rule_count"], body["event_count"], body["alert_count"]) == (1, 1, 1)
    assert body["alerts"][0]["alert_id"] == "ALT-A4FABDF3F2910D6C48B3F82F"
    assert body["alerts"][0]["event_id"] == "EVT-2026-00001"


def test_apollo_api_is_fail_closed_when_rule_pack_is_not_configured(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/apollo/rules", headers=AUTH)
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_metis_extract_is_versioned_offline_and_covers_every_format(tmp_path: Path) -> None:
    client = _client(tmp_path)

    text = client.post(
        "/api/v1/metis/extract",
        headers=AUTH,
        json={
            "source_format": "text",
            "text": "beacon to 203.0.113.9 from evil@bad.example, see CVE-2021-44228",
        },
    )
    assert text.status_code == 200, text.text
    body = text.json()
    assert body["schema_name"] == "olympus.metis-extraction"
    assert body["schema_version"] == "1.0.0"
    assert body["source_format"] == "text"
    kinds = {item["indicator_type"] for item in body["indicators"]}
    assert {"ipv4", "email", "domain", "cve"} <= kinds
    assert body["indicator_count"] == len(body["indicators"])
    assert body["skipped_count"] == 0

    stix_bundle = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--11111111-1111-4111-8111-111111111111",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--22222222-2222-4222-8222-222222222222",
                    "pattern": "[ipv4-addr:value = '198.51.100.7']",
                    "pattern_type": "stix",
                }
            ],
        }
    )
    stix = client.post(
        "/api/v1/metis/extract",
        headers=AUTH,
        json={"source_format": "stix", "text": stix_bundle},
    )
    assert stix.status_code == 200, stix.text
    assert stix.json()["indicators"] == [{"indicator_type": "ipv4", "value": "198.51.100.7"}]

    misp_event = json.dumps(
        {
            "Event": {
                "Attribute": [
                    {"type": "domain", "value": "bad.example"},
                    {"type": "comment", "value": "analyst note"},
                ]
            }
        }
    )
    misp = client.post(
        "/api/v1/metis/extract",
        headers=AUTH,
        json={"source_format": "misp", "text": misp_event},
    )
    assert misp.status_code == 200, misp.text
    misp_body = misp.json()
    assert misp_body["indicators"] == [{"indicator_type": "domain", "value": "bad.example"}]
    assert misp_body["skipped_count"] == 1
    assert "analyst note" in misp_body["skipped"][0]["value"]


def test_metis_extract_rejects_malformed_structured_input(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/metis/extract",
        headers=AUTH,
        json={"source_format": "stix", "text": "this is not a STIX bundle"},
    )
    assert response.status_code == 422


def test_metis_extract_requires_the_metis_read_scope(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                api_key_scopes=("capabilities:read",),
            )
        )
    )
    response = client.post(
        "/api/v1/metis/extract",
        headers=AUTH,
        json={"source_format": "text", "text": "203.0.113.9"},
    )
    assert response.status_code == 403


def test_athena_profiles_are_versioned_and_target_free(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/api/v1/athena/profiles", headers=AUTH)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_name"] == "olympus.athena-profile-list"
    assert body["schema_version"] == "1.0.0"
    by_id = {profile["profile_id"]: profile for profile in body["profiles"]}
    assert {"light", "deep"} <= set(by_id)
    # Light is passive; deep adds the active AEGIS scan step.
    assert by_id["light"]["active"] is False
    assert by_id["deep"]["active"] is True
    assert "themis" in by_id["deep"]["adapters"]
    # Profiles never carry a target of their own.
    assert "targets" not in by_id["light"]


def test_athena_plan_builds_a_signable_plan_from_a_profile(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/athena/plan",
        headers=AUTH,
        json={
            "profile": "light",
            "engagement_id": "ENG-2026-001",
            "approval_reference": "RoE-2026-001",
            "targets": [{"kind": "domain", "value": "app.example.com"}],
            "allowed_domains": ["example.com"],
            "report_formats": ["json", "markdown"],
            "confirmed": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_name"] == "olympus.athena-plan"
    assert body["schema_version"] == "1.0.0"
    assert body["profile_id"] == "light"
    assert body["engagement_id"] == "ENG-2026-001"
    assert body["authorized"] is True
    assert body["adapters"] == ["dns", "web-headers", "whois"]
    assert body["targets"] == [{"kind": "domain", "value": "app.example.com"}]
    assert body["allowed_domains"] == ["example.com"]
    assert body["report_formats"] == ["json", "markdown"]
    assert len(body["plan_digest"]) == 64
    assert len(body["scope_digest"]) == 64
    # The returned document is the exact canonical plan and re-digests identically.
    plan_doc = json.loads(body["plan_json"])
    assert plan_doc["schema_name"] == "olympus.athena.plan"
    assert plan_doc["authorization"]["confirmed"] is True


def test_athena_plan_requires_confirmed_authorization(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/athena/plan",
        headers=AUTH,
        json={
            "profile": "deep",
            "engagement_id": "ENG-1",
            "approval_reference": "RoE-1",
            "targets": [{"kind": "domain", "value": "app.example.com"}],
            "allowed_domains": ["example.com"],
            "confirmed": False,
        },
    )
    # A profile never self-authorizes a run: an unconfirmed request is rejected.
    assert response.status_code == 422


def test_athena_plan_rejects_an_out_of_scope_or_malformed_target(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/api/v1/athena/plan",
        headers=AUTH,
        json={
            "profile": "light",
            "engagement_id": "ENG-1",
            "approval_reference": "RoE-1",
            "targets": [{"kind": "domain", "value": "has space"}],
            "allowed_domains": ["example.com"],
            "confirmed": True,
        },
    )
    assert response.status_code == 422


def test_athena_endpoints_require_the_athena_read_scope(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                api_key_scopes=("capabilities:read",),
            )
        )
    )
    assert client.get("/api/v1/athena/profiles", headers=AUTH).status_code == 403
    plan = client.post(
        "/api/v1/athena/plan",
        headers=AUTH,
        json={
            "profile": "light",
            "engagement_id": "ENG-1",
            "approval_reference": "RoE-1",
            "targets": [{"kind": "domain", "value": "app.example.com"}],
            "allowed_domains": ["example.com"],
            "confirmed": True,
        },
    )
    assert plan.status_code == 403


def test_shared_key_defaults_to_capabilities_read_only(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
            )
        )
    )
    assert client.get("/api/v1/capabilities", headers=AUTH).status_code == 200
    denied = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={
            "scanner": "nmap",
            "target": "127.0.0.1",
            "scope_id": "engagement",
            "authorized": True,
        },
    )
    assert denied.status_code == 403
    assert "jobs:write" in denied.json()["detail"]


def test_api_rejects_excess_concurrent_requests_and_audits_them(
    tmp_path: Path, monkeypatch
) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    audit_path = tmp_path / "api-audit.jsonl"
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                api_key_scopes=SCOPES,
                audit_path=audit_path,
                max_concurrent_requests=1,
            )
        )
    )
    entered = threading.Event()
    release = threading.Event()
    original_submit = ThemisJobStore.submit

    def delayed_submit(self, **kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return original_submit(self, **kwargs)

    monkeypatch.setattr(ThemisJobStore, "submit", delayed_submit)
    payload = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "engagement",
        "authorized": True,
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.post, "/api/v1/jobs", headers=AUTH, json=payload)
        assert entered.wait(timeout=5)
        overloaded = client.post("/api/v1/jobs", headers=AUTH, json=payload)
        assert overloaded.status_code == 503
        assert overloaded.headers["retry-after"] == "1"
        assert overloaded.headers["x-request-id"]
        release.set()
        accepted = first.result(timeout=5)

    assert accepted.status_code == 201
    audit = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert any(record["outcome"] == "503" for record in audit)


def test_api_concurrency_limit_is_bounded_and_rejects_booleans(tmp_path: Path) -> None:
    for invalid in (0, -1, 4_097, True):
        settings = ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key=API_KEY,
            max_concurrent_requests=invalid,
        )
        try:
            settings.validate()
        except ValueError as exc:
            assert "max_concurrent_requests" in str(exc)
        else:
            raise AssertionError(f"accepted invalid concurrency limit {invalid!r}")


def test_api_accepts_minimum_concurrency_limit(tmp_path: Path) -> None:
    scope_directory = tmp_path / "scopes"
    scope_directory.mkdir()
    settings = ApiSettings(
        database=tmp_path / "jobs.sqlite3",
        scope_directory=scope_directory,
        api_key=API_KEY,
        max_concurrent_requests=1,
    )
    settings.validate()


@pytest.mark.parametrize(
    "setting_name",
    (
        "scope_directory",
        "findings_directory",
        "baseline_findings_directory",
        "incidents_directory",
        "apollo_rules_directory",
    ),
)
@pytest.mark.parametrize("broken", (False, True))
def test_api_rejects_symlinked_directories(tmp_path: Path, setting_name: str, broken: bool) -> None:
    scope_directory = tmp_path / "scopes"
    scope_directory.mkdir()
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(
            tmp_path / "missing" if broken else target_directory,
            target_is_directory=True,
        )
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    directory_settings = {setting_name: linked_directory}
    if setting_name == "scope_directory":
        scope_directory = linked_directory
        directory_settings = {}
    settings = ApiSettings(
        database=tmp_path / "jobs.sqlite3",
        scope_directory=scope_directory,
        api_key=API_KEY,
        **directory_settings,
    )
    with pytest.raises(ValueError, match="non-symlink directory"):
        settings.validate()


def test_shared_key_scopes_reject_empty_or_unknown_grants(tmp_path: Path) -> None:
    for invalid in ((), ("jobs:admin",), (42,)):
        settings = ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key=API_KEY,
            api_key_scopes=invalid,
        )
        try:
            settings.validate()
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid shared-key scopes {invalid!r}")


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
    assert listed.json()["schema_version"] == "3.0.0"


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


def test_api_requires_verifies_and_binds_signed_manifest(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    _scope(scopes)
    engagement = _seed_engagement(tmp_path)
    private_key, public_key = generate_keypair()
    now = datetime.now(UTC)
    manifest = EngagementManifest(
        engagement_id=engagement.engagement_id,
        client="Acme",
        owner="Security Owner",
        approver="Authorized Approver",
        contract_id="CONTRACT-API-01",
        scope=engagement.scope,
        valid_from=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        allowed_techniques=("nmap",),
    )
    signed = SignedEngagementManifest.sign_manifest(manifest, private_key_pem=private_key)
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=API_KEY,
                api_key_scopes=SCOPES,
                engagements_database=tmp_path / ENGAGEMENTS_DB_NAME,
                trusted_manifest_public_key_pem=public_key,
            )
        )
    )
    payload = {
        "scanner": "nmap",
        "target": "www.acme.test",
        "target_kind": "domain",
        "scope_id": "engagement",
        "authorized": True,
        "engagement_id": engagement.engagement_id,
    }
    missing = client.post("/api/v1/jobs", headers=AUTH, json=payload)
    assert missing.status_code == 403
    accepted = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**payload, "signed_manifest": signed.model_dump(mode="json")},
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["manifest_sha256"] == signed.manifest_sha256

    revocations = SqliteEngagementStore(tmp_path / ENGAGEMENTS_DB_NAME)
    try:
        retained = revocations.authorize_stored_manifest(
            signed.manifest_sha256,
            trusted_public_key_pem=public_key,
            target="www.acme.test",
            technique="nmap",
            now=datetime.now(UTC),
        )
        assert retained.manifest_id == signed.manifest.manifest_id
        revocations.revoke_manifest(signed, trusted_public_key_pem=public_key)
    finally:
        revocations.close()
    revoked = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**payload, "signed_manifest": signed.model_dump(mode="json")},
    )
    assert revoked.status_code == 403
    assert "revoked" in revoked.json()["detail"]

    wrong_scanner = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={**payload, "scanner": "nuclei", "signed_manifest": signed.model_dump(mode="json")},
    )
    assert wrong_scanner.status_code == 403


def test_api_rejects_manifest_when_no_trusted_key_is_configured(tmp_path: Path) -> None:
    client, engagement = _engagements_client(tmp_path)
    private_key, _ = generate_keypair()
    now = datetime.now(UTC)
    signed = SignedEngagementManifest.sign_manifest(
        EngagementManifest(
            engagement_id=engagement.engagement_id,
            client="Acme",
            owner="Owner",
            approver="Approver",
            contract_id="CONTRACT-API-02",
            scope=engagement.scope,
            valid_from=now - timedelta(minutes=1),
            expires_at=now + timedelta(hours=1),
            allowed_techniques=("nmap",),
        ),
        private_key_pem=private_key,
    )
    response = client.post(
        "/api/v1/jobs",
        headers=AUTH,
        json={
            "scanner": "nmap",
            "target": "www.acme.test",
            "target_kind": "domain",
            "scope_id": "engagement",
            "authorized": True,
            "engagement_id": engagement.engagement_id,
            "signed_manifest": signed.model_dump(mode="json"),
        },
    )
    assert response.status_code == 400

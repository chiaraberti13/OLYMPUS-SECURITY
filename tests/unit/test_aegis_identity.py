"""Tests for AEGIS API identities: scopes, rotation, revocation and rate limits.

The API is exercised through a real ASGI client rather than by calling the
dependency functions, so what is asserted is the status code a caller actually
receives.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.aegis.api import ApiSettings, create_app
from olympus.aegis.identity import (
    SCOPES,
    IdentityError,
    IdentityRegister,
    RateLimiter,
    add_identity,
    generate_secret,
    hash_secret,
    load_register,
    revoke_identity,
    rotate_identity,
    save_register,
)
from olympus.cli import app

runner = CliRunner()


def _scopes_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "scopes"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "engagement.json").write_text(
        json.dumps(
            {
                "schema_name": "olympus.aegis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    return directory


def _register_with(tmp_path: Path, **identities: list[str]) -> tuple[Path, dict[str, str]]:
    """Write a register granting each named identity its listed scopes."""
    register = IdentityRegister()
    secrets_by_id: dict[str, str] = {}
    for identity_id, scopes in identities.items():
        register, secret = add_identity(register, identity_id=identity_id, scopes=scopes)
        secrets_by_id[identity_id] = secret
    path = tmp_path / "identities.json"
    save_register(path, register)
    return path, secrets_by_id


def _client(tmp_path: Path, register_path: Path, audit: Path | None = None) -> TestClient:
    return TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=_scopes_directory(tmp_path),
                identities_path=register_path,
                audit_path=audit,
            )
        )
    )


def _submission() -> dict[str, object]:
    return {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "scope_id": "engagement",
        "authorized": True,
    }


# --- register contract ----------------------------------------------------- #
def test_secrets_are_stored_only_as_hashes(tmp_path: Path) -> None:
    path, secrets_by_id = _register_with(tmp_path, reader=["jobs:read"])
    stored = path.read_text(encoding="utf-8")
    assert secrets_by_id["reader"] not in stored
    assert hash_secret(secrets_by_id["reader"]) in stored
    assert path.stat().st_mode & 0o777 == 0o600


def test_a_register_round_trips_and_rejects_unknown_scopes(tmp_path: Path) -> None:
    path, _ = _register_with(tmp_path, reader=["jobs:read"])
    assert [item.identity_id for item in load_register(path).identities] == ["reader"]
    with pytest.raises(IdentityError, match="unknown API scopes"):
        add_identity(IdentityRegister(), identity_id="x", scopes=["jobs:delete-everything"])


def test_duplicate_identities_and_bad_names_are_refused() -> None:
    register, _ = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    with pytest.raises(IdentityError, match="already exists"):
        add_identity(register, identity_id="ops", scopes=["jobs:read"])
    with pytest.raises(IdentityError, match="identity_id"):
        add_identity(IdentityRegister(), identity_id="Ops Console", scopes=["jobs:read"])


def test_short_secrets_are_never_accepted() -> None:
    with pytest.raises(IdentityError, match="at least 32 characters"):
        hash_secret("too-short")
    register, _ = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    with pytest.raises(IdentityError, match="too short"):
        register.authenticate("short")


def test_generated_secrets_are_unique_and_long() -> None:
    first, second = generate_secret(), generate_secret()
    assert first != second
    assert len(first) >= 32


# --- authentication, expiry, rotation, revocation -------------------------- #
def test_authentication_returns_the_matching_identity() -> None:
    register, secret = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    assert register.authenticate(secret).identity_id == "ops"
    with pytest.raises(IdentityError, match="no usable API identity"):
        register.authenticate(generate_secret())


def test_an_expired_identity_authenticates_nothing() -> None:
    register, secret = add_identity(
        IdentityRegister(), identity_id="temp", scopes=["jobs:read"], expires_in_days=1
    )
    assert register.authenticate(secret).identity_id == "temp"
    later = datetime.now(UTC) + timedelta(days=2)
    with pytest.raises(IdentityError):
        register.authenticate(secret, moment=later)


def test_rotation_keeps_the_previous_secret_for_a_bounded_overlap() -> None:
    register, original = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    rotated, replacement = rotate_identity(register, "ops", overlap_seconds=300)
    assert rotated.authenticate(replacement).identity_id == "ops"
    assert rotated.authenticate(original).identity_id == "ops", "overlap must not break clients"
    after_overlap = datetime.now(UTC) + timedelta(seconds=301)
    with pytest.raises(IdentityError):
        rotated.authenticate(original, moment=after_overlap)
    assert rotated.authenticate(replacement, moment=after_overlap).identity_id == "ops"


def test_rotation_without_overlap_invalidates_the_old_secret_at_once() -> None:
    register, original = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    rotated, replacement = rotate_identity(register, "ops", overlap_seconds=0)
    assert rotated.authenticate(replacement).identity_id == "ops"
    with pytest.raises(IdentityError):
        rotated.authenticate(original)


def test_revocation_also_kills_a_secret_inside_its_rotation_window() -> None:
    register, original = add_identity(IdentityRegister(), identity_id="ops", scopes=["jobs:read"])
    rotated, replacement = rotate_identity(register, "ops", overlap_seconds=3_600)
    revoked = revoke_identity(rotated, "ops")
    for credential in (original, replacement):
        with pytest.raises(IdentityError):
            revoked.authenticate(credential)


def test_rotating_or_revoking_an_unknown_identity_is_an_error() -> None:
    with pytest.raises(IdentityError, match="unknown API identity"):
        rotate_identity(IdentityRegister(), "ghost")
    with pytest.raises(IdentityError, match="unknown API identity"):
        revoke_identity(IdentityRegister(), "ghost")


# --- rate limiting --------------------------------------------------------- #
def test_the_rate_limiter_bounds_a_window_and_then_reopens() -> None:
    limiter = RateLimiter(window_seconds=60.0)
    assert limiter.check("ops", 2, now=1000.0) is None
    assert limiter.check("ops", 2, now=1001.0) is None
    wait = limiter.check("ops", 2, now=1002.0)
    assert wait is not None and 0 < wait <= 60
    # A different identity has its own budget.
    assert limiter.check("other", 2, now=1002.0) is None
    # Once the window has passed, the identity is served again.
    assert limiter.check("ops", 2, now=1100.0) is None


# --- the API surface ------------------------------------------------------- #
def test_scopes_decide_what_an_identity_may_do(tmp_path: Path) -> None:
    register_path, secrets_by_id = _register_with(
        tmp_path, reader=["jobs:read"], submitter=["jobs:write", "jobs:read"]
    )
    client = _client(tmp_path, register_path)
    reader = {"X-Olympus-API-Key": secrets_by_id["reader"]}
    submitter = {"X-Olympus-API-Key": secrets_by_id["submitter"]}

    assert client.post("/api/v1/jobs", headers=reader, json=_submission()).status_code == 403
    created = client.post("/api/v1/jobs", headers=submitter, json=_submission())
    assert created.status_code == 201
    job_id = created.json()["job_id"]

    assert client.get("/api/v1/jobs", headers=reader).status_code == 200
    # Neither identity was granted jobs:cancel.
    cancelled = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=submitter)
    assert cancelled.status_code == 403
    assert "jobs:cancel" in cancelled.json()["detail"]


def test_an_unknown_or_revoked_credential_is_refused(tmp_path: Path) -> None:
    register_path, secrets_by_id = _register_with(tmp_path, ops=list(SCOPES))
    client = _client(tmp_path, register_path)
    headers = {"X-Olympus-API-Key": secrets_by_id["ops"]}
    assert client.get("/api/v1/jobs", headers=headers).status_code == 200
    assert client.get("/api/v1/jobs").status_code == 401
    assert (
        client.get("/api/v1/jobs", headers={"X-Olympus-API-Key": generate_secret()}).status_code
        == 401
    )

    # Revocation takes effect without restarting the server.
    save_register(register_path, revoke_identity(load_register(register_path), "ops"))
    assert client.get("/api/v1/jobs", headers=headers).status_code == 401


def test_a_rotated_credential_is_accepted_without_a_restart(tmp_path: Path) -> None:
    register_path, secrets_by_id = _register_with(tmp_path, ops=list(SCOPES))
    client = _client(tmp_path, register_path)
    rotated, replacement = rotate_identity(load_register(register_path), "ops")
    save_register(register_path, rotated)

    for credential in (secrets_by_id["ops"], replacement):
        response = client.get("/api/v1/jobs", headers={"X-Olympus-API-Key": credential})
        assert response.status_code == 200, "both secrets are valid during the overlap"


def test_an_unreadable_register_authenticates_nobody(tmp_path: Path) -> None:
    register_path, secrets_by_id = _register_with(tmp_path, ops=list(SCOPES))
    client = _client(tmp_path, register_path)
    headers = {"X-Olympus-API-Key": secrets_by_id["ops"]}
    assert client.get("/api/v1/jobs", headers=headers).status_code == 200
    register_path.write_text("{ not json", encoding="utf-8")
    assert client.get("/api/v1/jobs", headers=headers).status_code == 401


def test_the_api_enforces_the_identity_rate_limit(tmp_path: Path) -> None:
    register = IdentityRegister()
    register, secret = add_identity(
        register, identity_id="chatty", scopes=["jobs:read"], rate_limit_per_minute=2
    )
    register_path = tmp_path / "identities.json"
    save_register(register_path, register)
    client = _client(tmp_path, register_path)
    headers = {"X-Olympus-API-Key": secret}

    assert client.get("/api/v1/jobs", headers=headers).status_code == 200
    assert client.get("/api/v1/jobs", headers=headers).status_code == 200
    throttled = client.get("/api/v1/jobs", headers=headers)
    assert throttled.status_code == 429
    assert int(throttled.headers["retry-after"]) >= 1


def test_a_single_api_key_still_works_and_holds_every_scope(tmp_path: Path) -> None:
    key = "k" * 40
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=_scopes_directory(tmp_path),
                api_key=key,
            )
        )
    )
    headers = {"X-Olympus-API-Key": key}
    created = client.post("/api/v1/jobs", headers=headers, json=_submission())
    assert created.status_code == 201
    assert (
        client.post(f"/api/v1/jobs/{created.json()['job_id']}/cancel", headers=headers).status_code
        == 200
    )


def test_the_api_refuses_to_start_without_any_credential(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="either an API key or an identity register"):
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=_scopes_directory(tmp_path),
            )
        )


# --- request, correlation and audit identifiers ---------------------------- #
def test_every_response_carries_a_request_id(tmp_path: Path) -> None:
    register_path, _ = _register_with(tmp_path, ops=list(SCOPES))
    client = _client(tmp_path, register_path)
    generated = client.get("/health")
    assert generated.headers["x-request-id"].startswith("req-")
    assert generated.headers["x-correlation-id"].startswith("cor-")

    echoed = client.get(
        "/health", headers={"X-Request-ID": "req-abc.1", "X-Correlation-ID": "trace-42"}
    )
    assert echoed.headers["x-request-id"] == "req-abc.1"
    assert echoed.headers["x-correlation-id"] == "trace-42"

    # A caller cannot inject arbitrary text into the logs through the header.
    injected = client.get("/health", headers={"X-Request-ID": "req abc\tinjected"})
    assert injected.headers["x-request-id"].startswith("req-")


def test_each_request_is_audited_with_its_identity_and_id(tmp_path: Path) -> None:
    register_path, secrets_by_id = _register_with(tmp_path, ops=list(SCOPES))
    audit = tmp_path / "api-audit.ndjson"
    client = _client(tmp_path, register_path, audit=audit)
    response = client.post(
        "/api/v1/jobs",
        headers={"X-Olympus-API-Key": secrets_by_id["ops"], "X-Request-ID": "req-4711"},
        json=_submission(),
    )
    assert response.status_code == 201

    records = [json.loads(line) for line in audit.read_text().splitlines() if line]
    entry = next(item for item in records if item["execution_id"] == "req-4711")
    assert entry["action"] == "aegis.api POST /api/v1/jobs"
    assert entry["outcome"] == "201"
    assert entry["metadata"]["identity"] == "ops"
    assert secrets_by_id["ops"] not in audit.read_text()
    assert audit.stat().st_mode & 0o777 == 0o600


def test_a_rejected_request_is_audited_as_anonymous(tmp_path: Path) -> None:
    register_path, _ = _register_with(tmp_path, ops=list(SCOPES))
    audit = tmp_path / "api-audit.ndjson"
    client = _client(tmp_path, register_path, audit=audit)
    assert client.get("/api/v1/jobs").status_code == 401
    records = [json.loads(line) for line in audit.read_text().splitlines() if line]
    assert records[-1]["outcome"] == "401"
    assert records[-1]["metadata"]["identity"] == "anonymous"


# --- operator surface ------------------------------------------------------ #
def test_identity_cli_creates_rotates_and_revokes(tmp_path: Path) -> None:
    register_path = tmp_path / "identities.json"
    created = runner.invoke(
        app,
        [
            "aegis",
            "identities",
            "add",
            "ops-console",
            "--scopes",
            "jobs:read,jobs:write",
            "-f",
            str(register_path),
        ],
    )
    assert created.exit_code == 0, created.output
    secret = json.loads(created.output)["secret"]
    assert load_register(register_path).authenticate(secret).identity_id == "ops-console"

    listed = runner.invoke(app, ["aegis", "identities", "list", "-f", str(register_path)])
    assert json.loads(listed.output)["count"] == 1
    assert secret not in listed.output
    assert "secret" not in listed.output

    rotated = runner.invoke(
        app, ["aegis", "identities", "rotate", "ops-console", "-f", str(register_path)]
    )
    replacement = json.loads(rotated.output)["secret"]
    assert replacement != secret

    revoked = runner.invoke(
        app, ["aegis", "identities", "revoke", "ops-console", "-f", str(register_path)]
    )
    assert revoked.exit_code == 0
    with pytest.raises(IdentityError):
        load_register(register_path).authenticate(replacement)


def test_identity_cli_reports_missing_registers_and_bad_scopes(tmp_path: Path) -> None:
    missing = runner.invoke(
        app, ["aegis", "identities", "list", "-f", str(tmp_path / "absent.json")]
    )
    assert missing.exit_code == 2 and "not found" in missing.output

    bad = runner.invoke(
        app,
        [
            "aegis",
            "identities",
            "add",
            "ops",
            "--scopes",
            "jobs:everything",
            "-f",
            str(tmp_path / "identities.json"),
        ],
    )
    assert bad.exit_code == 2 and "unknown API scopes" in bad.output

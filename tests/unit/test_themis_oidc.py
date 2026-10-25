from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.themis.api import ApiSettings, create_app
from olympus.themis.identity import ApiIdentity, IdentityRegister, hash_secret, save_register
from olympus.themis.oidc import OidcError, OidcVerifier

ISSUER = "https://identity.example.test"
AUDIENCE = "olympus-control-plane"
KID = "operator-signing-1"


def _trust(tmp_path: Path) -> tuple[Path, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": KID, "alg": "RS256", "use": "sig"})
    path = tmp_path / "oidc.jwks.json"
    path.write_text(json.dumps({"keys": [jwk]}), encoding="utf-8")
    return path, private_key


def _token(private_key: rsa.RSAPrivateKey, **overrides: object) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "analyst",
        "iat": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": KID})


def _client(tmp_path: Path) -> tuple[TestClient, rsa.RSAPrivateKey, Path, Path]:
    jwks, private_key = _trust(tmp_path)
    identities = tmp_path / "identities.json"
    save_register(
        identities,
        IdentityRegister(
            identities=[
                ApiIdentity(
                    identity_id="analyst",
                    secret_sha256=hash_secret("synthetic-secret-for-api-testing-only"),
                    scopes=["capabilities:read"],
                    created_at=datetime.now(UTC),
                )
            ]
        ),
    )
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    audit = tmp_path / "audit.jsonl"
    app = create_app(
        ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=scopes,
            identities_path=identities,
            audit_path=audit,
            oidc_issuer=ISSUER,
            oidc_audience=AUDIENCE,
            oidc_jwks_path=jwks,
        )
    )
    return TestClient(app), private_key, identities, audit


def test_oidc_bearer_uses_local_scopes_and_audits_without_token(tmp_path: Path) -> None:
    client, private_key, _, audit = _client(tmp_path)
    token = _token(private_key)
    response = client.get("/api/v1/capabilities", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    record = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert record["metadata"]["identity"] == "analyst"
    assert record["metadata"]["authentication_method"] == "oidc"
    assert token not in audit.read_text(encoding="utf-8")


def test_oidc_local_revocation_is_immediate(tmp_path: Path) -> None:
    client, private_key, identities, _ = _client(tmp_path)
    token = _token(private_key)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/capabilities", headers=headers).status_code == 200
    register = IdentityRegister.model_validate_json(identities.read_text(encoding="utf-8"))
    revoked = register.identities[0].model_copy(update={"revoked": True})
    save_register(identities, register.model_copy(update={"identities": [revoked]}))
    assert client.get("/api/v1/capabilities", headers=headers).status_code == 401


@pytest.mark.parametrize(
    ("claim", "value"),
    [("iss", "https://attacker.invalid"), ("aud", "another-service"), ("sub", "UNMAPPED")],
)
def test_oidc_rejects_untrusted_claims(tmp_path: Path, claim: str, value: str) -> None:
    client, private_key, _, _ = _client(tmp_path)
    response = client.get(
        "/api/v1/capabilities",
        headers={"Authorization": f"Bearer {_token(private_key, **{claim: value})}"},
    )
    assert response.status_code == 401


def test_oidc_rejects_dual_credentials_and_excessive_lifetime(tmp_path: Path) -> None:
    client, private_key, _, _ = _client(tmp_path)
    now = datetime.now(UTC)
    long_token = _token(
        private_key,
        iat=int(now.timestamp()),
        exp=int((now + timedelta(hours=2)).timestamp()),
    )
    assert (
        client.get(
            "/api/v1/capabilities", headers={"Authorization": f"Bearer {long_token}"}
        ).status_code
        == 401
    )
    valid = _token(private_key)
    response = client.get(
        "/api/v1/capabilities",
        headers={"Authorization": f"Bearer {valid}", "X-Olympus-API-Key": "x" * 32},
    )
    assert response.status_code == 401


def test_oidc_configuration_is_all_or_none_and_https(tmp_path: Path) -> None:
    jwks, _ = _trust(tmp_path)
    with pytest.raises(OidcError, match="HTTPS"):
        OidcVerifier(issuer="http://issuer.test", audience=AUDIENCE, jwks_path=jwks)
    settings = ApiSettings(
        database=tmp_path / "jobs.sqlite3",
        scope_directory=tmp_path,
        api_key="x" * 32,
        oidc_issuer=ISSUER,
    )
    with pytest.raises(ValueError, match="configured together"):
        settings.validate()


@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.text(max_size=20_000))
def test_oidc_hostile_bearer_never_escapes_as_an_unhandled_error(
    tmp_path: Path, candidate: str
) -> None:
    jwks, _ = _trust(tmp_path)
    verifier = OidcVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_path=jwks)
    with pytest.raises(OidcError):
        verifier.verify(candidate)

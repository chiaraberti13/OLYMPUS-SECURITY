"""Tests for Minerva custody-ledger verification across core, API and Web.

The hash-chain verification engine already has deep coverage in
``test_minerva_custody.py``; these tests pin the *reuse* of that engine through
the new I/O-free :func:`inspect_ledger_text` core and the typed API/Web surfaces
that expose it (ROADMAP ``API-2``, ``WEB-3``, ``INT-3``). Verification stays
offline and read-only: no key is ever accepted from a caller, only the
server-owned Ed25519 verification key.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from olympus.core.coverage import RunStatus
from olympus.core.models import Evidence
from olympus.minerva.custody import (
    AcquisitionProvenance,
    CustodyAction,
    CustodyIntegrityError,
    append_entry,
    inspect_ledger,
    inspect_ledger_text,
)
from olympus.themis.api import ApiSettings, create_app
from olympus.themis.identity import SCOPES
from olympus.themis.web import create_web_app

API_KEY = "a" * 32
AUTH = {"X-Olympus-API-Key": API_KEY}
BASE = "https://testserver"


def _provenance() -> AcquisitionProvenance:
    return AcquisitionProvenance(
        tool="nmap",
        tool_version="7.95",
        policy_sha256="b" * 64,
        scope_sha256="c" * 64,
        command_template=("nmap", "-sV", "{target}"),
        coverage_status=RunStatus.CLEAN,
    )


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-demo/memory.raw",
        sha256="a" * 64,
    )


def _build_ledger_text(
    tmp_path: Path, *, ed25519_private_key: Ed25519PrivateKey | None = None
) -> str:
    """Build a real 2-entry custody ledger on disk and return its JSON text."""
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    append_entry(
        ledger,
        _evidence(),
        CustodyAction.COLLECTED,
        "responder",
        started,
        acquisition=_provenance(),
        ed25519_private_key=ed25519_private_key,
    )
    append_entry(
        ledger,
        _evidence(),
        CustodyAction.TRANSFERRED,
        "forensics",
        started + timedelta(minutes=30),
        ed25519_private_key=ed25519_private_key,
    )
    return ledger.read_text(encoding="utf-8")


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
    base: dict[str, object] = {
        "database": tmp_path / "jobs.sqlite3",
        "scope_directory": scopes,
        "api_key": API_KEY,
        "api_key_scopes": SCOPES,
        "audit_path": tmp_path / "audit.log",
    }
    base.update(overrides)
    return ApiSettings(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Core: the text variant mirrors the path variant and catches tampering.
# --------------------------------------------------------------------------- #


def test_inspect_ledger_text_matches_the_path_variant(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    append_entry(
        ledger,
        _evidence(),
        CustodyAction.COLLECTED,
        "responder",
        started,
        acquisition=_provenance(),
    )
    from_path = inspect_ledger(ledger)
    from_text = inspect_ledger_text(ledger.read_text(encoding="utf-8"))
    assert from_text == from_path
    assert from_text.schema_version == "3.0.0"
    assert from_text.evidence_anchored is True
    assert from_text.signed is False


def test_inspect_ledger_text_detects_a_tampered_entry(tmp_path: Path) -> None:
    payload = json.loads(_build_ledger_text(tmp_path))
    payload["entries"][0]["actor"] = "attacker"
    try:
        inspect_ledger_text(json.dumps(payload))
    except CustodyIntegrityError:
        pass
    else:  # pragma: no cover - the assertion communicates the failure
        raise AssertionError("tampering was not detected")


def test_inspect_ledger_text_rejects_an_oversize_document(tmp_path: Path) -> None:
    text = _build_ledger_text(tmp_path)
    try:
        inspect_ledger_text(text, max_bytes=16)
    except CustodyIntegrityError as exc:
        assert "16-byte limit" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("oversize document was not rejected")


# --------------------------------------------------------------------------- #
# API: POST /api/v1/minerva/verify-ledger
# --------------------------------------------------------------------------- #


def test_minerva_verify_api_returns_a_versioned_result(tmp_path: Path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    ledger = json.loads(_build_ledger_text(tmp_path))
    response = client.post("/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_name"] == "olympus.minerva-ledger-verification"
    assert body["schema_version"] == "1.0.0"
    assert body["chain_verified"] is True
    assert body["ledger_schema_version"] == "3.0.0"
    assert body["entry_count"] == 2
    assert body["evidence_anchored"] is True
    assert body["signed"] is False
    assert body["signature_verified"] is False
    assert [entry["sequence"] for entry in body["entries"]] == [1, 2]
    assert body["entries"][0]["actor"] == "responder"


def test_minerva_verify_api_rejects_a_tampered_ledger(tmp_path: Path) -> None:
    client = TestClient(create_app(_settings(tmp_path)))
    ledger = json.loads(_build_ledger_text(tmp_path))
    ledger["entries"][1]["evidence_sha256"] = "d" * 64
    response = client.post("/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger})
    assert response.status_code == 422, response.text


def test_minerva_verify_api_requires_the_minerva_read_scope(tmp_path: Path) -> None:
    client = TestClient(create_app(_settings(tmp_path, api_key_scopes=("capabilities:read",))))
    ledger = json.loads(_build_ledger_text(tmp_path))
    response = client.post("/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger})
    assert response.status_code == 403, response.text


def test_minerva_verify_api_checks_the_ed25519_signature_with_a_configured_key(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_hex = private_key.public_key().public_bytes_raw().hex()
    ledger = json.loads(_build_ledger_text(tmp_path, ed25519_private_key=private_key))

    configured = TestClient(
        create_app(_settings(tmp_path / "a", minerva_custody_public_key_hex=public_hex))
    )
    body = configured.post(
        "/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger}
    ).json()
    assert body["signed"] is True
    assert body["signature_algorithm"] == "Ed25519"
    assert body["signature_verified"] is True

    # Without a configured key the chain still verifies, but the signature is
    # reported unverified so a caller refuses to trust it.
    unconfigured = TestClient(create_app(_settings(tmp_path / "b")))
    unverified = unconfigured.post(
        "/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger}
    ).json()
    assert unverified["signed"] is True
    assert unverified["signature_verified"] is False


def test_minerva_verify_api_rejects_a_rewritten_signed_ledger(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_hex = private_key.public_key().public_bytes_raw().hex()
    ledger = json.loads(_build_ledger_text(tmp_path, ed25519_private_key=private_key))
    # Drop the sealed head entry: the signature commits to the original length.
    ledger["entries"] = ledger["entries"][:1]
    client = TestClient(
        create_app(_settings(tmp_path / "a", minerva_custody_public_key_hex=public_hex))
    )
    response = client.post("/api/v1/minerva/verify-ledger", headers=AUTH, json={"ledger": ledger})
    assert response.status_code == 422, response.text


# --------------------------------------------------------------------------- #
# Web: /minerva verification workbench
# --------------------------------------------------------------------------- #


def _web_client(tmp_path: Path, **overrides: object) -> TestClient:
    return TestClient(create_web_app(_settings(tmp_path, **overrides)), base_url=BASE)


def _login(client: TestClient) -> None:
    response = client.post("/login", data={"api_key": API_KEY}, follow_redirects=False)
    assert response.status_code == 303, response.text


def test_minerva_web_page_verifies_a_pasted_ledger(tmp_path: Path) -> None:
    client = _web_client(tmp_path)
    _login(client)
    page = client.get("/minerva")
    assert page.status_code == 200
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text)
    assert match is not None

    result = client.post(
        "/minerva/verify",
        data={"csrf_token": match.group(1), "ledger": _build_ledger_text(tmp_path)},
    )
    assert result.status_code == 200, result.text
    assert "chain verified" in result.text
    assert "olympus.custody 3.0.0" in result.text
    assert "responder" in result.text


def test_minerva_web_reports_a_tampered_ledger(tmp_path: Path) -> None:
    client = _web_client(tmp_path)
    _login(client)
    page = client.get("/minerva")
    match = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page.text)
    assert match is not None
    payload = json.loads(_build_ledger_text(tmp_path))
    payload["entries"][0]["entry_hash"] = "f" * 64
    result = client.post(
        "/minerva/verify",
        data={"csrf_token": match.group(1), "ledger": json.dumps(payload)},
    )
    assert result.status_code == 422, result.text
    assert "Verification failed" in result.text


def test_minerva_web_requires_the_minerva_read_scope(tmp_path: Path) -> None:
    client = _web_client(tmp_path, api_key_scopes=("capabilities:read",))
    _login(client)
    assert client.get("/minerva").status_code == 403

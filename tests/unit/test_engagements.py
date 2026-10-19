"""Unit tests for the Engagement contract and its SQLite store (WEB-B)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.core.enums import AssetType, EngagementStatus, Source
from olympus.core.models import Asset, Engagement, EngagementScope, Finding
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import (
    EngagementManifest,
    ManifestAuthorizationError,
    ManifestRevocationError,
    ManifestVerificationError,
    SignedEngagementManifest,
)
from olympus.engagements.store import EngagementStoreError, SqliteEngagementStore


def _engagement(name: str = "ACME") -> Engagement:
    return Engagement(
        name=name,
        client="ACME",
        scope=EngagementScope(
            included=("example.com", "api.example.com"), excluded=("db.example.com",)
        ),
        authorization_reference="CONTRACT-1",
    )


def test_scope_covers_included_but_not_excluded() -> None:
    scope = EngagementScope(included=("example.com",), excluded=("secret.example.com",))
    assert scope.covers("example.com")
    assert scope.covers("www.example.com")  # subdomain of an included domain
    assert not scope.covers("secret.example.com")  # excluded exactly
    assert not scope.covers("deep.secret.example.com")  # excluded subtree
    assert not scope.covers("other.org")  # not included


def test_scope_normalizes_entries() -> None:
    scope = EngagementScope(included=("  Example.COM. ",), excluded=("DB.Example.com",))
    assert scope.included == ("example.com",)
    assert scope.excluded == ("db.example.com",)


def test_scope_requires_at_least_one_included() -> None:
    with pytest.raises(ValidationError):
        EngagementScope(included=())


def test_scope_rejects_entries_with_spaces() -> None:
    with pytest.raises(ValidationError):
        EngagementScope(included=("bad domain",))


def test_engagement_has_stable_identity_and_schema() -> None:
    engagement = _engagement()
    assert engagement.schema_name == "olympus.engagement"
    assert engagement.engagement_id.startswith("ENG-")
    assert engagement.status is EngagementStatus.ACTIVE
    # The digest is deterministic for the same canonical content.
    assert (
        engagement.digest()
        == Engagement.model_validate(engagement.model_dump(mode="json")).digest()
    )


# --- WEB-B slice 2: association primitives ----------------------------------- #


def test_engagement_covers_forwards_to_scope() -> None:
    engagement = _engagement()
    assert engagement.covers("www.example.com")  # subdomain of an included domain
    assert not engagement.covers("db.example.com")  # excluded
    assert not engagement.covers("other.org")  # not included


def test_stamp_links_object_without_mutating_the_original() -> None:
    engagement = _engagement()
    finding = Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x")
    stamped = engagement.stamp(finding)
    assert stamped.engagement_id == engagement.engagement_id
    assert finding.engagement_id is None  # original untouched
    assert isinstance(stamped, Finding)  # concrete type preserved


def test_stamp_all_links_every_object() -> None:
    engagement = _engagement()
    assets = [Asset(asset_type=AssetType.HOST), Asset(asset_type=AssetType.IP)]
    stamped = engagement.stamp_all(assets)
    assert {a.engagement_id for a in stamped} == {engagement.engagement_id}
    assert all(original.engagement_id is None for original in assets)


def test_store_require_returns_or_raises(tmp_path: Path) -> None:
    store = SqliteEngagementStore(tmp_path / "engagements.db")
    try:
        engagement = _engagement()
        store.save(engagement)
        assert store.require(engagement.engagement_id).name == engagement.name
        with pytest.raises(EngagementStoreError):
            store.require("ENG-2026-99999")
    finally:
        store.close()


def test_store_round_trips_and_lists(tmp_path: Path) -> None:
    store = SqliteEngagementStore(tmp_path / "engagements.db")
    try:
        first = _engagement("first")
        second = _engagement("second")
        store.save(first)
        store.save(second)
        loaded = store.get(first.engagement_id)
        assert loaded is not None and loaded.name == "first"
        assert loaded.scope.covers("www.example.com")
        ids = {item.engagement_id for item in store.list()}
        assert {first.engagement_id, second.engagement_id} <= ids
        assert store.get("ENG-UNKNOWN") is None
    finally:
        store.close()


def test_store_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "engagements.db"
    store = SqliteEngagementStore(path)
    store.close()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_store_rejects_a_tampered_document(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteEngagementStore(tmp_path / "engagements.db")
    store.save(_engagement())
    store.close()
    conn = sqlite3.connect(str(tmp_path / "engagements.db"))
    conn.execute("UPDATE engagements SET document = ?", ('{"schema_name": "olympus.wrong"}',))
    conn.commit()
    conn.close()
    reopened = SqliteEngagementStore(tmp_path / "engagements.db")
    try:
        with pytest.raises(EngagementStoreError):
            reopened.list()
    finally:
        reopened.close()


def _manifest() -> EngagementManifest:
    start = datetime(2026, 10, 19, 0, 0, tzinfo=UTC)
    return EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Example Client",
        owner="Security Owner",
        approver="Authorized Approver",
        contract_id="CONTRACT-2026-01",
        scope=EngagementScope(included=("example.com",), excluded=("admin.example.com",)),
        valid_from=start,
        expires_at=start + timedelta(hours=8),
        allowed_techniques=("nmap", "httpx"),
        max_targets=20,
        max_concurrency=2,
        max_runtime_seconds=1800,
    )


def test_signed_manifest_is_canonical_pinned_and_operation_scoped() -> None:
    private_key, public_key = generate_keypair()
    signed = SignedEngagementManifest.sign_manifest(_manifest(), private_key_pem=private_key)
    reloaded = SignedEngagementManifest.model_validate_json(signed.model_dump_json())

    verified = reloaded.authorize(
        trusted_public_key_pem=public_key,
        target="www.example.com",
        technique="nmap",
        now=datetime(2026, 10, 19, 1, 0, tzinfo=UTC),
    )

    assert verified.engagement_id == "ENG-2026-00001"
    assert signed.manifest_sha256 == verified.digest()
    assert signed.manifest.manifest_id.startswith("MAN-")


@pytest.mark.parametrize(
    ("target", "technique", "now"),
    [
        ("outside.example.net", "nmap", datetime(2026, 10, 19, 1, 0, tzinfo=UTC)),
        ("admin.example.com", "nmap", datetime(2026, 10, 19, 1, 0, tzinfo=UTC)),
        ("www.example.com", "sqlmap", datetime(2026, 10, 19, 1, 0, tzinfo=UTC)),
        ("www.example.com", "nmap", datetime(2026, 10, 20, 0, 0, tzinfo=UTC)),
    ],
)
def test_signed_manifest_denies_out_of_scope_operation(
    target: str, technique: str, now: datetime
) -> None:
    private_key, public_key = generate_keypair()
    signed = SignedEngagementManifest.sign_manifest(_manifest(), private_key_pem=private_key)

    with pytest.raises(ManifestAuthorizationError):
        signed.authorize(
            trusted_public_key_pem=public_key,
            target=target,
            technique=technique,
            now=now,
        )


def test_signed_manifest_rejects_tampering_and_untrusted_signer() -> None:
    private_key, public_key = generate_keypair()
    other_private_key, other_public_key = generate_keypair()
    signed = SignedEngagementManifest.sign_manifest(_manifest(), private_key_pem=private_key)
    changed_manifest = signed.manifest.model_copy(update={"client": "Attacker"})
    tampered = signed.model_copy(update={"manifest": changed_manifest})

    with pytest.raises(ManifestVerificationError, match="digest"):
        tampered.authorize(
            trusted_public_key_pem=public_key,
            target="www.example.com",
            technique="nmap",
            now=datetime(2026, 10, 19, 1, 0, tzinfo=UTC),
        )
    with pytest.raises(ManifestVerificationError, match="signature verification"):
        signed.authorize(
            trusted_public_key_pem=other_public_key,
            target="www.example.com",
            technique="nmap",
            now=datetime(2026, 10, 19, 1, 0, tzinfo=UTC),
        )
    assert other_private_key != private_key


def _signed_and_keys() -> tuple[SignedEngagementManifest, str]:
    private_key, public_key = generate_keypair()
    signed = SignedEngagementManifest.sign_manifest(_manifest(), private_key_pem=private_key)
    return signed, public_key


def _authorize(signed: SignedEngagementManifest, public_key: str, **extra: object) -> object:
    return signed.authorize(
        trusted_public_key_pem=public_key,
        target="www.example.com",
        technique="nmap",
        now=datetime(2026, 10, 19, 1, 0, tzinfo=UTC),
        **extra,  # type: ignore[arg-type]
    )


def test_authorize_ignores_an_empty_or_unrelated_revocation_list() -> None:
    signed, public_key = _signed_and_keys()
    # No revocations, and a revocation list that names other engagements, both pass.
    assert _authorize(signed, public_key).engagement_id == "ENG-2026-00001"  # type: ignore[attr-defined]
    assert _authorize(signed, public_key, revoked=("ENG-2026-99999", "deadbeef")) is not None


def test_authorize_rejects_a_manifest_revoked_by_digest() -> None:
    signed, public_key = _signed_and_keys()
    with pytest.raises(ManifestRevocationError, match="revoked"):
        _authorize(signed, public_key, revoked=(signed.manifest_sha256,))


def test_authorize_rejects_a_manifest_revoked_by_engagement_or_manifest_id() -> None:
    signed, public_key = _signed_and_keys()
    with pytest.raises(ManifestRevocationError):
        _authorize(signed, public_key, revoked=(signed.manifest.engagement_id,))
    with pytest.raises(ManifestRevocationError):
        _authorize(signed, public_key, revoked=(signed.manifest.manifest_id,))
    # Revocation is a kind of authorization failure, so callers catching the base
    # class still see it.
    assert issubclass(ManifestRevocationError, ManifestAuthorizationError)


def test_revocation_never_masks_a_tampered_manifest() -> None:
    signed, public_key = _signed_and_keys()
    tampered = signed.model_copy(
        update={"manifest": signed.manifest.model_copy(update={"client": "Attacker"})}
    )
    # Even if the (stale) digest is on the revocation list, integrity is checked
    # first: the caller learns the manifest was tampered, not merely revoked.
    with pytest.raises(ManifestVerificationError, match="digest"):
        _authorize(tampered, public_key, revoked=(signed.manifest_sha256,))


def test_manifest_rejects_naive_or_inverted_authorization_window() -> None:
    from pydantic import ValidationError

    naive_window = _manifest().model_dump()
    naive_window["valid_from"] = datetime(2026, 10, 19)
    with pytest.raises(ValidationError, match="timezone"):
        EngagementManifest(**naive_window)
    inverted_window = _manifest().model_dump()
    inverted_window["expires_at"] = datetime(2026, 10, 18, tzinfo=UTC)
    with pytest.raises(ValidationError, match="expires_at"):
        EngagementManifest(**inverted_window)

"""Build verified, privacy-minimized authorization provenance for reports."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from olympus.core.fileio import read_regular_text
from olympus.core.models import AuthorizationProvenance
from olympus.engagements.manifest import SignedEngagementManifest
from olympus.themis.model import ThemisResultDocument
from olympus.vulcan.aggregate import AggregationError

MAX_PROVENANCE_FILES = 100
MAX_PROVENANCE_BYTES = 1_000_000


def load_authorization_provenance(
    result_paths: Sequence[Path],
    manifest_paths: Sequence[Path],
    *,
    trusted_public_key_pem: str | None,
) -> list[AuthorizationProvenance]:
    """Verify result-to-manifest bindings and return report-safe projections.

    Supplying any provenance input is fail-closed: both input sets and a pinned
    public key are required.  Signature, digest, target scope and scanner
    technique are verified.  Revocation and execution-time validity are not
    re-decided here; their signed policy window is preserved for audit instead.
    """
    if not result_paths and not manifest_paths and trusted_public_key_pem is None:
        return []
    if not result_paths or not manifest_paths or not trusted_public_key_pem:
        raise AggregationError(
            "Themis provenance requires result files, signed manifests and a trusted public key"
        )
    if len(result_paths) > MAX_PROVENANCE_FILES or len(manifest_paths) > MAX_PROVENANCE_FILES:
        raise AggregationError(f"provenance inputs exceed the {MAX_PROVENANCE_FILES} file limit")

    manifests: dict[str, SignedEngagementManifest] = {}
    for path in manifest_paths:
        signed = _load_manifest(path)
        try:
            signed.verify_signature(trusted_public_key_pem=trusted_public_key_pem)
        except ValueError as exc:
            raise AggregationError(f"signed manifest verification failed: {path}: {exc}") from exc
        existing_manifest = manifests.get(signed.manifest_sha256)
        if existing_manifest is not None and existing_manifest != signed:
            raise AggregationError("conflicting signed manifests share one digest")
        manifests[signed.manifest_sha256] = signed

    by_job: dict[str, AuthorizationProvenance] = {}
    for path in result_paths:
        result = _load_result(path)
        if result.job_id is None or result.manifest_sha256 is None:
            raise AggregationError(f"Themis result has no manifest-bound job provenance: {path}")
        matched_manifest = manifests.get(result.manifest_sha256)
        if matched_manifest is None:
            raise AggregationError(
                f"no verified signed manifest matches result digest {result.manifest_sha256}"
            )
        manifest = matched_manifest.manifest
        if not manifest.scope.covers(result.target):
            raise AggregationError(
                f"Themis result target is outside its signed manifest scope: {path}"
            )
        if result.scanner not in manifest.allowed_techniques:
            raise AggregationError(
                f"Themis result scanner is not allowed by its signed manifest: {path}"
            )
        projection = AuthorizationProvenance(
            job_id=result.job_id,
            scanner=result.scanner,
            result_state=result.state.value,
            manifest_sha256=result.manifest_sha256,
            manifest_id=manifest.manifest_id,
            engagement_id=manifest.engagement_id,
            scope=manifest.scope,
            allowed_techniques=manifest.allowed_techniques,
            valid_from=manifest.valid_from,
            expires_at=manifest.expires_at,
            max_targets=manifest.max_targets,
            max_concurrency=manifest.max_concurrency,
            max_runtime_seconds=manifest.max_runtime_seconds,
        )
        existing_provenance = by_job.get(result.job_id)
        if existing_provenance is not None and existing_provenance != projection:
            raise AggregationError(f"conflicting authorization provenance for job {result.job_id}")
        by_job[result.job_id] = projection
    return [by_job[job_id] for job_id in sorted(by_job)]


def _load_manifest(path: Path) -> SignedEngagementManifest:
    document = read_regular_text(path, max_bytes=MAX_PROVENANCE_BYTES, label="signed manifest")
    try:
        return SignedEngagementManifest.model_validate_json(document)
    except ValidationError as exc:
        raise AggregationError(f"invalid signed manifest: {path}") from exc


def _load_result(path: Path) -> ThemisResultDocument:
    document = read_regular_text(path, max_bytes=MAX_PROVENANCE_BYTES, label="Themis result")
    try:
        return ThemisResultDocument.model_validate_json(document)
    except ValidationError as exc:
        raise AggregationError(f"invalid Themis result: {path}") from exc

"""Verified authorization provenance in consolidated Vulcan reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest
from olympus.themis.model import ThemisResultDocument
from olympus.themis.states import ExecutionState
from olympus.vulcan.aggregate import AggregationError
from olympus.vulcan.application import VulcanApplicationService, VulcanReportRequest
from olympus.vulcan.provenance import load_authorization_provenance

runner = CliRunner()


def _provenance_files(
    tmp_path: Path,
    *,
    target: str = "host.example.test",
    scanner: str = "nmap",
) -> tuple[Path, Path, Path, SignedEngagementManifest, ThemisResultDocument]:
    private_key, public_key = generate_keypair()
    now = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
    manifest = EngagementManifest(
        manifest_id="MAN-2026-00001",
        engagement_id="ENG-2026-00001",
        client="Synthetic Client",
        owner="Synthetic Owner",
        approver="Synthetic Approver",
        contract_id="SYNTHETIC-CONTRACT",
        scope=EngagementScope(included=("example.test",), excluded=("blocked.example.test",)),
        valid_from=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        allowed_techniques=("nmap",),
        max_targets=4,
        max_concurrency=2,
        max_runtime_seconds=120,
    )
    signed = SignedEngagementManifest.sign_manifest(manifest, private_key_pem=private_key)
    result = ThemisResultDocument(
        job_id="THEMIS-0123456789ABCDEF0123456789ABCDEF",
        manifest_sha256=signed.manifest_sha256,
        scanner=scanner,
        state=ExecutionState.SIMULATION,
        real_execution=False,
        target=target,
        finding_count=0,
        asset_count=0,
        duration_seconds=0.1,
    )
    result_path = tmp_path / "result.json"
    manifest_path = tmp_path / "manifest.json"
    key_path = tmp_path / "manifest.pub.pem"
    result_path.write_text(result.model_dump_json(), encoding="utf-8")
    manifest_path.write_text(signed.model_dump_json(), encoding="utf-8")
    key_path.write_text(public_key, encoding="utf-8")
    return result_path, manifest_path, key_path, signed, result


def test_report_embeds_verified_privacy_minimized_provenance(tmp_path: Path) -> None:
    result_path, manifest_path, key_path, signed, _result = _provenance_files(tmp_path)

    outcome = VulcanApplicationService().report(
        VulcanReportRequest(
            engagement="synthetic",
            themis_result_paths=(result_path,),
            signed_manifest_paths=(manifest_path,),
            trusted_manifest_public_key_pem=key_path.read_text(encoding="utf-8"),
            render_markdown=True,
            render_html=True,
            render_pdf=True,
        )
    )

    assert outcome.report.schema_version == "1.1.0"
    assert len(outcome.report.authorization_provenance) == 1
    provenance = outcome.report.authorization_provenance[0]
    assert provenance.manifest_sha256 == signed.manifest_sha256
    assert provenance.signature_verified is True
    assert provenance.scope_verified is True
    assert provenance.technique_verified is True
    serialized = outcome.report.model_dump_json()
    for private_value in (
        "Synthetic Client",
        "Synthetic Owner",
        "Synthetic Approver",
        "SYNTHETIC-CONTRACT",
        "host.example.test",
        signed.signature_envelope,
    ):
        assert private_value not in serialized
    assert (
        outcome.markdown is not None
        and "signature, target scope and technique verified" in outcome.markdown
    )
    assert (
        outcome.html is not None
        and "signature, target scope and technique verified" in outcome.html
    )
    assert outcome.pdf is not None and outcome.pdf.startswith(b"%PDF-")


@pytest.mark.parametrize(
    ("target", "scanner", "message"),
    [
        ("outside.test", "nmap", "outside its signed manifest scope"),
        ("host.example.test", "nuclei", "scanner is not allowed"),
    ],
)
def test_provenance_rejects_scope_or_technique_mismatch(
    tmp_path: Path, target: str, scanner: str, message: str
) -> None:
    result_path, manifest_path, key_path, _signed, _result = _provenance_files(
        tmp_path, target=target, scanner=scanner
    )
    with pytest.raises(AggregationError, match=message):
        load_authorization_provenance(
            (result_path,),
            (manifest_path,),
            trusted_public_key_pem=key_path.read_text(encoding="utf-8"),
        )


def test_provenance_rejects_tampering_and_missing_inputs(tmp_path: Path) -> None:
    result_path, manifest_path, key_path, signed, result = _provenance_files(tmp_path)
    _, other_public = generate_keypair()
    with pytest.raises(AggregationError, match="signature verification failed"):
        load_authorization_provenance(
            (result_path,), (manifest_path,), trusted_public_key_pem=other_public
        )

    mismatched = result.model_copy(update={"manifest_sha256": "0" * 64})
    result_path.write_text(mismatched.model_dump_json(), encoding="utf-8")
    with pytest.raises(AggregationError, match="no verified signed manifest matches"):
        load_authorization_provenance(
            (result_path,),
            (manifest_path,),
            trusted_public_key_pem=key_path.read_text(encoding="utf-8"),
        )

    with pytest.raises(AggregationError, match="requires result files"):
        load_authorization_provenance(
            (), (manifest_path,), trusted_public_key_pem=key_path.read_text(encoding="utf-8")
        )
    assert signed.manifest_sha256 != mismatched.manifest_sha256


@settings(max_examples=12, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(mismatched_digest=st.binary(min_size=32, max_size=32).map(bytes.hex))
def test_provenance_rejects_any_unmatched_well_formed_digest(
    tmp_path: Path, mismatched_digest: str
) -> None:
    result_path, manifest_path, key_path, signed, result = _provenance_files(tmp_path)
    if mismatched_digest == signed.manifest_sha256:
        return
    result_path.write_text(
        result.model_copy(update={"manifest_sha256": mismatched_digest}).model_dump_json(),
        encoding="utf-8",
    )
    with pytest.raises(AggregationError, match="no verified signed manifest matches"):
        load_authorization_provenance(
            (result_path,),
            (manifest_path,),
            trusted_public_key_pem=key_path.read_text(encoding="utf-8"),
        )


@pytest.mark.posix_only
def test_provenance_rejects_symlink_input(tmp_path: Path) -> None:
    result_path, manifest_path, key_path, _signed, _result = _provenance_files(tmp_path)
    link = tmp_path / "result-link.json"
    link.symlink_to(result_path)
    with pytest.raises(OSError, match="symlink"):
        load_authorization_provenance(
            (link,),
            (manifest_path,),
            trusted_public_key_pem=key_path.read_text(encoding="utf-8"),
        )


def test_vulcan_cli_report_with_verified_provenance(tmp_path: Path) -> None:
    result_path, manifest_path, key_path, signed, _result = _provenance_files(tmp_path)
    output = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    invocation = runner.invoke(
        app,
        [
            "vulcan",
            "report",
            "--engagement",
            "synthetic",
            "--themis-result",
            str(result_path),
            "--signed-manifest",
            str(manifest_path),
            "--manifest-public-key",
            str(key_path),
            "--output",
            str(output),
            "--markdown",
            str(markdown),
        ],
    )
    assert invocation.exit_code == 0, invocation.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["authorization_provenance"][0]["manifest_sha256"] == signed.manifest_sha256
    assert "Authorization provenance" in markdown.read_text(encoding="utf-8")

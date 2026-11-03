"""Signed per-run evidence manifest: content, signature, secrecy and fail-closed behaviour."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from olympus.core.signing import generate_keypair
from olympus.engines import evidence as evidence_module
from olympus.engines.evidence import (
    SIGNING_KEY_VARIABLE,
    EngineRunEvidence,
    EvidenceError,
    build_evidence,
    canonical_bytes,
    evidence_sha256,
    signature_path,
    signer_from_environment,
    verify_signed,
    write_signed,
)
from olympus.themis import base as base_module
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.application import ThemisApplicationService, ThemisRunRequest
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput, TerminationCause, TerminationReport

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parents[1] / "fixtures" / "themis" / "nuclei"
COMPLETED = TerminationReport(cause=TerminationCause.COMPLETED, exit_code=0)
TARGET = "http://127.0.0.1:8099"


class _Lab(NucleiAdapter):
    def resolve(self, host: str) -> tuple[str, ...]:
        return ("127.0.0.1",)


@pytest.fixture
def stdout() -> str:
    return (FIXTURES / "multiple.jsonl").read_text(encoding="utf-8")


@pytest.fixture
def engine_runs(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    monkeypatch.setattr(base_module, "which", lambda _binary: "/usr/local/bin/nuclei")

    def runner(argv: list[str], **_kwargs: object) -> CommandOutput:
        if "-target" not in argv:
            banner = "[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1"
            return CommandOutput(0, "", banner, COMPLETED)
        return CommandOutput(0, stdout, "some stderr\n", COMPLETED)

    monkeypatch.setattr(base_module, "run_command", runner)


def _scan_request(**changes: object) -> ScanRequest:
    values: dict[str, object] = {
        "scanner": "nuclei",
        "target": TARGET,
        "target_kind": "url",
        "allowed": ("127.0.0.1",),
        "authorized": True,
        "live_enabled": True,
    }
    values.update(changes)
    return ScanRequest(**values)  # type: ignore[arg-type]


def _keys() -> tuple[str, str]:
    return generate_keypair()


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _service() -> ThemisApplicationService:
    return ThemisApplicationService(lambda name: _Lab(), isolation_verifier=lambda: None)


def _signer(private_pem: str):  # type: ignore[no-untyped-def]
    from olympus.core.signing import sign

    return lambda data: sign(data, private_pem)


def _evidence(engine_runs: None, **changes: object) -> EngineRunEvidence:
    request = _scan_request(**changes)
    result = _Lab().run(request)
    return build_evidence(run_id="themis-test", result=result, request=request)


# --- content ---------------------------------------------------------------- #
def test_the_manifest_names_engine_data_command_scope_and_output_digests(
    engine_runs: None, stdout: str
) -> None:
    evidence = _evidence(engine_runs)
    assert evidence.engine.name == "nuclei"
    assert evidence.engine.pinned_version == "v3.11.1"
    assert evidence.engine.detected_version == "[INF] Nuclei Engine Version: v3.11.1"  # no ANSI
    assert len(evidence.engine.manifest_sha256) == 64
    (templates,) = evidence.data_dependencies
    assert (templates.name, templates.pinned_version) == ("nuclei-templates", "v10.5.1")
    assert templates.commit == "79fb682760ab3d5b0e22afbb44709353cbebf023"
    assert evidence.command[:3] == ["nuclei", "-target", TARGET]
    assert evidence.scope.allowed_hosts == ["127.0.0.1"] and len(evidence.scope.scope_sha256) == 64
    assert evidence.outcome.state == "live" and evidence.outcome.finding_count == 10
    assert evidence.outputs is not None
    assert evidence.outputs.stdout_sha256 == hashlib.sha256(stdout.encode()).hexdigest()
    assert evidence.outputs.stderr_bytes == len("some stderr\n")


def test_raw_output_never_travels_inside_the_manifest(engine_runs: None, stdout: str) -> None:
    text = json.dumps(_evidence(engine_runs).model_dump(mode="json"))
    assert "http-missing-security-headers" not in text and "some stderr" not in text


def test_the_scope_digest_changes_with_the_scope(engine_runs: None) -> None:
    first = _evidence(engine_runs)
    second = _evidence(engine_runs, allowed=("127.0.0.1", "10.0.0.5"))
    assert first.scope.scope_sha256 != second.scope.scope_sha256


def test_a_partial_run_is_recorded_as_partial(
    monkeypatch: pytest.MonkeyPatch, engine_runs: None, stdout: str
) -> None:
    broken = stdout + '{"template-id": "cut off mid-record\n'

    def runner(argv: list[str], **_kwargs: object) -> CommandOutput:
        return CommandOutput(0, broken if "-target" in argv else "", "v3.11.1", COMPLETED)

    monkeypatch.setattr(base_module, "run_command", runner)
    evidence = _evidence(engine_runs)
    assert evidence.outcome.partial is True and evidence.outcome.partial_reason


def test_an_engine_without_a_manifest_cannot_produce_evidence(engine_runs: None) -> None:
    request = _scan_request()
    result = _Lab().run(request)
    from dataclasses import replace

    with pytest.raises(EvidenceError, match="no engine manifest"):
        build_evidence(run_id="x", result=replace(result, scanner="not-an-engine"), request=request)


def test_a_command_with_a_secret_option_is_redacted_everywhere(
    monkeypatch: pytest.MonkeyPatch, engine_runs: None
) -> None:
    class _Leaky(_Lab):
        def build_argv(self, host: str, request: ScanRequest) -> list[str]:
            return [*super().build_argv(host, request), "--api-key", "s3cr3t-value"]

    request = _scan_request()
    result = _Leaky().run(request)
    evidence = build_evidence(run_id="x", result=result, request=request)
    assert "s3cr3t-value" not in json.dumps(evidence.model_dump(mode="json"))
    assert "[REDACTED]" in evidence.command


# --- signature -------------------------------------------------------------- #
def test_a_signed_manifest_verifies_and_any_change_breaks_it(
    engine_runs: None, tmp_path: Path
) -> None:
    private_pem, public_pem = _keys()
    evidence = _evidence(engine_runs)
    path = tmp_path / "run.evidence.json"
    digest = write_signed(evidence, _signer(private_pem), path)
    assert digest == evidence_sha256(evidence) and signature_path(path).is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
    assert verify_signed(path, public_pem=public_pem) == evidence

    document = json.loads(path.read_text(encoding="utf-8"))
    document["outcome"]["finding_count"] = 0  # hide the findings
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(EvidenceError, match="altered"):
        verify_signed(path, public_pem=public_pem)


def test_a_signature_from_another_key_is_refused(engine_runs: None, tmp_path: Path) -> None:
    attacker_private, _ = _keys()
    _, trusted_public = _keys()
    path = tmp_path / "run.evidence.json"
    write_signed(_evidence(engine_runs), _signer(attacker_private), path)
    with pytest.raises(EvidenceError, match="different key"):
        verify_signed(path, public_pem=trusted_public)


def test_canonical_bytes_are_stable_and_whitespace_free(engine_runs: None) -> None:
    evidence = _evidence(engine_runs)
    assert canonical_bytes(evidence) == canonical_bytes(
        EngineRunEvidence.model_validate_json(evidence.model_dump_json())
    )
    expected = json.dumps(
        evidence.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    assert canonical_bytes(evidence) == expected and b"\n" not in expected


# --- the signing key comes from the environment, by path -------------------- #
def test_signer_needs_the_environment_and_never_echoes_the_key(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match=SIGNING_KEY_VARIABLE):
        signer_from_environment({})
    private_pem, public_pem = _keys()
    key_file = tmp_path / "key.pem"
    key_file.write_text(private_pem, encoding="utf-8")
    signer = signer_from_environment({SIGNING_KEY_VARIABLE: str(key_file)})
    assert '"scheme": "olympus.sig.v1"' in signer(b"data")
    key_file.write_text("not a key", encoding="utf-8")
    with pytest.raises(EvidenceError) as caught:
        signer_from_environment({SIGNING_KEY_VARIABLE: str(key_file)})(b"data")
    assert "not a key" not in str(caught.value)
    with pytest.raises(EvidenceError, match="cannot read"):
        signer_from_environment({SIGNING_KEY_VARIABLE: str(tmp_path / "missing.pem")})
    assert public_pem  # the public half is what verifiers hold


# --- through the application service ---------------------------------------- #
def _request(tmp_path: Path, **changes: object) -> ThemisRunRequest:
    values: dict[str, object] = {
        "scanner": "nuclei",
        "target": TARGET,
        "target_kind": "url",
        "scope_path": _scope(tmp_path),
        "authorized": True,
        "live_enabled": True,
        "audit_path": tmp_path / "audit.ndjson",
    }
    values.update(changes)
    return ThemisRunRequest(**values)  # type: ignore[arg-type]


def test_evidence_without_a_signer_is_refused_before_the_run_starts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsigned evidence is never produced"):
        _request(tmp_path, evidence_path=tmp_path / "e.json")


def test_a_run_writes_signed_evidence_and_the_audit_record_points_at_it(
    engine_runs: None, tmp_path: Path
) -> None:
    private_pem, public_pem = _keys()
    path = tmp_path / "e.json"
    result = _service().run(
        _request(tmp_path, evidence_path=path, evidence_signer=_signer(private_pem))
    )
    evidence = verify_signed(path, public_pem=public_pem)
    assert evidence.outcome.finding_count == len(result.findings) == 10
    audit = [json.loads(line) for line in (tmp_path / "audit.ndjson").read_text().splitlines()]
    assert audit[-1]["metadata"]["evidence_sha256"] == evidence_sha256(evidence)
    assert evidence.run_id == audit[-1]["execution_id"]  # one id ties the two records


def test_a_refused_run_leaves_no_evidence(engine_runs: None, tmp_path: Path) -> None:
    from olympus.themis.scope import OutOfScopeError

    private_pem, _ = _keys()
    path = tmp_path / "e.json"
    with pytest.raises(OutOfScopeError):
        _service().run(
            _request(
                tmp_path,
                target="http://8.8.8.8/",
                evidence_path=path,
                evidence_signer=_signer(private_pem),
            )
        )
    assert not path.exists() and not signature_path(path).exists()


def test_evidence_path_must_not_collide_with_other_outputs(tmp_path: Path) -> None:
    private_pem, _ = _keys()
    same = tmp_path / "same.json"
    with pytest.raises(ValueError, match="must differ"):
        _service().run(
            _request(
                tmp_path,
                output_path=same,
                evidence_path=same,
                evidence_signer=_signer(private_pem),
            )
        )


def test_the_published_contract_matches_the_model() -> None:
    from olympus.schema_catalog import legacy_schema_bundle

    schema = legacy_schema_bundle()["olympus.engine-run-evidence"]
    assert set(EngineRunEvidence.model_json_schema()["properties"]) == set(schema["properties"])
    assert evidence_module.EngineRunEvidence is EngineRunEvidence

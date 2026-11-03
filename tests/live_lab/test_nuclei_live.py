"""nuclei end to end through the real runner, against a local throw-away server.

Opt-in only (``make test-live-lab``): needs OLYMPUS_RUN_LIVE_LAB_TESTS=1 and
OLYMPUS_LIVE_LAB_AUTHORIZATION=I_HAVE_AUTHORIZATION, a world-readable ``nuclei`` on PATH (the
Themis sandbox runs it as an unprivileged user) and the pinned template checkout at
``THEMIS_NUCLEI_TEMPLATES``. The only target is a server this test starts on 127.0.0.1 and the
scope allows exactly that address, so nothing outside the machine is ever contacted.

What it proves that the offline tests cannot: the engine on PATH really is the pinned version,
the real argv built from the manifest is accepted by it, and the signed evidence describes a
real run.
"""

from __future__ import annotations

import http.server
import json
import shutil
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from olympus.core.signing import generate_keypair, sign
from olympus.engines.evidence import verify_signed
from olympus.engines.loader import manifest_for
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.application import ThemisApplicationService, ThemisRunRequest
from olympus.themis.scope import OutOfScopeError, SsrfBlockedError

pytestmark = pytest.mark.live_lab

_TEMPLATE = Path("http/misconfiguration/http-missing-security-headers.yaml")


class _Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<html><title>Olympus lab target</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return None


@pytest.fixture
def lab_url() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def one_template(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A directory with ONE pinned template, readable by the unprivileged sandbox user."""
    import os

    pinned = Path(os.environ.get("THEMIS_NUCLEI_TEMPLATES", ""))
    source = pinned / _TEMPLATE
    if not source.is_file():
        pytest.skip(
            f"set THEMIS_NUCLEI_TEMPLATES to the pinned nuclei-templates checkout ({source})"
        )
    if shutil.which("nuclei") is None:
        pytest.skip("nuclei is not on PATH")
    directory = Path(tempfile.mkdtemp(prefix="olympus-nuclei-live-"))
    try:
        target = directory / _TEMPLATE
        target.parent.mkdir(parents=True)
        shutil.copy(source, target)
        for path in [directory, *directory.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        monkeypatch.setenv("THEMIS_NUCLEI_TEMPLATES", str(directory))
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _request(tmp_path: Path, target: str, **changes: object) -> ThemisRunRequest:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
            }
        ),
        encoding="utf-8",
    )
    values: dict[str, object] = {
        "scanner": "nuclei",
        "target": target,
        "target_kind": "url",
        "scope_path": scope,
        "authorized": True,
        "live_enabled": True,
        "audit_path": tmp_path / "audit.ndjson",
        "timeout_seconds": 120.0,
    }
    values.update(changes)
    return ThemisRunRequest(**values)  # type: ignore[arg-type]


def _service() -> ThemisApplicationService:
    # Kernel isolation has its own contract tests; the process is still really sandboxed.
    return ThemisApplicationService(isolation_verifier=lambda: None)


def test_nuclei_runs_for_real_on_the_pinned_version_and_leaves_signed_evidence(
    lab_url: str, one_template: Path, tmp_path: Path
) -> None:
    private_pem, public_pem = generate_keypair()
    path = tmp_path / "run.evidence.json"
    result = _service().run(
        _request(
            tmp_path,
            lab_url,
            evidence_path=path,
            evidence_signer=lambda data: sign(data, private_pem),
        )
    )
    assert result.state.value == "live", result.error
    assert result.partial is False and result.findings, "the lab page lacks security headers"
    pinned = str(manifest_for("nuclei").engine.pinned_version).removeprefix("v")
    assert pinned in (result.version or ""), f"nuclei is {result.version!r}, pinned v{pinned}"

    evidence = verify_signed(path, public_pem=public_pem)
    assert evidence.engine.pinned_version == f"v{pinned}"
    assert evidence.outcome.finding_count == len(result.findings)
    assert evidence.outputs is not None and evidence.outputs.stdout_bytes > 0
    assert evidence.scope.allowed_hosts == ["127.0.0.1"]
    assert "-omit-raw" in evidence.command and "-no-interactsh" in evidence.command


def test_targets_outside_the_scope_are_refused_without_starting_nuclei(
    lab_url: str, one_template: Path, tmp_path: Path
) -> None:
    for outside in ("http://8.8.8.8/", "http://example.org/"):
        with pytest.raises(OutOfScopeError):
            _service().run(_request(tmp_path, outside))
    with pytest.raises((OutOfScopeError, SsrfBlockedError)):
        _service().run(_request(tmp_path, "http://127.0.0.2:9/"))  # same machine, not in scope


def test_the_adapter_is_the_one_the_manifest_names() -> None:
    entrypoint = str(manifest_for("nuclei").adapter.entrypoint)  # type: ignore[union-attr]
    assert entrypoint == f"{NucleiAdapter.__module__}:{NucleiAdapter.__name__}"

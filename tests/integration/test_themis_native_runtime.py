from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from olympus.cli import app
from olympus.themis.api import ApiSettings, create_app
from olympus.themis.jobs import SCHEMA_VERSION

runner = CliRunner()


@pytest.fixture
def isolated_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("OLYMPUS_VENDOR_DIR", str(tmp_path / "no-vendor"))
    for name in ("OLYMPUS_THEMIS_API_KEY", "OLYMPUS_AEGIS_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for prefix in ("THEMIS", "AEGIS", "VAP"):
        monkeypatch.delenv(f"{prefix}_ENABLE_LIVE_SCANS", raising=False)
        monkeypatch.delenv(f"{prefix}_SIMULATION_MODE", raising=False)
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    (scopes / "lab.json").write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.1/32"],
            }
        )
    )
    return scopes


def test_api_submission_native_worker_and_cancellation_share_the_store(
    tmp_path: Path,
    isolated_runtime: Path,
) -> None:
    database = tmp_path / "jobs.sqlite3"
    settings = ApiSettings(database=database, scope_directory=isolated_runtime, api_key="x" * 40)
    headers = {"X-Olympus-API-Key": settings.api_key}
    body = {
        "scanner": "nmap",
        "target": "127.0.0.1",
        "target_kind": "host",
        "scope_id": "lab",
        "authorized": True,
    }
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/v1/jobs", json=body).status_code == 401
        first = client.post("/api/v1/jobs", headers=headers, json=body)
        assert first.status_code == 201, first.text
        job_id = first.json()["job_id"]
        worked = runner.invoke(
            app,
            [
                "themis",
                "workers",
                "--once",
                "--database",
                str(database),
                "--audit",
                str(tmp_path / "audit.ndjson"),
            ],
        )
        assert worked.exit_code == 5, worked.output
        assert json.loads(worked.output)["job_id"] == job_id
        final = client.get(f"/api/v1/jobs/{job_id}", headers=headers).json()
        assert final["state"] == "partial"
        assert final["result"]["findings"] == []
        assert "scope_path" not in final
        second = client.post("/api/v1/jobs", headers=headers, json=body).json()
        assert (
            client.post(
                f"/api/v1/jobs/{second['job_id']}/cancel",
                headers=headers,
            ).json()["state"]
            == "cancelled"
        )
        empty = runner.invoke(app, ["themis", "workers", "--once", "-d", str(database)])
        assert empty.exit_code == 0, empty.output
        assert json.loads(empty.output)["claimed"] is False


@pytest.mark.parametrize("command", ["web", "serve"])
def test_web_and_serve_launch_the_identical_authenticated_native_app(
    command: str,
    tmp_path: Path,
    isolated_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    monkeypatch.setenv("OLYMPUS_THEMIS_API_KEY", "x" * 40)
    applications: list[FastAPI] = []

    def launch(application: FastAPI, **kwargs: object) -> None:
        applications.append(application)
        assert kwargs["proxy_headers"] is False
        assert kwargs["server_header"] is False

    monkeypatch.setattr(uvicorn, "run", launch)
    result = runner.invoke(
        app,
        [
            "themis",
            command,
            "--scope-directory",
            str(isolated_runtime),
            "--database",
            str(tmp_path / "jobs.sqlite3"),
            "--audit",
            str(tmp_path / "audit.ndjson"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(applications) == 1
    with TestClient(applications[0], base_url="https://testserver") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/jobs", follow_redirects=False).status_code == 303
        assert client.get("/login").status_code == 200


def test_legacy_web_and_celery_flags_cannot_reenable_vendor_execution(
    isolated_runtime: Path,
) -> None:
    for arguments in (["serve", "--allow-legacy-web"], ["workers", "--queue", "scans"]):
        result = runner.invoke(app, ["themis", *arguments])
        assert result.exit_code == 2
        assert "No such option" in result.output


def test_migrate_and_deprecated_aliases_work_without_vendor(tmp_path: Path) -> None:
    for module in ("themis", "aegis", "vap"):
        result = runner.invoke(app, [module, "migrate", "-d", str(tmp_path / f"{module}.sqlite3")])
        assert result.exit_code == 0, result.output
        assert f'"schema_version": {SCHEMA_VERSION}' in result.output


def test_malformed_database_is_an_actionable_usage_error(tmp_path: Path) -> None:
    database = tmp_path / "invalid.sqlite3"
    database.write_text("not a database")
    result = runner.invoke(app, ["themis", "migrate", "-d", str(database)])
    assert result.exit_code == 2
    assert "migration refused" in result.output
    assert database.read_text() == "not a database"


def test_invalid_worker_identity_is_refused_before_reporting_readiness(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "themis",
            "workers",
            "-d",
            str(tmp_path / "jobs.sqlite3"),
            "--worker-id",
            "bad identity",
        ],
    )
    assert result.exit_code == 2
    assert "invalid worker settings" in result.output
    assert '"ready": true' not in result.output


def test_runtime_diagnostics_do_not_load_vendored_code_or_mutate_sys_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream = tmp_path / "vulnerability-assessment-platform"
    upstream.mkdir()
    (upstream / "fastapi.py").write_text("raise RuntimeError('vendored code was loaded')")
    monkeypatch.setenv("OLYMPUS_VENDOR_DIR", str(tmp_path))
    original = sys.path.copy()
    for command in ("info", "deps", "doctor"):
        result = runner.invoke(app, ["themis", command])
        assert result.exit_code == 0, result.output
        assert sys.path == original
    assert json.loads(runner.invoke(app, ["themis", "info"]).output)["vendor_required"] is False


@pytest.mark.posix_only
def test_real_worker_process_honours_sigterm_during_idle_poll(tmp_path: Path) -> None:
    environment = dict(os.environ)
    for prefix in ("THEMIS", "AEGIS", "VAP"):
        environment.pop(f"{prefix}_ENABLE_LIVE_SCANS", None)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "olympus.cli",
            "themis",
            "workers",
            "--database",
            str(tmp_path / "jobs.sqlite3"),
            "--poll-interval",
            "30",
            "--audit",
            str(tmp_path / "audit.ndjson"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    ready: list[str] = []
    assert process.stdout is not None
    reader = threading.Thread(target=lambda: ready.append(process.stdout.readline()), daemon=True)
    try:
        reader.start()
        reader.join(timeout=10)
        assert ready and json.loads(ready[0])["ready"] is True
        process.send_signal(signal.SIGTERM)
        output, error = process.communicate(timeout=5)
        assert process.returncode == 7, error
        assert json.loads(output)["stopped"] is True
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)

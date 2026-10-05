from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_native_entry_points_cannot_import_the_vendored_runtime() -> None:
    for path in [
        ROOT / "src/olympus/integrations/cli.py",
        *(ROOT / "src/olympus/themis").rglob("*.py"),
    ]:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("olympus.integrations.vendored"), path
        if path.name == "cli.py":
            assert "ensure_on_path" not in path.read_text()
            assert "subprocess" not in path.read_text()


def test_native_extra_has_no_legacy_stack_dependencies() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requirements = project["project"]["optional-dependencies"]["themis"]
    assert not any(
        name in requirement
        for name in ("celery", "redis", "alembic", "sqlalchemy")
        for requirement in requirements
    )


def test_compose_uses_the_native_image_and_is_fail_closed() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = compose["services"]
    assert "redis" not in services
    for name in ("themis-migrate", "themis-api", "themis-app", "themis-worker"):
        service = services[name]
        assert service["build"] == {"context": ".", "dockerfile": "docker/Dockerfile"}
        assert service["user"] == "10001:10001" and service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["command"][:1] == ["themis"]
    assert services["themis-migrate"]["network_mode"] == "none"
    for name in ("themis-api", "themis-app"):
        service = services[name]
        assert "--identities" in service["command"]
        assert "--ssl-certfile" in service["command"]
        assert "--ssl-keyfile" in service["command"]
        assert all(port.startswith("127.0.0.1:") for port in service["ports"])
        assert (
            service["depends_on"]["themis-migrate"]["condition"] == "service_completed_successfully"
        )
    worker = services["themis-worker"]
    assert worker["environment"]["THEMIS_ENABLE_LIVE_SCANS"].endswith(":-false}")
    assert not any("themis-config" in mount or "themis-tls" in mount for mount in worker["volumes"])


def test_native_images_never_copy_vendor_or_the_whole_checkout() -> None:
    for name in ("Dockerfile", "Dockerfile.scanners"):
        source = (ROOT / "docker" / name).read_text()
        assert "COPY . ." not in source
        assert "COPY vendor" not in source
        assert "USER 10001:10001" in source
    overlay = yaml.safe_load((ROOT / "docker-compose.scanners.yml").read_text())
    assert set(overlay["services"]) == {"themis-worker"}
    assert overlay["services"]["themis-worker"]["build"]["context"] == "."

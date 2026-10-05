"""Exercise the installed native runtime over loopback, with live scanning off.

Runs against a clean wheel installation and the native container in CI. All
credentials, certificates, registered scopes and databases are temporary.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _run(arguments: list[str], environment: dict[str, str], expected: int = 0) -> str:
    result = subprocess.run(  # noqa: S603 - fixed Python CLI, no shell
        [sys.executable, "-m", "olympus.cli", "themis", *arguments],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    _check(result.returncode == expected, f"native CLI failed: {result.stderr}")
    return result.stdout


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = directory / "cert.pem", directory / "key.pem"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    return certfile, keyfile


def _request(
    url: str,
    key: str = "",
    body: dict[str, object] | None = None,
    context: ssl.SSLContext | None = None,
) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback test URL
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-Olympus-API-Key": key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5, context=context) as response:  # noqa: S310 - local test URL
        return response.read()


@contextmanager
def _serve(
    arguments: list[str],
    environment: dict[str, str],
    url: str,
    context: ssl.SSLContext | None = None,
) -> Iterator[None]:
    with tempfile.TemporaryFile(mode="w+t") as errors:
        process = subprocess.Popen(  # noqa: S603 - fixed local CLI, no shell
            [sys.executable, "-m", "olympus.cli", "themis", *arguments],
            env=environment,
            stdout=errors,
            stderr=errors,
            text=True,
        )
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    errors.seek(0)
                    raise RuntimeError(f"native service stopped: {errors.read()}")
                try:
                    _request(f"{url}/health", context=context)
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("native service did not become healthy") from None
                    time.sleep(0.1)
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> None:
    import secrets

    environment = dict(os.environ)
    for prefix in ("THEMIS", "AEGIS", "VAP"):
        for suffix in ("ENABLE_LIVE_SCANS", "SIMULATION_MODE"):
            environment.pop(f"{prefix}_{suffix}", None)
    environment["THEMIS_ENABLE_LIVE_SCANS"] = "false"
    key = secrets.token_urlsafe(32)
    environment["OLYMPUS_THEMIS_API_KEY"] = key
    with tempfile.TemporaryDirectory(prefix="olympus-native-smoke-") as temporary:
        root = Path(temporary)
        environment["OLYMPUS_STATE_DIR"] = str(root / "state")
        environment["OLYMPUS_VENDOR_DIR"] = str(root / "absent-vendor")
        scopes = root / "scopes"
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
        database = str(root / "jobs.sqlite3")
        common = ["--database", database, "--audit", str(root / "audit.ndjson")]
        migrated = json.loads(_run(["migrate", "--database", database], environment))
        _check(migrated["migrated"], "fresh database was not initialized")
        repeated = json.loads(_run(["migrate", "--database", database], environment))
        _check(not repeated["migrated"], "migration is not idempotent")
        port = _port()
        url = f"http://127.0.0.1:{port}"
        with _serve(
            ["api", *common, "--scope-directory", str(scopes), "--port", str(port)],
            environment,
            url,
        ):
            try:
                _request(f"{url}/api/v1/jobs")
            except urllib.error.HTTPError as exc:
                _check(exc.code == 401, "unauthenticated API did not fail closed")
            else:
                raise RuntimeError("unauthenticated API access was accepted")
            job = json.loads(
                _request(
                    f"{url}/api/v1/jobs",
                    key,
                    {
                        "scanner": "nmap",
                        "target": "127.0.0.1",
                        "target_kind": "host",
                        "scope_id": "lab",
                        "authorized": True,
                    },
                )
            )
            _run(["workers", "--once", *common], environment, expected=5)
            final = json.loads(_request(f"{url}/api/v1/jobs/{job['job_id']}", key))
            _check(final["state"] == "partial", "disabled scan must report lost coverage")
            _check(final["result"]["findings"] == [], "disabled scan invented findings")
        certfile, keyfile = _certificate(root)
        context = ssl.create_default_context(cafile=str(certfile))
        port = _port()
        url = f"https://127.0.0.1:{port}"
        with _serve(
            [
                "serve",
                *common,
                "--scope-directory",
                str(scopes),
                "--port",
                str(port),
                "--ssl-certfile",
                str(certfile),
                "--ssl-keyfile",
                str(keyfile),
            ],
            environment,
            url,
            context,
        ):
            _check(b"api_key" in _request(f"{url}/login", context=context), "web login missing")
            _check(bool(_request(f"{url}/static/app.css", context=context)), "packaged CSS missing")
    print("Native migration, API, HTTPS Web and worker smoke passed (no live scan).")


if __name__ == "__main__":
    main()

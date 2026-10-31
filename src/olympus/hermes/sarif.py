"""SARIF 2.1.0 serialization for Hermes findings."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any
from urllib.parse import quote

from olympus.core.execution import safe_terminal_text
from olympus.hermes.scanner import SecretFinding


def _artifact_uri(path: str) -> str:
    """Encode an untrusted local path as a URI reference, not a URI scheme."""
    normalized = path.replace("\\", "/")
    if len(normalized) >= 3 and normalized[0].isalpha() and normalized[1:3] == ":/":
        # Preserve absolute Windows paths without treating the drive letter as
        # an arbitrary URI scheme.
        drive = normalized[:2]
        remainder = quote(normalized[3:], safe="/-._~")
        return f"file:///{drive}/{remainder}"
    if normalized.startswith("//"):
        # A leading double slash is a URI network-path reference (authority).
        # Encode its first slash so untrusted filenames cannot link externally.
        return "%2F" + quote(normalized[1:], safe="/-._~")
    return quote(normalized, safe="/-._~")


def to_sarif(findings: list[SecretFinding]) -> dict[str, Any]:
    """Build a SARIF document containing masked values only."""
    rules = sorted({finding.rule for finding in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Olympus Hermes",
                        "rules": [{"id": rule} for rule in rules],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule,
                        # ``masked`` is derived from scanned file content, so it is
                        # target-controlled input a SARIF viewer or terminal renders.
                        # Neutralize ANSI/OSC and C0/C1 controls and collapse newlines
                        # so it cannot inject control sequences or forge log lines
                        # (SEC-H: contextual escaping in every export).
                        "message": {
                            "text": safe_terminal_text(
                                f"Potential secret detected: {finding.masked}"
                            )
                        },
                        "partialFingerprints": {"olympusSecretFingerprint": finding.fingerprint},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _artifact_uri(finding.path)},
                                    "region": {"startLine": finding.line},
                                }
                            }
                        ],
                    }
                    for finding in findings
                ],
            }
        ],
    }


def write_sarif(findings: list[SecretFinding], output: Path) -> None:
    """Write masked SARIF through a unique atomic temporary file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(to_sarif(findings), indent=2) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise

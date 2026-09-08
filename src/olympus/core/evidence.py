"""Create evidence references whose digest is computed at capture time (§5.2).

An :class:`~olympus.core.models.Evidence` reference carries a ``sha256`` that is
meant to bind the reference to a concrete artifact. The model only validates the
*shape* of that hex string — it cannot know whether the digest matches any real
material. Left to a hand-written value, the digest is trusted blindly: it may be
computed *a posteriori* against a file that has since changed, or simply be
wrong.

This module closes that gap by deriving the digest from the artifact's actual
bytes at the moment the reference is created:

* :func:`evidence_from_bytes` hashes in-memory bytes an artifact was built from.
* :func:`capture_evidence` reads a local artifact through the bounded,
  no-symlink reader and hashes exactly what it read.
* :func:`verify_evidence_artifact` re-derives the digest and compares it, so a
  stored reference can be checked against the material later.

Keeping this bridge in its own module lets :mod:`olympus.core.models` stay a
pure, IO-free interoperability contract while the hashing/IO lives beside the
file primitives it depends on.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from pathlib import Path
from typing import Any

from olympus.core.fileio import read_regular_bytes
from olympus.core.models import Evidence

#: A generous default cap for a single evidence artifact (256 MiB). Callers that
#: capture larger material (full disk images) pass an explicit, deliberate cap.
DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def evidence_from_bytes(
    data: bytes,
    *,
    evidence_type: str,
    uri: str,
    evidence_id: str | None = None,
    collected_at: datetime | None = None,
) -> Evidence:
    """Build an :class:`Evidence` whose ``sha256`` is computed from ``data``.

    The digest is derived here, at creation, so it provably matches the exact
    bytes the artifact was made of — it can never be a stale or mismatched value
    supplied by a caller.
    """
    # Optional identity/timestamp are only passed when set, so the model's own
    # defaults (a fresh id, "now") apply otherwise; ``extra`` is typed ``Any`` so
    # the conditional unpack stays type-clean.
    extra: dict[str, Any] = {}
    if evidence_id is not None:
        extra["evidence_id"] = evidence_id
    if collected_at is not None:
        extra["collected_at"] = collected_at
    return Evidence(
        evidence_type=evidence_type,
        uri=uri,
        sha256=hashlib.sha256(data).hexdigest(),
        **extra,
    )


def capture_evidence(
    artifact: Path,
    *,
    evidence_type: str,
    uri: str | None = None,
    evidence_id: str | None = None,
    collected_at: datetime | None = None,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> Evidence:
    """Read a local artifact and build evidence anchored to its real bytes.

    The artifact is read through :func:`olympus.core.fileio.read_regular_bytes`,
    which refuses a symlink or a non-regular file and enforces ``max_bytes``, so
    the digest is taken from bounded, real, on-disk content. ``uri`` defaults to
    the artifact's absolute ``file://`` URI when not given explicitly.
    """
    data = read_regular_bytes(artifact, max_bytes=max_bytes, label="evidence artifact")
    resolved_uri = uri if uri is not None else artifact.resolve().as_uri()
    return evidence_from_bytes(
        data,
        evidence_type=evidence_type,
        uri=resolved_uri,
        evidence_id=evidence_id,
        collected_at=collected_at,
    )


def verify_evidence_artifact(
    artifact: Path,
    evidence: Evidence,
    *,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> bool:
    """Return ``True`` iff ``artifact``'s current bytes match ``evidence.sha256``.

    Re-derives the digest from the file on disk and compares it in constant time
    to the reference. A mismatch means the material changed after the reference
    was created (or the reference never matched it).
    """
    data = read_regular_bytes(artifact, max_bytes=max_bytes, label="evidence artifact")
    actual = hashlib.sha256(data).hexdigest()
    return hmac.compare_digest(actual, evidence.sha256.lower())

"""Explicit, bounded authorization profile for direct live lab execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from olympus.core.fileio import read_regular_text
from olympus.core.policy import (
    LAB_SIGNING_KEY_VARIABLE,
    PolicyError,
    lab_activation_record,
    parse_policy,
)
from olympus.core.secrets import SecretProvider, resolve_secret

MAX_LAB_POLICY_BYTES = 1_000_000


@dataclass(frozen=True)
class LabExecutionProfile:
    """Minimized provenance passed to the Themis application boundary."""

    engagement: str
    allowed_networks: tuple[str, ...]
    policy_sha256: str
    activation_signature: str


def load_lab_execution_profile(
    path: Path, *, secrets: SecretProvider | None = None
) -> LabExecutionProfile:
    """Load one explicitly selected, signed and network-bounded lab profile.

    Discovery fallbacks are deliberately unavailable here: selecting the lab
    exception must remain visible in the command invocation. The HMAC key is
    mandatory for live execution even though ``policy show`` also supports
    unsigned informational activation records.
    """
    source = path.resolve()
    ruleset = parse_policy(
        read_regular_text(path, max_bytes=MAX_LAB_POLICY_BYTES, label="live lab policy"), path
    )
    if not ruleset.lab.enabled:
        raise PolicyError("live lab execution requires [lab].enabled = true")
    engagement = (ruleset.engagement or "").strip()
    if not engagement:
        raise PolicyError("live lab execution requires a non-empty engagement identifier")
    secret = resolve_secret(LAB_SIGNING_KEY_VARIABLE, provider=secrets)
    if secret is None:
        raise PolicyError(
            "live lab execution requires OLYMPUS_POLICY_LAB_KEY to sign the activation record"
        )
    signing_key = secret.get_secret_value()
    if len(signing_key.encode("utf-8")) < 32:
        raise PolicyError("OLYMPUS_POLICY_LAB_KEY must contain at least 32 UTF-8 bytes")
    activation = lab_activation_record(ruleset, source, signing_key=signing_key)
    signature = activation["signature"]
    digest = activation["policy_digest"]
    if not isinstance(signature, str) or not isinstance(digest, str):
        raise PolicyError("lab activation record is missing signed provenance")
    return LabExecutionProfile(
        engagement=engagement,
        allowed_networks=ruleset.lab.allowed_networks,
        policy_sha256=digest,
        activation_signature=signature,
    )

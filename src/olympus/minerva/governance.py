"""System data retention and privacy governance (DATA-3).

Olympus produces several classes of sensitive material — signed engine-run
evidence (`TOOLS-4.5`), finding history (`VAL-1`/`EXPL-1`), raw scanner output,
job/engagement records and the audit trail. `DATA-1`/`DATA-2` persist them and
:mod:`olympus.core.retention` and :mod:`olympus.minerva.custody` already bound and
protect them, but each class was governed ad hoc. This module is the **one system
policy** that classifies every class and binds it to a retention rule, a privacy
classification, and — for evidence — the verifiable custody chain.

It is pure and offline: it declares the policy, applies retention by reusing
:func:`olympus.core.retention.prune_paths`, and verifies the signed custody ledger
by reusing :func:`olympus.minerva.custody.inspect_ledger`. It performs no network
I/O and holds no secrets (custody keys are read from the environment by the custody
module). Per-class windows are documented defaults (`docs/data-governance.md`); the
mechanism, not the exact number of days, is the contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from olympus.core.retention import RetentionPolicy, RetentionReport, prune_paths
from olympus.minerva.custody import (
    inspect_ledger,
    load_custody_ed25519_public_key,
    load_custody_key,
)


class DataClass(StrEnum):
    """A class of sensitive material Olympus retains, each governed by one rule."""

    ENGINE_EVIDENCE = "engine-evidence"
    FINDING_HISTORY = "finding-history"
    SCANNER_OUTPUT = "scanner-output"
    JOB_RECORDS = "job-records"
    AUDIT_TRAIL = "audit-trail"


class Enforcement(StrEnum):
    """How a class's retention is enforced."""

    #: Prune regular files in a directory with ``core.retention.prune_paths``.
    PRUNE_DIR = "prune-dir"
    #: Rotate an append-only log with ``core.retention.rotate_log``.
    ROTATE_LOG = "rotate-log"
    #: Bounded inside the transactional store (``ThemisJobStore.prune`` / `jobs prune`).
    STORE_MANAGED = "store-managed"


@dataclass(frozen=True)
class GovernanceRule:
    """The system policy for one :class:`DataClass`."""

    data_class: DataClass
    description: str
    retention: RetentionPolicy
    enforcement: Enforcement
    #: File glob for PRUNE_DIR/ROTATE_LOG classes (one directory, no separators).
    pattern: str
    contains_targets: bool
    contains_identities: bool
    #: Whether egress of this class off the perimeter requires redaction first.
    redaction_required: bool
    #: Whether artefacts of this class are tracked in the verifiable custody chain.
    custody_tracked: bool


#: The system retention/privacy policy. Windows are conservative documented
#: defaults; raw scanner output (most sensitive, least summarised) is kept the
#: shortest, signed evidence and finding history the longest.
SYSTEM_POLICY: dict[DataClass, GovernanceRule] = {
    DataClass.ENGINE_EVIDENCE: GovernanceRule(
        data_class=DataClass.ENGINE_EVIDENCE,
        description="Signed olympus.engine-run-evidence manifests and their .sig (TOOLS-4.5).",
        retention=RetentionPolicy(max_age_days=365, max_files=10_000),
        enforcement=Enforcement.PRUNE_DIR,
        pattern="*-evidence.json*",
        contains_targets=True,
        contains_identities=False,
        redaction_required=False,
        custody_tracked=True,
    ),
    DataClass.FINDING_HISTORY: GovernanceRule(
        data_class=DataClass.FINDING_HISTORY,
        description="Exported finding history and result documents (VAL-1/EXPL-1).",
        retention=RetentionPolicy(max_age_days=365, max_files=10_000),
        enforcement=Enforcement.PRUNE_DIR,
        pattern="*.json",
        contains_targets=True,
        contains_identities=False,
        redaction_required=True,
        custody_tracked=False,
    ),
    DataClass.SCANNER_OUTPUT: GovernanceRule(
        data_class=DataClass.SCANNER_OUTPUT,
        description="Raw scanner result/output artefacts before summarisation.",
        retention=RetentionPolicy(max_age_days=30, max_files=5_000),
        enforcement=Enforcement.PRUNE_DIR,
        pattern="*",
        contains_targets=True,
        contains_identities=False,
        redaction_required=True,
        custody_tracked=False,
    ),
    DataClass.JOB_RECORDS: GovernanceRule(
        data_class=DataClass.JOB_RECORDS,
        description="Themis job/engagement records (names targets); in the SQLite store.",
        retention=RetentionPolicy(max_age_days=180),
        enforcement=Enforcement.STORE_MANAGED,
        pattern="",
        contains_targets=True,
        contains_identities=True,
        redaction_required=True,
        custody_tracked=False,
    ),
    DataClass.AUDIT_TRAIL: GovernanceRule(
        data_class=DataClass.AUDIT_TRAIL,
        description="Redacted structured audit log (names identities/actions).",
        retention=RetentionPolicy(max_age_days=365),
        enforcement=Enforcement.ROTATE_LOG,
        pattern="*.ndjson",
        contains_targets=False,
        contains_identities=True,
        redaction_required=True,
        custody_tracked=False,
    ),
}


class GovernanceError(ValueError):
    """A class is governed by a mechanism other than the one requested."""


def rule_for(data_class: DataClass) -> GovernanceRule:
    return SYSTEM_POLICY[data_class]


def describe_policy() -> list[dict[str, object]]:
    """A JSON-serialisable description of the whole policy, ordered by class."""
    out: list[dict[str, object]] = []
    for data_class in DataClass:
        rule = SYSTEM_POLICY[data_class]
        out.append(
            {
                "data_class": str(rule.data_class),
                "description": rule.description,
                "enforcement": str(rule.enforcement),
                "pattern": rule.pattern,
                "retention": {
                    "max_age_days": rule.retention.max_age_days,
                    "max_files": rule.retention.max_files,
                    "max_total_bytes": rule.retention.max_total_bytes,
                    "secure_delete": rule.retention.secure,
                },
                "privacy": {
                    "contains_targets": rule.contains_targets,
                    "contains_identities": rule.contains_identities,
                    "redaction_required": rule.redaction_required,
                },
                "custody_tracked": rule.custody_tracked,
            }
        )
    return out


def apply_retention(
    data_class: DataClass,
    directory: Path,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> RetentionReport:
    """Apply the class's retention rule to ``directory`` (PRUNE_DIR classes only).

    Reuses :func:`olympus.core.retention.prune_paths`, so the same secure-delete
    and bounds apply. Classes enforced elsewhere (the SQLite store, log rotation)
    raise :class:`GovernanceError` pointing at the right mechanism rather than
    silently doing nothing.
    """
    rule = SYSTEM_POLICY[data_class]
    if rule.enforcement is Enforcement.STORE_MANAGED:
        raise GovernanceError(
            f"{data_class} lives in the transactional store; prune it with "
            "`olympus themis jobs prune`, not a directory pass"
        )
    if rule.enforcement is Enforcement.ROTATE_LOG:
        raise GovernanceError(
            f"{data_class} is an append-only log; rotate it with "
            "`olympus themis retention rotate` / core.retention.rotate_log"
        )
    return prune_paths(
        directory, policy=rule.retention, pattern=rule.pattern, dry_run=dry_run, now=now
    )


@dataclass(frozen=True)
class CustodyVerification:
    """The result of checking a custody ledger backs the evidence chain."""

    ledger: str
    entries: int
    evidence_anchored: bool
    signed: bool
    signature_verified: bool
    signature_algorithm: str | None

    @property
    def ok(self) -> bool:
        # A verifiable chain anchors evidence digests and, when signed, verifies.
        return self.evidence_anchored and (not self.signed or self.signature_verified)

    def to_dict(self) -> dict[str, object]:
        return {
            "ledger": self.ledger,
            "entries": self.entries,
            "evidence_anchored": self.evidence_anchored,
            "signed": self.signed,
            "signature_verified": self.signature_verified,
            "signature_algorithm": self.signature_algorithm,
            "ok": self.ok,
        }


def verify_custody(
    ledger: Path,
    *,
    env: Mapping[str, str] | None = None,
) -> CustodyVerification:
    """Verify the custody chain for evidence historicization (DATA-3).

    Reuses :func:`olympus.minerva.custody.inspect_ledger` with the keys from the
    environment (Ed25519 public key or HMAC key), so a signed ledger is checked
    against its key and an unsigned one is reported as such. This is the verifiable
    link the policy requires for ``custody_tracked`` classes.
    """
    source = dict(env) if env is not None else None
    inspection = inspect_ledger(
        ledger,
        missing_ok=False,
        key=load_custody_key(source),
        ed25519_public_key=load_custody_ed25519_public_key(source),
    )
    return CustodyVerification(
        ledger=str(ledger),
        entries=len(inspection.entries),
        evidence_anchored=inspection.evidence_anchored,
        signed=inspection.signed,
        signature_verified=inspection.signature_verified,
        signature_algorithm=inspection.signature_algorithm,
    )

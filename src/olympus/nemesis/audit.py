"""Pure, offline credential-audit core: weak, default and reused passwords.

No I/O, no network, no process: given credential entries, a policy and an optional
local list of known-weak/default passwords, it returns a masked report. The raw
secret never leaves this module — findings carry only a mask and a salted-free
SHA-256 fingerprint (so identical secrets group without exposing the value).

Classification is deliberately split by epistemic class:

* **deterministic** — policy breaches (length, character classes), membership in the
  supplied known-password list, and reuse across accounts. These are facts about the
  input.
* **inference** — the entropy estimate is a *model* of guessability (pool-size
  heuristic), never a measurement, so it is reported separately and a policy may opt
  into a minimum only explicitly.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from enum import StrEnum

#: Bounds so a hostile or careless input cannot exhaust memory.
MAX_ENTRIES = 1_000_000
MAX_SECRET_LENGTH = 4096
MAX_ACCOUNT_LENGTH = 1024

_SYMBOLS = set("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ")


class Weakness(StrEnum):
    """A single reason a credential failed the audit (deterministic unless noted)."""

    TOO_SHORT = "too-short"
    TOO_LONG = "too-long"
    MISSING_UPPERCASE = "missing-uppercase"
    MISSING_LOWERCASE = "missing-lowercase"
    MISSING_DIGIT = "missing-digit"
    MISSING_SYMBOL = "missing-symbol"
    KNOWN_OR_DEFAULT = "known-or-default"  # present in the supplied weak-password list
    REUSED = "reused"  # the same secret is used by more than one account
    LOW_ENTROPY = "low-entropy"  # inference: below the policy's estimated-bits floor


@dataclass(frozen=True)
class PasswordPolicy:
    """An explicit, reviewable credential policy. Validated on construction."""

    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    #: Minimum *estimated* entropy bits (inference); 0 disables the check.
    min_entropy_bits: float = 0.0
    max_length: int = 128

    def __post_init__(self) -> None:
        if not 1 <= self.min_length <= self.max_length <= MAX_SECRET_LENGTH:
            raise ValueError("require 1 <= min_length <= max_length <= 4096")
        if not 0.0 <= self.min_entropy_bits <= 1024.0:
            raise ValueError("min_entropy_bits must be between 0 and 1024")


@dataclass(frozen=True)
class CredentialEntry:
    """One account and the secret to audit for it."""

    account: str
    secret: str


@dataclass(frozen=True)
class CredentialFinding:
    """A masked verdict for one credential; never carries the raw secret."""

    account: str
    masked_secret: str
    fingerprint: str
    weaknesses: tuple[Weakness, ...]
    estimated_entropy_bits: float
    reuse_count: int
    compliant: bool


@dataclass(frozen=True)
class AuditReport:
    """The whole audit outcome: per-credential findings plus honest coverage."""

    findings: tuple[CredentialFinding, ...]
    audited: int
    compliant: int
    weak: int
    reused_accounts: int
    known_password_list_checked: bool


def _mask(secret: str) -> str:
    """Mask a secret for display: never reveal the middle, never the whole value."""
    if len(secret) <= 8:
        return "*" * 8
    return f"{secret[:2]}{'*' * 6}{secret[-2:]}"


def _fingerprint(secret: str) -> str:
    """Stable SHA-256 of the secret, to group reuse without exposing the value."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def estimate_entropy_bits(secret: str) -> float:
    """Pool-size entropy *estimate* (inference), ``len * log2(pool)``.

    The pool is the sum of the character-class sizes the secret draws from. This is
    the conventional strength heuristic, not a guarantee: it ignores dictionary words
    and patterns (the known-password list covers those separately).
    """
    if not secret:
        return 0.0
    pool = 0
    if any(c.islower() for c in secret):
        pool += 26
    if any(c.isupper() for c in secret):
        pool += 26
    if any(c.isdigit() for c in secret):
        pool += 10
    if any(c in _SYMBOLS for c in secret):
        pool += len(_SYMBOLS)
    other = {c for c in secret if not (c.islower() or c.isupper() or c.isdigit() or c in _SYMBOLS)}
    pool += len(other)
    return round(len(secret) * math.log2(pool), 2) if pool else 0.0


def _weaknesses(
    secret: str, policy: PasswordPolicy, *, known: bool, reused: bool, entropy: float
) -> tuple[Weakness, ...]:
    found: list[Weakness] = []
    if len(secret) < policy.min_length:
        found.append(Weakness.TOO_SHORT)
    if len(secret) > policy.max_length:
        found.append(Weakness.TOO_LONG)
    if policy.require_uppercase and not any(c.isupper() for c in secret):
        found.append(Weakness.MISSING_UPPERCASE)
    if policy.require_lowercase and not any(c.islower() for c in secret):
        found.append(Weakness.MISSING_LOWERCASE)
    if policy.require_digit and not any(c.isdigit() for c in secret):
        found.append(Weakness.MISSING_DIGIT)
    if policy.require_symbol and not any(c in _SYMBOLS for c in secret):
        found.append(Weakness.MISSING_SYMBOL)
    if policy.min_entropy_bits > 0 and entropy < policy.min_entropy_bits:
        found.append(Weakness.LOW_ENTROPY)
    if known:
        found.append(Weakness.KNOWN_OR_DEFAULT)
    if reused:
        found.append(Weakness.REUSED)
    return tuple(found)


def audit_credentials(
    entries: list[CredentialEntry],
    policy: PasswordPolicy | None = None,
    *,
    known_passwords: frozenset[str] | None = None,
) -> AuditReport:
    """Audit credentials offline for weak, default and reused secrets (skip nothing).

    ``known_passwords`` is a local set of weak/default/breached passwords (loaded by
    the caller, never fetched); when ``None`` the known-password check is reported as
    *not performed* rather than silently passing. Membership is checked case-sensitively
    and against a lowercased form, so ``Password1`` matches a list entry ``password1``.
    """
    resolved = policy or PasswordPolicy()
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"too many credentials (>{MAX_ENTRIES})")
    for entry in entries:
        if len(entry.secret) > MAX_SECRET_LENGTH or len(entry.account) > MAX_ACCOUNT_LENGTH:
            raise ValueError("credential account or secret exceeds the bounded length")

    # Reuse is a property of the whole set: count accounts per secret fingerprint.
    counts: dict[str, int] = {}
    for entry in entries:
        counts[_fingerprint(entry.secret)] = counts.get(_fingerprint(entry.secret), 0) + 1

    findings: list[CredentialFinding] = []
    for entry in entries:
        fingerprint = _fingerprint(entry.secret)
        reuse_count = counts[fingerprint]
        known = known_passwords is not None and (
            entry.secret in known_passwords or entry.secret.lower() in known_passwords
        )
        entropy = estimate_entropy_bits(entry.secret)
        weaknesses = _weaknesses(
            entry.secret, resolved, known=known, reused=reuse_count > 1, entropy=entropy
        )
        findings.append(
            CredentialFinding(
                account=entry.account,
                masked_secret=_mask(entry.secret),
                fingerprint=fingerprint,
                weaknesses=weaknesses,
                estimated_entropy_bits=entropy,
                reuse_count=reuse_count,
                compliant=not weaknesses,
            )
        )

    compliant = sum(1 for f in findings if f.compliant)
    reused_accounts = sum(1 for f in findings if f.reuse_count > 1)
    return AuditReport(
        findings=tuple(findings),
        audited=len(findings),
        compliant=compliant,
        weak=len(findings) - compliant,
        reused_accounts=reused_accounts,
        known_password_list_checked=known_passwords is not None,
    )


def report_to_dict(report: AuditReport) -> dict[str, object]:
    """Serialize a report to a masked JSON-safe dict (never contains a raw secret).

    ``estimated_entropy_bits`` is labelled an inference in ``epistemics`` so a
    consumer never mistakes the guessability model for a measured fact.
    """
    return {
        "tool": "olympus.nemesis",
        "report_version": "1.0.0",
        "summary": {
            "audited": report.audited,
            "compliant": report.compliant,
            "weak": report.weak,
            "reused_accounts": report.reused_accounts,
            "known_password_list_checked": report.known_password_list_checked,
        },
        "epistemics": {
            "deterministic": [w.value for w in Weakness if w is not Weakness.LOW_ENTROPY],
            "inference": [Weakness.LOW_ENTROPY.value, "estimated_entropy_bits"],
        },
        "findings": [
            {
                "account": f.account,
                "masked_secret": f.masked_secret,
                "fingerprint": f.fingerprint,
                "weaknesses": [w.value for w in f.weaknesses],
                "estimated_entropy_bits": f.estimated_entropy_bits,
                "reuse_count": f.reuse_count,
                "compliant": f.compliant,
            }
            for f in report.findings
        ],
    }

"""Application boundary for an authorized, offline credential audit.

Fail-closed: the audit refuses to run without an authorized :class:`ExecutionPolicy`
(the operator asserting they may review these credentials), reads only bounded,
regular, non-symlink files, and never contacts the network. Input and the optional
known-password list are loaded here; the pure core does the judging.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from olympus.core.execution import ExecutionPolicy, ExecutionPolicyError
from olympus.core.fileio import read_regular_text
from olympus.nemesis.audit import (
    MAX_ENTRIES,
    AuditReport,
    CredentialEntry,
    PasswordPolicy,
    audit_credentials,
)

DEFAULT_MAX_INPUT_BYTES = 10_000_000
DEFAULT_MAX_WORDLIST_BYTES = 50_000_000
DEFAULT_MAX_WORDLIST_ENTRIES = 5_000_000


@dataclass(frozen=True)
class AuditRequest:
    """One bounded, authorized credential-audit request."""

    input_path: Path
    wordlist_path: Path | None = None
    policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_wordlist_bytes: int = DEFAULT_MAX_WORDLIST_BYTES
    max_wordlist_entries: int = DEFAULT_MAX_WORDLIST_ENTRIES


def parse_credentials(text: str) -> list[CredentialEntry]:
    """Parse credentials from NDJSON (``{"account","secret"}``) or ``account:secret`` lines.

    Blank lines are ignored; any other malformed line raises — an auditor must not
    silently drop a credential it could not read (that would under-report weakness).
    """
    entries: list[CredentialEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip("\n")
        if not line.strip():
            continue
        if len(entries) >= MAX_ENTRIES:
            raise ValueError(f"too many credentials (>{MAX_ENTRIES})")
        if line.lstrip().startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {number}: invalid JSON credential") from exc
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("account"), str)
                or not isinstance(record.get("secret"), str)
            ):
                raise ValueError(f"line {number}: JSON credential needs string account and secret")
            entries.append(CredentialEntry(record["account"], record["secret"]))
            continue
        account, sep, secret = line.partition(":")
        if not sep or not account:
            raise ValueError(f"line {number}: expected 'account:secret' or a JSON object")
        entries.append(CredentialEntry(account, secret))
    return entries


def load_known_passwords(path: Path, *, max_bytes: int, max_entries: int) -> frozenset[str]:
    """Load a local weak/default/breached-password list (one per line), bounded.

    Entries are kept verbatim and lowercased membership is handled by the core, so a
    list that mixes cases still catches case variants. No network; a symlink or
    irregular file is refused by :func:`read_regular_text`.
    """
    text = read_regular_text(path, max_bytes=max_bytes, label="known-password list")
    words: set[str] = set()
    for raw in text.splitlines():
        word = raw.strip()
        if not word:
            continue
        words.add(word)
        words.add(word.lower())
        if len(words) > max_entries * 2:  # two forms per entry
            raise ValueError(f"known-password list exceeds {max_entries} entries")
    return frozenset(words)


def run_audit(request: AuditRequest, *, policy: ExecutionPolicy) -> AuditReport:
    """Run one authorized, offline credential audit and return the masked report."""
    policy.require_authorization("credential audit")
    if not policy.approval_reference:
        raise ExecutionPolicyError("credential audit requires an approval reference")
    text = read_regular_text(
        request.input_path, max_bytes=request.max_input_bytes, label="credential input"
    )
    entries = parse_credentials(text)
    if not entries:
        raise ExecutionPolicyError("refusing to audit an empty credential set")
    known = (
        load_known_passwords(
            request.wordlist_path,
            max_bytes=request.max_wordlist_bytes,
            max_entries=request.max_wordlist_entries,
        )
        if request.wordlist_path is not None
        else None
    )
    return audit_credentials(entries, request.policy, known_passwords=known)

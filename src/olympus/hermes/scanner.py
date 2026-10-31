"""Bounded secret detection for regular text files and Git history."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import shutil
import stat as stat_module
import subprocess
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from olympus.core.contracts import validate_contract_header
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled

PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
}
TOKEN = re.compile(r"\b[A-Za-z0-9+/=_-]{20,}\b")
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

DEFAULT_MAX_FILE_BYTES = 10_000_000
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_HISTORY_BYTES = 20_000_000
DEFAULT_MAX_COMMITS = 1_000
BASELINE_SCHEMA_NAME = "olympus.hermes-baseline"
BASELINE_SCHEMA_VERSION = "1.0.0"
ALLOWLIST_SCHEMA_NAME = "olympus.hermes-allowlist"
ALLOWLIST_SCHEMA_VERSION = "1.0.0"
#: Bounds on an allowlist document so a hostile or careless file cannot blow up
#: memory or compile time.
_MAX_ALLOWLIST_PATTERNS = 10_000
_MAX_ALLOWLIST_PATTERN_LEN = 1_000
try:
    _NOFOLLOW = os.O_NOFOLLOW
except AttributeError:  # pragma: no cover - Windows lacks this flag
    _NOFOLLOW = 0


class ScanLimitError(RuntimeError):
    """Raised when a configured file, history, or deadline bound is reached."""


@dataclass(frozen=True)
class SecretFinding:
    """A masked potential secret location."""

    rule: str
    path: str
    line: int
    masked: str
    fingerprint: str


@dataclass(frozen=True)
class Allowlist:
    """Operator-declared known-safe patterns that suppress a match.

    Distinct from a baseline (which fingerprints *specific* accepted findings):
    an allowlist suppresses by shape, so a class of false positives — test
    fixtures under a path, or a documentation placeholder value — never has to be
    fingerprinted one by one.

    * ``path_patterns`` are ``fnmatch`` globs tested against the finding's path
      (for history findings, the ``git-history/<commit>/<file>`` location).
    * ``value_patterns`` are regexes searched against the *raw* matched value, so
      they must be applied at detection time, before the value is masked.
    """

    path_patterns: tuple[str, ...] = ()
    value_patterns: tuple[re.Pattern[str], ...] = ()

    def allows(self, path: str, value: str) -> bool:
        if any(fnmatch.fnmatch(path, pattern) for pattern in self.path_patterns):
            return True
        return any(pattern.search(value) for pattern in self.value_patterns)


@dataclass(frozen=True)
class SkippedFile:
    """One intentionally ignored or unsuccessfully read path."""

    path: str
    reason: str


@dataclass(frozen=True)
class PathScanResult:
    """Findings plus enough coverage evidence to avoid false-clean results."""

    findings: tuple[SecretFinding, ...]
    scanned_files: int
    ignored_files: tuple[SkippedFile, ...]
    partial_errors: tuple[SkippedFile, ...]


def _mask(value: str) -> str:
    return f"{value[:4]}…{value[-4:]}" if len(value) > 8 else "********"


def _entropy(value: str) -> float:
    frequencies = {character: value.count(character) for character in set(value)}
    return -sum(
        (count / len(value)) * math.log2(count / len(value)) for count in frequencies.values()
    )


def _validate_entropy_threshold(value: float) -> float:
    if not 0.0 <= value <= 8.0:
        raise ValueError("entropy_threshold must be between 0 and 8")
    return value


def scan_text(
    text: str,
    path: str,
    entropy_threshold: float = 4.5,
    *,
    fingerprint_scope: str | None = None,
    allowlist: Allowlist | None = None,
) -> list[SecretFinding]:
    """Scan text using known prefixes followed by configurable entropy detection.

    ``allowlist`` suppresses a match whose path or raw value it covers, before the
    value is masked into a finding.
    """
    threshold = _validate_entropy_threshold(entropy_threshold)
    findings: list[SecretFinding] = []
    seen_values: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        matches = [
            (rule, match.group())
            for rule, pattern in PATTERNS.items()
            for match in pattern.finditer(line)
        ]
        matches.extend(
            ("high-entropy", match.group())
            for match in TOKEN.finditer(line)
            if _entropy(match.group()) >= threshold
        )
        for rule, value in matches:
            if value in seen_values:
                continue
            seen_values.add(value)
            if allowlist is not None and allowlist.allows(path, value):
                continue
            scope = fingerprint_scope or path
            fingerprint = hashlib.sha256(f"{scope}:{rule}:{value}".encode()).hexdigest()
            findings.append(SecretFinding(rule, path, line_number, _mask(value), fingerprint))
    return findings


def _scan_git_patch(
    patch: str, entropy_threshold: float, allowlist: Allowlist | None = None
) -> list[SecretFinding]:
    """Map changed patch lines to their introducing commit/file without exposing values."""
    current_commit = "unknown"
    current_path = "unknown"
    old_line = 0
    new_line = 0
    findings: list[SecretFinding] = []
    seen: set[str] = set()
    for line in patch.splitlines():
        if line.startswith("commit:"):
            current_commit = line.removeprefix("commit:").strip()
            continue
        if line.startswith("+++ "):
            candidate = line.removeprefix("+++ ").strip()
            if candidate != "/dev/null":
                current_path = candidate.removeprefix("b/")
            continue
        if match := HUNK_HEADER.match(line):
            old_line, new_line = int(match.group(1)), int(match.group(2))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            content, source_line = line[1:], new_line
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            content, source_line = line[1:], old_line
            old_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1
            continue
        else:
            continue
        location = f"git-history/{current_commit}/{current_path}"
        for finding in scan_text(
            content,
            location,
            entropy_threshold,
            fingerprint_scope=f"git-history/{current_path}",
            allowlist=allowlist,
        ):
            if finding.fingerprint in seen:
                continue
            seen.add(finding.fingerprint)
            findings.append(
                SecretFinding(
                    finding.rule,
                    finding.path,
                    source_line,
                    finding.masked,
                    finding.fingerprint,
                )
            )
    return findings


def _validate_scan_limits(max_file_bytes: int, max_files: int) -> None:
    if not 1 <= max_file_bytes <= 100_000_000:
        raise ValueError("max_file_bytes must be between 1 and 100000000")
    if not 1 <= max_files <= 100_000:
        raise ValueError("max_files must be between 1 and 100000")


def _collect_candidates(
    paths: list[Path],
    max_files: int,
    excluded_paths: set[Path],
    policy: ExecutionPolicy,
    cancellation: Cancellation,
    deadline: float,
) -> tuple[list[tuple[Path, bool]], list[SkippedFile]]:
    candidates: list[tuple[Path, bool]] = []
    ignored: list[SkippedFile] = []
    seen: set[Path] = set()

    def check_limits() -> None:
        policy.check_cancellation(cancellation)
        if time.monotonic() >= deadline:
            raise ScanLimitError("Hermes scan deadline exceeded during path enumeration")
        if len(candidates) + len(ignored) > max_files:
            raise ScanLimitError(f"scan traversal exceeds the {max_files} entry limit")

    def add_candidate(file: Path, explicit: bool) -> None:
        resolved = file.resolve()
        if resolved in excluded_paths:
            if explicit:
                raise ValueError(f"scan input conflicts with an output or baseline path: {file}")
            ignored.append(SkippedFile(str(file), "output or baseline artifact"))
        elif resolved not in seen:
            seen.add(resolved)
            candidates.append((file, explicit))
        check_limits()

    for path in paths:
        check_limits()
        if path.is_symlink():
            raise ValueError(f"scan path must not be a symlink: {path}")
        if not path.exists():
            raise FileNotFoundError(f"scan path does not exist: {path}")
        if path.is_file():
            add_candidate(path, True)
        elif path.is_dir():

            def raise_walk_error(error: OSError) -> None:
                raise error

            for current, directory_names, file_names in os.walk(
                path, topdown=True, onerror=raise_walk_error, followlinks=False
            ):
                check_limits()
                current_path = Path(current)
                kept_directories: list[str] = []
                for name in sorted(directory_names):
                    child = current_path / name
                    if name == ".git":
                        ignored.append(SkippedFile(str(child), "git metadata (use --history)"))
                    elif child.is_symlink():
                        ignored.append(SkippedFile(str(child), "symlink directory"))
                    else:
                        kept_directories.append(name)
                    check_limits()
                directory_names[:] = kept_directories
                for name in sorted(file_names):
                    file = current_path / name
                    if file.is_symlink():
                        ignored.append(SkippedFile(str(file), "symlink file"))
                        check_limits()
                        continue
                    if not file.is_file():
                        ignored.append(SkippedFile(str(file), "non-regular file"))
                        check_limits()
                        continue
                    add_candidate(file, False)
        else:
            raise ValueError(f"scan path must be a regular file or directory: {path}")
    return candidates, ignored


def scan_paths_bounded(
    paths: list[Path],
    *,
    entropy_threshold: float = 4.5,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    excluded_paths: tuple[Path, ...] = (),
    policy: ExecutionPolicy,
    cancellation: Cancellation | None = None,
    allowlist: Allowlist | None = None,
) -> PathScanResult:
    """Scan regular UTF-8 text files within a shared deadline and resource bounds."""
    if not paths:
        raise ValueError("at least one scan path is required")
    threshold = _validate_entropy_threshold(entropy_threshold)
    _validate_scan_limits(max_file_bytes, max_files)
    token = cancellation or NeverCancelled()
    deadline = time.monotonic() + policy.deadline_seconds
    excluded = {path.resolve() for path in excluded_paths}
    candidates, ignored = _collect_candidates(paths, max_files, excluded, policy, token, deadline)
    findings: list[SecretFinding] = []
    partial_errors: list[SkippedFile] = []
    scanned_files = 0
    for file, explicit in candidates:
        policy.check_cancellation(token)
        if time.monotonic() >= deadline:
            raise ScanLimitError("Hermes scan deadline exceeded")
        try:
            descriptor = os.open(file, os.O_RDONLY | _NOFOLLOW)
            with os.fdopen(descriptor, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if not stat_module.S_ISREG(metadata.st_mode):
                    raise OSError("path changed to a non-regular file")
                if metadata.st_size > max_file_bytes:
                    message = f"file exceeds the {max_file_bytes} byte limit"
                    if explicit:
                        raise ScanLimitError(f"{file}: {message}")
                    partial_errors.append(SkippedFile(str(file), message))
                    continue
                content = handle.read(max_file_bytes + 1)
        except ScanLimitError:
            raise
        except OSError as exc:
            partial_errors.append(SkippedFile(str(file), f"read failed: {exc}"))
            continue
        if len(content) > max_file_bytes:
            message = f"file grew beyond the {max_file_bytes} byte limit"
            if explicit:
                raise ScanLimitError(f"{file}: {message}")
            partial_errors.append(SkippedFile(str(file), message))
            continue
        if b"\x00" in content:
            ignored.append(SkippedFile(str(file), "binary content"))
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            ignored.append(SkippedFile(str(file), "non-UTF-8 content"))
            continue
        findings.extend(scan_text(text, str(file), threshold, allowlist=allowlist))
        scanned_files += 1
    return PathScanResult(tuple(findings), scanned_files, tuple(ignored), tuple(partial_errors))


def scan_path(path: Path, entropy_threshold: float = 4.5) -> list[SecretFinding]:
    """Compatibility wrapper for one bounded path; partial reads fail explicitly."""
    result = scan_paths_bounded(
        [path],
        entropy_threshold=entropy_threshold,
        policy=ExecutionPolicy(timeout_seconds=30.0, deadline_seconds=600.0),
    )
    if result.partial_errors:
        details = "; ".join(f"{item.path}: {item.reason}" for item in result.partial_errors)
        raise ScanLimitError(f"partial path scan: {details}")
    return list(result.findings)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1.0)
    if process.poll() is None:
        process.kill()
        process.wait(timeout=1.0)


def _read_pipe(
    pipe: BinaryIO,
    output: bytearray,
    limit: int,
    exceeded: threading.Event,
) -> None:
    while chunk := pipe.read(65_536):
        remaining = limit - len(output)
        if len(chunk) > remaining:
            output.extend(chunk[: max(remaining, 0)])
            exceeded.set()
            return
        output.extend(chunk)


def scan_git_history(
    repository: Path,
    entropy_threshold: float = 4.5,
    *,
    policy: ExecutionPolicy,
    cancellation: Cancellation | None = None,
    max_history_bytes: int = DEFAULT_MAX_HISTORY_BYTES,
    max_commits: int = DEFAULT_MAX_COMMITS,
    allowlist: Allowlist | None = None,
) -> list[SecretFinding]:
    """Scan a bounded Git patch stream without checkout, textconv, pager, or shell."""
    threshold = _validate_entropy_threshold(entropy_threshold)
    if repository.is_symlink() or not repository.is_dir():
        raise ValueError(f"history path must be a regular non-symlink directory: {repository}")
    if not 1 <= max_history_bytes <= 100_000_000:
        raise ValueError("max_history_bytes must be between 1 and 100000000")
    if not 1 <= max_commits <= 100_000:
        raise ValueError("max_commits must be between 1 and 100000")
    git = shutil.which("git")
    if git is None:
        raise OSError("git executable not found")
    command = [
        git,
        "-c",
        "core.pager=cat",
        "--no-pager",
        "log",
        f"--max-count={max_commits}",
        "--all",
        "--reverse",
        "--format=commit:%H",
        "-p",
        "--no-ext-diff",
        "--no-textconv",
    ]
    environment = dict(os.environ)
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0"})
    token = cancellation or NeverCancelled()
    policy.check_cancellation(token)
    process = subprocess.Popen(  # noqa: S603 - executable/arguments are controlled
        command,
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_pipe, stderr_pipe = process.stdout, process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_process(process)
        raise RuntimeError("Git process pipes were not created")
    stdout = bytearray()
    stderr = bytearray()
    stdout_exceeded = threading.Event()
    stderr_exceeded = threading.Event()
    readers = [
        threading.Thread(
            target=_read_pipe,
            args=(stdout_pipe, stdout, max_history_bytes, stdout_exceeded),
            daemon=True,
        ),
        threading.Thread(
            target=_read_pipe,
            args=(stderr_pipe, stderr, 65_536, stderr_exceeded),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + min(policy.timeout_seconds, policy.deadline_seconds)
    try:
        while process.poll() is None:
            policy.check_cancellation(token)
            if stdout_exceeded.is_set():
                raise ScanLimitError(f"Git history exceeds the {max_history_bytes} byte limit")
            if stderr_exceeded.is_set():
                raise ScanLimitError("Git stderr exceeds the 65536 byte limit")
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, policy.timeout_seconds)
            time.sleep(0.02)
    except BaseException:
        _terminate_process(process)
        raise
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
    policy.check_cancellation(token)
    if stdout_exceeded.is_set():
        raise ScanLimitError(f"Git history exceeds the {max_history_bytes} byte limit")
    if stderr_exceeded.is_set():
        raise ScanLimitError("Git stderr exceeds the 65536 byte limit")
    if process.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise subprocess.CalledProcessError(process.returncode, command, stderr=message)
    return _scan_git_patch(stdout.decode("utf-8", errors="replace"), threshold, allowlist)


def load_baseline(path: Path) -> set[str]:
    """Load a strict versioned baseline, migrating the previous bare array."""
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        raw = {
            "schema_name": BASELINE_SCHEMA_NAME,
            "schema_version": BASELINE_SCHEMA_VERSION,
            "fingerprints": raw,
        }
    document = validate_contract_header(raw, schema_name=BASELINE_SCHEMA_NAME)
    if set(document) != {"schema_name", "schema_version", "fingerprints"}:
        raise ValueError(
            "baseline must define exactly schema_name, schema_version and fingerprints"
        )
    fingerprints = document["fingerprints"]
    if not isinstance(fingerprints, list) or len(fingerprints) > 100_000:
        raise ValueError("baseline fingerprints must be an array of at most 100000 entries")
    if not all(isinstance(item, str) and FINGERPRINT.fullmatch(item) for item in fingerprints):
        raise ValueError("baseline fingerprints must be lowercase SHA-256 strings")
    return set(fingerprints)


def apply_baseline(findings: list[SecretFinding], baseline: set[str]) -> list[SecretFinding]:
    """Drop findings whose fingerprint is in the accepted baseline."""
    return [finding for finding in findings if finding.fingerprint not in baseline]


def _validate_pattern_list(raw: object, field: str) -> list[str]:
    if not isinstance(raw, list) or len(raw) > _MAX_ALLOWLIST_PATTERNS:
        raise ValueError(
            f"allowlist {field} must be an array of at most {_MAX_ALLOWLIST_PATTERNS} entries"
        )
    for item in raw:
        if not isinstance(item, str) or not item or len(item) > _MAX_ALLOWLIST_PATTERN_LEN:
            raise ValueError(
                f"allowlist {field} entries must be non-empty strings under 1000 chars"
            )
    return list(raw)


def load_allowlist(path: Path) -> Allowlist:
    """Load a strict, versioned allowlist of path globs and value regexes.

    The document must define exactly ``schema_name``, ``schema_version``,
    ``path_patterns`` and ``value_patterns``; each list may be empty. Value
    patterns are compiled here so a bad regex fails loudly at load, not silently
    at scan time.
    """
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    document = validate_contract_header(raw, schema_name=ALLOWLIST_SCHEMA_NAME)
    if set(document) != {"schema_name", "schema_version", "path_patterns", "value_patterns"}:
        raise ValueError(
            "allowlist must define exactly schema_name, schema_version, path_patterns "
            "and value_patterns"
        )
    path_patterns = _validate_pattern_list(document["path_patterns"], "path_patterns")
    value_sources = _validate_pattern_list(document["value_patterns"], "value_patterns")
    compiled: list[re.Pattern[str]] = []
    for source in value_sources:
        try:
            compiled.append(re.compile(source))
        except re.error as exc:
            raise ValueError(
                f"allowlist value_pattern {source!r} is not a valid regex: {exc}"
            ) from exc
    return Allowlist(path_patterns=tuple(path_patterns), value_patterns=tuple(compiled))


def write_baseline(findings: list[SecretFinding], path: Path) -> None:
    """Atomically write a private, versioned fingerprint baseline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_name": BASELINE_SCHEMA_NAME,
        "schema_version": BASELINE_SCHEMA_VERSION,
        "fingerprints": sorted({finding.fingerprint for finding in findings}),
    }
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise

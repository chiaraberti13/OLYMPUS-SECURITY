"""Application boundary for bounded Hermes secret scans."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.hermes.scanner import (
    DEFAULT_MAX_COMMITS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_HISTORY_BYTES,
    Allowlist,
    SecretFinding,
    SkippedFile,
    apply_baseline,
    load_allowlist,
    load_baseline,
    scan_git_history,
    scan_paths_bounded,
)


class HistoryScanner(Protocol):
    """Injected port for bounded repository-history scanning."""

    def __call__(
        self,
        repository: Path,
        entropy_threshold: float,
        *,
        policy: ExecutionPolicy,
        cancellation: Cancellation | None,
        max_history_bytes: int,
        max_commits: int,
        allowlist: Allowlist | None,
    ) -> list[SecretFinding]: ...


@dataclass(frozen=True)
class SecretScanRequest:
    paths: tuple[Path, ...]
    entropy_threshold: float = 4.5
    history: bool = False
    baseline_path: Path | None = None
    allowlist_path: Path | None = None
    timeout_seconds: float = 30.0
    deadline_seconds: float = 600.0
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_history_bytes: int = DEFAULT_MAX_HISTORY_BYTES
    max_commits: int = DEFAULT_MAX_COMMITS
    excluded_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class SecretScanOutcome:
    findings: tuple[SecretFinding, ...]
    scanned_files: int
    ignored_files: tuple[SkippedFile, ...]
    partial_errors: tuple[SkippedFile, ...]
    history_scanned: bool


@dataclass(frozen=True)
class SecretScanService:
    """Validate limits, scan working files/history, and apply one baseline."""

    cancellation: Cancellation = field(default_factory=NeverCancelled)
    history_scanner: HistoryScanner = scan_git_history

    def run(self, request: SecretScanRequest) -> SecretScanOutcome:
        if request.history and (
            len(request.paths) != 1
            or request.paths[0].is_symlink()
            or not request.paths[0].is_dir()
        ):
            raise ValueError(
                "--history requires exactly one regular non-symlink repository directory"
            )
        policy = ExecutionPolicy(
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.deadline_seconds,
        )
        baseline = (
            load_baseline(request.baseline_path) if request.baseline_path is not None else None
        )
        allowlist = (
            load_allowlist(request.allowlist_path)
            if request.allowlist_path is not None
            else None
        )
        started = time.monotonic()
        file_result = scan_paths_bounded(
            list(request.paths),
            entropy_threshold=request.entropy_threshold,
            max_file_bytes=request.max_file_bytes,
            max_files=request.max_files,
            excluded_paths=request.excluded_paths,
            policy=policy,
            cancellation=self.cancellation,
            allowlist=allowlist,
        )
        findings = list(file_result.findings)
        if request.history:
            remaining = request.deadline_seconds - (time.monotonic() - started)
            if remaining < 0.05:
                raise TimeoutError("Hermes overall deadline exceeded before Git history")
            history_policy = replace(
                policy,
                timeout_seconds=min(policy.timeout_seconds, remaining),
                deadline_seconds=min(policy.deadline_seconds, remaining),
            )
            findings.extend(
                self.history_scanner(
                    request.paths[0],
                    request.entropy_threshold,
                    policy=history_policy,
                    cancellation=self.cancellation,
                    max_history_bytes=request.max_history_bytes,
                    max_commits=request.max_commits,
                    allowlist=allowlist,
                )
            )
        if baseline is not None:
            findings = apply_baseline(findings, baseline)
        return SecretScanOutcome(
            findings=tuple(findings),
            scanned_files=file_result.scanned_files,
            ignored_files=file_result.ignored_files,
            partial_errors=file_result.partial_errors,
            history_scanned=request.history,
        )

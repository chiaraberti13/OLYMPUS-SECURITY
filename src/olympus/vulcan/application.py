"""Application services for bounded Vulcan aggregation and reporting."""

from __future__ import annotations

import json
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from olympus.core.enums import Severity
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Finding, SecurityReport
from olympus.vulcan.aggregate import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_ITEMS_PER_FILE,
    DEFAULT_MAX_TOTAL_ITEMS,
    AggregationError,
    dedupe_alerts,
    dedupe_assets,
    dedupe_findings,
    filter_min_severity,
    load_alerts,
    load_assets,
    load_findings,
    rank_findings,
)
from olympus.vulcan.report import build_report_model, render_report_html, render_report_markdown

DEFAULT_MAX_OUTPUT_BYTES = 100_000_000
DEFAULT_MAX_TOTAL_INPUT_BYTES = 200_000_000


@dataclass(frozen=True)
class VulcanReportRequest:
    engagement: str
    asset_paths: tuple[Path, ...] = ()
    finding_paths: tuple[Path, ...] = ()
    alert_paths: tuple[Path, ...] = ()
    excluded_paths: tuple[Path, ...] = ()
    min_severity: Severity | None = None
    render_markdown: bool = False
    render_html: bool = False
    max_files: int = DEFAULT_MAX_FILES
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_total_input_bytes: int = DEFAULT_MAX_TOTAL_INPUT_BYTES
    max_items_per_file: int = DEFAULT_MAX_ITEMS_PER_FILE
    max_total_items: int = DEFAULT_MAX_TOTAL_ITEMS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    deadline_seconds: float = 120.0


@dataclass(frozen=True)
class VulcanRankRequest:
    finding_paths: tuple[Path, ...]
    max_files: int = DEFAULT_MAX_FILES
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES
    max_total_input_bytes: int = DEFAULT_MAX_TOTAL_INPUT_BYTES
    max_items_per_file: int = DEFAULT_MAX_ITEMS_PER_FILE
    max_total_items: int = DEFAULT_MAX_TOTAL_ITEMS
    deadline_seconds: float = 60.0


@dataclass(frozen=True)
class VulcanReportOutcome:
    report: SecurityReport
    markdown: str | None
    html: str | None


@dataclass(frozen=True)
class VulcanApplicationService:
    """Load producer contracts once and build every report view consistently."""

    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def report(self, request: VulcanReportRequest) -> VulcanReportOutcome:
        engagement = _single_line(request.engagement, "engagement", 500)
        all_inputs = request.asset_paths + request.finding_paths + request.alert_paths
        _validate_limits(request)
        _validate_input_set(all_inputs, request.max_files, request.max_total_input_bytes)
        _validate_output_conflicts(all_inputs, request.excluded_paths)
        _validate_output_limit(request.max_output_bytes)
        progress = self._progress(request.deadline_seconds, "Vulcan report")
        assets = dedupe_assets(
            load_assets(
                request.asset_paths,
                max_files=request.max_files,
                max_bytes=request.max_input_bytes,
                max_items_per_file=request.max_items_per_file,
                max_total_items=request.max_total_items,
                progress_check=progress,
            )
        )
        findings = dedupe_findings(
            load_findings(
                request.finding_paths,
                max_files=request.max_files,
                max_bytes=request.max_input_bytes,
                max_items_per_file=request.max_items_per_file,
                max_total_items=request.max_total_items,
                progress_check=progress,
            )
        )
        alerts = dedupe_alerts(
            load_alerts(
                request.alert_paths,
                max_files=request.max_files,
                max_bytes=request.max_input_bytes,
                max_items_per_file=request.max_items_per_file,
                max_total_items=request.max_total_items,
                progress_check=progress,
            )
        )
        if len(assets) + len(findings) + len(alerts) > request.max_total_items:
            raise AggregationError(
                f"aggregate exceeds the {request.max_total_items} total item limit"
            )
        if request.min_severity is not None:
            findings = filter_min_severity(findings, request.min_severity)
        if assets:
            known_assets = {asset.asset_id for asset in assets}
            missing = sorted({finding.asset_id for finding in findings} - known_assets)
            if missing:
                sample = ", ".join(missing[:5])
                raise AggregationError(f"findings reference unknown report assets: {sample}")
        progress()
        report = build_report_model(engagement, assets, findings, alerts)
        json_content = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
        _ensure_output_size(json_content.encode(), request.max_output_bytes, "JSON")
        markdown = render_report_markdown(report) if request.render_markdown else None
        if markdown is not None:
            _ensure_output_size(markdown.encode(), request.max_output_bytes, "Markdown")
        progress()
        html = render_report_html(report) if request.render_html else None
        if html is not None:
            _ensure_output_size(html.encode(), request.max_output_bytes, "HTML")
        progress()
        return VulcanReportOutcome(report, markdown, html)

    def rank(self, request: VulcanRankRequest) -> tuple[Finding, ...]:
        if not 1 <= request.max_files <= 1_000:
            raise AggregationError("max_files must be between 1 and 1000")
        if not 1 <= request.max_input_bytes <= 1_000_000_000:
            raise AggregationError("max_input_bytes must be between 1 and 1000000000")
        if not 1 <= request.max_total_input_bytes <= 1_000_000_000:
            raise AggregationError("max_total_input_bytes must be between 1 and 1000000000")
        if not 1 <= request.max_items_per_file <= 1_000_000:
            raise AggregationError("max_items_per_file must be between 1 and 1000000")
        if not 1 <= request.max_total_items <= 1_000_000:
            raise AggregationError("max_total_items must be between 1 and 1000000")
        _validate_input_set(request.finding_paths, request.max_files, request.max_total_input_bytes)
        progress = self._progress(request.deadline_seconds, "Vulcan rank")
        findings = load_findings(
            request.finding_paths,
            max_files=request.max_files,
            max_bytes=request.max_input_bytes,
            max_items_per_file=request.max_items_per_file,
            max_total_items=request.max_total_items,
            progress_check=progress,
        )
        progress()
        return tuple(rank_findings(dedupe_findings(findings)))

    def _progress(self, deadline_seconds: float, operation: str) -> Callable[[], None]:
        policy = ExecutionPolicy(deadline_seconds=deadline_seconds)
        deadline = time.monotonic() + policy.deadline_seconds

        def check() -> None:
            policy.check_cancellation(self.cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{operation} deadline exceeded")

        return check


def _single_line(value: str, label: str, maximum: int) -> str:
    if not 1 <= len(value) <= maximum:
        raise AggregationError(f"{label} must contain between 1 and {maximum} characters")
    if value != value.strip() or any(character in value for character in "\r\n\x00"):
        raise AggregationError(f"{label} must be trimmed single-line text without NUL")
    return value


def _validate_output_conflicts(inputs: tuple[Path, ...], outputs: tuple[Path, ...]) -> None:
    resolved_inputs = {path.resolve() for path in inputs}
    resolved_outputs = [path.resolve() for path in outputs]
    if len(resolved_outputs) != len(set(resolved_outputs)):
        raise AggregationError("JSON, Markdown and HTML output paths must be distinct")
    if resolved_inputs.intersection(resolved_outputs):
        raise AggregationError("report output paths must not overwrite input files")


def _validate_output_limit(max_output_bytes: int) -> None:
    if not 1 <= max_output_bytes <= 1_000_000_000:
        raise AggregationError("max_output_bytes must be between 1 and 1000000000")


def _validate_limits(request: VulcanReportRequest) -> None:
    if not 1 <= request.max_files <= 1_000:
        raise AggregationError("max_files must be between 1 and 1000")
    if not 1 <= request.max_input_bytes <= 1_000_000_000:
        raise AggregationError("max_input_bytes must be between 1 and 1000000000")
    if not 1 <= request.max_total_input_bytes <= 1_000_000_000:
        raise AggregationError("max_total_input_bytes must be between 1 and 1000000000")
    if not 1 <= request.max_items_per_file <= 1_000_000:
        raise AggregationError("max_items_per_file must be between 1 and 1000000")
    if not 1 <= request.max_total_items <= 1_000_000:
        raise AggregationError("max_total_items must be between 1 and 1000000")


def _validate_input_set(inputs: tuple[Path, ...], max_files: int, max_total_bytes: int) -> None:
    if len(inputs) > max_files:
        raise AggregationError(f"input set exceeds the {max_files} file limit")
    total = 0
    for path in inputs:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise AggregationError(f"input file not found: {path}") from exc
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise AggregationError(f"aggregation input must be a non-symlink regular file: {path}")
        total += metadata.st_size
        if total > max_total_bytes:
            raise AggregationError(f"input set exceeds the {max_total_bytes} aggregate byte limit")


def _ensure_output_size(content: bytes, maximum: int, label: str) -> None:
    if len(content) > maximum:
        raise AggregationError(f"{label} report exceeds the {maximum} byte output limit")

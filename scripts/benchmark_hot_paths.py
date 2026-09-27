#!/usr/bin/env python3
"""Repeatable, offline microbenchmarks for Olympus hot paths.

The harness is diagnostic by default. Use ``--enforce`` to compare the worst
observed sample with the generous reference budgets in ``docs/performance.md``.
All generated inputs are deterministic and stay in a temporary directory.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Keep this developer script runnable directly from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from olympus.aegis.jobs import AegisJobStore
from olympus.apollo.ingest import iter_access_log
from olympus.core.enums import AssetType, Criticality, Severity, Source
from olympus.core.models import Asset, Event, Finding
from olympus.vulcan.aggregate import dedupe_findings
from olympus.vulcan.report import build_report_model, render_report_html

PROFILES = {
    "quick": {"records": 1_000, "jobs": 50, "repeats": 3},
    "standard": {"records": 10_000, "jobs": 250, "repeats": 5},
}

# Seconds and peak traced Python allocations at the `quick` profile size.
# The budgets are guardrails for gross regressions, not machine-specific SLOs.
BUDGETS = {
    "access_log_ingest": {"wall_seconds": 5.0, "cpu_seconds": 4.5, "peak_mib": 128.0},
    "finding_deduplication": {"wall_seconds": 2.5, "cpu_seconds": 2.3, "peak_mib": 64.0},
    "large_report_render": {"wall_seconds": 5.0, "cpu_seconds": 4.5, "peak_mib": 128.0},
    "aegis_queue_lifecycle": {"wall_seconds": 15.0, "cpu_seconds": 12.0, "peak_mib": 128.0},
}

FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _access_log(records: int) -> str:
    return "".join(
        f"192.0.2.{index % 250 + 1} - - [01/Jan/2026:00:00:{index % 60:02d} +0000] "
        f'"GET /items/{index}?page=1 HTTP/1.1" 200 512 "-" "OlympusBenchmark/1.0"\n'
        for index in range(records)
    )


def _findings(unique: int) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            finding_id=f"FND-BENCH-{index:08d}",
            asset_id=f"AST-BENCH-{index % 200:06d}",
            source=Source.AEGIS,
            title=f"Synthetic benchmark finding {index:08d}",
            description="Deterministic synthetic record used only for a local benchmark.",
            severity=(Severity.HIGH, Severity.MEDIUM, Severity.LOW)[index % 3],
            first_seen=FIXED_TIME,
            last_seen=FIXED_TIME,
        )
        for index in range(unique)
    )


def _measure(
    operation: Callable[[], int], *, repeats: int, warmups: int = 1
) -> dict[str, float | int]:
    for _ in range(warmups):
        operation()
    wall: list[float] = []
    cpu: list[float] = []
    peak_bytes = 0
    output_count = 0
    for _ in range(repeats):
        tracemalloc.start()
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        output_count = operation()
        cpu.append(time.process_time() - cpu_start)
        wall.append(time.perf_counter() - wall_start)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_bytes = max(peak_bytes, peak)
    return {
        "median_wall_seconds": round(statistics.median(wall), 6),
        "worst_wall_seconds": round(max(wall), 6),
        "median_cpu_seconds": round(statistics.median(cpu), 6),
        "worst_cpu_seconds": round(max(cpu), 6),
        "peak_mib": round(peak_bytes / (1024 * 1024), 3),
        "output_count": output_count,
        "samples": repeats,
    }


def _queue_lifecycle(jobs: int, root: Path) -> int:
    db_path = root / "aegis-jobs.sqlite3"
    scope_path = root / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "schema_name": "olympus.aegis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    store = AegisJobStore(db_path, backoff_seconds=0.0)
    store.initialize()
    for index in range(jobs):
        store.submit(
            scanner="benchmark",
            target="127.0.0.1",
            target_kind="host",
            scope_path=scope_path,
            authorized=True,
            idempotency_key=f"benchmark-{index}",
        )
    claimed = 0
    while store.claim_next("benchmark-worker") is not None:
        claimed += 1
    if claimed != jobs:
        raise RuntimeError(f"AEGIS benchmark claimed {claimed} of {jobs} queued jobs")
    return claimed


def _scenario_operations(records: int, jobs: int) -> dict[str, tuple[int, Callable[[], int]]]:
    access_text = _access_log(records)
    access_lines = tuple(access_text.splitlines())
    unique_findings = _findings(records)
    duplicate_findings = unique_findings + unique_findings
    assets = [
        Asset(
            asset_id=f"AST-BENCH-{index:06d}",
            asset_type=AssetType.HOST,
            hostname=f"host-{index}.example.invalid",
            criticality=Criticality.MEDIUM,
            source=Source.AEGIS,
            first_seen=FIXED_TIME,
            last_seen=FIXED_TIME,
        )
        for index in range(min(200, records))
    ]
    report_findings = unique_findings[: min(1_000, records)]

    def ingest() -> int:
        parsed = iter_access_log(access_lines, max_lines=records)
        event_count = sum(isinstance(item, Event) for item in parsed)
        if event_count != records:
            raise RuntimeError("access-log benchmark fixture did not parse completely")
        return event_count

    def deduplicate() -> int:
        unique = dedupe_findings(duplicate_findings)
        if len(unique) != len(unique_findings):
            raise RuntimeError("finding deduplication returned an unexpected count")
        return len(unique)

    def render_report() -> int:
        report = build_report_model(
            "BENCHMARK-ENGAGEMENT",
            assets,
            report_findings,
            [],
            generated_at=FIXED_TIME,
        )
        rendered = render_report_html(report)
        if len(rendered) < 100:
            raise RuntimeError("report renderer returned an unexpectedly small document")
        return len(rendered.encode("utf-8"))

    def aegis_queue() -> int:
        with tempfile.TemporaryDirectory(prefix="olympus-bench-aegis-") as directory:
            return _queue_lifecycle(jobs, Path(directory))

    return {
        "access_log_ingest": (records, ingest),
        "finding_deduplication": (len(duplicate_findings), deduplicate),
        "large_report_render": (len(assets) + len(report_findings), render_report),
        "aegis_queue_lifecycle": (jobs, aegis_queue),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="quick")
    parser.add_argument("--enforce", action="store_true", help="Fail when reference budgets miss.")
    parser.add_argument(
        "--output", type=Path, help="Write JSON results to this path as well as stdout."
    )
    args = parser.parse_args()
    profile = PROFILES[args.profile]
    operations = _scenario_operations(profile["records"], profile["jobs"])
    results: dict[str, Any] = {}
    failed: list[str] = []

    for name, (items, operation) in operations.items():
        measurement = _measure(operation, repeats=profile["repeats"])
        budget = BUDGETS[name]
        measurement["input_items"] = items
        measurement["budget"] = budget
        measurement["budget_status"] = "not_enforced"
        if args.enforce:
            quick_counts = {
                "access_log_ingest": PROFILES["quick"]["records"],
                "finding_deduplication": PROFILES["quick"]["records"] * 2,
                "large_report_render": min(200, PROFILES["quick"]["records"])
                + min(1_000, PROFILES["quick"]["records"]),
                "aegis_queue_lifecycle": PROFILES["quick"]["jobs"],
            }
            scale = max(1.0, items / quick_counts[name])
            active_budget = {key: value * scale for key, value in budget.items()}
            passed = (
                float(measurement["worst_wall_seconds"]) <= active_budget["wall_seconds"]
                and float(measurement["worst_cpu_seconds"]) <= active_budget["cpu_seconds"]
                and float(measurement["peak_mib"]) <= active_budget["peak_mib"]
            )
            measurement["enforced_budget"] = active_budget
            measurement["budget_status"] = "pass" if passed else "fail"
            if not passed:
                failed.append(name)
        results[name] = measurement

    document = {
        "schema_name": "olympus.performance-benchmark",
        "schema_version": "1.0.0",
        "profile": args.profile,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "results": results,
    }
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    if failed:
        print("Performance budget exceeded: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

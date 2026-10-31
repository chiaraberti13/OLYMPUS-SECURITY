#!/usr/bin/env python3
"""Measure local SQLite job submission under competing worker processes.

The benchmark is fully offline: it uses synthetic submissions and a private
temporary database. It reports latency percentiles and error counts; it does not
start scanner processes or make a production capacity claim.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from olympus.themis.jobs import ThemisJobStore


def _submit_batch(database: str, scope_path: str, writer: int, jobs: int) -> dict[str, Any]:
    """Submit one writer's batch from a separate process and return timings."""
    store = ThemisJobStore(Path(database))
    durations: list[float] = []
    errors: dict[str, int] = {}
    for index in range(jobs):
        started = time.perf_counter()
        try:
            store.submit(
                scanner="benchmark",
                target="127.0.0.1",
                target_kind="host",
                scope_path=Path(scope_path),
                authorized=True,
                idempotency_key=f"bench:{writer}:{index}",
            )
        except Exception as exc:  # benchmark measures all failed writes, including lock errors
            name = type(exc).__name__
            errors[name] = errors.get(name, 0) + 1
        else:
            durations.append(time.perf_counter() - started)
    return {"writer": writer, "durations": durations, "errors": errors}


def _percentile(values: list[float], percentile: float) -> float:
    """Return the nearest-rank percentile for a non-empty sample."""
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((percentile * len(ordered) + 99) // 100) - 1))
    return ordered[index]


def run(processes: int, jobs_per_process: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="olympus-themis-load-") as directory:
        root = Path(directory)
        database = root / "jobs.sqlite3"
        scope_path = root / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "schema_name": "olympus.themis-scope",
                    "schema_version": "1.0.0",
                    "allowed_hosts": ["127.0.0.1"],
                    "allowed_cidrs": ["127.0.0.0/8"],
                }
            ),
            encoding="utf-8",
        )
        started = time.perf_counter()
        latencies: list[float] = []
        errors: dict[str, int] = {}
        with ProcessPoolExecutor(max_workers=processes) as pool:
            futures = [
                pool.submit(_submit_batch, str(database), str(scope_path), writer, jobs_per_process)
                for writer in range(processes)
            ]
            for future in as_completed(futures):
                result = future.result()
                latencies.extend(result["durations"])
                for name, count in result["errors"].items():
                    errors[name] = errors.get(name, 0) + count
        elapsed = time.perf_counter() - started
        total = processes * jobs_per_process
        counts = ThemisJobStore(database).counts_by_state()
        persisted = sum(counts.values())
        report: dict[str, Any] = {
            "schema_name": "olympus.themis-concurrency-benchmark",
            "schema_version": "1.0.0",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processes": processes,
            "jobs_per_process": jobs_per_process,
            "jobs_requested": total,
            "jobs_persisted": persisted,
            "elapsed_seconds": round(elapsed, 6),
            "throughput_per_second": round(persisted / elapsed, 3) if elapsed else 0.0,
            "submit_latency_seconds": {
                "samples": len(latencies),
                "median": round(statistics.median(latencies), 6) if latencies else None,
                "p95": round(_percentile(latencies, 95), 6) if latencies else None,
                "max": round(max(latencies), 6) if latencies else None,
            },
            "errors": errors,
            "state_counts": counts,
            "generated_at": datetime.now(UTC).isoformat(),
            "offline_synthetic_only": True,
        }
        if persisted != total - sum(errors.values()):
            raise RuntimeError("persisted row count does not match successful submissions")
        if errors:
            raise RuntimeError(json.dumps(report, sort_keys=True))
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processes", type=int, default=4)
    parser.add_argument("--jobs-per-process", type=int, default=50)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.processes <= 16 or not 1 <= args.jobs_per_process <= 2_000:
        parser.error("processes must be 1..16 and jobs-per-process must be 1..2000")
    report = run(args.processes, args.jobs_per_process)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

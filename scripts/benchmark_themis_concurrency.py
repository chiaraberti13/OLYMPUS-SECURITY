#!/usr/bin/env python3
"""Measure local SQLite job submission under competing worker processes.

The benchmark is fully offline: it uses synthetic submissions and a private
temporary database. It reports latency percentiles and error counts; it does not
start scanner processes or make a production capacity claim.

Diagnostics (``QA-4``). A bare aggregate like ``{"OperationalError": 7}`` cannot
tell SQLite write contention apart from any other failure, so every failed
submission is also recorded individually with its synthetic request id, the
writer process that sent it and — when the driver exposes them — the
``sqlite_errorcode`` and ``sqlite_errorname`` (e.g. ``5`` / ``SQLITE_BUSY`` for
lock contention). The aggregate count the CI already consumes is kept as well.

At the end the synthetic request ids that were *submitted* are reconciled
against the ids actually *present* in the database: any missing request (a write
that never landed) or duplicate request (a key stored more than once) is a
discrepancy. The benchmark fails on any discrepancy, and the JSON report is
produced even when it fails so the evidence is never lost.
"""

from __future__ import annotations

import argparse
import json
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from olympus.themis.jobs import ThemisJobStore


def _request_id(writer: int, index: int) -> str:
    """The synthetic idempotency key for one writer's nth submission."""
    return f"bench:{writer}:{index}"


def _failure_detail(request_id: str, writer: int, exc: BaseException) -> dict[str, Any]:
    """Describe one failed submission: which request, which writer, which error.

    ``sqlite_errorcode`` / ``sqlite_errorname`` are read from the exception when
    the SQLite driver set them (Python 3.11+), falling back to the chained cause
    so a wrapped lock error is still attributed to ``SQLITE_BUSY`` and not hidden
    behind a generic class name.
    """
    code = getattr(exc, "sqlite_errorcode", None)
    name = getattr(exc, "sqlite_errorname", None)
    cause = exc.__cause__
    if code is None and name is None and cause is not None:
        code = getattr(cause, "sqlite_errorcode", None)
        name = getattr(cause, "sqlite_errorname", None)
    return {
        "request_id": request_id,
        "writer": writer,
        "error_type": type(exc).__name__,
        "sqlite_errorcode": code,
        "sqlite_errorname": name,
    }


def _submit_batch(database: str, scope_path: str, writer: int, jobs: int) -> dict[str, Any]:
    """Submit one writer's batch from a separate process and return timings."""
    store = ThemisJobStore(Path(database))
    durations: list[float] = []
    errors: dict[str, int] = {}
    failures: list[dict[str, Any]] = []
    for index in range(jobs):
        request_id = _request_id(writer, index)
        started = time.perf_counter()
        try:
            store.submit(
                scanner="benchmark",
                target="127.0.0.1",
                target_kind="host",
                scope_path=Path(scope_path),
                authorized=True,
                idempotency_key=request_id,
            )
        except Exception as exc:  # benchmark measures all failed writes, including lock errors
            name = type(exc).__name__
            errors[name] = errors.get(name, 0) + 1
            failures.append(_failure_detail(request_id, writer, exc))
        else:
            durations.append(time.perf_counter() - started)
    return {"writer": writer, "durations": durations, "errors": errors, "failures": failures}


def _present_key_counts(database: Path) -> Counter[str]:
    """Count the synthetic request ids actually stored in the database."""
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT idempotency_key FROM themis_jobs WHERE idempotency_key IS NOT NULL"
        ).fetchall()
    finally:
        connection.close()
    return Counter(str(key) for (key,) in rows)


def _reconcile(submitted: set[str], present: Counter[str]) -> dict[str, Any]:
    """Compare the submitted request ids with those present in the database.

    ``missing`` are requests that were submitted but never landed; ``duplicate``
    are request ids stored more than once. Either is a discrepancy.
    """
    distinct_present = set(present)
    missing = sorted(submitted - distinct_present)
    duplicate = sorted(key for key, count in present.items() if count > 1)
    unexpected = sorted(distinct_present - submitted)
    return {
        "submitted": len(submitted),
        "present": sum(present.values()),
        "distinct_present": len(distinct_present),
        "missing_count": len(missing),
        "missing": missing,
        "duplicate_count": len(duplicate),
        "duplicate": [{"request_id": key, "count": present[key]} for key in duplicate],
        "unexpected_count": len(unexpected),
        "unexpected": unexpected,
    }


def _percentile(values: list[float], percentile: float) -> float:
    """Return the nearest-rank percentile for a non-empty sample."""
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((percentile * len(ordered) + 99) // 100) - 1))
    return ordered[index]


def run(processes: int, jobs_per_process: int, *, migrate_first: bool = False) -> dict[str, Any]:
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
        if migrate_first:
            # The deployed services start only after the migration job completes.
            ThemisJobStore(database).initialize()
        started = time.perf_counter()
        latencies: list[float] = []
        errors: dict[str, int] = {}
        failures: list[dict[str, Any]] = []
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
                failures.extend(result["failures"])
        elapsed = time.perf_counter() - started
        total = processes * jobs_per_process
        counts = ThemisJobStore(database).counts_by_state()
        persisted = sum(counts.values())

        submitted = {
            _request_id(writer, index)
            for writer in range(processes)
            for index in range(jobs_per_process)
        }
        reconciliation = _reconcile(submitted, _present_key_counts(database))
        failures.sort(key=lambda item: (item["writer"], item["request_id"]))

        discrepancy = (
            bool(errors)
            or reconciliation["missing_count"] > 0
            or reconciliation["duplicate_count"] > 0
            or reconciliation["unexpected_count"] > 0
            or persisted != reconciliation["present"]
        )

        report: dict[str, Any] = {
            "schema_name": "olympus.themis-concurrency-benchmark",
            "schema_version": "2.0.0",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "processes": processes,
            "jobs_per_process": jobs_per_process,
            "migrated_before_writers": migrate_first,
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
            "submission_failures": failures,
            "reconciliation": reconciliation,
            "state_counts": counts,
            "ok": not discrepancy,
            "generated_at": datetime.now(UTC).isoformat(),
            "offline_synthetic_only": True,
        }
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processes", type=int, default=4)
    parser.add_argument("--jobs-per-process", type=int, default=50)
    parser.add_argument(
        "--migrate-first",
        action="store_true",
        help="Prepare the database before measuring writes, as in the Compose deployment.",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.processes <= 16 or not 1 <= args.jobs_per_process <= 2_000:
        parser.error("processes must be 1..16 and jobs-per-process must be 1..2000")
    report = run(args.processes, args.jobs_per_process, migrate_first=args.migrate_first)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    # The report is always produced — written and printed — even on failure, so a
    # discrepancy leaves committed evidence instead of only a non-zero exit code.
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

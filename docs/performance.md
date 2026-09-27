# Olympus performance baselines

`scripts/benchmark_hot_paths.py` measures four deterministic, offline paths:

| Scenario | Workload (`quick`) | What is timed |
|---|---:|---|
| Access-log ingest | 1,000 records | Parse and normalize into `core.Event` models |
| Finding deduplication | 2,000 inputs / 1,000 unique | Exact-ID deduplication and conflict-safe lookup |
| Large report rendering | 200 assets + 1,000 findings | Build a canonical report and render escaped HTML |
| AEGIS queue lifecycle | 50 jobs | Initialize SQLite, submit with idempotency keys, claim the queue |

Inputs use fixed synthetic values and a fixed timestamp. No real target, external
service, scanner binary, credential or repository data is used. The AEGIS case
uses an isolated temporary database and loopback-only scope. Every scenario runs
once as warm-up followed by three measured samples in the quick profile; standard
uses ten times the record count (up to 10,000) and five times the queue job
volume (250 jobs), with five measured samples. Compare reports only across
the same profile and equivalent Python/OS environments.

Each sample records wall time, process CPU time and peak Python allocations via
`tracemalloc`. CPU time excludes other system processes; traced memory does not
include native allocator or child-process RSS. Results are diagnostic rather
than a substitute for production profiling.

## Initial budgets

The initial fail thresholds below apply to the quick profile. They are
intentionally broad regression guards rather than product SLOs. The `--enforce`
mode scales time and traced-memory limits linearly with each scenario's input
count for larger profiles.

| Scenario | Max wall | Max CPU | Max traced memory |
|---|---:|---:|---:|
| Access-log ingest | 5.0 s | 4.5 s | 128 MiB |
| Finding deduplication | 2.5 s | 2.3 s | 64 MiB |
| Large report rendering | 5.0 s | 4.5 s | 128 MiB |
| AEGIS queue lifecycle | 15.0 s | 12.0 s | 128 MiB |

Record machine, Python version, profile and commit alongside benchmark JSON.
Run the same host at least three times before changing a budget; revise a limit
only with an explained workload and measurements, not to hide a regression.
Budgets are not yet CI blockers because shared runners have variable performance.

## Run

```bash
make benchmark
make benchmark-standard
python scripts/benchmark_hot_paths.py --profile quick --enforce
python scripts/benchmark_hot_paths.py --profile standard --output benchmark.json
```

The quick result currently passes on Python 3.12/Linux. A baseline sample from
the implementation session measured approximately 0.22 s / 1.43 MiB for ingest,
0.003 s / 0.05 MiB for deduplication, 0.025 s / 1.37 MiB for report rendering,
and 0.48 s / 0.02 MiB for the 50-job lifecycle. These observations describe one
container run and are not portable SLO promises.

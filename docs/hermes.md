# Hermes bounded secret scanning

Hermes scans local regular UTF-8 text and, optionally, committed Git patches.
It is offline work, so it does not invent an authorization confirmation. It does
apply the shared execution policy for strict timeout/deadline validation and
cooperative cancellation.

## Coverage and limits

Defaults are deliberately finite:

| Resource | Default | Accepted maximum |
| --- | ---: | ---: |
| Regular file | 10,000,000 bytes | 100,000,000 bytes |
| Traversal entries | 10,000 | 100,000 |
| Git patch stream | 20,000,000 bytes | 100,000,000 bytes |
| Git commits | 1,000 | 100,000 |
| Git process timeout | 30 seconds | shared policy maximum |
| Overall deadline | 600 seconds | shared policy maximum |

Use `--max-file-bytes`, `--max-files`, `--max-history-bytes`,
`--max-commits`, `--timeout`, and `--deadline` to tighten these values.
Invalid limits fail rather than clamp.

An explicit input must exist and be a regular file or directory. Direct
symlinks and devices fail; directory symlinks are not traversed; `.git` is
excluded from working-tree scanning. Files are opened with `O_NOFOLLOW` where
the platform supports it. Existing SARIF/baseline outputs are excluded to avoid
feedback findings. Oversized/unreadable directory members produce a partial
exit (`2`) after writing available SARIF, never a false clean result.

## Git process boundary

`--history` requires exactly one non-symlink repository directory. Hermes invokes
the resolved Git executable as an argument array with no shell, stdin, pager,
external diff, or textconv. It limits commits and concurrently drains stdout/stderr
into capped buffers. Timeout, overall deadline, output overflow, cancellation and
non-zero Git exit all terminate or fail the operation explicitly.

Changed lines are mapped to `git-history/<commit>/<path>` locations. Repeated
appearances of the same secret in a file share one stable fingerprint, so add/remove
patches do not inflate results and line movement does not invalidate a baseline.

## Masking, SARIF and baselines

Reports contain only the first/last four characters of a candidate plus a one-way
fingerprint; the complete value is never serialized. SARIF 2.1.0 is written through
a unique, fsynced, atomic temporary file.

New baselines use `olympus.hermes-baseline` version `1.0.0`, validate exact fields
and lowercase SHA-256 fingerprints, and are written atomically with mode `0600` on
POSIX systems. The previous bare fingerprint array has one explicit read migration.

```bash
olympus hermes scan src --output hermes.sarif
olympus hermes scan . --history --max-commits 500 --output history.sarif
olympus hermes scan src --write-baseline accepted.json --output first.sarif
olympus hermes scan src --baseline accepted.json --output current.sarif
```

Exit `0` means all supported inputs were scanned with no unsuppressed finding,
`1` means findings are present, `2` means invalid input, `5` means that only part
of the requested input was scanned, and `7` means cancellation. A partial scan
never reports as a clean or generic usage result.

# Retention and secure deletion

Olympus accumulates the most sensitive material in an engagement: scanner
output, evidence exports, job records naming targets, and audit trails naming
identities. `olympus.core.retention` bounds how long that is kept and removes it
in a way that does not simply leave the plaintext on disk.

Implemented in `src/olympus/core/retention.py` and `ThemisJobStore.prune`;
operated with `olympus themis retention …` and `olympus themis jobs prune`; tested
in `tests/unit/test_core_retention.py` and `tests/unit/test_themis_jobs.py`.

## What "secure deletion" here does and does not promise

`secure_delete` overwrites a file's current contents with random bytes,
truncates it, fsyncs, and unlinks it. That removes the plaintext from the blocks
the file occupies, which defeats undelete-style recovery and casual inspection
of free space.

It is **not** a guarantee of erasure. A copy-on-write or journalling filesystem
(Btrfs, ZFS, APFS, ext4 with data journalling), a snapshot, an SSD's
wear-levelling layer, or a backup may keep an older copy that no userspace write
can reach. **The dependable control for data at rest is full-disk or filesystem
encryption**; this is defence in depth on top of it, not a replacement.

Two safety rules are enforced: a symlink is never followed (deleting through one
would let an attacker aim the overwrite at any file the server can write), and
anything that is not a regular file is refused. Files larger than 512 MiB are
truncated rather than fully overwritten — writing tens of gigabytes to delete one
artefact is its own kind of outage.

## Artefact retention

A policy bounds **age**, **count**, **total size**, or any combination; the
oldest files go first. Only regular files directly inside the directory are
considered — subdirectories and symlinks are left alone rather than followed.

```bash
# Keep 30 days of exported results, at most 500 files, at most 2 GiB.
olympus themis retention prune ./evidence \
  --pattern '*.json' --older-than-days 30 --max-files 500 --max-bytes 2147483648

olympus themis retention prune ./evidence --older-than-days 30 --dry-run
```

`--dry-run` reports exactly what would be removed and deletes nothing. A policy
that bounds nothing is refused rather than treated as "keep everything" or
"delete everything".

## Log rotation

An append-only audit log must not be rewritten in place, so it is **rolled**
rather than truncated: the live file becomes `.1`, each generation shifts up,
and anything past `--keep` is securely deleted.

```bash
olympus themis retention rotate-log ~/.local/state/olympus/audit/themis-audit.ndjson \
  --max-bytes 50000000 --keep 5
```

Below the size budget nothing happens, so this is safe to run from cron or a
systemd timer. `--keep 0` removes the log outright instead of keeping history.

## Job retention

```bash
olympus themis jobs prune --older-than-days 30 [--dry-run]
```

Only **terminal** jobs are pruned. Queued and running work is never removed from
under a worker, however old it is — a partition test pins that every job state
is classified as either active or terminal, so a new state cannot quietly fall
outside retention.

The store runs with `PRAGMA secure_delete = ON`, so deleted rows are zeroed
rather than left in free pages; pruning then VACUUMs the database and truncates
the write-ahead log, which would otherwise keep the pre-deletion page images
readable in the `-wal` file.

## Operating advice

- Run retention on a timer, not by hand: a policy that is only applied when
  someone remembers is not a policy.
- Point `--older-than-days` at whatever the engagement's contract requires, and
  keep the exported evidence an engagement actually delivers outside the pruned
  directory.
- Retention is not a substitute for encryption at rest, and neither is a
  substitute for not collecting what the engagement does not need.

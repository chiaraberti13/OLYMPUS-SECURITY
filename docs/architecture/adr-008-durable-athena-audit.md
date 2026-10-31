# ADR-008: Durable audit sequencing in Athena

- Status: Accepted, 2026-10-29
- Roadmap: SEC-E-01; residual work DEV-E-01
- Participants: architecture, data, AppSec and QA analysis in the repository audit;
  no consultation with external people is implied.

## Problem

The coordinator's per-assessment counter starts at zero in every process. The
SQLite audit sink previously persisted that counter with INSERT OR REPLACE.
A later CLI cancel/recover invocation could overwrite the original audit prefix.
The duplicate and restart regression tests fail on the original implementation.

## Alternatives and decision

1. INSERT alone prevents replacement but causes recovery to fail after a state
   transition, because the restarted coordinator still submits sequence zero.
2. Seeding an in-memory counter from MAX once avoids a sequential restart
   collision but races with other writers.
3. Allocate the persistent sequence in the repository for every append. Chosen:
   BEGIN IMMEDIATE obtains SQLite's writer lock, then MAX(sequence)+1 is read for
   that assessment and inserted with plain INSERT in the same transaction.

The sink passes sequence=None to request allocation. Explicit sequence callers
retain their values; duplicate keys raise sqlite3.IntegrityError without modifying
history. In-memory events keep producer-local counters. No schema or document
contract migration is required; existing rows and sequence gaps remain intact.

## Consequences and residual risk

Concurrent connections serialize allocation; SQLite's existing busy timeout
bounds contention. An insertion failure rolls back and releases the transaction.
The composite primary key supports the per-assessment maximum lookup. No process
networking, scanner behavior, scope policy or CLI output contract changes.

This protects appends through this API, not against a database administrator
rewriting files. State transitions and audit appends are still separate
transactions: crash consistency across both is DEV-E-01 and is not declared solved.
Already overwritten historical events cannot be reconstructed by this change.
Back up the database before upgrade; investigate older recovery/cancel histories
against independent logs where available, without fabricating missing evidence.

## Validation and reconsideration

Tests assert duplicate rejection, unchanged old rows, two independent concurrent
connections, per-assessment allocation, reopen + CLI recover/cancel, and repeated
terminal no-ops. Reconsider this decision for an atomic state/audit unit of work,
a remote persistence backend, or measured writer-lock contention exceeding the
published workload budget. These conditions do not justify Postgres preemptively.

## Nota operativa italiana

La sequenza persistente è assegnata da SQLite dentro una transazione esclusiva
tra scrittori: un riavvio non riutilizza la sequenza zero. I duplicati espliciti
sono rifiutati e lo storico resta invariato. Non serve una migrazione dello
schema; conservare un backup. La correzione non ricostruisce eventi già persi e
non rende atomica la coppia transizione di stato + evento audit (`DEV-E-01`).

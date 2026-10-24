from __future__ import annotations

import sqlite3
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from olympus.themis.concurrency import RequestConcurrencyGate


@pytest.mark.parametrize("invalid", (0, 4_097, True))
def test_gate_rejects_invalid_limits(tmp_path: Path, invalid: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 4096"):
        RequestConcurrencyGate(tmp_path / "jobs.sqlite3", invalid)


def test_independent_gate_instances_share_one_control_plane_limit(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    first = RequestConcurrencyGate(database, 1, token_factory=lambda: "first")
    second = RequestConcurrencyGate(database, 1, token_factory=lambda: "second")

    lease = first.try_acquire()
    assert lease is not None
    assert second.try_acquire() is None

    first.release(lease)
    next_lease = second.try_acquire()
    assert next_lease is not None
    second.release(next_lease)


def test_separate_interpreters_share_one_control_plane_limit(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    script = (
        "import sys; from pathlib import Path; "
        "from olympus.themis.concurrency import RequestConcurrencyGate; "
        "gate=RequestConcurrencyGate(Path(sys.argv[1]), 1); lease=gate.try_acquire(); "
        "assert lease is not None; print('ready', flush=True); "
        "sys.stdin.readline(); gate.release(lease)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(database)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None and process.stdin is not None
    try:
        assert process.stdout.readline().strip() == "ready"
        peer = RequestConcurrencyGate(database, 1)
        assert peer.try_acquire() is None
        process.stdin.write("release\n")
        process.stdin.flush()
        assert process.wait(timeout=10) == 0
        assert peer.try_acquire() is not None
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)


def test_expired_crash_lease_is_recovered_and_live_lease_can_be_renewed(
    tmp_path: Path,
) -> None:
    now = [1_000.0]
    tokens = iter(("abandoned", "replacement"))
    gate = RequestConcurrencyGate(
        tmp_path / "jobs.sqlite3",
        1,
        lease_seconds=3.0,
        clock=lambda: now[0],
        token_factory=lambda: next(tokens),
    )

    abandoned = gate.try_acquire()
    assert abandoned is not None
    now[0] += 2.0
    assert gate.renew(abandoned)
    now[0] += 2.0
    assert gate.try_acquire() is None
    now[0] += 2.0

    recovered = gate.try_acquire()
    assert recovered is not None and recovered != abandoned
    assert not gate.renew(abandoned)


def test_gate_refuses_limit_change_while_a_shared_lease_is_active(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    gate = RequestConcurrencyGate(database, 1)
    lease = gate.try_acquire()
    assert lease is not None

    with pytest.raises(ValueError, match="cannot change"):
        RequestConcurrencyGate(database, 2)

    gate.release(lease)
    changed = RequestConcurrencyGate(database, 2)
    assert changed.try_acquire() is not None


def test_gate_fails_closed_instead_of_waiting_for_a_locked_store(tmp_path: Path) -> None:
    gate = RequestConcurrencyGate(tmp_path / "jobs.sqlite3", 1)
    with sqlite3.connect(gate.path, isolation_level=None) as writer:
        writer.execute("BEGIN IMMEDIATE")
        assert gate.try_acquire() is None


def test_release_waits_for_a_temporary_store_lock(tmp_path: Path) -> None:
    gate = RequestConcurrencyGate(tmp_path / "jobs.sqlite3", 1)
    lease = gate.try_acquire()
    assert lease is not None

    with sqlite3.connect(gate.path, isolation_level=None) as writer:
        writer.execute("BEGIN IMMEDIATE")
        with ThreadPoolExecutor(max_workers=1) as pool:
            released = pool.submit(gate.release, lease)
            time.sleep(0.05)
            writer.commit()
            released.result(timeout=2)

    replacement = gate.try_acquire()
    assert replacement is not None
    gate.release(replacement)


@pytest.mark.posix_only
def test_gate_sidecar_is_private_and_rejects_symlinks(tmp_path: Path) -> None:
    database = tmp_path / "jobs.sqlite3"
    gate = RequestConcurrencyGate(database, 1)
    assert stat.S_IMODE(gate.path.stat().st_mode) == 0o600

    linked_database = tmp_path / "linked.sqlite3"
    linked_sidecar = linked_database.with_name(f"{linked_database.name}.requests")
    linked_sidecar.symlink_to(gate.path)
    with pytest.raises(ValueError, match="must not be a symlink"):
        RequestConcurrencyGate(linked_database, 1)

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container records' directory is checked and used through one descriptor.

A path checked as a directory of this user's and then used by path can be
swapped for a symlink in between, and the record write, the chmod or the sweep's
read and removal would go through it. The directory is therefore opened once
with ``O_NOFOLLOW``, checked with ``fstat``, tightened with ``fchmod``, and every
record is read, written and removed relative to that descriptor.

The runtime is a shell stub that logs its arguments and exits 0; no real
runtime or process is touched.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from automated_security_helper.interactions import container_leftovers

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="records use POSIX directory descriptors"
    ),
]


def _record(directory: Path, name: str, pid: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "kind": "container",
                "host": container_leftovers.host_key(),
                "name": name,
                "creator_pid": pid,
                "creator_start": None,
            }
        ),
        encoding="utf-8",
    )
    return path


def _swap_for_a_symlink(monkeypatch, real: Path, decoy: Path, moved: Path) -> None:
    """At the moment the directory has been opened and checked, put a symlink to
    ``decoy`` where ``real`` was, as an attacker racing a path-based check would."""

    def swap() -> None:
        real.rename(moved)
        real.symlink_to(decoy, target_is_directory=True)

    monkeypatch.setattr(container_leftovers, "_AFTER_STATE_DIR_OPENED", swap)


def test_a_symlink_swapped_in_after_the_check_is_never_written_through(
    tmp_path, monkeypatch
):
    real = tmp_path / "state"
    decoy = tmp_path / "decoy"
    moved = tmp_path / "state-moved"
    real.mkdir()
    decoy.mkdir()
    real.chmod(0o755)
    decoy.chmod(0o755)
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(real))
    _swap_for_a_symlink(monkeypatch, real, decoy, moved)
    name = container_leftovers.new_container_name()

    container_leftovers.record_container(name)

    assert list(decoy.iterdir()) == [], "a record was written through the symlink"
    assert decoy.stat().st_mode & 0o777 == 0o755, "the symlink's target was chmodded"
    assert [p.name for p in moved.iterdir()] == [f"{name}.json"]
    assert moved.stat().st_mode & 0o777 == 0o700


def test_a_symlink_swapped_in_after_the_check_is_never_swept(tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    dead = _dead_pid()
    real = tmp_path / "state"
    decoy = tmp_path / "decoy"
    moved = tmp_path / "state-moved"
    ours = f"ash-scan-{dead}-0a1b2c3d"
    theirs = f"ash-scan-{dead}-ffffffff"
    _record(real, ours, dead)
    decoy_record = _record(decoy, theirs, dead)
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(real))
    _swap_for_a_symlink(monkeypatch, real, decoy, moved)

    removed = container_leftovers.sweep_leftover_containers([str(stub)])

    assert removed == [ours]
    assert log.read_text(encoding="utf-8").splitlines() == [f"rm -f {ours}"], (
        "the decoy's record reached the runtime"
    )
    assert decoy_record.exists()
    assert list(moved.iterdir()) == []


def test_a_directory_swapped_between_reading_the_records_and_removing_is_refused(
    tmp_path, monkeypatch
):
    """The split form opens the directory again to remove: a symlink put there since
    the records were read is refused, and nothing reaches the runtime."""
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    dead = _dead_pid()
    real = tmp_path / "state"
    decoy = tmp_path / "decoy"
    moved = tmp_path / "state-moved"
    name = f"ash-scan-{dead}-0a1b2c3d"
    record = _record(real, name, dead)
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(real))
    records = container_leftovers.leftover_records()
    assert records == [(record.name, name)]
    decoy.mkdir()
    real.rename(moved)
    real.symlink_to(decoy, target_is_directory=True)

    removed = container_leftovers.remove_leftovers([str(stub)], records)

    assert removed == []
    assert not log.exists(), "the runtime was called through a swapped directory"
    assert (moved / record.name).exists()


def _dead_pid() -> int:
    import subprocess  # nosec B404 - the running interpreter, fixed argv

    child = subprocess.Popen(  # nosec B603
        [sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    child.wait(timeout=30)
    return child.pid

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of the leftover-container records and the private-directory sweep.

* A ``~``-prefixed state directory is expanded, and a relative one is said once.
* The private-directory sweep searches where ``tempfile`` puts a directory under
  ``TEMP`` or ``TMP``, not only under ``TMPDIR``.
* A record naming this pid with another process's start time is not alive.
* A runtime that exits 0 while saying it has no such container did not remove one,
  and a container the runtime never had is not reported as removed.
* A temporary record file stranded between create and rename, and a record file
  that cannot be read, are removed by their age.
* An env-dir record with a boolean creator pid is ignored, and one whose parent is
  no longer searched is forgotten by the age bound.
* A live creator's private directory is kept whatever its age.
* On a platform with no directory descriptors the sweep is a no-op, not a warning.

Nothing here starts a process: the runtime is a function, and every directory is
under ``tmp_path``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.interactions import container_leftovers as leftovers
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the records need directory descriptors"
    ),
]

A_WEEK_AND_A_DAY = 8 * 24 * 3600


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self, level: int) -> List[str]:
        return [r.getMessage() for r in self.records if r.levelno == level]


@pytest.fixture
def logged():
    handler = _Records()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


@pytest.fixture
def state(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv(leftovers.STATE_DIR_ENV, str(directory))
    return directory


def _age(path: Path, seconds: float) -> None:
    stamp = leftovers._now() - seconds
    os.utime(path, (stamp, stamp))


# ---------------------------------------------------------------------------
# The state directory's name
# ---------------------------------------------------------------------------


def test_a_tilde_state_dir_is_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(leftovers.STATE_DIR_ENV, "~/ash-state")

    assert leftovers.state_dir() == tmp_path / "ash-state"


def test_a_relative_state_dir_is_said_once(monkeypatch, logged):
    monkeypatch.setattr(leftovers, "_RELATIVE_STATE_DIR_WARNED", False)
    monkeypatch.setenv(leftovers.STATE_DIR_ENV, "relative-state")

    first = leftovers.state_dir()
    second = leftovers.state_dir()

    assert first == second == Path("relative-state")
    warnings = [
        m for m in logged.messages(logging.WARNING) if leftovers.STATE_DIR_ENV in m
    ]
    assert len(warnings) == 1, warnings
    assert "relative" in warnings[0]


# ---------------------------------------------------------------------------
# Where the private directories are looked for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variable", ["TMPDIR", "TEMP", "TMP"])
def test_the_sweep_searches_each_temporary_directory_variable_alone(
    tmp_path, monkeypatch, variable
):
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)
    place = tmp_path / "from-the-variable"
    place.mkdir()
    monkeypatch.setenv(variable, str(place))

    parents = leftovers._env_dir_parents()

    assert parents[0] == os.path.normcase(os.path.abspath(str(place)))


def test_the_sweep_searches_the_tempfile_default_when_no_variable_names_one(
    monkeypatch,
):
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)
    default = tempfile.gettempdir()
    monkeypatch.setattr(tempfile, "tempdir", None)

    parents = leftovers._env_dir_parents()

    assert os.path.normcase(os.path.abspath(default)) in parents


# ---------------------------------------------------------------------------
# Whether a creator is alive
# ---------------------------------------------------------------------------


def test_a_record_of_this_pid_with_another_start_time_is_not_alive(monkeypatch):
    monkeypatch.setattr(leftovers, "_process_start", lambda pid: "200")

    assert leftovers._creator_alive(os.getpid(), "100") is False
    assert leftovers._creator_alive(os.getpid(), "200") is True
    assert leftovers._creator_alive(os.getpid(), None) is True


# ---------------------------------------------------------------------------
# What the runtime's answer means
# ---------------------------------------------------------------------------


def test_an_exit_zero_that_says_no_such_container_is_not_a_removal(
    monkeypatch, tmp_path
):
    # The runtime is a stub file under the run's temp root, as the unit guard
    # asks of every runtime a record names; the faked run_command never starts it.
    stub = tmp_path / "docker"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)

    def run_command(cmd, **kwargs):
        return create_completed_process(
            args=[str(c) for c in cmd],
            returncode=0,
            stdout="",
            stderr="Error response from daemon: No such container: ash-scan-1-00000000\n",
        )

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)

    assert leftovers._removed([str(stub)], "ash-scan-1-00000000") is leftovers._ABSENT


def test_a_container_the_runtime_never_had_is_not_reported_removed(
    state, monkeypatch, logged
):
    runner = ["/nonexistent/docker"]
    name = leftovers.new_container_name()
    path = leftovers.record_container(name, runner)
    assert path is not None and path.exists()
    monkeypatch.setattr(leftovers, "_removed", lambda command, n: leftovers._ABSENT)

    removed = leftovers.remove_leftovers(runner, [(path.name, name)])

    assert removed == []
    assert not path.exists()
    assert not any("Removed" in m for m in logged.messages(logging.INFO))


# ---------------------------------------------------------------------------
# Files nothing can act on
# ---------------------------------------------------------------------------


def test_a_stranded_temporary_record_is_removed_by_age(state):
    old = state / ".record-0123456789abcdef"
    old.write_text("", encoding="utf-8")
    _age(old, 2 * leftovers._TEMPORARY_RECORD_MAX_AGE_SECONDS)
    young = state / ".record-fedcba9876543210"
    young.write_text("", encoding="utf-8")

    leftovers.leftover_records()

    assert not old.exists()
    assert young.exists()


def test_an_unreadable_record_is_forgotten_by_age(state):
    old = state / "ash-scan-1-00000001.json"
    old.write_text("{not json", encoding="utf-8")
    _age(old, A_WEEK_AND_A_DAY)
    young = state / "ash-scan-1-00000002.json"
    young.write_text("{not json", encoding="utf-8")

    leftovers.leftover_records()

    assert not old.exists()
    assert young.exists()


# ---------------------------------------------------------------------------
# The env-dir records
# ---------------------------------------------------------------------------


def _env_dir_record(state: Path, directory: Path, **fields) -> Path:
    record = {
        "kind": leftovers._KIND_ENV_DIR,
        "host": leftovers.host_key(),
        "dir": str(directory),
        "creator_pid": os.getpid(),
        "creator_start": leftovers._process_start(os.getpid()),
        "created": leftovers._now(),
    }
    record.update(fields)
    path = state / f"{leftovers._ENV_DIR_RECORD_PREFIX}{directory.name}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_a_boolean_creator_pid_is_not_an_env_dir_record(state, tmp_path, monkeypatch):
    parent = tmp_path / "tmpdir"
    parent.mkdir()
    monkeypatch.setenv("TMPDIR", str(parent))
    monkeypatch.setattr(tempfile, "tempdir", None)
    directory = parent / "ash-container-env-abc123"
    _env_dir_record(state, directory, creator_pid=True)

    fd = leftovers._open_state_dir(state)
    assert fd is not None
    try:
        found = leftovers._env_dir_records(fd)
    finally:
        os.close(fd)
    monkeypatch.setattr(tempfile, "tempdir", None)

    assert found == {}


def test_an_env_dir_record_under_an_unsearched_parent_is_forgotten_by_age(
    state, tmp_path, monkeypatch
):
    searched = tmp_path / "tmpdir"
    searched.mkdir()
    # The sweep stays inside tmp_path: TMPDIR is the one searched parent, the
    # fixed places are emptied, and the other temp variables and tempfile's
    # cached answer are cleared, so no real directory is listed or deleted.
    monkeypatch.setenv("TMPDIR", str(searched))
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setattr(leftovers, "_ENV_DIR_PARENTS", ())
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    aged = _env_dir_record(
        state,
        elsewhere / "ash-container-env-aged00",
        created=leftovers._now() - A_WEEK_AND_A_DAY,
    )
    young = _env_dir_record(state, elsewhere / "ash-container-env-young0")

    leftovers.sweep_env_dirs()
    monkeypatch.setattr(tempfile, "tempdir", None)

    assert not aged.exists()
    assert young.exists()


def test_a_live_creators_directory_is_kept_whatever_its_age():
    here = leftovers.host_key()
    if here is None:
        pytest.skip("this host has no identity for records")
    entry = (
        "ash-envdir-x.json",
        {
            "host": here,
            "creator_pid": os.getpid(),
            "creator_start": leftovers._process_start(os.getpid()),
        },
    )
    ancient = SimpleNamespace(st_mtime=0.0)
    if entry[1]["creator_start"] is None:
        pytest.skip("this host reports no process start times")

    assert leftovers._env_dir_sweepable(ancient, entry, here) is False
    assert leftovers._env_dir_sweepable(ancient, None, here) is True


def test_a_creator_alive_by_pid_alone_keeps_only_the_age_bound(monkeypatch):
    """Without a start time to confirm it (no /proc, or a record written without
    one) a live pid may be another process given the creator's number, so the
    directory is kept only as long as the age bound allows."""
    here = leftovers.host_key()
    if here is None:
        pytest.skip("this host has no identity for records")
    entry = (
        "ash-envdir-x.json",
        {"host": here, "creator_pid": os.getpid(), "creator_start": None},
    )
    ancient = SimpleNamespace(st_mtime=0.0)
    young = SimpleNamespace(st_mtime=leftovers._now())

    assert leftovers._env_dir_sweepable(ancient, entry, here) is True
    assert leftovers._env_dir_sweepable(young, entry, here) is False

    # The same with a recorded start time the host can no longer read.
    confirmed = dict(entry[1], creator_start="100")
    monkeypatch.setattr(leftovers, "_process_start", lambda pid: None)

    assert leftovers._env_dir_sweepable(ancient, (entry[0], confirmed), here) is True
    assert leftovers._env_dir_sweepable(young, (entry[0], confirmed), here) is False


# ---------------------------------------------------------------------------
# A platform with no directory descriptors
# ---------------------------------------------------------------------------


def test_the_sweep_is_a_no_op_without_directory_descriptors(monkeypatch, logged):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(os, "O_DIRECTORY", raising=False)

    assert leftovers.sweep_env_dirs() == []
    assert logged.messages(logging.WARNING) == []

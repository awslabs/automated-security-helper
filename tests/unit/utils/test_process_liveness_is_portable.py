# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tests' liveness check works where there is no /proc.

The process-stopping tests asserted ``not _alive(pid)`` with an ``_alive`` that
read ``/proc/<pid>/stat`` and answered "not running" when the file was missing.
On macOS, where the unit tests also run, there is no /proc, so every such
assertion passed whatever the process was doing. tests.utils.processes reads
/proc where it exists and otherwise asks the kernel (kill with signal 0) and
``ps`` for the state, so a zombie still counts as not running.

The checks without /proc run here by pointing the helper at an empty directory;
``ps`` is the same command on Linux and macOS.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from tests.utils.processes import forget_running_groups, process_running

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process states")

_SLEEP = [sys.executable, "-c", "import time; time.sleep(60)"]


@pytest.fixture
def no_proc(tmp_path):
    root = tmp_path / "no-proc"
    root.mkdir()
    return root


@pytest.fixture
def sleeper():
    child = subprocess.Popen(_SLEEP, start_new_session=True)
    yield child
    if child.poll() is None:
        child.kill()
    child.wait(timeout=10)


@pytest.mark.parametrize("where", ["proc", "no-proc"])
def test_a_running_process_is_running(where, sleeper, no_proc):
    kwargs = {"proc_root": no_proc} if where == "no-proc" else {}
    assert process_running(sleeper.pid, **kwargs)


@pytest.mark.parametrize("where", ["proc", "no-proc"])
def test_a_zombie_is_not_running(where, sleeper, no_proc):
    kwargs = {"proc_root": no_proc} if where == "no-proc" else {}
    sleeper.kill()
    # Exited and not reaped: os.waitid with WNOWAIT waits for the exit and
    # leaves the zombie in place.
    os.waitid(os.P_PID, sleeper.pid, os.WEXITED | os.WNOWAIT)
    assert not process_running(sleeper.pid, **kwargs)


@pytest.mark.parametrize("where", ["proc", "no-proc"])
def test_a_reaped_process_is_not_running(where, sleeper, no_proc):
    kwargs = {"proc_root": no_proc} if where == "no-proc" else {}
    sleeper.kill()
    sleeper.wait(timeout=10)
    assert not process_running(sleeper.pid, **kwargs)


@pytest.fixture
def fake_proc(tmp_path):
    """A /proc of the test's own: ``self`` is there, so the helper reads it."""
    root = tmp_path / "fake-proc"
    (root / "self").mkdir(parents=True)
    return root


def test_a_process_gone_while_its_stat_is_read_is_not_running(fake_proc, monkeypatch):
    """A process killed between the lookup and the read makes the read raise
    ProcessLookupError (ESRCH), not FileNotFoundError: one under a gate's load
    did, and the error went up through the test that wanted it gone."""
    (fake_proc / "4242").mkdir()
    (fake_proc / "4242" / "stat").write_text("4242 (sleep) S 1\n", encoding="ascii")
    read_text = Path.read_text

    def _gone(self, *args, **kwargs):
        if self.name == "stat":
            raise ProcessLookupError(3, "No such process")
        return read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _gone)

    assert process_running(4242, proc_root=fake_proc) is False


def test_a_stat_read_empty_as_its_process_goes_is_not_running(fake_proc):
    (fake_proc / "4242").mkdir()
    (fake_proc / "4242" / "stat").write_text("", encoding="ascii")

    assert process_running(4242, proc_root=fake_proc) is False


def test_a_recorded_group_is_killed_and_forgotten(sleeper):
    """What the autouse fixture in tests/conftest.py does after every test.

    A cancellable spawn's child stays recorded until it is reaped, and a test
    whose child outlives it left the entry for the next test in its worker, which
    then counted it (test_every_running_group_is_killed_on_request).
    """
    subprocess_utils._register_group(sleeper)
    assert sleeper.pid in subprocess_utils._RUNNING_GROUPS

    forget_running_groups()

    assert subprocess_utils._RUNNING_GROUPS == {}
    assert sleeper.wait(timeout=5) is not None

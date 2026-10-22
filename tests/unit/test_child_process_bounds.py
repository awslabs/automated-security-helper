# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test's bound on a child process ends a child that outlives it, fast and by name.

``tests/utils/helpers.py`` gives a test that starts a real child a bound three ways:
``CHILD_TIMEOUT_SECONDS`` for a call that takes a timeout, ``KillAfter`` for a
``Popen`` child the test reads from, and ``bound_run_command`` for a child started
through ASH code that takes no timeout of its own (the installer's
``dependencies.run_command``). Without one, a child that never exits stalls its
xdist worker and the run with it. These tests hold the two helpers to that: a child
that sleeps far past a small bound must end within the bound plus a margin, and
the failure must say what was killed and after how long.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from automated_security_helper.cli import dependencies as dependencies_module
from tests.utils.helpers import KillAfter, bound_run_command

BOUND = 1.0
#: Generous on purpose: the child is a python start-up on a loaded runner. The test
#: only has to end near the bound rather than when the sleeper's minute is up.
MARGIN = 20.0
SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]


def test_kill_after_ends_a_read_from_a_child_that_never_writes() -> None:
    child = subprocess.Popen(SLEEPER, stdout=subprocess.PIPE)
    started = time.monotonic()
    try:
        with pytest.raises(
            AssertionError,
            match=r"^the sleeper was still running after 1\.0s and was killed$",
        ):
            with KillAfter(child, "the sleeper", seconds=BOUND):
                child.stdout.read()
        elapsed = time.monotonic() - started
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=30)

    assert elapsed < BOUND + MARGIN, f"took {elapsed:.1f}s"


def test_kill_after_leaves_a_child_that_finishes_on_its_own() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "print('done')"], stdout=subprocess.PIPE, text=True
    )
    with KillAfter(child, "the quick child", seconds=60) as watchdog:
        printed = child.stdout.read()
        child.wait(timeout=60)

    assert printed.strip() == "done"
    assert watchdog.fired is False


def test_bound_run_command_fails_a_child_the_installer_started(monkeypatch) -> None:
    """The installer catches Exception; the failure has to get past it."""
    bound_run_command(monkeypatch, seconds=BOUND)
    started = time.monotonic()

    with pytest.raises(
        pytest.fail.Exception, match=r"was still running after 1\.0s and was killed"
    ):
        dependencies_module.run_command(SLEEPER)

    elapsed = time.monotonic() - started
    assert elapsed < BOUND + MARGIN, f"took {elapsed:.1f}s"


def test_bound_run_command_lets_a_child_that_finishes_return(monkeypatch) -> None:
    bound_run_command(monkeypatch, seconds=60)

    assert dependencies_module.run_command([sys.executable, "-c", "pass"]) == 0

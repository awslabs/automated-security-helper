# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container records stay in the test's own home, and no test runs a real runtime.

The records a container-mode run takes were already contained by the per-test home
(``$HOME/.ash/state/containers`` under a home of the test's own). These cells pin
the containment rather than restore it: the default location is under the test's
home, a record aimed at a guarded root is seen by the real-home guard, and a record
in the test's home is not.

The sweep removes a recorded container with the runtime's ``rm -f``. The unit
conftest wraps that step so a runner that is not a stub under the run's base temp
directory fails the test before any process starts; the last two cells pin that
wrapper from both sides. No runtime is started here.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.interactions import container_leftovers
from tests.utils import real_home_guard

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="records use POSIX directory descriptors"
)


def test_the_default_state_dir_is_under_the_tests_home(monkeypatch):
    """With nothing set but the home, the state directory is in the test's home."""
    monkeypatch.delenv(container_leftovers.STATE_DIR_ENV, raising=False)
    home = Path(os.environ["HOME"])

    state = container_leftovers.state_dir()

    assert state is not None
    assert state.is_relative_to(home), (state, home)
    assert not real_home_guard.is_guarded(state), state
    developer = real_home_guard.passwd_home()
    if developer is not None:
        assert not state.is_relative_to(developer / ".ash"), (state, developer)


def test_the_fixture_names_the_state_dir_under_the_tests_home():
    """The autouse fixture sets the variable, so a replaced HOME cannot move it."""
    named = os.environ.get(container_leftovers.STATE_DIR_ENV)

    assert named, "the state directory is not named by the test setup"
    assert Path(named).is_relative_to(Path(os.environ["HOME"])), named


def test_a_record_aimed_at_a_guarded_root_is_seen_by_the_guard(tmp_path, monkeypatch):
    """The arm that must disagree: the guard's mkdir event is the catch.

    The record file itself is written through a directory descriptor, which the
    guard cannot see; the path-based mkdir of the directory is what it sees.
    """
    sentinel = tmp_path / "fake-real-home"
    target = sentinel / ".ash" / "state" / "containers"
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(target))

    with real_home_guard.watching(sentinel):
        # The swallow of the refusal is the documented behavior: no raise.
        container_leftovers.record_container(container_leftovers.new_container_name())
        writes = real_home_guard.drain()

    assert any(
        event == "os.mkdir" and Path(path).is_relative_to(sentinel)
        for event, path in writes
    ), writes
    assert not target.exists()


def test_a_record_in_the_tests_home_is_not_seen_by_the_guard():
    """The negative control: the same call at the default location is not seen."""
    path = container_leftovers.record_container(
        container_leftovers.new_container_name()
    )

    assert path is not None and path.exists()
    assert real_home_guard.drain() == []


def test_a_runtime_that_is_not_a_stub_in_the_run_is_refused():
    """The control: ``docker`` resolves outside the base temp directory."""
    with pytest.raises(pytest.fail.Exception):
        container_leftovers._removed(["docker"], "ash-scan-1-00000000")


def test_a_stub_runtime_in_the_run_is_called_through(tmp_path):
    """The positive arm: a stub under the base temp directory runs and is logged."""
    log = tmp_path / "calls.log"
    stub = tmp_path / "fake-runtime"
    stub.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)

    removed = container_leftovers._removed([str(stub)], "ash-scan-1-00000000")

    assert removed is True
    assert log.read_text(encoding="utf-8").splitlines() == ["rm -f ash-scan-1-00000000"]

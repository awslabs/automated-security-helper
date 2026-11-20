# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ``apt-get install`` that fails once is retried, up to three attempts."""

from __future__ import annotations

import types

import pytest

from automated_security_helper.cli import dependencies

pytestmark = pytest.mark.unit

APT = ["apt-get", "install", "-y", "curl"]


def _script(monkeypatch, codes):
    """Stand in for run_command and sleep; return (calls, sleeps)."""
    calls, sleeps = [], []
    remaining = list(codes)

    def fake_run(args, shell=False):
        calls.append(list(args))
        return remaining.pop(0)

    monkeypatch.setattr(dependencies, "run_command", fake_run)
    monkeypatch.setattr(
        dependencies, "time", types.SimpleNamespace(sleep=sleeps.append)
    )
    return calls, sleeps


def test_a_transient_failure_then_success_is_one_successful_install(monkeypatch):
    calls, sleeps = _script(monkeypatch, [100, 0])

    assert dependencies._run_install_command(APT) == 0
    assert calls == [APT, APT]
    assert sleeps == [2]


def test_a_persistent_failure_returns_the_last_exit_code_after_three_attempts(
    monkeypatch,
):
    calls, sleeps = _script(monkeypatch, [100, 100, 100])

    assert dependencies._run_install_command(APT) == 100
    assert len(calls) == 3
    assert sleeps == [2, 5]


def test_a_first_try_success_does_not_sleep_or_rerun(monkeypatch):
    calls, sleeps = _script(monkeypatch, [0])

    assert dependencies._run_install_command(APT) == 0
    assert len(calls) == 1
    assert sleeps == []


def test_a_non_apt_command_is_run_once(monkeypatch):
    calls, sleeps = _script(monkeypatch, [1])

    assert dependencies._run_install_command(["npm", "install", "-g", "x"]) == 1
    assert len(calls) == 1
    assert sleeps == []


def test_a_command_stopped_at_its_timeout_is_not_retried(monkeypatch):
    """A stalled apt-get (the dpkg lock held) would stall again, an hour each."""
    calls, sleeps = _script(monkeypatch, [dependencies._TimedOutExitCode(124), 0, 0])

    assert dependencies._run_install_command(APT) == 124
    assert len(calls) == 1
    assert sleeps == []


def test_run_command_reports_a_timed_out_command_distinctly(monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    def stopped(*args, **kwargs):
        return subprocess_utils.TimedOutProcess(
            args=APT, returncode=-1, stdout="", stderr=""
        )

    def failed(*args, **kwargs):
        return subprocess_utils.subprocess.CompletedProcess(APT, 100, "", "")

    monkeypatch.setattr(subprocess_utils, "run_command", stopped)
    timed_out = dependencies.run_command(APT)
    monkeypatch.setattr(subprocess_utils, "run_command", failed)
    plain = dependencies.run_command(APT)

    assert isinstance(timed_out, dependencies._TimedOutExitCode) and timed_out != 0
    assert plain == 100 and not isinstance(plain, dependencies._TimedOutExitCode)

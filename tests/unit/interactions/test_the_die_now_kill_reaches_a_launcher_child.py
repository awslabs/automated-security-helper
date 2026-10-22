# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The die-now signal reaches a launcher child, which leads no process group.

The second-SIGTERM path signals what the handler's module records. Its group
half uses ``os.killpg``, and a launcher child (the container runtime, the
Nix shell) is spawned without a session of its own, so a group kill aimed at
its pid is ESRCH and passed over: measured, that left the child running.
The pid record exists for exactly this child, and this file proves the signal
(an interrupt, not a kill) reaches it. The kill function is called directly, not through a signal: it
only touches recorded ids, and the launcher's child here is this test's own
interpreter sleeping.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - the child is this test's own interpreter
import sys
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.interactions.run_ash_container import run_cmd_direct
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="process groups and SIGKILL are POSIX"
)

_CHILD_SLEEP_SECONDS = 20.0
_BOUND_SECONDS = 10.0


def _child_that_reports_start(marker: Path) -> list[str]:
    return [
        sys.executable,
        "-c",
        (
            "import pathlib, time; "
            f"pathlib.Path({str(marker)!r}).write_text('started', encoding='utf-8'); "
            f"time.sleep({_CHILD_SLEEP_SECONDS})"
        ),
    ]


def test_the_die_now_kill_reaches_a_container_runtime(tmp_path, monkeypatch):
    marker = tmp_path / "child-started"
    spawned: "list[subprocess.Popen]" = []
    real_spawn = subprocess_utils.create_process_with_pipes

    def _capturing_spawn(**kwargs):
        process = real_spawn(**kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", _capturing_spawn)
    results: "list[object]" = []

    def _run() -> None:
        results.append(run_cmd_direct(_child_that_reports_start(marker), check=False))

    runner = threading.Thread(target=_run, daemon=True)
    runner.start()
    deadline = time.monotonic() + _CHILD_SLEEP_SECONDS
    while time.monotonic() < deadline and not marker.exists():
        time.sleep(0.05)
    assert marker.exists(), "the launcher child never started"
    (child,) = spawned
    # The measured gap this file pins: the child leads no group, so the
    # group half's killpg at its pid cannot reach it.
    assert os.getpgid(child.pid) != child.pid
    assert child.pid in cancellation._TOOL_PIDS

    started = time.monotonic()
    cancellation._kill_recorded_groups()
    runner.join(timeout=_BOUND_SECONDS)
    assert not runner.is_alive(), "the wait did not end after the die-now signal"
    assert time.monotonic() - started < _BOUND_SECONDS
    (result,) = results
    import signal as _signal

    # The recorded child is interrupted, not killed: it is the runtime client
    # or the inner ASH, and an interrupt is the second one it takes its own
    # die-now branch on. The child here is a Python interpreter, which reports
    # an interrupt as a KeyboardInterrupt.
    assert result.returncode != -int(_signal.SIGKILL), result.returncode
    assert "KeyboardInterrupt" in result.stderr, result.stderr

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SIGTERM to ``ash scan`` in container or Nix mode stops the mode's child.

End to end through the real pieces: the console script installs the handler,
the CLI registers its cancel event, and the mode's launcher sits waiting on its
child -- the OCI runner for container mode, the ``nix develop`` shell for Nix
mode. One SIGTERM to the ASH process must make that wait read the cancel
event, stop the child through the launcher's interrupt stop path, unwind, and
exit ASH_EXIT_TERMINATED with one line saying so. Before the launchers read
the event, the handler set it and returned, nobody looked, and the scan ran to
completion as though no signal had arrived: the SIGTERM was swallowed.

The children are stand-ins (tests/test_data/sigterm_stop/fake-docker and
fake-nix): they run no container, enter no shell, fetch nothing, and block in
a plain ``sleep`` after recording their pid. The ASH child is disarmed: a
scratch HOME and a source tree of one file, and the scan never reaches a
scanner because the mode's child is the first thing it waits on.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess  # nosec B404 - fixed argv, the checkout's own console script
import sys
import time
from pathlib import Path

import pytest

from automated_security_helper.core.constants import ASH_EXIT_TERMINATED
from tests.utils.helpers import checkout_env
from tests.utils.processes import process_running

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="the pid identity checks read /proc, which only Linux has; on another "
    "POSIX the readlink raises before the SIGTERM is ever sent, and the cleanup's "
    "identity read answers nothing, so the stand-in tool outlives the test",
)

FIXTURE = Path(__file__).resolve().parents[2] / "test_data" / "sigterm_stop"

#: Far longer than any step takes on an idle host: the child's imports and mode
#: dispatch before the stand-in starts, and the stop path's grace afterwards.
WAIT_SECONDS = 120.0

#: PATH prefix, the extra scan arguments, and the stand-in's blocking word, per
#: mode. Container mode is exercised at both of its waits: blocked in the image
#: build, and blocked in the container run, which the run step's own SIGTERM
#: handling must stop the same way (a handler swap there exited on the first
#: SIGTERM with no stop line and the runner left running).
_MODES = {
    "container-build": (
        FIXTURE / "fake-docker",
        ["--mode", "container", "--oci-runner", "docker"],
        "build",
    ),
    "container-run": (
        FIXTURE / "fake-docker",
        ["--mode", "container", "--oci-runner", "docker"],
        "run",
    ),
    "nix": (FIXTURE / "fake-nix", ["--mode", "nix"], "build"),
}


def _ash_executable() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    if not found:
        pytest.fail("the ash entry point is not installed beside this interpreter")
    return found


def _wait_for(predicate, what: str) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(f"{what} did not happen within {WAIT_SECONDS} s")
        time.sleep(0.05)


def _recorded_pid(pid_file: Path) -> "int | None":
    text = pid_file.read_text() if pid_file.exists() else ""
    return int(text) if text.strip() else None


def _cmdline(pid: int) -> str:
    try:
        return (
            Path(f"/proc/{pid}/cmdline")
            .read_bytes()
            .replace(b"\0", b" ")
            .decode("utf-8", "replace")
        )
    except OSError:
        return ""


#: Well above a stop's cost (the interrupt lands within the grace) and well
#: below the stand-in's own 60 s sleep, so a runner the stop missed is still
#: alive when the window closes: waiting the full WAIT_SECONDS would let the
#: stand-in's natural end read as a stop that worked.
_SURVIVOR_WINDOW_SECONDS = 30.0


def _gone_within_window(pid: int) -> bool:
    """Whether the process ends within the survivor window. Returns, never
    fails: the caller records the answer before cleanup and asserts it after."""
    deadline = time.monotonic() + _SURVIVOR_WINDOW_SECONDS
    while process_running(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


@pytest.mark.parametrize("mode", sorted(_MODES))
def test_a_sigterm_stops_the_modes_child_and_exits_terminated(tmp_path, mode):
    fake_dir, mode_args, block_on = _MODES[mode]
    home = tmp_path / "home"
    home.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    pid_file = tmp_path / "runner.pid"
    env = {
        **os.environ,
        "HOME": str(home),
        "PATH": os.pathsep.join([str(fake_dir), os.environ.get("PATH", "")]),
        "ASH_FAKE_RUNNER_PID_FILE": str(pid_file),
        "ASH_FAKE_BLOCK_ON": block_on,
    }
    command = [
        _ash_executable(),
        "scan",
        *mode_args,
        "--source-dir",
        str(source),
        "--output-dir",
        str(tmp_path / "out"),
        "--no-progress",
    ]
    child = subprocess.Popen(  # nosec B603 - fixed argv
        command,
        env=checkout_env(env),
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    runner_pid: "int | None" = None
    try:
        # The pid captured at spawn is the process signalled below; the cwd read
        # proves it is this test's child and not a recycled pid.
        assert Path(f"/proc/{child.pid}/cwd").readlink() == tmp_path

        def runner_started() -> bool:
            if child.poll() is not None:
                # The scan ended before its mode spawned the stand-in: show why
                # instead of watching a pid file nothing will write.
                stdout, stderr = child.communicate()
                pytest.fail(
                    f"ash exited {child.returncode} before the stand-in runner "
                    f"started.\nstdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
                )
            return _recorded_pid(pid_file) is not None

        _wait_for(runner_started, "the mode's stand-in child")
        runner_pid = _recorded_pid(pid_file)
        assert runner_pid is not None
        signalled_at = time.monotonic()
        child.send_signal(signal.SIGTERM)
        stdout, stderr = child.communicate(timeout=WAIT_SECONDS)
        # Both read here, before the cleanup below can kill what the scan
        # failed to stop, and asserted after the finally: an assert placed
        # below the cleanup used to pass whatever the stop did, because the
        # cleanup had already killed the survivor it was meant to detect.
        #
        # The liveness read is the discriminator for container mode: the stop
        # path waits its child out before the scan exits, so by the time
        # communicate() returns, a stopped runner is already gone, and one
        # still running was never stopped. The elapsed half is load-bearing
        # for nix mode: its stand-in inherits the scan's own stdio, so a
        # missed stop does not show as a surviving pid here -- communicate()
        # itself is held open until the stand-in's natural end, and only the
        # time from the signal betrays it.
        runner_alive_after_exit = process_running(runner_pid)
        runner_stopped = (
            time.monotonic() - signalled_at < _SURVIVOR_WINDOW_SECONDS
        ) and _gone_within_window(runner_pid)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=30)
        leftover = _recorded_pid(pid_file)
        # The identity check keeps a recycled pid from being killed: only a
        # process still running this test's `sleep` stand-in is this test's.
        if (
            leftover is not None
            and process_running(leftover)
            and "sleep 60" in _cmdline(leftover)
        ):
            os.kill(leftover, signal.SIGKILL)

    assert child.returncode == ASH_EXIT_TERMINATED, (
        f"ash exited {child.returncode}, not {ASH_EXIT_TERMINATED}: an exit by "
        "the scan's own verdict means the mode's wait never read the cancel "
        "event and the SIGTERM was swallowed; a negative code means the "
        "default kill ran and no stop path did.\n"
        f"stdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
    )
    assert "stopped by SIGTERM" in stderr, stderr[-4000:]
    assert not runner_alive_after_exit, (
        "the mode's stand-in child was still running when the scan exited: "
        "the stop path never ended the runner, whatever the exit code said"
    )
    assert runner_stopped, (
        "the mode's stand-in child outlived the stop: the scan exited "
        "without ending the runner it had started"
    )

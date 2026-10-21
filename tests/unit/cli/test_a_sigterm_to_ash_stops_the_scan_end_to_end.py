# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A SIGTERM to a running ``ash scan`` stops the scanner's tool and exits 143.

End to end through the real pieces: the console script's entry point installs
the handler, a real scan loads the fixture scanner (tests/test_data/sigterm_stop)
through ``ash_plugin_modules``, that scanner spawns its blocking tool through
``_run_subprocess`` like a builtin scanner, and one SIGTERM to the ASH process
must make the cancellable spawn stop the tool's whole group (the tool ignores
SIGTERM, so ending it takes the stop path's SIGKILL), unwind the scan, and exit
ASH_EXIT_TERMINATED with one line saying so. Without the handler the process
dies by the signal (waitpid says -SIGTERM), prints nothing, and the tool is
orphaned mid-sleep -- which is the finding this cell exists to pin.

The child is disarmed: a scratch HOME, ``--offline``, ``--sandbox off``, local
mode, and the only tool it spawns is the fixture's blocker.
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

#: Far longer than any step takes on an idle host: the child's imports and plugin
#: load before the blocker starts, and the stop path's grace afterwards.
WAIT_SECONDS = 120.0


def _ash_executable() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    if not found:
        pytest.fail("the ash entry point is not installed beside this interpreter")
    return found


def _wait_for(predicate, what: str, evidence=None) -> None:
    """Wait for *predicate*; on timeout fail WITH the evidence, not without.

    *evidence* is called only on the timeout. A hang here used to fail with
    one line and nothing else, so a run that hit it left nothing to diagnose;
    the evidence callback is where the caller kills its child and returns the
    output it had written, so the next hang leaves its own record.
    """
    deadline = time.monotonic() + WAIT_SECONDS
    while not predicate():
        if time.monotonic() > deadline:
            detail = f"\n{evidence()}" if evidence is not None else ""
            pytest.fail(f"{what} did not happen within {WAIT_SECONDS} s{detail}")
        time.sleep(0.05)


def _blocker_pid(pid_file: Path) -> "int | None":
    text = pid_file.read_text() if pid_file.exists() else ""
    return int(text) if text else None


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


#: Well above a stop's cost (the group SIGKILL lands within the grace plus the
#: reap wait) and well below the blocker's own 120 s sleep, so a tool the stop
#: missed is still alive when the window closes: waiting the full WAIT_SECONDS
#: would let the blocker's natural end read as a stop that worked.
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


def test_a_sigterm_to_ash_stops_the_scanner_tool_and_exits_terminated(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    (source / ".ash").mkdir()
    # No ash_plugin_modules entry: the scanned tree's own config cannot select
    # plugin modules (config/plugin_module_trust.py ignores its entries with a
    # warning), so the fixture module is named on the command line below, the
    # operator's route the warning itself points at.
    (source / ".ash" / ".ash.yaml").write_text("project_name: sigterm-stop\n")
    output = tmp_path / "out"
    pid_file = tmp_path / "blocker.pid"
    env = {
        **os.environ,
        "HOME": str(home),
        "PYTHONPATH": os.pathsep.join(
            [str(FIXTURE), os.environ.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep),
        "ASH_SIGTERM_STOP_BLOCKER": str(FIXTURE / "blocker.py"),
        "ASH_SIGTERM_STOP_PID_FILE": str(pid_file),
    }
    command = [
        _ash_executable(),
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--ash-plugin-modules",
        "sigterm_ash_plugins",
        "--scanners",
        "sigterm-stop",
        "--sandbox",
        "off",
        "--offline",
        "--no-progress",
        "--no-fail-on-findings",
    ]
    child = subprocess.Popen(  # nosec B603 - fixed argv
        command,
        env=checkout_env(env),
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    tool_pid: "int | None" = None
    try:
        # The pid captured at spawn is the process signalled below; the cwd read
        # proves it is this test's child and not a recycled pid.
        assert Path(f"/proc/{child.pid}/cwd").readlink() == tmp_path

        def blocker_started() -> bool:
            if child.poll() is not None:
                # The scan ended before its scanner spawned the tool: show why
                # instead of watching a pid file nothing will write.
                stdout, stderr = child.communicate()
                pytest.fail(
                    f"ash exited {child.returncode} before the blocker started."
                    f"\nstdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
                )
            return _blocker_pid(pid_file) is not None

        def hung_ash_output() -> str:
            # The hang's evidence: kill the still-running child and drain its
            # pipes, so the failure carries what ASH wrote before hanging
            # instead of one line and a thrown-away capture.
            if child.poll() is None:
                child.kill()
            stdout, stderr = child.communicate()
            return (
                f"ash was killed for evidence (returncode {child.returncode})."
                f"\nstdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
            )

        _wait_for(blocker_started, "the blocker tool", evidence=hung_ash_output)
        tool_pid = _blocker_pid(pid_file)
        assert tool_pid is not None
        child.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = child.communicate(timeout=WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            # Same rule as the wait above: a stop that hangs must leave its
            # output behind, not a bare TimeoutExpired over a killed capture.
            pytest.fail(
                f"ash did not exit within {WAIT_SECONDS} s of the SIGTERM.\n"
                + hung_ash_output()
            )
        # Recorded here, before the cleanup below can kill what the scan
        # failed to stop. Asserted after the finally: an assert placed below
        # the cleanup used to pass whatever the stop did, because the cleanup
        # had already killed the survivor it was meant to detect.
        tool_stopped = _gone_within_window(tool_pid)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=30)
        blocker = _blocker_pid(pid_file)
        # The identity check keeps a recycled pid from being killed: only a
        # process still running this test's blocker is this test's.
        if (
            blocker is not None
            and process_running(blocker)
            and "blocker.py" in _cmdline(blocker)
        ):
            os.kill(blocker, signal.SIGKILL)

    assert child.returncode == ASH_EXIT_TERMINATED, (
        f"ash exited {child.returncode}, not {ASH_EXIT_TERMINATED}: a negative "
        "code means the default kill ran and no stop path did.\n"
        f"stdout:\n{stdout[-4000:]}\nstderr:\n{stderr[-4000:]}"
    )
    assert "stopped by SIGTERM" in stderr, stderr[-4000:]
    assert tool_stopped, (
        "the scanner's tool outlived the stop: the scan exited without "
        "ending its tool's process group"
    )

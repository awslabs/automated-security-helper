# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cancelled scan stops its scanner's whole process tree, not only the child.

cancel_scan stops a running scan by stopping the child process of the scanner it
is waiting on (subprocess_utils._run_cancellable). Signalling that child alone
would leave a scanner's own processes (a wrapper script, a language server, a
worker pool) running after the cancel, still writing into the output directory
the scan is putting back, and a child that had already exited while one of its
own children held its output pipe would not be signalled at all.

Inside a cancel scope an unsandboxed child starts in a process group of its
own, and a cancel or a timeout stops the group: SIGTERM, and SIGKILL for whatever
is left after the grace period. A sandboxed child is left as it was: the Landlock
wrapper calls setsid itself and kills its own tree on SIGTERM.

POSIX only. On Windows the tree is ended with ``taskkill /T``; which taskkill is
run is tested in test_taskkill_runs_from_the_system_directory.py.
"""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import run_command
from tests.utils.processes import process_running

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="process groups are POSIX"
)

# The child starts a grandchild, records both pids, and waits. Each one ignores
# SIGTERM when asked to.
TREE = r"""
import os, pathlib, signal, subprocess, sys, time
out = pathlib.Path(sys.argv[1])
ignore_child, ignore_grandchild, child_exits = sys.argv[2], sys.argv[3], sys.argv[4]
grandchild = subprocess.Popen([sys.executable, "-c",
    "import os, pathlib, signal, sys, time\n"
    "if sys.argv[2] == '1': signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
    "time.sleep(60)\n",
    str(out / "grandchild.pid"), ignore_grandchild])
if ignore_child == "1":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
for _ in range(200):
    if (out / "grandchild.pid").exists():
        break
    time.sleep(0.05)
(out / "child.pid").write_text(str(os.getpid()))
if child_exits == "1":
    sys.exit(0)
time.sleep(60)
"""


def _alive(pid: int) -> bool:
    """Running, as opposed to gone or a zombie waiting to be reaped.

    Not /proc alone: macOS has none, and every check here passed there.
    """
    return process_running(pid)


def _wait_for(path: Path, what: str, seconds: float = 20.0) -> None:
    """Wait for a test child to write ``path``, and fail saying so if it never does.

    Without the message, a slow start under load surfaces as a FileNotFoundError
    from the read after the wait, or as a later assertion about something else.
    """
    deadline = time.monotonic() + seconds
    while not (path.exists() and path.read_text()):
        assert time.monotonic() < deadline, (
            f"{what} never wrote {path.name} in {seconds:g}s"
        )
        time.sleep(0.05)


def _read_pid(path: Path, what: str) -> int:
    _wait_for(path, what)
    return int(path.read_text())


def _popen_waiting_for(path: Path, what: str, base: type = subprocess.Popen) -> type:
    """A Popen whose communicate waits for ``path`` before its own wait begins.

    For a spawn with a timeout: _run_cancellable checks its deadline only after a
    communicate has returned, so the timeout cannot land before the child has
    written ``path``, however long the child takes to start.
    """

    class _Waiting(base):
        def communicate(self, data=None, timeout=None):
            _wait_for(path, what)
            return super().communicate(data, timeout)

    return _Waiting


def _cancel_when(path: Path, event: threading.Event) -> threading.Thread:
    def watch() -> None:
        for _ in range(400):
            if path.exists():
                break
            time.sleep(0.05)
        event.set()

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread


def _run_tree(tmp_path: Path, *, ignore_child="0", ignore_grandchild="0", exits="0"):
    event = threading.Event()
    watcher = _cancel_when(tmp_path / "child.pid", event)
    started = time.monotonic()
    with cancel_scope(event):
        with pytest.raises(ScanCancelled):
            run_command(
                [
                    sys.executable,
                    "-c",
                    TREE,
                    str(tmp_path),
                    ignore_child,
                    ignore_grandchild,
                    exits,
                ]
            )
    watcher.join(timeout=5)
    took = time.monotonic() - started
    pids = {
        name: _read_pid(tmp_path / f"{name}.pid", "the TREE child")
        for name in ("child", "grandchild")
    }
    return pids, took


@pytest.fixture(autouse=True)
def _short_grace(monkeypatch):
    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 1.0)


def _reap_leftovers(pids) -> None:
    for pid in pids.values():
        if _alive(pid):
            os.kill(pid, 9)


@pytest.mark.integration
def test_a_cancel_stops_the_grandchild(tmp_path):
    pids, _ = _run_tree(tmp_path)
    try:
        assert not _alive(pids["grandchild"]), "the grandchild outlived the cancel"
        assert not _alive(pids["child"])
    finally:
        _reap_leftovers(pids)


@pytest.mark.integration
def test_a_grandchild_that_ignores_sigterm_is_killed(tmp_path):
    pids, took = _run_tree(tmp_path, ignore_grandchild="1")
    try:
        assert not _alive(pids["grandchild"]), "SIGKILL never reached the grandchild"
        assert took < 8, took
    finally:
        _reap_leftovers(pids)


@pytest.mark.integration
def test_a_child_that_ignores_sigterm_is_killed_with_its_tree(tmp_path):
    pids, took = _run_tree(tmp_path, ignore_child="1", ignore_grandchild="1")
    try:
        assert not _alive(pids["child"])
        assert not _alive(pids["grandchild"])
        assert took < 8, took
    finally:
        _reap_leftovers(pids)


@pytest.mark.integration
def test_a_grandchild_holding_the_pipe_of_a_child_that_exited(tmp_path):
    """The child is gone; its grandchild keeps the output pipe open."""
    pids, took = _run_tree(tmp_path, exits="1")
    try:
        assert not _alive(pids["grandchild"])
        assert took < 8, took
    finally:
        _reap_leftovers(pids)


#: For the timeout: the child records its pid first, so it is there whenever the
#: timeout lands, and its grandchild outlives it by a minute. With the same
#: lifetime for both, a stop that never killed the group still passed: the call
#: waited for the child to end on its own, and by then the grandchild had too.
TIMEOUT_TREE = r"""
import os, pathlib, subprocess, sys, time
out = pathlib.Path(sys.argv[1])
(out / "child.pid").write_text(str(os.getpid()))
subprocess.Popen([sys.executable, "-c",
    "import os, pathlib, sys, time\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
    "time.sleep(120)\n",
    str(out / "grandchild.pid")])
time.sleep(60)
"""


@pytest.mark.integration
def test_a_timeout_stops_the_tree_as_well(tmp_path):
    event = threading.Event()
    started = time.monotonic()
    with cancel_scope(event):
        result = run_command(
            [sys.executable, "-c", TIMEOUT_TREE, str(tmp_path)],
            timeout=3,
        )
    took = time.monotonic() - started
    pids = {
        name: _read_pid(tmp_path / f"{name}.pid", "the TIMEOUT_TREE child")
        for name in ("child", "grandchild")
    }
    try:
        assert result.returncode != 0
        assert not _alive(pids["grandchild"]), "the grandchild outlived the timeout"
        assert took < 10, f"the timeout of 3s took {took:.1f}s"
    finally:
        _reap_leftovers(pids)


#: A sandbox wrapper that leads a session of its own: it calls setsid, as the
#: macOS sandbox-exec wrapper does before it execs the tool (sandbox/backends.py,
#: _SETSID_EXEC), then starts a child and waits. It does nothing on SIGTERM to
#: end what it started.
SETSID_WRAPPER = r"""
import os, pathlib, subprocess, sys, time
out = pathlib.Path(sys.argv[1])
os.setsid()
subprocess.Popen([sys.executable, "-c",
    "import os, pathlib, sys, time\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
    "time.sleep(120)\n",
    str(out / "grandchild.pid")])
for _ in range(200):
    if (out / "grandchild.pid").exists():
        break
    time.sleep(0.05)
(out / "child.pid").write_text(str(os.getpid()))
time.sleep(120)
"""


@pytest.mark.integration
@pytest.mark.parametrize("ending", ["cancel", "timeout"])
def test_a_sandboxed_child_that_leads_a_group_is_stopped_with_its_group(
    tmp_path, ending, monkeypatch
):
    """A stop reaches a sandboxed spawn's group once the child leads one.

    Stopped by its pid alone, the processes a wrapper that called setsid had
    started would outlive a cancel or a timeout: nothing ends them, since
    sandbox-exec's wrapper execs the tool and is not there to.
    The timeout lands only once the wrapper has recorded its pid, so after its
    setsid, however slowly it starts.
    """
    event = threading.Event()
    if ending == "cancel":
        _cancel_when(tmp_path / "child.pid", event)
    else:
        monkeypatch.setattr(
            subprocess_utils.subprocess,
            "Popen",
            _popen_waiting_for(tmp_path / "child.pid", "the setsid wrapper"),
        )
    argv = [sys.executable, "-c", SETSID_WRAPPER, str(tmp_path)]
    expected = ScanCancelled if ending == "cancel" else subprocess.TimeoutExpired
    try:
        with pytest.raises(expected):
            subprocess_utils._run_cancellable(
                argv,
                cancel_event=event,
                graceful_timeout=True,
                capture_output=True,
                **({"timeout": 3} if ending == "timeout" else {}),
            )
        pids = {
            name: _read_pid(tmp_path / f"{name}.pid", "the setsid wrapper")
            for name in ("child", "grandchild")
        }
        assert not _alive(pids["child"])
        assert not _alive(pids["grandchild"]), (
            "the sandbox wrapper's child outlived the stop"
        )
    finally:
        for name in ("child", "grandchild"):
            _kill_if_alive(tmp_path / f"{name}.pid")


def _getpgid_refused(monkeypatch) -> None:
    """getpgid fails for every pid, as a policy that hides another session can make it."""

    def refused(pid):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils.os, "getpgid", refused)


@pytest.mark.integration
@pytest.mark.parametrize("ending", ["cancel", "timeout"])
def test_a_child_whose_group_cannot_be_read_is_stopped_with_its_group(
    tmp_path, ending, monkeypatch, caplog
):
    """A getpgid that fails is not taken to mean the child leads no group.

    Taken that way, silently, the stop would signal the sandbox wrapper alone,
    and what a wrapper that had called setsid started would keep running. A child
    not yet reaped keeps its pid, so a group carrying that pid can be its own and
    no other process's: the stop signals that group as well, and logs that it
    could not tell.
    """
    _getpgid_refused(monkeypatch)
    event = threading.Event()
    if ending == "cancel":
        _cancel_when(tmp_path / "child.pid", event)
    else:
        monkeypatch.setattr(
            subprocess_utils.subprocess,
            "Popen",
            _popen_waiting_for(tmp_path / "child.pid", "the setsid wrapper"),
        )
    expected = ScanCancelled if ending == "cancel" else subprocess.TimeoutExpired
    try:
        with pytest.raises(expected):
            subprocess_utils._run_cancellable(
                [sys.executable, "-c", SETSID_WRAPPER, str(tmp_path)],
                cancel_event=event,
                graceful_timeout=True,
                capture_output=True,
                **({"timeout": 3} if ending == "timeout" else {}),
            )
        pids = {
            name: _read_pid(tmp_path / f"{name}.pid", "the setsid wrapper")
            for name in ("child", "grandchild")
        }
        assert not _alive(pids["child"])
        assert not _alive(pids["grandchild"]), (
            "what the wrapper started outlived the stop"
        )
        warnings = [
            record.getMessage()
            for record in caplog.records
            if record.levelname == "WARNING"
        ]
        assert any(f"pid {pids['child']}" in message for message in warnings), warnings
    finally:
        for name in ("child", "grandchild"):
            _kill_if_alive(tmp_path / f"{name}.pid")


@pytest.mark.integration
def test_a_child_whose_group_cannot_be_read_and_that_leads_none_is_stopped(
    tmp_path, monkeypatch
):
    """The group is tried when getpgid fails, but a child that leads none is not in it.

    It is stopped by its pid, rather than left running once no group
    carrying its pid turned out to exist.
    """
    _getpgid_refused(monkeypatch)
    pid_file = tmp_path / "child.pid"
    event = threading.Event()
    _cancel_when(pid_file, event)
    started = time.monotonic()
    try:
        with pytest.raises(ScanCancelled):
            subprocess_utils._run_cancellable(
                [sys.executable, "-c", STUBBORN, str(pid_file), "60"],
                cancel_event=event,
                graceful_timeout=True,
            )
        took = time.monotonic() - started
        assert not _alive(_read_pid(pid_file, "the STUBBORN child")), (
            "the child outlived the stop"
        )
        assert took < 8, took
    finally:
        _kill_if_alive(pid_file)


@pytest.mark.integration
def test_a_reaped_child_is_never_taken_for_a_group_leader(monkeypatch):
    """Once reaped, a child's pid can be another process's, a group leader's even.

    getpgid then answers for that process, and the stop signalled its group.
    """
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait(timeout=30)
    monkeypatch.setattr(subprocess_utils.os, "getpgid", lambda pid: pid)

    assert subprocess_utils._leads_its_own_group(child) is False


#: The child exits at SIGTERM; its child takes a moment on SIGTERM to finish up,
#: records that it did, and exits.
SLOW_TO_FINISH = r"""
import os, pathlib, signal, subprocess, sys, time
out = pathlib.Path(sys.argv[1])
subprocess.Popen([sys.executable, "-c",
    "import os, pathlib, signal, sys, time\n"
    "out = pathlib.Path(sys.argv[1])\n"
    "def finish(*_):\n"
    "    time.sleep(0.5)\n"
    "    (out / 'finished').write_text('yes')\n"
    "    sys.exit(0)\n"
    "signal.signal(signal.SIGTERM, finish)\n"
    "(out / 'grandchild.pid').write_text(str(os.getpid()))\n"
    "time.sleep(60)\n",
    str(out)])
for _ in range(200):
    if (out / "grandchild.pid").exists():
        break
    time.sleep(0.05)
(out / "child.pid").write_text(str(os.getpid()))
time.sleep(60)
"""


@pytest.mark.integration
def test_the_grace_lasts_until_the_whole_group_is_gone(tmp_path):
    """A child that is gone does not end the grace while its group still runs.

    The stop waits for the group as well as the child, so what the child started
    gets the whole grace to finish after SIGTERM, not a SIGKILL the moment the
    child exits.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", SLOW_TO_FINISH, str(tmp_path)], start_new_session=True
    )
    try:
        _wait_for(tmp_path / "child.pid", "the SLOW_TO_FINISH child")
        subprocess_utils._stop_tree(child, 5.0)

        assert (tmp_path / "finished").exists(), (
            "the grandchild was killed before it could finish after SIGTERM"
        )
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=10)
        _kill_if_alive(tmp_path / "grandchild.pid")


class _OutputlessTimeouts(subprocess.Popen):
    """Popen as on Windows, where a communicate that times out carries no output."""

    def communicate(self, data=None, timeout=None):
        try:
            return super().communicate(data, timeout)
        except subprocess.TimeoutExpired as expired:
            raise subprocess.TimeoutExpired(expired.cmd, expired.timeout) from None


class _WindowsOs:
    """The os module, reporting Windows."""

    name = "nt"

    def __getattr__(self, attribute: str):
        return getattr(os, attribute)


@pytest.mark.integration
def test_a_timeout_on_windows_reports_what_the_child_wrote_before_it(
    tmp_path, monkeypatch
):
    """The TimeoutExpired of a timed-out spawn carries the output written so far.

    It was the last communicate's TimeoutExpired output, which is None on
    Windows. subprocess.run reads the pipes once more after the kill there.
    Windows is stood in for: the module's os reports it, and communicate times
    out without output as it does there. With no system directory to find
    taskkill in, the stop kills the child alone.

    The timeout lands only once the child has flushed its line: with a 1s
    timeout and nothing to wait on, a child slow to start under load had not
    written it yet, and the test failed on a missing line it never printed.
    """
    flushed = tmp_path / "flushed"
    monkeypatch.setattr(subprocess_utils, "os", _WindowsOs())
    for name in ("SystemRoot", "SYSTEMROOT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        subprocess_utils.subprocess,
        "Popen",
        _popen_waiting_for(flushed, "the child", base=_OutputlessTimeouts),
    )
    child = (
        "import pathlib, sys, time; print('written before the timeout', flush=True); "
        "pathlib.Path(sys.argv[1]).write_text('yes'); time.sleep(30)"
    )
    with pytest.raises(subprocess.TimeoutExpired) as expired:
        subprocess_utils._run_cancellable(
            [sys.executable, "-c", child, str(flushed)],
            cancel_event=threading.Event(),
            graceful_timeout=False,
            own_group=True,
            capture_output=True,
            text=True,
            timeout=1,
        )

    assert "written before the timeout" in (expired.value.output or ""), (
        expired.value.output
    )


def _group_report(tmp_path: Path) -> str:
    return (
        "import os, pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text("
        "str(os.getpgid(0) == os.getpid()))\n"
    )


@pytest.mark.integration
def test_an_unsandboxed_child_in_a_cancel_scope_leads_its_own_group(tmp_path):
    report = tmp_path / "group.txt"
    with cancel_scope(threading.Event()):
        run_command([sys.executable, "-c", _group_report(tmp_path), str(report)])
    assert report.read_text() == "True"


@pytest.mark.integration
def test_a_sandboxed_child_is_not_given_a_group_here(tmp_path):
    """The Landlock wrapper calls setsid itself; this leaves its spawn alone."""
    report = tmp_path / "group.txt"
    subprocess_utils._run_cancellable(
        [sys.executable, "-c", _group_report(tmp_path), str(report)],
        cancel_event=threading.Event(),
        graceful_timeout=True,
    )
    assert report.read_text() == "False"


@pytest.mark.integration
def test_outside_a_cancel_scope_nothing_changes(tmp_path):
    report = tmp_path / "group.txt"
    run_command([sys.executable, "-c", _group_report(tmp_path), str(report)])
    assert report.read_text() == "False"


# A group that stays in existence after SIGKILL: the scanner's tool ignores
# SIGTERM and starts a helper; the helper forks a process that exits at once,
# then moves itself into a group of its own without reaping it. The unreaped
# zombie keeps the tool's group alive, and the helper, outside it, is never
# signalled. Teardown kills the helper by PID, which lets init reap the zombie.
STUBBORN_GROUP = r"""
import os, pathlib, signal, subprocess, sys, time
out = pathlib.Path(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([sys.executable, "-c",
    "import os, pathlib, sys, time\n"
    "zombie = os.fork()\n"
    "if zombie == 0:\n"
    "    os._exit(0)\n"
    "os.setpgid(0, 0)\n"
    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
    "time.sleep(120)\n",
    str(out / "helper.pid")])
for _ in range(200):
    if (out / "helper.pid").exists():
        break
    time.sleep(0.05)
(out / "child.pid").write_text(str(os.getpid()))
time.sleep(120)
"""


@pytest.mark.integration
def test_a_timeout_stops_a_stubborn_group_once_and_within_its_bound(
    tmp_path, monkeypatch
):
    """The timeout path stops the group once, not again on the way out.

    A second stop would send SIGTERM to a group still held by a zombie and wait
    out the whole grace period for it to go, so the timeout would run that much
    longer than its bound.
    """
    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 3.0)
    stops = []
    real_stop_tree = subprocess_utils._stop_tree

    def counting_stop_tree(process, grace, *args, **kwargs):
        stops.append(grace)
        return real_stop_tree(process, grace, *args, **kwargs)

    monkeypatch.setattr(subprocess_utils, "_stop_tree", counting_stop_tree)
    timeout = 2.0
    started = time.monotonic()
    try:
        with cancel_scope(threading.Event()):
            result = run_command(
                [sys.executable, "-c", STUBBORN_GROUP, str(tmp_path)],
                timeout=timeout,
            )
        took = time.monotonic() - started
    finally:
        for name in ("child", "helper"):
            pid_file = tmp_path / f"{name}.pid"
            if pid_file.exists():
                pid = int(pid_file.read_text())
                if _alive(pid):
                    os.kill(pid, 9)

    assert result.returncode != 0
    assert len(stops) == 1, f"the group was stopped {len(stops)} times: {stops}"
    bound = timeout + subprocess_utils._KILLED_GROUP_SETTLE_SECONDS + 1.0
    assert took < bound, (round(took, 2), bound)


@pytest.mark.integration
def test_a_timeout_stop_that_raises_is_not_retried(tmp_path, monkeypatch):
    """killpg can raise PermissionError; the stop is then not tried again.

    The timeout marked the child stopped only after its stop returned, so a stop
    that raised fell into the handler as a child nobody had stopped, and was
    stopped a second time with the full cancel grace.
    """
    stops = []

    def failing_stop_tree(process, grace, *args, **kwargs):
        stops.append(grace)
        # Ends the child, so Popen's own exit does not wait out its sleep, then
        # fails the way killpg does on a group it may not signal.
        process.kill()
        process.wait()
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils, "_stop_tree", failing_stop_tree)
    with cancel_scope(threading.Event()):
        result = run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=0.5,
        )

    assert result.returncode != 0, result
    assert len(stops) == 1, f"the child was stopped {len(stops)} times: {stops}"


#: A child that ignores SIGTERM, records its pid and waits: only SIGKILL ends it.
STUBBORN = r"""
import os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(float(sys.argv[2]))
"""


def _kill_if_alive(pid_file: Path) -> None:
    if pid_file.exists() and _alive(int(pid_file.read_text())):
        os.kill(int(pid_file.read_text()), 9)


@pytest.mark.integration
def test_a_prompt_stop_asked_for_during_the_grace_shortens_it(tmp_path, monkeypatch):
    """A cancel began the stop with the ordinary grace; then the server was told to stop.

    On SIGTERM the server sets stop_promptly on every scan's cancel event and exits
    soon after. A stop already waiting out the ordinary grace did not notice: its
    child, in a session of its own, outlived the server.
    """
    from automated_security_helper.core.cancellation import CancelEvent

    monkeypatch.setattr(subprocess_utils, "SANDBOX_STOP_GRACE_SECONDS", 8.0)
    pid_file = tmp_path / "child.pid"
    event = CancelEvent()
    asked = {}

    def server_told_to_stop() -> None:
        for _ in range(400):
            if pid_file.exists():
                break
            time.sleep(0.05)
        event.set()
        # Half a second into the ordinary grace, SIGTERM reaches the server.
        time.sleep(0.5)
        asked["at"] = time.monotonic()
        event.stop_promptly = True

    thread = threading.Thread(target=server_told_to_stop, daemon=True)
    thread.start()
    try:
        with cancel_scope(event):
            with pytest.raises(ScanCancelled):
                run_command([sys.executable, "-c", STUBBORN, str(pid_file), "60"])
        took = time.monotonic() - asked["at"]
        thread.join(timeout=5)
        assert not _alive(_read_pid(pid_file, "the STUBBORN child")), (
            "the child outlived the stop"
        )
        assert took < 1.5, (
            f"the stop took {took:.1f}s after a prompt stop was asked for, so it "
            f"waited out the ordinary grace"
        )
    finally:
        _kill_if_alive(pid_file)


@pytest.mark.integration
def test_a_stop_the_kernel_refuses_leaves_the_call_bounded_and_logged(
    tmp_path, monkeypatch, caplog
):
    """killpg can fail with EPERM; the call then returns instead of waiting forever.

    The child was not stopped, so reaping it waited for it to exit on its own,
    for as long as that took.
    """
    pids = []

    def refused(process, grace, *args, **kwargs):
        pids.append(process.pid)
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils, "_stop_tree", refused)
    started = time.monotonic()
    try:
        with cancel_scope(threading.Event()):
            result = run_command(
                [sys.executable, "-c", STUBBORN, str(tmp_path / "child.pid"), "20"],
                timeout=0.5,
            )
        took = time.monotonic() - started
    finally:
        for pid in pids:
            if _alive(pid):
                os.kill(pid, 9)

    assert result.returncode != 0, result
    assert took < 5.0, f"the call waited {took:.1f}s for a child it could not stop"
    assert "could not stop" in caplog.text.lower(), caplog.text


@pytest.mark.integration
def test_every_running_group_is_killed_on_request(tmp_path):
    """What the server calls just before it exits: no scanner group outlives it."""
    pid_file = tmp_path / "child.pid"
    outcome = {}

    def scan() -> None:
        with cancel_scope(threading.Event()):
            outcome["result"] = run_command(
                [sys.executable, "-c", STUBBORN, str(pid_file), "60"]
            )

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    try:
        _wait_for(pid_file, "the STUBBORN child")
        killed = subprocess_utils.kill_running_groups()
        thread.join(timeout=10)
        assert killed == 1, killed
        assert not thread.is_alive(), (
            "the spawn did not return after its group was killed"
        )
        assert not _alive(int(pid_file.read_text()))
    finally:
        _kill_if_alive(pid_file)


@pytest.mark.integration
@pytest.mark.parametrize("stop", ["_stop", "_stop_tree"])
def test_a_prompt_stop_asked_for_before_the_stop_shortens_it_too(tmp_path, stop):
    """A stop that starts with the prompt already set gets the short grace.

    A cancel picks its grace when the stop starts, but a timeout passes the full
    one (SANDBOX_STOP_GRACE_SECONDS for a sandboxed spawn) whatever the prompt
    says, and _wait_out_grace shortened the grace only for a prompt set during
    the wait.
    """
    pid_file = tmp_path / "child.pid"
    child = subprocess.Popen(
        [sys.executable, "-c", STUBBORN, str(pid_file), "60"], start_new_session=True
    )
    prompt = threading.Event()
    prompt.set()
    try:
        _wait_for(pid_file, "the STUBBORN child")
        started = time.monotonic()
        getattr(subprocess_utils, stop)(child, 8.0, prompt)
        took = time.monotonic() - started
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=10)

    assert took < 1.5, f"{stop} waited {took:.1f}s with the prompt already set"


#: A pid no process can have: Linux pid_max is at most 2**22, macOS's is 99999.
_NO_SUCH_PID = 2**30


class _Unstoppable:
    """A child that never exits, whatever it is sent, and records every wait."""

    pid = _NO_SUCH_PID

    def __init__(self) -> None:
        self.waits = []

    def poll(self):
        return None

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if timeout is None:
            raise AssertionError("waited for the child with no bound")
        raise subprocess.TimeoutExpired("child", timeout)


@pytest.mark.unit
def test_stop_waits_a_bounded_time_after_its_kill(monkeypatch):
    """A child a SIGKILL did not end (uninterruptible sleep, say) leaves the stop bounded."""
    child = _Unstoppable()

    subprocess_utils._stop(child, 0.05)

    assert child.waits and None not in child.waits, child.waits


@pytest.mark.unit
def test_stop_tree_waits_a_bounded_time_after_its_kill(monkeypatch):
    monkeypatch.setattr(subprocess_utils, "_signal_group", lambda pgid, signum: False)
    child = _Unstoppable()

    subprocess_utils._stop_tree(child, 0.0)

    assert child.waits and None not in child.waits, child.waits


class _Recorded:
    def __init__(self) -> None:
        self.pid = _NO_SUCH_PID

    def poll(self):
        return None


@pytest.mark.unit
def test_unregistering_an_old_child_leaves_a_new_one_with_its_pid():
    """Once a child is reaped its pid can be reused, and recorded for a new child.

    The old child's own unregistering must not drop the new child's entry, or
    kill_running_groups can no longer reach it.
    """
    old, new = _Recorded(), _Recorded()
    try:
        subprocess_utils._register_group(old)
        subprocess_utils._register_group(new)

        subprocess_utils._unregister_group(old)

        assert subprocess_utils._RUNNING_GROUPS.get(_NO_SUCH_PID) is new
    finally:
        with subprocess_utils._RUNNING_GROUPS_LOCK:
            subprocess_utils._RUNNING_GROUPS.pop(_NO_SUCH_PID, None)
        # _register_group mirrored the pid for the SIGTERM handler's die-now
        # kill; the pop above is not a path that discards it.
        from automated_security_helper.core.cancellation import discard_tool_group

        discard_tool_group(_NO_SUCH_PID)


@pytest.mark.integration
def test_the_final_group_kill_is_skipped_once_the_group_is_gone(monkeypatch):
    """A group id the kernel has released can be a stranger's at once.

    The grace wait reaps the leader and ends when the group is observed
    empty; the kernel has then released the id, and a new process group can
    hold it. A SIGKILL sent there is aimed at whoever got the id next, so
    once the leader is reaped and the group observed gone, no final group
    kill may be sent and no survivor check may read the released id.
    """
    calls = []
    real_killpg = os.killpg

    def recording_killpg(pgid: int, sig: int):
        calls.append((pgid, sig))
        return real_killpg(pgid, sig)

    monkeypatch.setattr(subprocess_utils.os, "killpg", recording_killpg)
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
    )
    try:
        subprocess_utils._stop_tree(child, 10.0)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)

    assert child.returncode is not None, "the stop did not end the child"
    assert (child.pid, signal.SIGTERM) in calls, calls
    assert (child.pid, signal.SIGKILL) not in calls, (
        "a group kill was sent after the group was observed gone, where the "
        f"released id can already be a stranger's: {calls}"
    )

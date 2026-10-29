# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On SIGTERM the server kills every scanner process group still running, then exits.

_stop_on_signal stops the scans with the short grace and calls os._exit(0) once
they have stopped or the wait ran out (130 for Ctrl-C, which takes the same path;
tests/unit/cli/mcp/test_server_exit_paths.py covers it). A scanner's tool runs in a session of its
own, so os._exit does not end it: a scan still stopping when the wait ran out would
leave its tool running after the server had gone. Every process group a cancellable
spawn started is recorded, and whatever of them is left is killed before the exit.

The signal is delivered by replacing anyio's signal receiver, and os._exit by a
recorder, so the test process is neither signalled nor ended.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, List, Optional

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import run_command
from tests.utils.processes import process_running

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the SIGTERM watcher is POSIX only"
    ),
]

#: Ignores SIGTERM, records its pid and waits: only SIGKILL ends it. The pid file
#: is created empty and written ``argv[2]`` seconds later, as a busy host can
#: leave it between the two steps of one write_text.
STUBBORN = (
    "import os, pathlib, signal, sys, time; "
    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    "pid_file = pathlib.Path(sys.argv[1]); "
    "pid_file.touch(); "
    "time.sleep(float(sys.argv[2])); "
    "pid_file.write_text(str(os.getpid())); "
    "time.sleep(60)"
)

#: The two orders a busy host can run a spawn in, each made certain by a delay.
#: "pid written late": the pid file is there and still empty. "recorded late":
#: the tool has written its pid before run_command has recorded its group.
RACES = {
    "none": (0.0, 0.0),
    "pid written late": (1.0, 0.0),
    "recorded late": (0.0, 1.0),
}


class _Spawns:
    """subprocess.Popen, pausing after each child has started, before it returns.

    The pause is the window between a cancellable spawn's child starting and
    run_command recording its group, made as long as a descheduled thread can
    make it.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, pause: float) -> None:
        self.pause = pause
        self.started = threading.Event()
        self.children: List[subprocess.Popen] = []
        real = subprocess.Popen

        def popen(*args: Any, **kwargs: Any) -> subprocess.Popen:
            child = real(*args, **kwargs)
            self.children.append(child)
            self.started.set()
            time.sleep(self.pause)
            return child

        monkeypatch.setattr(subprocess, "Popen", popen)

    def kill_left(self) -> None:
        for child in self.children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)


@pytest.fixture(params=sorted(RACES))
def race(request, monkeypatch) -> float:
    """The race to make certain; returns the tool's delay before writing its pid."""
    write_delay, record_delay = RACES[request.param]
    if record_delay:
        _Spawns(monkeypatch, record_delay)
    return write_delay


@pytest.fixture
def sigkilled(monkeypatch) -> List[int]:
    """Each process group subprocess_utils sends SIGKILL to, in order."""
    killed: List[int] = []
    real = subprocess_utils._signal_group

    def recording(pgid: int, signum: int) -> bool:
        if signum == signal.SIGKILL:
            killed.append(pgid)
        return real(pgid, signum)

    monkeypatch.setattr(subprocess_utils, "_signal_group", recording)
    return killed


#: How long a cell waits for the tool to be running and recorded, and then for it
#: to end. Far longer than either takes on an idle host, and longer than any bound
#: of the stop path (kill_running_groups waits _KILLED_GROUP_SETTLE_SECONDS for a
#: killed group to go), and far shorter than the tool's own 60 s: a tool nothing
#: killed is still running when the wait ends.
WAIT_SECONDS = 20.0


def _alive(pid: int) -> bool:
    return process_running(pid)


def _pid_in(pid_file: Path) -> Optional[int]:
    text = pid_file.read_text() if pid_file.exists() else ""
    return int(text) if text else None


def _recorded_tool(pid_file: Path) -> int:
    """The tool's pid, once it has written it and run_command has recorded its group.

    Both, because the cell is about a recorded group still running: the pid file
    is there before its pid is written, and the tool can write its pid before the
    thread that started it has recorded its group.
    """
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        pid = _pid_in(pid_file)
        if pid is not None:
            with subprocess_utils._RUNNING_GROUPS_LOCK:
                if pid in subprocess_utils._RUNNING_GROUPS:
                    return pid
        time.sleep(0.05)
    pytest.fail(f"the tool was not running and recorded within {WAIT_SECONDS} s")


def _ends(pid: int) -> bool:
    """Whether the tool ends within WAIT_SECONDS: only a SIGKILL ends it that soon.

    Not whether it has ended at the moment of the exit: the stop path sends the
    SIGKILL and waits only _KILLED_GROUP_SETTLE_SECONDS for the group to go, and a
    busy host can take longer than that to end a killed process.
    """
    deadline = time.monotonic() + WAIT_SECONDS
    while _alive(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


def _kill_left(pid_file: Path) -> None:
    pid = _pid_in(pid_file)
    if pid is not None and _alive(pid):
        os.kill(pid, 9)


class _OneSigterm:
    """anyio.open_signal_receiver, delivering one SIGTERM."""

    def __init__(self, *signals):
        self.signals = signals

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __aiter__(self):
        return self._one()

    async def _one(self):
        yield self.signals[0]


def test_sigterm_leaves_no_scanner_group_running(
    tmp_path, monkeypatch, race, sigkilled
):
    pid_file = tmp_path / "tool.pid"
    exits = []
    killed_at_exit: List[int] = []

    def recorded_exit(code: int) -> None:
        exits.append(code)
        killed_at_exit.extend(sigkilled)
        raise SystemExit(code)

    async def stop_nothing(*args, **kwargs) -> None:
        # The scans did not stop within the wait; the tool is still running.
        return None

    def scan() -> None:
        with cancel_scope(threading.Event()):
            run_command([sys.executable, "-c", STUBBORN, str(pid_file), str(race)])

    monkeypatch.setattr(mcp_server.anyio, "open_signal_receiver", _OneSigterm)
    monkeypatch.setattr(mcp_server, "stop_running_scans", stop_nothing)
    monkeypatch.setattr(mcp_server.os, "_exit", recorded_exit)
    monkeypatch.setattr(mcp_server.logging, "shutdown", lambda: None)

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    try:
        pid = _recorded_tool(pid_file)
        with pytest.raises(SystemExit):
            asyncio.run(mcp_server._stop_on_signal())
        ended = _ends(pid)
        thread.join(timeout=10)
    finally:
        _kill_left(pid_file)

    assert exits == [0], exits
    # The stop path sent the kill before the exit; after it, nothing would.
    assert pid in killed_at_exit, "the tool's group was not killed before the exit"
    assert ended, "the scanner's tool did not end after its group was killed"


def test_a_client_leaving_leaves_no_scanner_group_running(
    tmp_path, monkeypatch, race, sigkilled
):
    """The other way a stdio server ends: its client closed the connection.

    The lifespan stops the scans as SIGTERM does, and the process ends right
    after, by the client's own SIGTERM if not sooner; a tool still running then
    outlived it the same way.
    """
    pid_file = tmp_path / "tool.pid"

    async def stop_nothing(*args, **kwargs) -> None:
        return None

    def scan() -> None:
        with cancel_scope(threading.Event()):
            run_command([sys.executable, "-c", STUBBORN, str(pid_file), str(race)])

    monkeypatch.setattr(mcp_server, "stop_running_scans", stop_nothing)
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    try:
        pid = _recorded_tool(pid_file)

        async def serve_and_leave() -> None:
            async with mcp_server._lifespan(mcp_server.mcp):
                pass

        asyncio.run(serve_and_leave())
        killed_by_the_lifespan = list(sigkilled)
        ended = _ends(pid)
        thread.join(timeout=10)
    finally:
        _kill_left(pid_file)

    assert pid in killed_by_the_lifespan, "the lifespan did not kill the tool's group"
    assert ended, "the scanner's tool did not end after its group was killed"


@pytest.mark.parametrize(
    "inside_the_window", [False, True], ids=["once recorded", "while it starts"]
)
def test_a_stop_while_a_tool_starts_kills_it(
    tmp_path, monkeypatch, sigkilled, inside_the_window
):
    """A stop that lands after the tool's child started and before its group is
    recorded.

    kill_running_groups kills the groups recorded when it runs, and the server
    exits right after it. A group recorded only later was never killed: the tool
    outlived the server. "once recorded" is the control: the stop after the
    group is recorded.
    """
    pid_file = tmp_path / "tool.pid"
    spawns = _Spawns(monkeypatch, 1.0 if inside_the_window else 0.0)
    ended_scan: List[BaseException] = []

    def scan() -> None:
        try:
            with cancel_scope(threading.Event()):
                run_command([sys.executable, "-c", STUBBORN, str(pid_file), "0"])
        except BaseException as error:  # the stop ends the spawn
            ended_scan.append(error)

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    try:
        assert spawns.started.wait(WAIT_SECONDS), "the tool was not started"
        (child,) = spawns.children
        if not inside_the_window:
            _recorded_tool(pid_file)
        subprocess_utils.kill_running_groups()
        # What a server exiting now would have done to the tool.
        killed_by_the_stop = list(sigkilled)
        ended = _ends(child.pid)
        thread.join(timeout=10)
    finally:
        spawns.kill_left()
        _kill_left(pid_file)

    assert child.pid in killed_by_the_stop, "the stop returned without killing it"
    assert ended, "the scanner's tool did not end after its group was killed"


def test_a_tool_recorded_after_the_stop_gave_up_waiting_is_killed(
    tmp_path, monkeypatch, sigkilled
):
    """The stop waits only _SPAWN_SETTLE_SECONDS for a spawn already starting.

    One still starting after that records its child after the stop's own kill
    has run, and kills it then: the lifespan's process lives on for a moment, and
    a stop that exits later would otherwise leave the child running.
    """
    monkeypatch.setattr(subprocess_utils, "_SPAWN_SETTLE_SECONDS", 0.05)
    pid_file = tmp_path / "tool.pid"
    spawns = _Spawns(monkeypatch, 1.0)
    ended_scan: List[BaseException] = []

    def scan() -> None:
        try:
            with cancel_scope(threading.Event()):
                run_command([sys.executable, "-c", STUBBORN, str(pid_file), "0"])
        except BaseException as error:
            ended_scan.append(error)

    thread = threading.Thread(target=scan, daemon=True)
    thread.start()
    try:
        assert spawns.started.wait(WAIT_SECONDS), "the tool was not started"
        (child,) = spawns.children
        subprocess_utils.kill_running_groups()
        assert child.pid not in sigkilled, "the stop waited for the spawn after all"
        ended = _ends(child.pid)
        thread.join(timeout=10)
    finally:
        spawns.kill_left()
        _kill_left(pid_file)

    assert child.pid in sigkilled, "the spawn did not kill the child it recorded"
    assert ended, "the scanner's tool did not end after its group was killed"
    assert [type(error).__name__ for error in ended_scan] == ["ScanCancelled"]


def test_a_spawn_after_the_stop_starts_nothing(monkeypatch):
    """Once the server is stopping, a cancellable spawn does not start its child."""
    spawns = _Spawns(monkeypatch, 0.0)
    subprocess_utils.kill_running_groups()

    with pytest.raises(ScanCancelled, match="the server is stopping"):
        with cancel_scope(threading.Event()):
            run_command([sys.executable, "-c", "pass"])

    assert spawns.children == []


def test_the_lifespan_kills_a_recorded_group_itself(monkeypatch):
    """The same, with no scan and no thread: a recorded group and the lifespan's exit.

    The test above depends on a spawn in a thread; this one only on the call in
    the lifespan, so it fails whenever that call is gone.
    """

    async def stop_nothing(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(mcp_server, "stop_running_scans", stop_nothing)
    monkeypatch.setattr(mcp_server, "_serving_stdio", True)
    stand_in = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )
    try:
        subprocess_utils._register_group(stand_in)

        async def serve_and_leave() -> None:
            async with mcp_server._lifespan(mcp_server.mcp):
                pass

        asyncio.run(serve_and_leave())
        try:
            returncode = stand_in.wait(timeout=5)
        except subprocess.TimeoutExpired:
            returncode = None
    finally:
        if stand_in.poll() is None:
            stand_in.kill()
            stand_in.wait(timeout=10)

    assert returncode is not None, "the lifespan left the recorded group running"

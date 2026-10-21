# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stopping MCP server ends the long-running children ASH starts for itself.

Why this exists
---------------
The server's last step before it exits kills the process groups it recorded
(subprocess_utils.kill_running_groups), and only cancellable spawns were
recorded: the scanners' tools. Two children ASH starts for itself ran through
plain subprocess.run, in the server's own process group and unrecorded, so a
server that stopped while one ran exited and left it running:

- nbconvert, which the Jupyter converter runs for each notebook of a scan, for
  up to 60 s;
- git clone, fetch and checkout, which set_source_git runs for a client's
  repository, with no time limit.

Each runs through subprocess_utils.run_ended_with_the_server, so its group is
recorded and killed with the rest. Each cell puts a stand-in for the tool first
on PATH that ignores SIGTERM and sleeps for a minute, stops the server while it
runs, and asserts that the stop killed it and that it ended.
"""

from __future__ import annotations

import os
import signal
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, List, Optional

import pytest

from automated_security_helper.core.cancellation import cancel_scope
from automated_security_helper.utils import subprocess_utils
from tests.unit.converters.nbconvert_stand_in import accept_stand_in_nbconvert
from tests.utils.processes import process_running

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="process groups and SIGKILL are POSIX"
)

#: Far longer than a stand-in takes to start or to end once killed, and far
#: shorter than the minute it sleeps: a stand-in nothing killed is still running.
WAIT_SECONDS = 20.0

#: Ignores SIGTERM, writes its pid to $STAND_IN_PID_FILE and sleeps a minute.
STAND_IN = """\
#!{python}
import os, pathlib, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(os.environ["STAND_IN_PID_FILE"]).write_text(str(os.getpid()))
time.sleep(60)
"""


@pytest.fixture
def stand_in(tmp_path, monkeypatch) -> Path:
    """A bin directory first on PATH, whose tools are the stand-in; its pid file."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("jupyter-nbconvert", "git"):
        tool = bin_dir / name
        tool.write_text(STAND_IN.format(python=sys.executable), encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    pid_file = tmp_path / "stand-in.pid"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("STAND_IN_PID_FILE", str(pid_file))
    return pid_file


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


def _pid_in(pid_file: Path) -> Optional[int]:
    text = pid_file.read_text() if pid_file.exists() else ""
    return int(text) if text else None


def _running_stand_in(pid_file: Path) -> int:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        pid = _pid_in(pid_file)
        if pid is not None:
            return pid
        time.sleep(0.05)
    pytest.fail(f"the stand-in did not start within {WAIT_SECONDS} s")


def _ends(pid: int) -> bool:
    deadline = time.monotonic() + WAIT_SECONDS
    while process_running(pid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


def _stop_while_it_runs(run: Any, pid_file: Path, sigkilled: List[int]) -> None:
    """Start ``run`` on a thread, stop the server once the stand-in runs, check it."""
    ended_with: List[BaseException] = []

    def target() -> None:
        try:
            run()
        except BaseException as error:  # the kill ends the call
            ended_with.append(error)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    pid: Optional[int] = None
    try:
        pid = _running_stand_in(pid_file)
        subprocess_utils.kill_running_groups()
        killed_by_the_stop = list(sigkilled)
        ended = _ends(pid)
        thread.join(timeout=WAIT_SECONDS)
    finally:
        if pid is not None and process_running(pid):
            os.kill(pid, signal.SIGKILL)

    assert pid in killed_by_the_stop, "the stop did not kill the stand-in's group"
    assert ended, "the stand-in did not end after its group was killed"


def test_a_stop_ends_nbconvert(
    stand_in, sigkilled, test_plugin_context, tmp_path, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
        JupyterConverterConfig,
    )

    converter = JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )
    # The converter runs only a jupyter-nbconvert the dependency check verified,
    # and a stand-in belongs to no nbconvert distribution. This cell's subject is
    # the stop, so the stand-in is taken as verified; the check itself is
    # test_nbconvert_runs_directly_only_once_verified's subject.
    accept_stand_in_nbconvert(monkeypatch)
    converter.use_uv_tool = False
    notebook = tmp_path / "stage" / "analysis.ipynb"
    notebook.parent.mkdir()
    notebook.write_text("{}", encoding="utf-8")

    def convert() -> None:
        # As in a scan, which runs its converters in a cancel scope.
        with cancel_scope(threading.Event()):
            converter._run_nbconvert(notebook, tmp_path / "out" / "analysis.py", "x")

    _stop_while_it_runs(convert, stand_in, sigkilled)


def test_a_stop_ends_git_clone(stand_in, sigkilled, tmp_path):
    from automated_security_helper.cli.mcp.source_delivery import set_source_git

    def clone() -> None:
        # A tool call, outside any scan's cancel scope.
        set_source_git(
            "https://example.invalid/repository.git",
            workspace_root=tmp_path / "workspaces",
            session_id="client-one",
        )

    (tmp_path / "workspaces").mkdir()
    _stop_while_it_runs(clone, stand_in, sigkilled)

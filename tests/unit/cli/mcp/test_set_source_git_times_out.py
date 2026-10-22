# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A git command of ``set_source_git`` that stalls is stopped after a bounded time.

Each git command a delivery runs (the clone, and for a ref the fetch and the
checkout) has ``source_delivery.GIT_TIMEOUT_SECONDS`` to finish. One that runs
longer is killed together with every process it started, the partial tree is
removed, and the tool answers with ``error_type: clone_timed_out``.

The git here is a stand-in that hangs in the named subcommand after starting a
helper process of its own, the way git starts ssh or ``git-remote-https``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git
from automated_security_helper.utils.subprocess_utils import clear_find_executable_cache

URL = "https://git.example.invalid/team/repo.git"
SESSION = "clone-session"
#: How long the test lets the server take before calling the call stuck.
CALL_DEADLINE_SECONDS = 20.0

_FAKE_GIT = """\
import json, os, subprocess, sys, time
from pathlib import Path

PIDS = Path({pids!r})
HANG_IN = {hang_in!r}
argv = sys.argv[1:]
subcommand = next(
    (arg for arg in argv if arg in ("clone", "fetch", "checkout")), None
)
if subcommand == "clone" and HANG_IN != "clone":
    Path(argv[-1]).mkdir(parents=True, exist_ok=True)
if subcommand != HANG_IN:
    sys.exit(0)
helper = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(3600)"],
    stdin=subprocess.DEVNULL,
)
PIDS.mkdir(parents=True, exist_ok=True)
(PIDS / "pids.json").write_text(json.dumps({{"git": os.getpid(), "helper": helper.pid}}))
time.sleep(3600)
"""


def _alive(pid: int) -> bool:
    if os.name == "nt":
        listing = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return f'"{pid}"' in listing
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False
    return True


def _gone_within(pids: List[int], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not any(_alive(pid) for pid in pids):
            return True
        time.sleep(0.05)
    return not any(_alive(pid) for pid in pids)


def _kill(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            check=False,
        )
        return
    try:
        os.kill(pid, 9)
    except OSError:
        pass


@pytest.fixture
def fake_git(tmp_path, monkeypatch) -> Iterator[Dict[str, Any]]:
    """A git on PATH that hangs in the subcommand ``state["hang_in"]`` names."""
    state: Dict[str, Any] = {"pids": tmp_path / "pids", "bin": tmp_path / "bin"}
    state["bin"].mkdir()
    workspace = tmp_path / "ws"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.setattr(sd, "GIT_TIMEOUT_SECONDS", 2)
    state["workspace"] = workspace
    reset_default_registry_for_tests()

    def install(hang_in: str) -> None:
        script = state["bin"] / "git"
        script.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(
                _FAKE_GIT.format(pids=str(state["pids"]), hang_in=hang_in)
            )
        )
        script.chmod(0o755)
        if os.name == "nt":
            # Windows starts only a git.exe found on PATH, so the stand-in is
            # named directly there.
            monkeypatch.setattr(sd, "_GIT_ARGV", (sys.executable, str(script)))
        else:
            monkeypatch.setenv(
                "PATH", f"{state['bin']}{os.pathsep}{os.environ.get('PATH', '')}"
            )
        # set_source_git resolves git through find_executable, whose answers are
        # cached by name: an earlier test's lookup must not hide the stand-in.
        clear_find_executable_cache()

    state["install"] = install
    yield state
    clear_find_executable_cache()
    pid_file = state["pids"] / "pids.json"
    if pid_file.exists():
        for pid in json.loads(pid_file.read_text()).values():
            _kill(pid)
    reset_default_registry_for_tests()


def _call_with_deadline(**arguments) -> Dict[str, Any]:
    outcome: Dict[str, Any] = {}

    def run() -> None:
        outcome["result"] = mcp_set_source_git(session_id=SESSION, **arguments)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(CALL_DEADLINE_SECONDS)
    assert not worker.is_alive(), "set_source_git was still running past the deadline"
    return outcome["result"]


@pytest.mark.parametrize(
    "hang_in, arguments",
    [
        ("clone", {"url": URL}),
        ("fetch", {"url": URL, "ref": "release"}),
        ("checkout", {"url": URL, "ref": "release"}),
    ],
)
def test_a_stalled_git_command_is_stopped_with_its_processes(
    fake_git, hang_in, arguments
) -> None:
    fake_git["install"](hang_in)

    result = _call_with_deadline(**arguments)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_timed_out", result
    pids = json.loads((fake_git["pids"] / "pids.json").read_text())
    assert _gone_within(list(pids.values()), 10), (
        f"git or its helper still runs: {pids}"
    )
    source = fake_git["workspace"] / SESSION / "source"
    assert not source.exists(), "the partial tree was left behind"


def test_the_session_can_clone_again_after_a_timeout(fake_git) -> None:
    fake_git["install"]("clone")
    assert _call_with_deadline(url=URL).get("error_type") == "clone_timed_out"

    fake_git["install"]("nothing")
    result = _call_with_deadline(url=URL)

    assert result.get("success") is True, result

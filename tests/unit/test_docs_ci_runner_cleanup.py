# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a CI-runner launch leaves behind: no process, no container.

WHY THIS EXISTS
---------------
``env.launch`` starts a runner as ``env -i ... <runner>``, and ``env`` execs into the
runner. The runner starts children of its own: act's host-mode steps, Jenkins' ``sh``
steps, the docker CLI, and through the Docker socket containers that are not its
children at all. Stopping only the runner when its time limit runs out leaves the rest
running; they go on writing to the log after it says the launch was stopped, and they
change the fixture the next block of the leg runs on. So a launch starts the runner in
a session of its own, and when it ends (by its time limit or not) every process of
that session's group, and every other process the launch started, is stopped:
SIGTERM, a short grace, SIGKILL, then a wait until none is left. The containers the
launch started are then removed, and only after that does the log say the launch was
stopped.

A process can leave both the group and the runner's tree: a double fork into a new
session is re-parented before anything looks for it. So for the launch the test
process is the child subreaper of everything the launch starts, and what the launch
started is found below the test process, whether the runner ended by itself or ran
out of time; and each launch's runner carries an environment marker of its own, which
what it starts inherits unless it clears its environment, as a second net. A process
that both clears its environment and leaves the group after a double fork is found
by the subreaper alone. Since the stop takes whatever below the test process was not
there when the launch began, a process runs one launch at a time.

No runner lets the harness label every container its run starts (act runs steps on
the host, the CodeBuild agent and ``circleci local execute`` start containers through
the socket, and Jenkins' and GitLab's jobs run the docker CLI themselves), so the
launch's containers are the set difference of ``docker ps -aq`` before and after it.

These tests start real processes, but only small shell scripts written into tmp_path;
``docker`` is a fake on the launch's PATH that records its calls. Nothing here starts
a runner, java, docker or a container. Every test kills what its scripts started,
pass or fail.
"""

from __future__ import annotations

import ctypes
import functools
import importlib
import importlib.util
import inspect
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
#: The stop line ``env.launch`` writes when a launch runs out of time.
STOP_LINE = "the launch was stopped"
#: What a left-behind child writes once its delay is over.
LATE = "late-write"
#: The time limit of a launch that is meant to run out, and the delay, longer than
#: the limit and the stop together, after which a left-behind child writes.
LIMIT = 1.5
DELAY = 3

#: prctl(2)'s request for whether a process is a child subreaper.
PR_GET_CHILD_SUBREAPER = 37

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "the runners run on Linux, and a launch makes the test process a child "
        "subreaper and reads /proc, which only Linux has"
    ),
)


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(name: str):
    module = _module("env")
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/env.py defines no {name}")
    return getattr(module, name)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class Scripts:
    """A bin directory for one launch, and the pids its scripts record.

    ``group`` is where a runner records its process group id. It is kept out of
    ``pids``, whose every entry ``kill_all`` may kill: if the runner did not lead a
    group of its own, that id is the test process's own group.
    """

    def __init__(self, tmp_path: Path):
        self.bin = tmp_path / "bin"
        self.pids = tmp_path / "pids"
        self.state = tmp_path / "docker-state"
        self.group = tmp_path / "group"
        self.bin.mkdir()
        self.pids.mkdir()
        self.state.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()

    def write(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def pid(self, name: str) -> int | None:
        path = self.pids / name
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8").strip()
        return int(text) if text.isdigit() else None

    def env(self) -> dict[str, str]:
        return {
            "HOME": str(self.home),
            "PATH": f"{self.bin}{os.pathsep}{_api('SYSTEM_PATH')}",
            "LANG": "C.UTF-8",
        }

    def kill_all(self) -> None:
        """Kill whatever the scripts started, whether or not the launch did.

        Where /proc shows each process's environment, those are the processes whose
        HOME is this test's own; elsewhere, the pids the scripts recorded.
        """
        marker = f"HOME={self.home}".encode()
        proc = Path("/proc")
        if (proc / "self" / "environ").is_file():
            for entry in proc.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    environ = (entry / "environ").read_bytes()
                except OSError:
                    continue
                if marker in environ.split(b"\0"):
                    try:
                        os.kill(int(entry.name), signal.SIGKILL)
                    except OSError:
                        pass
            return
        leader = self.pid("leader")
        if leader is not None:
            try:
                os.killpg(leader, signal.SIGKILL)
            except OSError:
                pass
        for path in self.pids.iterdir():
            text = path.read_text(encoding="utf-8").strip()
            if text.isdigit():
                try:
                    os.kill(int(text), signal.SIGKILL)
                except OSError:
                    pass


@pytest.fixture
def scripts(tmp_path):
    made = Scripts(tmp_path)
    try:
        yield made
    finally:
        made.kill_all()


def _quick():
    """The launch's own process runner, with a SIGTERM grace short enough for a test
    whose child ignores SIGTERM."""
    return functools.partial(_api("run_in_new_session"), stop_grace=0.3)


def _launch(scripts: Scripts, tmp_path: Path, *, timeout: float | None, **extra):
    """``env.launch`` of the fake runner, with launch's own default process runner
    unless ``run`` is given."""
    return _api("launch")(
        scripts.env(),
        [str(scripts.bin / "runner")],
        cwd=tmp_path,
        log=tmp_path / "logs" / "runner.log",
        timeout=timeout,
        **extra,
    )


def _log(tmp_path: Path) -> list[str]:
    return (tmp_path / "logs" / "runner.log").read_text(encoding="utf-8").splitlines()


def _the_stop_line_is_last(lines: list[str]) -> None:
    written = [line for line in lines if line.strip()]
    assert written and STOP_LINE in written[-1], written[-5:]
    assert not any(LATE in line for line in lines), "a child wrote after the stop"


# ---------------------------------------------------------------------------
# A launch that runs out of time leaves no process behind
# ---------------------------------------------------------------------------

#: The fake runners: each records its pid as ``leader``, starts a child that writes
#: to the log after a delay longer than the launch's time limit, records the child's
#: pid, and then outlives the limit.
LEFT_CHILDREN = {
    "a child in the runner's group": (
        '( sleep {delay}; echo "{late}" ) &\necho $! > "{pids}/child"\n'
    ),
    "a child that ignores SIGTERM": (
        '( trap \'\' TERM; sleep {delay}; echo "{late}" ) &\necho $! > "{pids}/child"\n'
    ),
}


def _runner_with(scripts: Scripts, child: str, *, then: str = "exec sleep 30") -> None:
    scripts.write(
        "runner",
        f'echo $$ > "{scripts.pids}/leader"\n'
        f'ps -o pgid= -p $$ > "{scripts.group}"\n'
        + child.format(late=LATE, pids=scripts.pids, delay=DELAY)
        + f'echo ready > "{scripts.pids}/ready"\n'
        + then
        + "\n",
    )


@pytest.mark.integration
@pytest.mark.parametrize("child", sorted(LEFT_CHILDREN))
def test_a_launch_that_runs_out_of_time_leaves_no_process_and_no_later_write(
    scripts, tmp_path, child
):
    _runner_with(scripts, LEFT_CHILDREN[child])
    quick = {"run": _quick()} if "SIGTERM" in child else {}
    with pytest.raises(_api("LaunchTimedOut")):
        _launch(scripts, tmp_path, timeout=LIMIT, **quick)
    assert (scripts.pids / "ready").is_file(), (
        "the fake runner had not started its child when the time limit ran out"
    )
    leader, pid = scripts.pid("leader"), scripts.pid("child")
    assert leader is not None and pid is not None
    group = scripts.group.read_text(encoding="utf-8").strip()
    assert group == str(leader), (
        f"the runner {leader} is in process group {group}, not a group of its own"
    )
    assert not _group_alive(leader), "a process of the launch's group is still alive"
    assert not _alive(pid), f"the runner's child {pid} is still alive"
    _the_stop_line_is_last(_log(tmp_path))


@pytest.mark.integration
def test_a_child_in_a_session_of_its_own_is_stopped_too(scripts, tmp_path):
    """util-linux's script, which the CodeBuild leg runs codebuild_build.sh under,
    starts its child in a new session: that child leaves the runner's process group,
    and is still below the runner when the launch is stopped."""
    if (
        shutil.which("setsid", path=_api("SYSTEM_PATH")) is None
        or not Path("/proc/self/stat").is_file()
    ):
        pytest.skip("needs util-linux's setsid and /proc")
    _runner_with(
        scripts,
        f'setsid sh -c \'echo $$ > "{scripts.pids}/child"; sleep {DELAY}; '
        f'echo "{LATE}"\' &\n'
        "sleep 0.2\n",
    )
    with pytest.raises(_api("LaunchTimedOut")):
        _launch(scripts, tmp_path, timeout=LIMIT)
    pid = scripts.pid("child")
    assert pid is not None, "the fake runner had not started its child"
    assert not _alive(pid), f"the child in its own session, {pid}, is still alive"
    _the_stop_line_is_last(_log(tmp_path))


@pytest.mark.integration
def test_a_runner_that_exits_leaves_no_child_behind(scripts, tmp_path):
    """A runner that exits with a child still running: the child is stopped before
    the launch returns, so it cannot write to the log or the fixture afterwards."""
    _runner_with(scripts, LEFT_CHILDREN["a child in the runner's group"], then="exit 3")
    assert _launch(scripts, tmp_path, timeout=10.0) == 3
    pid = scripts.pid("child")
    assert pid is not None
    assert not _alive(pid), f"the runner's child {pid} outlived the launch"
    assert not any(LATE in line for line in _log(tmp_path))


def _require_setsid() -> None:
    if shutil.which("setsid", path=_api("SYSTEM_PATH")) is None:
        pytest.skip("needs util-linux's setsid")


def _session_child(scripts: Scripts, delay: float = DELAY) -> str:
    """A shell command: a child in a session of its own that records its pid, then
    writes to the log after ``delay`` seconds."""
    return (
        f'setsid sh -c \'echo $$ > "{scripts.pids}/child"; sleep {delay}; '
        f'echo "{LATE}"\''
    )


def _child_stopped(scripts: Scripts, tmp_path: Path, what: str) -> None:
    pid = scripts.pid("child")
    assert pid is not None, "the fake runner had not started its child"
    assert not _alive(pid), f"{what}, {pid}, is still alive"
    assert not any(LATE in line for line in _log(tmp_path))


@pytest.mark.integration
def test_a_double_fork_into_a_new_session_is_stopped_when_the_time_limit_runs_out(
    scripts, tmp_path
):
    """The runner's child forks a grandchild into a session of its own and exits, so
    the grandchild is re-parented before the time limit runs out: it is neither in
    the runner's group nor below the runner. The test process is the subreaper of
    what the launch starts, so the grandchild is below the test process."""
    _require_setsid()
    _runner_with(scripts, f"( {_session_child(scripts)} & )\nsleep 0.2\n")
    with pytest.raises(_api("LaunchTimedOut")):
        _launch(scripts, tmp_path, timeout=LIMIT)
    _child_stopped(scripts, tmp_path, "the grandchild in a session of its own")
    _the_stop_line_is_last(_log(tmp_path))


@pytest.mark.integration
def test_a_child_in_a_session_of_its_own_is_stopped_when_the_runner_exits(
    scripts, tmp_path
):
    """No time limit ran out: the runner exited, and its child in a session of its
    own, outside the group, is stopped before the launch returns."""
    _require_setsid()
    _runner_with(scripts, f"{_session_child(scripts)} &\nsleep 0.2\n", then="exit 3")
    assert _launch(scripts, tmp_path, timeout=10.0) == 3
    _child_stopped(scripts, tmp_path, "the child in a session of its own")


@pytest.mark.integration
def test_a_process_outside_the_tree_is_found_by_the_launch_s_marker(
    scripts, tmp_path, monkeypatch
):
    """The second net: with the tree below the test process hidden, a child in a
    session of its own is still found by the marker its launch's environment holds.
    Finding it so reads every process's environment, which takes longer on a busy
    host than a look at the tree, so the child waits longer before it writes."""
    _require_setsid()
    monkeypatch.setattr(_module("env"), "_descendants", lambda *args, **kwargs: set())
    child = _session_child(scripts, delay=4 * DELAY)
    _runner_with(scripts, f"{child} &\nsleep 0.2\n", then="exit 3")
    assert _launch(scripts, tmp_path, timeout=10.0) == 3
    _child_stopped(scripts, tmp_path, "the child the tree did not show")


def _wait_for(path: Path) -> str:
    """A shell command: wait up to 20 s until ``path`` holds something."""
    return (
        f'i=0; while [ ! -s "{path}" ] && [ "$i" -lt 400 ]; do '
        "sleep 0.05; i=$((i + 1)); done\n"
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    "then,timeout",
    [("exit 3", 20.0), ("exec sleep 60", 4.0)],
    ids=["ended", "timed out"],
)
def test_a_double_forked_child_with_a_cleared_environment_is_found_by_the_subreaper(
    scripts, tmp_path, monkeypatch, then, timeout
):
    """The runner's child double-forks a grandchild that clears its environment
    (``env -i``, so it carries no launch marker) and leads a session of its own
    (``setsid``, so it is out of the runner's group), and exits, so the grandchild is
    re-parented before anything looks for it. Only the test process being the child
    subreaper of what the launch starts keeps the grandchild below the test process,
    where the stop finds it. While the launch runs, the test process is a subreaper.

    The grandchild keeps one variable of the test's own, its HOME, so the fixture
    finds and kills it whatever the launch did. It writes after longer than the time
    limit and the stop together."""
    _require_setsid()
    env = _module("env")
    flags: list[int] = []

    def flagged(real):
        def call(*args, **kwargs):
            flags.append(_child_subreaper_flag())
            return real(*args, **kwargs)

        return call

    monkeypatch.setattr(env, "_processes_before", flagged(env._processes_before))
    monkeypatch.setattr(env, "_stop_launch", flagged(env._stop_launch))
    pids = scripts.pids
    grandchild = (
        f"env -i HOME={shlex.quote(str(scripts.home))} "
        f"PATH={shlex.quote(_api('SYSTEM_PATH'))} setsid sh -c '"
        f'env > "{pids}/grandchild-env"; '
        f'ps -o pgid= -p $$ > "{pids}/grandchild-group"; '
        f'echo $$ > "{pids}/child"; sleep {4 * DELAY}; echo "{LATE}"\''
    )
    _runner_with(
        scripts, f"( {grandchild} & )\n" + _wait_for(pids / "child"), then=then
    )
    if then == "exit 3":
        assert _launch(scripts, tmp_path, timeout=timeout) == 3
    else:
        with pytest.raises(_api("LaunchTimedOut")):
            _launch(scripts, tmp_path, timeout=timeout)
    environ = (pids / "grandchild-env").read_text(encoding="utf-8").splitlines()
    assert not [line for line in environ if line.startswith(_api("LAUNCH_MARKER"))], (
        "the grandchild still carries the launch's marker, so the subreaper is not "
        "the only net that finds it"
    )
    group = (pids / "grandchild-group").read_text(encoding="utf-8").strip()
    child = scripts.pid("child")
    assert group.isdigit() and group == str(child), (
        f"the grandchild {child} does not lead a process group of its own, so it may "
        f"be in the runner's group: ps gave {group!r}"
    )
    assert flags and set(flags) == {1}, (
        f"the test process's subreaper flag while the launch ran: {flags}"
    )
    _child_stopped(scripts, tmp_path, "the grandchild that cleared its environment")
    if then != "exit 3":
        _the_stop_line_is_last(_log(tmp_path))


def _group_states(pgid: int) -> dict[int, str]:
    """The state of each process in the process group ``pgid``, from /proc."""
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_bytes()
        except OSError:
            continue
        fields = stat.rsplit(b")", 1)[-1].split()
        if len(fields) > 2 and fields[2] == str(pgid).encode():
            found[int(entry.name)] = fields[0].decode(errors="replace")
    return found


#: What the log says when a runner ended and left processes running.
STILL_RUNNING = "still running after it ended"


@pytest.mark.integration
def test_a_group_left_with_only_ended_processes_gets_no_still_running_note(
    scripts, tmp_path, monkeypatch
):
    """The runner's child ends after the runner became ``sleep``, which never reaps
    it, so when the runner ends the child is left in the runner's group as a zombie,
    re-parented to the test process. Nothing is running, so the log does not say that
    processes were still running after the runner ended."""
    env = _module("env")
    states: list[dict[int, str]] = []
    real_stop = env._stop_launch

    def stop(process, **kwargs):
        states.append(_group_states(process.pid))
        return real_stop(process, **kwargs)

    monkeypatch.setattr(env, "_stop_launch", stop)
    scripts.write(
        "runner",
        f'echo $$ > "{scripts.pids}/leader"\n( exec sleep 1 ) &\nexec sleep 2\n',
    )
    assert _launch(scripts, tmp_path, timeout=20.0) == 0
    assert states and states[0] and set(states[0].values()) == {"Z"}, (
        "the runner's group did not hold only an ended process when the stop began, "
        f"so this does not test what it says: {states}"
    )
    assert not any(STILL_RUNNING in line for line in _log(tmp_path)), _log(tmp_path)


@pytest.mark.integration
def test_a_group_left_with_a_running_child_gets_the_still_running_note(
    scripts, tmp_path
):
    """The note is kept for what it is for: a child still running in the runner's
    group after the runner ended, which the stop then ends at once."""
    _runner_with(scripts, LEFT_CHILDREN["a child in the runner's group"], then="exit 3")
    assert _launch(scripts, tmp_path, timeout=10.0) == 3
    assert any(STILL_RUNNING in line for line in _log(tmp_path)), _log(tmp_path)
    _child_stopped(scripts, tmp_path, "the runner's child")


@pytest.mark.integration
def test_an_ended_child_started_before_the_launch_keeps_its_exit_code(
    scripts, tmp_path, monkeypatch
):
    """A child the test process started before the launch, which ended and was not
    yet reaped, is outside the runner's group and in what the launch listed before
    its runner started. When the stop reaps the ended processes left in the runner's
    group, it leaves that child to its own Popen, which reads the code it exited
    with."""
    env = _module("env")
    states: list[dict[int, str]] = []
    real_stop = env._stop_launch

    def stop(process, **kwargs):
        states.append(_group_states(process.pid))
        return real_stop(process, **kwargs)

    monkeypatch.setattr(env, "_stop_launch", stop)
    other = subprocess.Popen(
        ["sh", "-c", "exit 7"],
        env=scripts.env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20.0
        stat = env._proc_stat(other.pid)
        while (stat is None or stat.state != "Z") and time.monotonic() < deadline:
            time.sleep(0.05)
            stat = env._proc_stat(other.pid)
        assert stat is not None and stat.state == "Z", (
            f"the test's own child {other.pid} had not ended before the launch: {stat}"
        )
        scripts.write(
            "runner",
            f'echo $$ > "{scripts.pids}/leader"\n( exec sleep 1 ) &\nexec sleep 2\n',
        )
        assert _launch(scripts, tmp_path, timeout=20.0) == 0
        assert states and states[0] and set(states[0].values()) == {"Z"}, (
            "the runner's group did not hold only an ended process when the stop "
            f"began, so the stop had nothing of its own to reap: {states}"
        )
        assert other.wait(timeout=10.0) == 7, (
            "the stop reaped a child of the test process that was there before the "
            "launch"
        )
    finally:
        other.kill()
        other.wait()


@pytest.mark.integration
def test_a_child_another_thread_starts_during_a_launch_is_left_alone(scripts, tmp_path):
    """The runner leads a session of its own, and no process joins an older session,
    so nothing of a launch is in the test process's own session. A child another
    thread of the test process starts while a launch runs is in that session, so the
    stop neither signals nor reaps it: one still running goes on running, and one that
    has ended keeps its exit code for its own Popen.

    That holds only for a child that stays in the test process's session, as these
    two do (_sleeper with no own_group, and a plain Popen). A child started in a
    session of its own (start_new_session, setsid) is taken for the launch's: the stop
    signals it, and reaps it if it has ended, so its own Popen then reports 0."""
    env = _module("env")
    pids = scripts.pids
    scripts.write(
        "runner",
        f'echo $$ > "{pids}/leader"\n'
        f'echo ready > "{pids}/ready"\n'
        f"{_wait_for(pids / 'go')}"
        "exit 0\n",
    )
    result: dict[str, object] = {}

    def first() -> None:
        try:
            result["code"] = _launch(scripts, tmp_path, timeout=60.0)
        except BaseException as error:
            result["error"] = error

    started: list[subprocess.Popen] = []
    thread = threading.Thread(target=first, daemon=True)
    thread.start()
    try:
        try:
            deadline = time.monotonic() + 15.0
            while not (pids / "ready").is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert (pids / "ready").is_file(), "the launch's runner never started"
            running = _sleeper(scripts)
            started.append(running)
            ended = subprocess.Popen(
                ["sh", "-c", "exit 7"],
                env=scripts.env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            started.append(ended)
            stat = env._proc_stat(ended.pid)
            while (stat is None or stat.state != "Z") and time.monotonic() < deadline:
                time.sleep(0.05)
                stat = env._proc_stat(ended.pid)
            assert stat is not None and stat.state == "Z", (
                f"the other thread's child {ended.pid} had not ended: {stat}"
            )
            leader = scripts.pid("leader")
            assert thread.is_alive() and leader is not None and _alive(leader), (
                "the launch ended before the other thread's children started, so "
                "this does not test what it says"
            )
        finally:
            (pids / "go").write_text("go\n", encoding="utf-8")
            thread.join(timeout=60.0)
        assert result == {"code": 0}, result
        assert running.poll() is None, "the stop signalled the other thread's child"
        assert ended.wait(timeout=10.0) == 7, (
            "the stop reaped the other thread's child, so its Popen lost the exit code"
        )
    finally:
        for each in started:
            each.kill()
            each.wait()


@pytest.mark.integration
def test_a_second_launch_while_one_runs_in_the_same_process_is_refused(
    scripts, tmp_path
):
    """One launch at a time per process. A stop takes every process below the test
    process that was not there when its launch began, so a launch running beside
    another would stop the other's processes, and whichever ended first would put
    the subreaper setting back while the other still needed it. A second launch is
    refused before its runner starts, and the first runs on untouched."""
    pids = scripts.pids
    scripts.write(
        "runner",
        f'echo $$ > "{pids}/leader"\n'
        f'echo ready > "{pids}/ready"\n'
        f"{_wait_for(pids / 'go')}"
        "exit 4\n",
    )
    second = scripts.write("second", f'echo ran > "{pids}/second-ran"\n')
    result: dict[str, object] = {}

    def first() -> None:
        try:
            result["code"] = _launch(scripts, tmp_path, timeout=60.0)
        except BaseException as error:
            result["error"] = error

    thread = threading.Thread(target=first, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20.0
        while not (pids / "ready").is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert (pids / "ready").is_file(), "the first launch's runner never started"
        with pytest.raises(_api("LaunchCleanupFailed"), match="one launch at a time"):
            _api("launch")(
                scripts.env(),
                [str(second)],
                cwd=tmp_path,
                log=tmp_path / "logs" / "second.log",
                timeout=10.0,
            )
        assert not (pids / "second-ran").exists(), "the second launch's runner started"
        leader = scripts.pid("leader")
        assert leader is not None and _alive(leader), "the first launch's runner ended"
    finally:
        (pids / "go").write_text("go\n", encoding="utf-8")
        thread.join(timeout=60.0)
    assert result == {"code": 4}, result
    after = _api("launch")(
        scripts.env(),
        [str(second)],
        cwd=tmp_path,
        log=tmp_path / "logs" / "third.log",
        timeout=10.0,
    )
    assert after == 0, "a launch after the first ended was refused"


@pytest.mark.integration
def test_each_launch_s_runner_carries_a_marker_of_its_own(scripts, tmp_path):
    marker = _api("LAUNCH_MARKER")
    scripts.write("runner", f'env > "{scripts.pids}/env-$$"\n')
    for _ in range(2):
        assert _launch(scripts, tmp_path, timeout=10.0) == 0
    values = []
    for path in sorted(scripts.pids.glob("env-*")):
        lines = path.read_text(encoding="utf-8").splitlines()
        mine = [line for line in lines if line.startswith(f"{marker}=")]
        assert len(mine) == 1, lines
        values.append(mine[0])
    assert len(values) == 2, values
    assert values[0] != values[1], "each launch has a marker of its own"
    assert all(len(value) >= len(marker) + 1 + 32 for value in values), values


@pytest.mark.integration
def test_a_process_this_test_had_before_the_launch_is_left_alone(scripts, tmp_path):
    """A child the test process already had when the launch began is in what the
    launch listed, by pid and start time, before its runner started, so the stop
    leaves it alone."""
    keeper = subprocess.Popen(
        ["sleep", "30"],
        env=scripts.env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _runner_with(scripts, "", then="exit 0")
        assert _launch(scripts, tmp_path, timeout=10.0) == 0
        assert keeper.poll() is None, "the launch stopped a process it did not start"
    finally:
        keeper.kill()
        keeper.wait()


@pytest.mark.integration
def test_a_quick_look_finds_the_children_a_full_scan_finds(scripts):
    """A stop looks at the tree below the test process through the children files
    the kernel keeps, a few reads, before it confirms with a scan of every process,
    which on a busy host takes long enough for a left-behind child to write first."""
    keeper = subprocess.Popen(
        ["sleep", "30"],
        env=scripts.env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        descendants = _api("_descendants")
        assert keeper.pid in descendants({os.getpid()}, quick=True)
        assert keeper.pid in descendants({os.getpid()})
    finally:
        keeper.kill()
        keeper.wait()


@pytest.mark.integration
def test_what_is_left_in_the_group_of_a_runner_that_exited_is_signalled_at_once(
    scripts, tmp_path, monkeypatch
):
    """Everything still in the runner's group is the launch's, so it gets SIGTERM
    before the stop takes any time to look for the rest."""
    env = _module("env")
    order: list[str] = []
    real_signal, real_look = env._signal, env._launch_processes

    def signal_(pgid, pids, sig):
        order.append(f"signal {signal.Signals(sig).name} {sorted(pids)}")
        real_signal(pgid, pids, sig)

    def look(*args, **kwargs):
        order.append(f"look {kwargs.get('full')}")
        return real_look(*args, **kwargs)

    monkeypatch.setattr(env, "_signal", signal_)
    monkeypatch.setattr(env, "_launch_processes", look)
    _runner_with(scripts, LEFT_CHILDREN["a child in the runner's group"], then="exit 3")
    assert _launch(scripts, tmp_path, timeout=10.0) == 3
    assert order and order[0] == "signal SIGTERM []", order
    _child_stopped(scripts, tmp_path, "the runner's child")


def _child_subreaper_flag() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int(-1)
    result = libc.prctl(
        ctypes.c_int(PR_GET_CHILD_SUBREAPER),
        ctypes.byref(value),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    assert result == 0, os.strerror(ctypes.get_errno())
    return value.value


@pytest.mark.integration
def test_a_launch_leaves_the_test_process_s_subreaper_setting_as_it_was(
    scripts, tmp_path
):
    before = _child_subreaper_flag()
    _runner_with(scripts, "", then="exit 0")
    assert _launch(scripts, tmp_path, timeout=10.0) == 0
    assert _child_subreaper_flag() == before


@pytest.mark.unit
def test_the_launch_runs_the_process_runner_that_stops_its_group():
    """launch's default is the runner that stops the whole group, never plain
    subprocess.run, which stops only the runner."""
    default = inspect.signature(_api("launch")).parameters["run"].default
    assert default is _api("run_in_new_session")


@pytest.mark.unit
def test_every_process_is_held_before_any_gets_its_signal(monkeypatch):
    """The processes outside the runner's group get their signals one at a time.
    A shell whose child got its signal first and ended could run its next command,
    and write to the log, before its own signal came. So every process of a stop is
    held with SIGSTOP before any gets the signal, and continued after."""
    env = _module("env")
    sent: list[tuple[object, int]] = []
    monkeypatch.setattr(env.os, "killpg", lambda pgid, sig: sent.append(("group", sig)))
    monkeypatch.setattr(env.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    # The processes are named by pid and start time; these two still run, as /proc
    # would say.
    monkeypatch.setattr(env, "_proc_stat", lambda pid: env._Stat("S", 1, 77, 4242))
    env._signal(4242, {4243: 77, 4244: 77}, signal.SIGTERM)
    held = [signal.SIGSTOP] * 3
    assert [sig for _, sig in sent] == held + [signal.SIGTERM] * 3 + [
        signal.SIGCONT
    ] * 3, sent
    assert {target for target, _ in sent} == {"group", 4243, 4244}


def _sleeper(scripts: Scripts, *, own_group: bool = False) -> subprocess.Popen:
    return subprocess.Popen(
        ["sleep", "30"],
        env=scripts.env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=own_group,
    )


@pytest.mark.integration
def test_a_pid_now_held_by_a_process_started_later_is_not_signalled(scripts):
    """A stop names each process it saw by pid and start time. A pid whose process
    now started at another time was handed anew to a process the launch did not
    start, and gets no signal; the group is signalled all the same."""
    env = _module("env")
    keeper, group = _sleeper(scripts), _sleeper(scripts, own_group=True)
    try:
        stat = env._proc_stat(keeper.pid)
        assert stat is not None
        env._signal(group.pid, {keeper.pid: stat.start + 1}, signal.SIGTERM)
        assert group.wait(timeout=10.0) == -signal.SIGTERM, "the group was signalled"
        with pytest.raises(subprocess.TimeoutExpired):
            keeper.wait(timeout=0.5)
        env._signal(None, {keeper.pid: stat.start}, signal.SIGTERM)
        assert keeper.wait(timeout=10.0) == -signal.SIGTERM
    finally:
        for each in (keeper, group):
            each.kill()
            each.wait()


@pytest.mark.integration
def test_a_process_seen_is_running_only_while_its_start_time_is_the_same(scripts):
    env = _module("env")
    keeper = _sleeper(scripts)
    try:
        stat = env._proc_stat(keeper.pid)
        assert stat is not None
        assert env._running(keeper.pid, stat.start, keeper)
        assert not env._running(keeper.pid, stat.start + 1, keeper)
        assert keeper.poll() is None, "a process taken for another was reaped"
    finally:
        keeper.kill()
        keeper.wait()


@pytest.mark.integration
def test_a_group_seen_gone_is_never_signalled_again(scripts, tmp_path, monkeypatch):
    """Once no process is left in the runner's group, its id is free for the system
    to hand out again. So the stop sends no signal to that id while the group is
    empty, and once it has seen the group gone it sends that id none at all, while
    the processes it saw outside the group still get theirs: here a child in a
    session of its own that ignores SIGTERM, which only SIGKILL ends."""
    _require_setsid()
    env = _module("env")
    real = os.killpg
    gone: set[int] = set()
    late: list[tuple[int, int]] = []

    def killpg(pgid, sig):
        if sig != 0:
            try:
                real(pgid, 0)
            except ProcessLookupError:
                late.append((pgid, sig))
            except OSError:
                pass
        try:
            real(pgid, sig)
        except ProcessLookupError:
            if sig == 0:
                gone.add(pgid)
            raise

    monkeypatch.setattr(env.os, "killpg", killpg)
    _runner_with(
        scripts,
        'setsid sh -c \'trap "" TERM; '
        f'echo $$ > "{scripts.pids}/child"; sleep {4 * DELAY}; echo "{LATE}"\' &\n'
        + _wait_for(scripts.pids / "child"),
    )
    with pytest.raises(_api("LaunchTimedOut")):
        _launch(scripts, tmp_path, timeout=4.0, run=_quick())
    leader = scripts.pid("leader")
    assert leader in gone, "the stop never found the runner's group gone"
    assert not late, f"signals sent to the group's id with no process in it: {late}"
    _child_stopped(scripts, tmp_path, "the child that ignores SIGTERM")
    _the_stop_line_is_last(_log(tmp_path))


@pytest.mark.unit
def test_a_group_seen_gone_stays_gone(monkeypatch):
    """A group id that was seen with no process left is never taken back, even if a
    later look finds a group of that id: that is a group the system made anew."""
    env = _module("env")
    answers = iter([True, False, True])
    monkeypatch.setattr(env, "_group_alive", lambda pgid: next(answers))
    group = _api("_Group")(4242)
    assert group.current() == 4242
    assert group.current() is None
    assert group.current() is None, "a group id seen gone was taken back"


@pytest.mark.integration
def test_a_stop_looks_at_the_group_in_every_round_while_it_waits(scripts, monkeypatch):
    """While processes it saw still run, a stop still looks at the runner's group in
    each round, so it knows the group gone as soon as it is empty, before the system
    can hand its id to a new group."""
    env = _module("env")
    keeper = _sleeper(scripts)
    try:
        stat = env._proc_stat(keeper.pid)
        assert stat is not None
        monkeypatch.setattr(env, "_group_alive", lambda pgid: False)
        monkeypatch.setattr(env, "_launch_processes", lambda *args, **kwargs: {})
        group = env._Group(4242)
        stopped, seen = env._settle(
            keeper,
            {keeper.pid: stat.start},
            group=group,
            before={},
            marker=None,
            until=time.monotonic() + 0.2,
            sig=signal.SIGCONT,
        )
        assert not stopped and keeper.pid in seen, seen
        assert group.id is None, "the stop did not look at the group while it waited"
    finally:
        keeper.kill()
        keeper.wait()


# ---------------------------------------------------------------------------
# The containers a launch started are removed, and nothing else
# ---------------------------------------------------------------------------


def _fake_docker(
    scripts: Scripts,
    *,
    ps_fails: bool = False,
    endless: bool = False,
    in_progress: bool = False,
    late: int | None = None,
):
    """A docker that records its calls and lists the containers its state names.

    ``ps`` lists ``existing`` and ``created`` less ``removed``; ``rm -f`` adds to
    ``removed`` and says so on stderr. ``endless`` makes every ``ps`` after the first
    list one more container than before, as if something kept starting them.
    ``in_progress`` makes the first ``rm -f`` of c-new-1 leave it listed, as a
    container the daemon is already removing stays listed for a while. ``late`` lists
    c-late from that ``ps`` on, until it is removed, as a container the daemon creates
    for a client that was stopped after asking for it.
    """
    state = scripts.state
    (state / "existing").write_text("c-old\n", encoding="utf-8")
    listing = (
        f'for id in $(cat "{state}/existing" "{state}/created" 2>/dev/null); do\n'
        f'  grep -qx "$id" "{state}/removed" 2>/dev/null || echo "$id"\n'
        "done\n"
    )
    if late is not None:
        listing += (
            f'n=$(grep -c "^ps" "{state}/calls")\n'
            f'if [ "$n" -ge {late} ] && ! grep -qx c-late "{state}/removed" '
            "2>/dev/null; then echo c-late; fi\n"
        )
    if endless:
        listing += (
            f'n=$(grep -c "^ps" "{state}/calls")\n'
            'if [ "$n" -gt 1 ]; then echo "c-loop-$n"; fi\n'
        )
    failing = (
        'echo "Cannot connect to the Docker daemon" >&2; exit 1\n' if ps_fails else ""
    )
    stuck = (
        f'    if [ "$id" = c-new-1 ] && [ ! -f "{state}/stuck" ]; then\n'
        f'      : > "{state}/stuck"; echo "removal of $id is in progress" >&2; '
        "continue\n"
        "    fi\n"
        if in_progress
        else ""
    )
    scripts.write(
        "docker",
        f'printf \'%s\\n\' "$*" >> "{state}/calls"\n'
        'case "$1" in\n'
        "ps)\n" + failing + listing + ";;\n"
        "rm)\n"
        '  shift; [ "$1" = "-f" ] || exit 2; shift\n'
        '  for id in "$@"; do\n' + stuck + f'    echo "$id" >> "{state}/removed"; '
        'echo "removed container $id" >&2\n'
        "  done\n"
        ";;\n"
        "*) exit 2 ;;\n"
        "esac\n",
    )


def _container_runner(scripts: Scripts, *, then: str) -> None:
    """A runner that starts two containers, as far as the fake docker can tell."""
    state = scripts.state
    scripts.write(
        "runner",
        f'echo $$ > "{scripts.pids}/leader"\n'
        f'echo runner >> "{state}/calls"\n'
        f"printf 'c-new-1\\nc-new-2\\n' >> \"{state}/created\"\n" + then + "\n",
    )


def _calls(scripts: Scripts) -> list[list[str]]:
    path = scripts.state / "calls"
    if not path.is_file():
        return []
    return [line.split() for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_swept(calls: list[list[str]]) -> None:
    lists = [i for i, call in enumerate(calls) if call[:2] == ["ps", "-aq"]]
    removals = [call for call in calls if call[:1] == ["rm"]]
    started = calls.index(["runner"])
    assert lists and lists[0] < started, "the containers are listed before the launch"
    assert any(i > started for i in lists), "and listed again after it"
    assert removals == [["rm", "-f", "c-new-1", "c-new-2"]], removals
    assert lists[-1] > calls.index(removals[0]), "and listed once more to check"


@pytest.mark.integration
@pytest.mark.parametrize(
    "then,timeout",
    [("exec sleep 30", LIMIT), ("exit 3", 10.0)],
    ids=["timed out", "ended"],
)
def test_the_containers_the_launch_started_are_removed_and_no_other(
    scripts, tmp_path, then, timeout
):
    _fake_docker(scripts)
    _container_runner(scripts, then=then)
    if then == "exit 3":
        assert _launch(scripts, tmp_path, timeout=timeout, remove_containers=True) == 3
    else:
        with pytest.raises(_api("LaunchTimedOut")):
            _launch(scripts, tmp_path, timeout=timeout, remove_containers=True)
    calls = _calls(scripts)
    _assert_swept(calls)
    assert not any("c-old" in call for call in calls if call[:1] == ["rm"])
    lines = _log(tmp_path)
    removed = [i for i, line in enumerate(lines) if "removed container c-new" in line]
    assert len(removed) == 2, "docker's own output goes to the launch's log"
    if then != "exit 3":
        stop = max(i for i, line in enumerate(lines) if STOP_LINE in line)
        assert max(removed) < stop, "the containers are gone before the stop line"
        _the_stop_line_is_last(lines)


@pytest.mark.integration
def test_a_launch_that_removes_no_containers_never_runs_docker(scripts, tmp_path):
    _fake_docker(scripts)
    _container_runner(scripts, then="exit 0")
    assert _launch(scripts, tmp_path, timeout=10.0) == 0
    assert _calls(scripts) == [["runner"]]


@pytest.mark.integration
def test_a_launch_whose_containers_cannot_be_listed_never_starts(scripts, tmp_path):
    _fake_docker(scripts, ps_fails=True)
    _container_runner(scripts, then="exit 0")
    with pytest.raises(RuntimeError, match="container"):
        _launch(scripts, tmp_path, timeout=10.0, remove_containers=True)
    assert ["runner"] not in _calls(scripts), "the runner started anyway"


@pytest.mark.integration
def test_a_container_still_listed_after_its_removal_is_removed_again(scripts, tmp_path):
    _fake_docker(scripts, in_progress=True)
    _container_runner(scripts, then="exit 0")
    assert _launch(scripts, tmp_path, timeout=10.0, remove_containers=True) == 0
    removals = [call for call in _calls(scripts) if call[:1] == ["rm"]]
    assert removals == [["rm", "-f", "c-new-1", "c-new-2"], ["rm", "-f", "c-new-1"]]
    assert _calls(scripts)[-1][:2] == ["ps", "-aq"], "listed once more to check"


@pytest.mark.integration
def test_containers_that_keep_appearing_fail_the_launch(scripts, tmp_path):
    _fake_docker(scripts, endless=True)
    _container_runner(scripts, then="exit 0")
    with pytest.raises(_api("LaunchCleanupFailed")) as raised:
        _launch(scripts, tmp_path, timeout=10.0, remove_containers=True)
    assert "c-loop" in str(raised.value)


@pytest.mark.integration
def test_a_launch_that_needed_sigkill_lists_its_containers_once_more(scripts, tmp_path):
    """A docker client stopped by SIGKILL may have asked the daemon for a container
    that exists only after the client is gone: after the listing that finds none
    left, one more listing, a pause later, finds it and removes it."""
    # The ps calls: before the launch, after it (c-new-1 and c-new-2), after their
    # removal (none), and then the one more, which lists c-late.
    _fake_docker(scripts, late=4)
    _container_runner(scripts, then="trap '' TERM\nexec sleep 30")
    with pytest.raises(_api("LaunchTimedOut")):
        _launch(scripts, tmp_path, timeout=LIMIT, remove_containers=True, run=_quick())
    removals = [call for call in _calls(scripts) if call[:1] == ["rm"]]
    assert removals == [["rm", "-f", "c-new-1", "c-new-2"], ["rm", "-f", "c-late"]]
    assert _calls(scripts)[-1][:2] == ["ps", "-aq"], "listed once more to check"
    _the_stop_line_is_last(_log(tmp_path))

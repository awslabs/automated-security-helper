# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment a CI runner starts in, and where the runner tests may run at all.

The runner tests run under ``uv run``, so their own PATH starts with the test
virtualenv's ``bin``, which holds the checkout's editable ``ash``, and their environment
carries setup-uv's cache and tool directories, the outer job's GITHUB_PATH and its
token. act in host mode and Jenkins' ``sh`` steps hand their environment to every step
of the pipeline they run, so a pipeline that scanned before it installed, or whose PATH
line was broken, would find that ``ash`` and pass. Each runner is therefore started as
``env -i`` with an environment built here from nothing: a new, empty HOME, a fixed
system PATH after the directory that holds the runner itself, LANG, the pytest
session's one ASH tool download cache, and only what that runner needs (JAVA_HOME for
Jenkinsfile Runner, ImageOS and ImageVersion for the setup actions under act).

A second control sits outside: ``write_poisoned_ash`` puts an ``ash`` that touches a
sentinel file first on the test process's own PATH. If any pipeline ever reached the
outer environment, the sentinel would exist when the session ends.

A launch leaves nothing running. ``env`` execs into the runner, and the runner starts
children of its own (act's host-mode steps, Jenkins' ``sh`` steps, the docker CLI) and,
through the Docker socket, containers. So the runner leads a session of its own, and
for the launch the test process is a child subreaper (prctl PR_SET_CHILD_SUBREAPER): a
process the launch started whose parent ends is re-parented to the test process, not
to init, so it stays below it even after a double fork into a new session
(util-linux's ``script``, which the CodeBuild leg runs under, starts its child in a new
session too). Each launch's runner also gets an environment marker of its own,
LAUNCH_MARKER, which everything it starts inherits unless it clears its environment.
When the runner ends, by its time limit or not, every process of its session's group,
every process below the test process that the launch started, and every process whose
environment holds the marker gets SIGTERM, a short grace, then SIGKILL, and the launch
waits until none is left. Each process is named by its pid and its start time, so a pid
the system hands out again is never signalled, and the group's id is not signalled once
the group is gone. A launch that asks for it then removes the containers it started.
Only after that does the log say a launch was stopped, so nothing it started writes to
the log afterwards or changes the fixture the next block runs on. Where the test
process cannot be a subreaper or there is no /proc (anywhere but Linux), a launch is
refused before it starts.

A stop takes every process below the test process that was not there when its launch
began, and the subreaper setting is the whole process's, so a process runs one launch
at a time: a second launch while one runs, from another thread, is refused.

The runs mount the Docker socket into containers (the CodeBuild agent and ``circleci
local execute`` do), so they refuse to start anywhere but a GitHub-hosted runner unless
DOCTEST_CI_RUNNERS_ANYWHERE=1 is set, and that refusal is an error, never a skip. A
machine given DOCTEST_CI_RUNNERS_ANYWHERE=1 must not share its Docker daemon with
anything else: each launch removes every container the daemon gained while it ran.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RUNNERS = (
    "act",
    "gitlab-ci-local",
    "jenkinsfile-runner-lts",
    "jenkinsfile-runner-bundled",
    "codebuild-agent",
    "circleci",
)
JENKINS_RUNNERS = ("jenkinsfile-runner-lts", "jenkinsfile-runner-bundled")

#: The system directories a GitHub-hosted Ubuntu runner keeps its own tools in: git,
#: docker, python3, rsync and util-linux's ``script`` in /usr/bin, node (which act runs
#: JavaScript actions with) in /usr/local/bin. Nothing of a virtualenv, uv or the
#: setup actions' tool cache.
SYSTEM_PATH = os.pathsep.join(
    ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
)

#: The image variables the setup actions read to find their prebuilt tools.
ACT_IMAGE_VARIABLES = ("ImageOS", "ImageVersion")

ANYWHERE = "DOCTEST_CI_RUNNERS_ANYWHERE"

#: Programs that start only from an argv their own launcher built after checking what
#: they run: Jenkinsfile Runner, whose core and plugins jenkinsfile_runner_argv
#: hashes first. An argv of any other type with a word that holds one of these names,
#: in any case (its jar, a versioned install, a log or leg named after it), is refused.
CHECKED_PROGRAMS = ("jenkinsfile-runner",)
#: Programs an argv of any other type may not name at all: java runs Jenkinsfile
#: Runner's jars directly. A word is split into shell words (at blanks, quotes,
#: ``;&|()<>`` and ``=``), so the program is found behind a wrapper (``env java``,
#: ``timeout 60 java``) and in a shell string (``sh -c``, ``script -c``, ``env -S``),
#: by its name or a path that ends in it.
CHECKED_INTERPRETERS = ("java",)
_SHELL_WORD_BREAKS = re.compile(r"[\s;&|()<>'\"`=]+")

#: The environment variable each launch's runner gets a value of its own in. What the
#: runner starts inherits it, so a process of the launch is found by it even after it
#: left the runner's group and the tree below the test process.
LAUNCH_MARKER = "DOCTEST_CI_RUNNER_LAUNCH"
#: prctl(2) requests: make the calling process a child subreaper, or read whether it is.
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
#: Seconds between full looks for the launch's processes while a stop waits.
STOP_LOOK_EVERY = 0.5

#: Seconds the processes of an ending launch get to exit after SIGTERM, before SIGKILL.
STOP_GRACE = 10.0
#: Seconds to wait, after SIGKILL, until none of them is left.
STOP_WAIT = 30.0
#: How often a stop looks whether the processes are gone.
STOP_POLL = 0.05
#: Seconds each docker command of a container sweep may take.
DOCKER_TIMEOUT = 120.0
#: Rounds of listing and removing before containers that keep appearing fail a launch.
SWEEP_ROUNDS = 5
#: Seconds between rounds when a removed container is still listed.
SWEEP_PAUSE = 2.0

#: Held for the whole of a launch: one launch at a time per process.
_ONE_LAUNCH = threading.Lock()


class NotOnAGitHubHostedRunner(RuntimeError):
    """Raised when the runner tests are asked to run on any other host."""


class LaunchTimedOut(RuntimeError):
    """A runner did not finish within the time its launch was given."""


class LaunchCleanupFailed(RuntimeError):
    """A launch's processes or containers could not all be stopped or removed, or,
    before it started, another launch of this process was still running, its
    containers could not be listed, or the test process could not be made the
    subreaper of what it starts."""


class _Stopped(subprocess.TimeoutExpired):
    """The time limit ran out, and what could not be stopped or removed after it."""

    def __init__(self, cmd: Sequence[str], timeout: float, problems: list[str]):
        super().__init__(list(cmd), timeout)
        self.problems = problems


class CheckedArgv(tuple):
    """An argv its launcher built after checking what it starts.

    Only run_jenkinsfile_runner.jenkinsfile_runner_argv makes one; launch_argv starts
    a program of CHECKED_PROGRAMS from nothing else.
    """

    __slots__ = ()


def host_problem(environ: Mapping[str, str]) -> str | None:
    """Why this host may not run the runners, or None when it may.

    A GitHub-hosted runner sets GITHUB_ACTIONS=true and RUNNER_ENVIRONMENT=github-hosted;
    act sets ACT and not RUNNER_ENVIRONMENT. DOCTEST_CI_RUNNERS_ANYWHERE=1, exactly,
    overrides.
    """
    if environ.get(ANYWHERE) == "1":
        return None
    if (
        environ.get("GITHUB_ACTIONS") == "true"
        and environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and "ACT" not in environ
    ):
        return None
    return (
        "the CI-runner tests start containers that are given the Docker socket, so "
        "they run only on a GitHub-hosted runner (GITHUB_ACTIONS=true, "
        "RUNNER_ENVIRONMENT=github-hosted, ACT unset); set "
        f"{ANYWHERE}=1 to run them on a machine you can throw away, whose Docker "
        "daemon is not shared with anything else: each launch removes every "
        "container the daemon gained while it ran"
    )


def require_github_hosted(environ: Mapping[str, str]) -> None:
    """Raise NotOnAGitHubHostedRunner unless ``environ`` is a host the runs may use."""
    problem = host_problem(environ)
    if problem is not None:
        raise NotOnAGitHubHostedRunner(problem)


def launch_env(
    runner: str,
    *,
    home: Path,
    runner_bin: Path,
    tool_cache: Path,
    outer: Mapping[str, str],
    java: str | None = None,
) -> dict[str, str]:
    """The whole environment ``runner`` starts in.

    ``home`` must be an existing, empty directory, so nothing installed by an earlier
    pipeline is found by this one. ``outer`` is the test process's environment, read
    only for the values a runner needs from the hosted runner itself.
    """
    if runner not in RUNNERS:
        raise ValueError(f"no runner named {runner!r}; the runners are {RUNNERS}")
    home = Path(home)
    if not home.is_dir() or any(home.iterdir()):
        raise ValueError(f"HOME {home} must be a new, empty directory")
    env = {
        "HOME": str(home),
        "PATH": f"{runner_bin}{os.pathsep}{SYSTEM_PATH}",
        "LANG": "C.UTF-8",
        "ASH_TOOL_DOWNLOAD_CACHE": str(tool_cache),
    }
    if runner == "act":
        for name in ACT_IMAGE_VARIABLES:
            if not outer.get(name):
                raise ValueError(f"{name} is not set; act's setup actions read it")
            env[name] = outer[name]
    if runner in JENKINS_RUNNERS:
        if not java or not java.isdigit():
            raise ValueError(
                f"{runner} needs the Java version of its core, not {java!r}"
            )
        name = f"JAVA_HOME_{java}_X64"
        if not outer.get(name):
            raise ValueError(f"{name} is not set; {runner}'s core runs on Java {java}")
        env["JAVA_HOME"] = outer[name]
    elif java is not None:
        raise ValueError(f"{runner} takes no Java version")
    return env


def _names_an_interpreter(word: str) -> bool:
    """Whether a shell word of ``word`` is a program of CHECKED_INTERPRETERS, by its
    name or a path that ends in it."""
    for part in _SHELL_WORD_BREAKS.split(word.lower()):
        if any(
            part == name or part.endswith(f"/{name}") for name in CHECKED_INTERPRETERS
        ):
            return True
    return False


def launch_argv(env: Mapping[str, str], argv: Sequence[str | os.PathLike]) -> list[str]:
    """``env -i K=V ... argv``: the command line that starts ``argv`` with ``env`` only.

    Unless ``argv`` is the CheckedArgv its launcher built, it is refused when any word
    holds a name of CHECKED_PROGRAMS in any case (as the program, a shell command
    string, a path under its install, its jar), or when any word, or any shell word of
    one, is a program of CHECKED_INTERPRETERS: argv0 itself, the program a wrapper
    such as ``env`` or ``timeout`` runs, or one in a ``sh -c``, ``script -c`` or ``env
    -S`` string. A word that only mentions the name, a log path, is refused too: no
    launch has a reason to carry one. What this cannot see: java started through a
    variable (``"$JAVA"``), an alias or a function, a script file that starts it, or a
    program of another name that execs it. None of the launchers builds those; only
    jenkinsfile_runner_argv starts java.
    """
    words = [os.fspath(word) for word in argv]
    if not words:
        raise ValueError("nothing to launch")
    if "=" in words[0]:
        raise ValueError(f"{words[0]!r} would be read by env as a variable")
    if not isinstance(argv, CheckedArgv):
        named = [
            word
            for word in words
            if any(program in word.lower() for program in CHECKED_PROGRAMS)
        ]
        if named:
            raise ValueError(
                f"{named[0]!r} names a program that only an argv from "
                "jenkinsfile_runner_argv, which checks its core and plugins, may start"
            )
        java = [word for word in words if _names_an_interpreter(word)]
        if java:
            raise ValueError(
                f"{java[0]!r} runs Java, which only an argv from "
                "jenkinsfile_runner_argv, which checks its core and plugins, may start"
            )
    assignments = []
    for key, value in env.items():
        if not key or "=" in key or "\0" in key or "\0" in value:
            raise ValueError(f"{key!r} cannot be passed through env")
        assignments.append(f"{key}={value}")
    return ["env", "-i", *assignments, *words]


def _note(out: Any, text: str) -> None:
    """Append one line to a launch's log, when its output goes to one."""
    if hasattr(out, "write"):
        out.write(f"\n{text}\n".encode(errors="replace"))
        out.flush()


@dataclass(frozen=True, eq=False)
class ContainerSweep:
    """Finds the containers a launch started, and removes them when it ends.

    No runner lets the harness label every container its run starts. act runs its jobs
    on the host, and their steps run the docker CLI themselves, as Jenkins' ``sh``
    steps do and gitlab-ci-local does, with no option that adds a label; the CodeBuild
    agent and ``circleci local execute`` start their build containers from inside a
    container, through the Docker socket. So a launch's containers are the ones
    ``docker ps -aq`` lists after it and did not list before it. That counts every
    container the daemon gained meanwhile, so the runs need a Docker daemon nothing
    else uses, as a GitHub-hosted runner's is.

    docker runs through env -i with the launch's own environment, so it is the docker
    the runner itself finds. Its own messages go to the launch's log.
    """

    env: Mapping[str, str]

    def _docker(self, args: list[str], out: Any) -> subprocess.CompletedProcess:
        if hasattr(out, "flush"):
            out.flush()
        return subprocess.run(
            launch_argv(self.env, ["docker", *args]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=out if hasattr(out, "fileno") else subprocess.DEVNULL,
            env={"PATH": SYSTEM_PATH},
            timeout=DOCKER_TIMEOUT,
            check=False,
        )

    def containers(self, out: Any = None) -> set[str]:
        """The full id of every container, running or not.

        Raises LaunchCleanupFailed when docker cannot list them.
        """
        try:
            listed = self._docker(["ps", "-aq", "--no-trunc"], out)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LaunchCleanupFailed(
                f"docker ps -aq could not list the containers: {error}"
            ) from None
        if listed.returncode != 0:
            raise LaunchCleanupFailed(
                "docker ps -aq could not list the containers: it exited "
                f"{listed.returncode}"
            )
        return set(listed.stdout.decode(errors="replace").split())

    def remove_new(
        self, before: set[str], out: Any = None, *, settle: bool = False
    ) -> list[str]:
        """Remove every container not in ``before`` with ``docker rm -f``, and list
        again until none is left; the problems, [] when none is.

        A container still listed after its ``docker rm -f`` (one the daemon is already
        removing, as it does a ``--rm`` container whose client was stopped) is given
        SWEEP_PAUSE seconds before the next round. With ``settle``, for a launch whose
        processes needed SIGKILL, the first listing that finds none left is followed
        by one more, SWEEP_PAUSE seconds later: a docker client killed mid-request may
        have asked for a container the daemon creates only after the client is gone.
        """
        new: list[str] = []
        settled = not settle
        for _ in range(SWEEP_ROUNDS):
            try:
                listed = sorted(self.containers(out) - before)
            except LaunchCleanupFailed as error:
                return [str(error)]
            if not listed:
                if settled:
                    return []
                settled = True
                time.sleep(SWEEP_PAUSE)
                continue
            if set(listed) & set(new):
                time.sleep(SWEEP_PAUSE)
            new = listed
            _note(out, f"removing the containers this launch started: {' '.join(new)}")
            try:
                self._docker(["rm", "-f", *new], out)
            except (OSError, subprocess.TimeoutExpired) as error:
                return [f"docker rm -f could not remove {' '.join(new)}: {error}"]
        return [
            (
                f"containers kept appearing after {SWEEP_ROUNDS} rounds of docker rm "
                f"-f; the last round found {' '.join(new)}"
            )
        ]


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class _Group:
    """The runner's process group, by its id, until it is seen with no process left.

    From then on the system may hand its id to a new group, so ``current`` gives None
    for good and the id is never signalled again.
    """

    def __init__(self, pgid: int):
        self.id: int | None = pgid

    def current(self) -> int | None:
        """The group's id while it has a process left, else None."""
        if self.id is not None and not _group_alive(self.id):
            self.id = None
        return self.id


def _reap_ended(pgid: int) -> None:
    """Reap each child of this process in the group ``pgid`` that has ended.

    Call it only once the runner, the group's leader and a child of this process,
    has been reaped by subprocess, so it is never taken from subprocess here. What
    is left is the launch's own: the runner made the group, and an orphan of the
    launch is re-parented to this process, its subreaper. An ended process, a
    zombie, runs no longer, but until it is reaped it keeps the group in being.
    """
    waitid = getattr(os, "waitid", None)
    if waitid is None:
        return
    while True:
        try:
            if waitid(os.P_PGID, pgid, os.WEXITED | os.WNOHANG) is None:
                return
        except ChildProcessError:
            return


@dataclass(frozen=True)
class _Stat:
    """What /proc/<pid>/stat says of a process: its state, its parent, when it
    started (clock ticks since boot), which tells it from a later process given the
    same pid, and its session."""

    state: str
    ppid: int
    start: int
    session: int


def _proc_stat(pid: int | str) -> _Stat | None:
    """/proc/<pid>/stat, or None when the process is gone or it cannot be read."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            stat = handle.read()
    except OSError:
        return None
    # The command name in parentheses may hold anything; the fields after it are the
    # state, the parent's pid, the process group, the session, and 15 more up to the
    # start time.
    fields = stat.rsplit(b")", 1)[-1].split()
    if len(fields) < 20 or not all(fields[i].isdigit() for i in (1, 3, 19)):
        return None
    return _Stat(
        fields[0].decode(errors="replace"),
        int(fields[1]),
        int(fields[19]),
        int(fields[3]),
    )


def _children_files(pids: set[int]) -> set[int] | None:
    """Every process below ``pids``, from the children file /proc keeps for each
    thread: a few reads, where a full scan reads every process on the host. None
    where the kernel keeps no such files (CONFIG_PROC_CHILDREN)."""
    own = os.getpid()
    if not os.path.isfile(f"/proc/{own}/task/{own}/children"):
        return None
    found: set[int] = set()
    queue = list(pids)
    while queue:
        pid = queue.pop()
        try:
            tasks = os.listdir(f"/proc/{pid}/task")
        except OSError:
            continue
        for task in tasks:
            try:
                with open(f"/proc/{pid}/task/{task}/children", "rb") as handle:
                    children = handle.read().split()
            except OSError:
                continue
            for child in map(int, children):
                if child not in found:
                    found.add(child)
                    queue.append(child)
    return found


def _descendants(pids: set[int], *, quick: bool = False) -> set[int]:
    """Every process below ``pids``, read from /proc; none where there is no /proc.

    With ``quick``, from the children files where the kernel keeps them. Those can
    miss a child that starts or ends while they are read, so a stop ends only on a
    full scan, of every process's parent.
    """
    if quick:
        found = _children_files(pids)
        if found is not None:
            return found
    try:
        names = os.listdir("/proc")
    except OSError:
        return set()
    children: dict[int, list[int]] = {}
    for name in names:
        stat = _proc_stat(name) if name.isdigit() else None
        if stat is not None:
            children.setdefault(stat.ppid, []).append(int(name))
    found = set()
    queue = list(pids)
    while queue:
        for child in children.get(queue.pop(), []):
            if child not in found:
                found.add(child)
                queue.append(child)
    return found


def _marked(marker: str) -> set[int]:
    """Every process whose environment holds ``marker``, a ``NAME=value`` entry.

    A process's environment can be read by its own user, which every process of a
    launch runs as, and by root.
    """
    wanted = marker.encode()
    found: set[int] = set()
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/environ", "rb") as handle:
                entries = handle.read().split(b"\0")
        except OSError:
            continue
        if wanted in entries:
            found.add(int(name))
    return found


def _prctl(option: int, argument: Any) -> None:
    """prctl(2) with one argument; OSError where it fails, or where there is none."""
    if not sys.platform.startswith("linux"):
        raise OSError(
            errno.ENOSYS, f"prctl(2) is Linux's, and this host is {sys.platform}"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    unused = ctypes.c_ulong(0)
    if libc.prctl(ctypes.c_int(option), argument, unused, unused, unused) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _child_subreaper(value: int) -> int:
    """Make this process a child subreaper (1) or not (0); return what it was.

    A child subreaper is the parent every orphan below it is re-parented to, instead
    of init. Raises LaunchCleanupFailed where that cannot be done: anywhere but Linux.
    """
    previous = ctypes.c_int(0)
    try:
        _prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(previous))
        _prctl(_PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(value))
    except (OSError, AttributeError) as error:
        raise LaunchCleanupFailed(
            "a launch makes the test process the child subreaper of what it starts, "
            "so a process that leaves the runner's tree is still found and stopped, "
            f"and this host cannot (prctl PR_SET_CHILD_SUBREAPER, Linux only): {error}"
        ) from None
    return previous.value


def _processes_before() -> dict[int, int]:
    """Each process below this one, by pid, with its start time: what a launch that
    starts now did not start."""
    found = {}
    for pid in _descendants({os.getpid()}):
        stat = _proc_stat(pid)
        if stat is not None:
            found[pid] = stat.start
    return found


def _running(pid: int, start: int, runner: subprocess.Popen) -> bool:
    """Whether the process ``pid`` that started at ``start`` still runs.

    A pid whose process started at another time was handed to a later process,
    which is not the one seen, so it does not. A process that has ended and not been
    reaped (a zombie) does not either. When this process is its parent, as it is of
    every orphan of a launch, it is reaped here, so the group it was in empties; the
    runner itself is left to subprocess, which keeps its exit code.
    """
    stat = _proc_stat(pid)
    if stat is None or stat.start != start:
        return False
    if stat.state not in ("Z", "X"):
        return True
    if pid != runner.pid:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
    return False


def _launch_processes(
    runner: subprocess.Popen,
    before: Mapping[int, int],
    marker: str | None,
    *,
    full: bool,
) -> dict[int, int]:
    """The processes of the launch ``runner`` leads that still run, by pid, with
    their start times.

    Those are every process below this one that was not there when the launch began
    (``before``, by pid and start time), which, this process being the subreaper of
    what the launch starts, takes in those that left the runner's tree; and, in a
    ``full`` look, every process whose environment holds the launch's ``marker``. A
    look that is not full reads only the tree's children files, where the kernel
    keeps them, so it is quick however many processes the host runs.

    A process in this process's own session is never the launch's: the runner leads
    a session of its own, and no process joins an older session. So a child another
    thread of this process starts during a launch, and that stays in this session, is
    left out, and the stop neither signals it nor reaps it. A child that thread
    starts in a session of its own (start_new_session, setsid) is not told apart
    from the launch's: the stop signals it, and reaps it if it has ended, so its own
    Popen then reports 0.
    """
    runner.poll()
    own_session = os.getsid(0)
    found: dict[int, int] = {}
    for pid in _descendants({os.getpid()}, quick=not full):
        stat = _proc_stat(pid)
        if (
            stat is not None
            and stat.session != own_session
            and before.get(pid) != stat.start
        ):
            found[pid] = stat.start
    if full and marker is not None:
        for pid in _marked(marker):
            stat = _proc_stat(pid)
            if stat is not None and stat.session != own_session:
                found[pid] = stat.start
    found.pop(os.getpid(), None)
    return {pid: start for pid, start in found.items() if _running(pid, start, runner)}


def _signal(
    pgid: int | None, processes: Mapping[int, int], sig: signal.Signals
) -> None:
    """Send ``sig`` to the process group ``pgid``, unless it is None, and to each of
    ``processes`` (pid and start time), all at once as far as they can tell.

    Each is stopped (SIGSTOP) before any gets ``sig``, and continued (SIGCONT) after.
    Signalled one at a time, a shell whose child ended first could run its next
    command, and write to the log, before its own signal came. A pid whose process
    started at another time than the one seen was handed to a later process, which
    gets nothing.
    """
    targets = dict(processes)
    for each in (signal.SIGSTOP, sig, signal.SIGCONT):
        if pgid is not None:
            try:
                os.killpg(pgid, each)
            except OSError:
                pass
        for pid, start in list(targets.items()):
            stat = _proc_stat(pid)
            if stat is None or stat.start != start:
                del targets[pid]
                continue
            try:
                os.kill(pid, each)
            except OSError:
                pass


def _settle(
    runner: subprocess.Popen,
    seen: dict[int, int],
    *,
    group: _Group,
    before: Mapping[int, int],
    marker: str | None,
    until: float,
    sig: signal.Signals,
) -> tuple[bool, dict[int, int]]:
    """Wait until nothing of the launch is left, or until ``until`` (time.monotonic).

    Between looks only ``seen`` (pid and start time) and the runner's ``group`` are
    checked, the group every round, so it is known gone as soon as it is empty.
    Every STOP_LOOK_EVERY seconds the tree below this process is looked at again,
    quickly; once ``seen`` and the group are gone, a full look, the marker's
    included, has to find nothing. A process a look finds that was not seen gets
    ``sig`` too. Returns whether nothing is left, and what still runs.
    """
    next_look = time.monotonic() + STOP_LOOK_EVERY
    while True:
        runner.poll()
        seen = {
            pid: start for pid, start in seen.items() if _running(pid, start, runner)
        }
        found: dict[int, int] = {}
        gone = group.current() is None
        if not seen and gone:
            found = _launch_processes(runner, before, marker, full=True)
            if not found and group.current() is None:
                return True, {}
        elif time.monotonic() >= next_look:
            found = _launch_processes(runner, before, marker, full=False)
            next_look = time.monotonic() + STOP_LOOK_EVERY
        new = {pid: start for pid, start in found.items() if seen.get(pid) != start}
        if new:
            _signal(group.current(), new, sig)
            seen.update(new)
        if time.monotonic() >= until:
            return False, seen
        time.sleep(STOP_POLL)


def _stop_launch(
    process: subprocess.Popen,
    *,
    grace: float,
    wait: float,
    out: Any,
    before: Mapping[int, int],
    marker: str | None,
) -> tuple[list[str], bool]:
    """Stop every process of the launch ``process`` leads; the problems, [] when none
    is left, and whether that took SIGKILL.

    Those are the processes of its group (``process`` started a session of its own,
    so its pid is the group's id), every process below this one that the launch
    started, and every process whose environment holds ``marker``
    (_launch_processes), whether the runner ended or ran out of time. Whatever is
    still in the runner's group gets SIGTERM before anything is looked for, and what
    a quick look finds below this process right after. Each process gets SIGTERM,
    then SIGKILL ``grace`` seconds after the stop began, and the stop waits up to
    ``wait`` seconds more for none to be left. Only a full look that finds nothing
    left, the marker's included, ends a stop. ``process`` itself is reaped by
    subprocess as it ends, so the group's id stays its own until then. Each process
    is signalled by pid only while that pid's process has the start time it was seen
    with, so a pid the system hands out anew is left alone; and the group's id is
    not signalled once the group is seen gone (_Group).

    When the runner had ended by itself, the processes of its group that ended too,
    and that the runner never reaped, are reaped first: those zombies run no longer,
    so the log's note that processes were still running after the runner ended names
    only what was running.
    """
    group = _Group(process.pid)
    began = time.monotonic()
    process.poll()
    ended = process.returncode is not None
    if ended:
        _reap_ended(process.pid)
    grouped = group.current() is not None
    if grouped:
        # All of the group is the launch's: no look needed before its signal.
        _signal(group.current(), {}, signal.SIGTERM)
    seen = _launch_processes(process, before, marker, full=False)
    if not seen and group.current() is None:
        seen = _launch_processes(process, before, marker, full=True)
    if ended and (grouped or seen):
        _note(out, "processes the launch started were still running after it ended")
    if not seen and group.current() is None:
        return [], False
    _signal(group.current(), seen, signal.SIGTERM)
    stopped, seen = _settle(
        process,
        seen,
        group=group,
        before=before,
        marker=marker,
        until=began + grace,
        sig=signal.SIGTERM,
    )
    if stopped:
        return [], False
    _signal(group.current(), seen, signal.SIGKILL)
    stopped, seen = _settle(
        process,
        seen,
        group=group,
        before=before,
        marker=marker,
        until=time.monotonic() + wait,
        sig=signal.SIGKILL,
    )
    if stopped:
        return [], True
    left = " ".join(map(str, sorted(seen)))
    pgid = group.current()
    held = f"process group {pgid}" if pgid is not None else ""
    named = ", ".join(filter(None, [held, left]))
    return [f"processes of the launch are still running after SIGKILL: {named}"], True


def run_in_new_session(
    command: Sequence[str],
    *,
    timeout: float | None = None,
    containers: ContainerSweep | None = None,
    marker: str | None = None,
    stop_grace: float = STOP_GRACE,
    stop_wait: float = STOP_WAIT,
    check: bool = False,
    start_new_session: bool = True,
    **popen: Any,
) -> subprocess.CompletedProcess:
    """subprocess.run for a launch: the runner leads a session of its own, and nothing
    it started outlives it.

    For the launch this process is a child subreaper, so whatever the launch starts
    stays below it, and ``marker``, the ``NAME=value`` entry the launch put in the
    runner's environment, finds what left even that tree. When the runner ends, or
    runs out of ``timeout`` seconds, every process of its session's group, every
    process below this one that the launch started, and every process with
    ``marker`` is stopped (SIGTERM, ``stop_grace`` seconds, SIGKILL, up to
    ``stop_wait`` seconds more); then ``containers``, when given, removes the
    containers the launch started, listed before the runner starts, with one more
    listing after a pause when the stop took SIGKILL. A time limit that runs out
    raises subprocess.TimeoutExpired only after all that. Anything that could not be
    stopped or removed is written to the runner's stdout and raises
    LaunchCleanupFailed (with the time limit, it rides on the TimeoutExpired). A host
    where this process cannot be a child subreaper, or that has no /proc, refuses the
    launch with LaunchCleanupFailed before anything starts. The subreaper setting is
    put back as it was afterwards. ``popen`` is passed to subprocess.Popen.

    One launch at a time per process. A stop takes every process below this one that
    was not there when its launch began, and the subreaper setting is the process's,
    not a thread's, so two launches at once would stop each other's processes, and
    whichever ended first would put the setting back while the other still needed
    it. A launch started while another of this process runs is refused with
    LaunchCleanupFailed before anything starts; nothing waits for the other to end.
    A child that another thread of this process starts while a launch runs is in this
    process's own session, which nothing of a launch is in, so the stop leaves it
    alone (_launch_processes), unless it starts a session of its own: then it is
    taken for the launch's, as any process below this one that the launch did not
    find at its start is.
    """
    if not start_new_session:
        raise ValueError("a launch's runner always starts in a session of its own")
    if not _ONE_LAUNCH.acquire(blocking=False):
        raise LaunchCleanupFailed(
            "one launch at a time per process: another launch of this process is "
            "still running, and a stop takes every process below this one that was "
            "not there when its own launch began"
        )
    try:
        previous = _child_subreaper(1)
        try:
            if _proc_stat(os.getpid()) is None:
                raise LaunchCleanupFailed(
                    "a launch finds the processes it started in /proc, and this host "
                    "has none to read"
                )
            out = popen.get("stdout")
            before = _processes_before()
            listed = containers.containers(out) if containers is not None else set()
            process = subprocess.Popen(list(command), start_new_session=True, **popen)
            timed_out = False
            try:
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
            finally:
                problems, killed = _stop_launch(
                    process,
                    grace=stop_grace,
                    wait=stop_wait,
                    out=out,
                    before=before,
                    marker=marker,
                )
                if containers is not None:
                    problems += containers.remove_new(listed, out, settle=killed)
                for problem in problems:
                    _note(out, problem)
        finally:
            _child_subreaper(previous)
    finally:
        _ONE_LAUNCH.release()
    if timed_out:
        raise _Stopped(command, timeout or 0.0, problems)
    if problems:
        raise LaunchCleanupFailed("; ".join(problems))
    code = process.returncode
    if check and code != 0:
        raise subprocess.CalledProcessError(code, list(command))
    return subprocess.CompletedProcess(list(command), code)


def launch(
    env: Mapping[str, str],
    argv: Sequence[str | os.PathLike],
    *,
    cwd: Path,
    log: Path,
    run: Callable[..., subprocess.CompletedProcess] = run_in_new_session,
    timeout: float | None = None,
    remove_containers: bool = False,
) -> int:
    """Start ``argv`` with exactly ``env``, its output appended to ``log``, and wait.

    The child's stdin is /dev/null and its stdout and stderr go to ``log`` only, never
    to this process's output, which the job log shows. ``env`` itself is found on the
    system PATH, not on this process's own. The runner leads a session of its own,
    and gets LAUNCH_MARKER with a value of this launch's own on top of ``env``; every
    process the launch started is stopped when the runner ends (run_in_new_session);
    with ``remove_containers``, so is every container it started (ContainerSweep).
    One launch at a time per process: run_in_new_session refuses a second while one
    runs. Returns the exit code. A run that takes longer than ``timeout`` seconds is
    stopped the same way, then the log says so, and LaunchTimedOut is raised naming
    the log.

    ``run`` replaces run_in_new_session in tests: one that starts nothing leaves
    nothing to stop or remove.
    """
    token = secrets.token_hex(16)
    env = {**env, LAUNCH_MARKER: token}
    command = launch_argv(env, argv)
    sweep = ContainerSweep(dict(env)) if remove_containers else None
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as out:
        try:
            completed = run(
                command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                env={"PATH": SYSTEM_PATH},
                check=False,
                timeout=timeout,
                start_new_session=True,
                containers=sweep,
                marker=f"{LAUNCH_MARKER}={token}",
            )
        except subprocess.TimeoutExpired as expired:
            problems = list(getattr(expired, "problems", []))
            out.write(
                f"\nthe launch was stopped after its time limit of {timeout} s\n".encode()
            )
            left = f"; and {'; '.join(problems)}" if problems else ""
            raise LaunchTimedOut(
                f"{os.fspath(argv[0])} did not finish within {timeout} s; its log is "
                f"{log}{left}"
            ) from None
    return completed.returncode


def fresh_home(parent: Path, name: str) -> Path:
    """A new, empty directory ``parent/name`` for one launch's HOME."""
    home = Path(parent) / name
    home.parent.mkdir(parents=True, exist_ok=True)
    home.mkdir()
    return home


def write_poisoned_ash(bin_dir: Path, sentinel: Path) -> Path:
    """Write ``bin_dir/ash``, which records that it ran in ``sentinel`` and fails."""
    bin_dir = Path(bin_dir)
    sentinel = Path(sentinel)
    bin_dir.mkdir(parents=True, exist_ok=True)
    ash = bin_dir / "ash"
    ash.write_text(
        "#!/bin/sh\n"
        "# The ash on the runner tests' own PATH. A pipeline that reaches it is not\n"
        "# running in the environment it was given.\n"
        f"mkdir -p {shlex.quote(str(sentinel.parent))}\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(sentinel))}\n"
        "echo 'the outer ash ran; the pipeline reached the test process environment' >&2\n"
        "exit 97\n",
        encoding="utf-8",
    )
    ash.chmod(0o755)
    return ash


def poisoned_ash_problem(sentinel: Path) -> str | None:
    """A problem naming ``sentinel`` when the poisoned ash ran, else None."""
    sentinel = Path(sentinel)
    if not sentinel.exists():
        return None
    try:
        first = sentinel.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    except OSError:
        first = []
    called = f" (called as: ash {first[0][:200]})" if first else ""
    return (
        f"the outer ash ran{called}: {sentinel} exists, so a pipeline found the test "
        "process's own PATH"
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run the shell and python blocks of a docs page the way a reader would.

Not a test module: test_docs_examples.py runs every page through this, and
test_docs_runner_can_fail.py proves it reports what it should. Blocks and markers come
from scripts/docs_checks.py, the same parser the static checks use, so the two never
disagree about which blocks exist or what their markers say.

A text block marked ``<!-- doctest: output -->`` directly after a block that runs is
that block's output sample: the runner compares the two (docs_checks.normalize_output
says what is ignored) and fails the sample when a line of it is not in the output.

One page is one session. Its blocks run in document order in one copy of a fixture
project, so a later block sees the files an earlier one wrote. Each shell block is its
own bash process, and the session is carried between them: the working directory, and
every variable the block exported or assigned (blocks run under ``set -a``, so a plain
``FOO=bar`` is exported too). A python block runs in a fresh interpreter, in the
session's directory and environment, and changes neither.

A block that leaves a process running past its shell fails. Each block starts in a
session of its own, so the shell's pid is the id of the block's process group. When the
shell has exited the runner reads that group, ends whatever still runs in it with
SIGKILL, and fails the block: its report names each process by pid and command, and the
block counts for nothing. A reader's shell returns when the example's commands do, so an
example that starts something and never waits for it behaves differently for the reader
too, and a process left running keeps the coverage context of the block that started it:
what it runs after that block ended would be credited to the block, though nothing of
the block shows it. A block that starts a process in the background waits for it, or
stops it and waits for it to end. A process that leaves the group (``setsid``, a daemon
that detaches into a session of its own) is not seen.

What a block can reach is narrowed, not sandboxed. HOME and the XDG directories are
private to the session. PATH is the interpreter's bin directory, the directories ASH
installs scanner tools into for the invoking user, and the system's (session_path),
never the rest of the invoking user's PATH: a tool found there would run in a session
on one machine and be missing on another. Every proxy variable points at a local port
that refuses connections, so a client that honors them (uv, pip, npm, curl, requests, urllib) fails
at once instead of after a retry budget; uv, pip and npm are also told they are
offline, and the container clients point at a socket that does not exist. Measured: a
default ``ash`` scan of the sample fixture took 134 s with only the proxies set (uv
retried each tool install) and 12.6 s with UV_OFFLINE added.

Not covered: a program that opens a socket itself, ignoring the proxy variables,
reaches the network; and every block runs as the invoking user, with that user's
access to the filesystem outside the session. A network namespace (``unshare -rn``)
would close the first, but it maps the user to root inside the namespace, which
changes what the commands under test do, starts with loopback down, and needs the
AppArmor user-namespace restriction lifted on Ubuntu 24.04 runners. Run the examples
where a doc's commands are trusted, as CI does.

Where it runs: POSIX hosts, and the docs job runs it on Linux. A shell block is run by
``bash`` (``sh`` for an ``sh`` block) and hands its session to the next block through
``env -0`` and ``pwd``. A block that runs past its timeout is ended with ``os.killpg``,
which Windows lacks, and a session's PATH ends in the POSIX directories of SYSTEM_PATH.
The docs job has no Windows runner (scripts/docs_checks.py, WINDOWS_SHELLS), so the
tests of this runner skip on Windows instead of running against a session built for
POSIX.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from tests.utils.runner_state import developer_environment_record

REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_TAIL_LINES = 25


def load_docs_checks():
    """scripts/docs_checks.py, loaded by path the way verify_docs_freshness.py loads it."""
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "docs_checks.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Shell exit codes for a command that could not run: not executable, not found.
COULD_NOT_RUN = (126, 127)


@dataclass
class BlockResult:
    page: str
    line: int
    lang: str
    command: str
    expected: str
    exit_code: int | None
    output: str
    seconds: float
    timed_out: bool = False
    #: Why the step failed when it is not about an exit code (a refused save-as).
    refused: str | None = None
    #: For an output sample: the line of it the output lacks.
    mismatch: str | None = None
    #: The session's directories and what an output comparison reads them as.
    paths: tuple[tuple[str, str], ...] = ()
    #: What the block left running when its shell exited, each as ``<pid> <command>``:
    #: the processes of its process group that the runner then ended. A block that left
    #: one fails whatever its exit code was.
    left_running: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        if (
            self.refused
            or self.mismatch
            or self.timed_out
            or self.left_running
            or self.exit_code is None
        ):
            return False
        if self.expected == "any":
            return True
        if self.expected == "nonzero":
            # 126 and 127: the command could not run at all, which is a broken
            # example, not the failure the block is meant to show. macOS
            # /bin/bash 3.2 exits 1 for a non-executable file, so there the
            # guard is weaker by the shell, not by this runner.
            return self.exit_code not in (0, *COULD_NOT_RUN)
        return self.exit_code == int(self.expected)

    def report(self) -> str:
        tail = "\n".join(self.output.rstrip().splitlines()[-OUTPUT_TAIL_LINES:])
        command = "\n".join(
            "    " + line for line in self.command.strip().splitlines()[:12]
        )
        if self.refused:
            verdict = self.refused
        elif self.mismatch:
            verdict = self.mismatch
        elif self.timed_out:
            verdict = f"timed out after {self.seconds:.0f} s"
        elif self.left_running:
            verdict = (
                "left a process running after its shell exited, which the runner "
                f"ended (exit code {self.exit_code}, expected {self.expected})"
            )
        elif self.exit_code in COULD_NOT_RUN:
            verdict = (
                f"exit code {self.exit_code}: a command was not found or not "
                f"executable (expected {self.expected})"
            )
        else:
            verdict = f"exit code {self.exit_code}, expected {self.expected}"
        left = ""
        if self.left_running:
            left = "  left running, ended by the runner:\n" + "".join(
                f"    {member}\n" for member in self.left_running
            )
        return (
            f"{self.page}:{self.line}: {self.lang} block failed: {verdict}\n"
            f"  command:\n{command}\n"
            f"{left}"
            f"  output (last {OUTPUT_TAIL_LINES} lines):\n"
            + "\n".join("    " + line for line in tail.splitlines())
        )


def runnable_blocks(page) -> list:
    """The blocks of a page the runner executes: unmarked or ``run`` shell and python."""
    checks = load_docs_checks()
    return [block for block in page.blocks if checks.runner_runs(block)]


def compared_samples(page) -> dict[int, object]:
    """The output samples the runner compares, by id: each maps to the block above it,
    whose output it shows. These are the blocks the CLI check reads as output
    (docs_checks.output_samples); the marker check reports an output marker anywhere
    else."""
    return load_docs_checks().output_samples(page)


def session_blocks(page) -> list:
    """Every block a session handles, in page order: runnable ones, save-as ones, and
    the output samples to compare.

    A save-as block whose path is refused stays in, so the refusal is reported.
    """
    runnable = {id(block) for block in runnable_blocks(page)}
    samples = compared_samples(page)
    return [
        block
        for block in page.blocks
        if block.closed
        and (
            id(block) in runnable
            or id(block) in samples
            or (block.save_as and block.mode != "illustrative")
        )
    ]


#: The system's directories, last on a session's PATH.
SYSTEM_PATH = ("/usr/local/bin", "/usr/bin", "/bin")


#: The variables tests/conftest.py moves into a private directory for the whole pytest
#: run, or removes for it, and records (those that were set) as JSON in
#: ASH_TEST_DEVELOPER_HOME. The record also holds the other uv directory variables;
#: only the two that name uv's tool bin directory are restored here, because those
#: are the ones _uv_tool_bin_dir and the ``uv tool dir --bin`` child read.
_MOVED_BY_THE_TEST_SESSION = (
    "HOME",
    "USERPROFILE",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "UV_TOOL_BIN_DIR",
    "XDG_BIN_HOME",
)


def invoking_user_environment() -> dict[str, str]:
    """This process's environment, with the variables the test session moved put back.

    tests/conftest.py points HOME, USERPROFILE and three XDG directories at a private
    directory before collection, so Path.home() here is that directory, which holds
    no tool. It also removes uv's directory variables for the whole session. ``ash
    dependencies install`` ran as the invoking user, outside the test session, and put
    its tools under that user's home, or under the directory the user's
    UV_TOOL_BIN_DIR or XDG_BIN_HOME names. The values the session replaced or removed
    are the ``env`` part of the JSON in ASH_TEST_DEVELOPER_HOME (read by
    developer_environment_record), and a variable that was unset is absent from it.
    A variable absent from the record is removed from the copy, which is also what
    the session did, so a value the process holds now is not trusted. Without the
    record (this module run outside that conftest) nothing was moved and the
    environment is returned as it is.
    """
    env = dict(os.environ)
    recorded = developer_environment_record()
    if recorded:
        for name in _MOVED_BY_THE_TEST_SESSION:
            value = recorded.get(name)
            if value:
                env[name] = str(value)
            else:
                env.pop(name, None)
    return env


def _uv_tool_bin_dir(user_env: dict[str, str], home: Path) -> Path:
    """uv's tool bin directory for ``user_env``, resolved the way ``uv tool dir --bin``
    resolves it: UV_TOOL_BIN_DIR, else XDG_BIN_HOME, else ``home``/.local/bin.

    Read from the environment, not from uv, so the directory is known where the
    pytest process cannot run uv at all: a runner that installs the tools with a uv
    on its own PATH and then runs pytest from a virtual environment that has no uv
    beside its interpreter and no uv on the process's PATH.
    """
    for name in ("UV_TOOL_BIN_DIR", "XDG_BIN_HOME"):
        value = user_env.get(name)
        if value:
            return Path(value)
    return home / ".local" / "bin"


def _uv_executable() -> str | None:
    """uv beside this interpreter, else uv on PATH; None when neither is there."""
    beside = shutil.which("uv", path=str(Path(sys.executable).parent))
    return beside or shutil.which("uv")


def ash_tool_dirs() -> list[Path]:
    """The directories ASH installs scanner tools into for the invoking user, that exist.

    ``ash dependencies install`` puts a downloaded binary in ASH's bin directory
    (ASH_BIN_PATH, else ~/.ash/bin, as core/constants.py resolves it) and a Python
    tool in uv's tool bin directory with ``uv tool install`` (UV_TOOL_BIN_DIR, else
    XDG_BIN_HOME, else ~/.local/bin, as ``uv tool dir --bin`` resolves it). A
    session's HOME is private, so ASH and uv inside it would look only in the
    session's own, empty copies; on PATH, the invoking user's are found the way ASH
    finds any tool on PATH. "The invoking user's" means the home the user had before
    the test session moved it (invoking_user_environment): in the pytest process
    Path.home() is the session's private home, where nothing is installed.

    uv's directory is resolved from that environment first (_uv_tool_bin_dir), so it
    is found with no uv reachable from this process; when uv is reachable it is also
    asked, as a further source, since a uv configured through its own settings files
    can answer another directory. Duplicates are dropped, in first-seen order.
    """
    user_env = invoking_user_environment()
    from_env = user_env.get("ASH_BIN_PATH")
    home = Path(user_env["HOME"]) if user_env.get("HOME") else Path.home()
    dirs = [Path(from_env) if from_env else home / ".ash" / "bin"]
    dirs.append(_uv_tool_bin_dir(user_env, home))
    uv_path = _uv_executable()
    if uv_path:
        try:
            answer = subprocess.run(
                [uv_path, "tool", "dir", "--bin"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=user_env,
            )
        except (OSError, subprocess.TimeoutExpired):
            answer = None
        if answer is not None and answer.returncode == 0 and answer.stdout.strip():
            dirs.append(Path(answer.stdout.strip()))
    return [d for d in dict.fromkeys(dirs) if d.is_dir()]


def session_path() -> str:
    """The PATH a session runs with: this interpreter's bin directory, the directories
    ASH installed tools into (ash_tool_dirs), then the system's."""
    return os.pathsep.join(
        dict.fromkeys(
            [str(Path(sys.executable).parent)]
            + [str(d) for d in ash_tool_dirs()]
            + list(SYSTEM_PATH)
        )
    )


def session_environment(root: Path, port: int, path: str) -> dict[str, str]:
    """The environment every session starts with, for a session directory ``root``.

    Every proxy variable points at ``port``, which refuses connections, and HOME, the
    XDG directories and TMPDIR are inside ``root``. A block sees this, plus what earlier
    blocks of its session set; docs_checks.check_session_variables reads its names.
    """
    home = root / "home"
    proxy = f"http://127.0.0.1:{port}"
    env = {
        "PATH": path,
        "VIRTUAL_ENV": str(Path(sys.executable).parent.parent),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "TMPDIR": str(home / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "COLUMNS": "100",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Docs Example",
        "GIT_AUTHOR_EMAIL": "docs-example@example.com",
        "GIT_COMMITTER_NAME": "Docs Example",
        "GIT_COMMITTER_EMAIL": "docs-example@example.com",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
        # No container daemon either: a scan in container mode would pull images
        # through the daemon, which does not read the proxy variables above.
        "DOCKER_HOST": f"unix://{root / 'no-docker.sock'}",
        "CONTAINER_HOST": f"unix://{root / 'no-podman.sock'}",
        "UV_OFFLINE": "1",
        "UV_NO_PROGRESS": "1",
        "PIP_NO_INDEX": "1",
        "npm_config_offline": "true",
        "NO_PROXY": "",
        "no_proxy": "",
    }
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env[name] = proxy
    return env


def marker_env(block) -> dict[str, str]:
    """The variables a marker's env="A=1,B=2" sets, for its own block only."""
    pairs = "" if block.marker is None else str(block.marker.keys.get("env", ""))
    env = {}
    for pair in pairs.split(","):
        name, sep, value = pair.strip().partition("=")
        if sep:
            env[name] = value
    return env


def block_fixture(block) -> str:
    """The fixture project a block runs in: its marker's fixture=, or the default."""
    checks = load_docs_checks()
    if block.marker is None:
        return checks.DEFAULT_FIXTURE
    return str(block.marker.keys.get("fixture", checks.DEFAULT_FIXTURE))


def starts_session(block, fixture_in_use: str | None) -> bool:
    """Whether the runner starts a new session for a block it runs or saves.

    It does at a page's first such block, at a block marked fresh, and at a block on
    another fixture than the session in use. A new session holds only
    session_environment, and nothing an earlier block set.
    """
    fresh = block.marker is not None and bool(block.marker.keys.get("fresh", False))
    return fixture_in_use is None or fresh or block_fixture(block) != fixture_in_use


def page_sessions(page) -> list[tuple[int, str, object]]:
    """(session number, the session's fixture, block) for each block a page's run
    runs or saves, in page order. Output samples are compared, not run, so they
    start no session and are left out."""
    samples = compared_samples(page)
    sessions: list[tuple[int, str, object]] = []
    number, fixture = 0, None
    for block in session_blocks(page):
        if id(block) in samples:
            continue
        if starts_session(block, fixture):
            number += 1
            fixture = block_fixture(block)
        sessions.append((number, fixture, block))
    return sessions


def _refusing_port() -> tuple[socket.socket, int]:
    """A socket and a loopback port on which connections are refused at once.

    On Linux a bound, never-listening socket answers a connection with a reset, and
    holding it keeps the port from being handed to another process. On macOS a
    connection to such a socket is not answered and the client waits out its timeout
    (a 30 s urlopen timed out instead of being refused), so there the socket is
    closed once the port is read: a port nothing holds is refused by every OS.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    if sys.platform != "linux":
        sock.close()
    return sock, port


@dataclass
class Session:
    root: Path
    fixture: str
    cwd: Path
    env: dict[str, str]
    blocked_port: socket.socket = field(repr=False)
    #: The fixture copy the page runs in; save-as paths are relative to it.
    project: Path | None = None


#: Set in the pytest process to switch the docs feature coverage collection on: the
#: directory the coverage data and the runner's per-page records are written to.
COVERAGE_DIR_VARIABLE = "ASH_DOCS_COVERAGE_DIR"
#: Given to each block's own processes: the coverage context its lines are recorded
#: under. Not an ``ASH_`` name, which ASH's own namespace and the scanner sandbox's
#: environment allowlist use.
COVERAGE_CONTEXT_VARIABLE = "DOCS_COVERAGE_CONTEXT"
#: The version of the per-page record ``DocsCoverage.write_record`` writes.
RECORD_SCHEMA = 1

#: What every measured process reads (coverage.py starts in each Python process of a
#: session through its ``a1_coverage.pth`` when COVERAGE_PROCESS_START names a file).
#: ``source_pkgs`` names the package, where ``source`` would be read as a directory
#: relative to the process's own working directory, which is the page's fixture copy.
#: The data file is an absolute path, so a process that lost a variable cannot write
#: to ``/data``. ``patch = fork`` re-arms coverage in a forked child, and nothing is
#: saved inside ``os._exit``: multiprocessing's fork workers end there, and a pool shut
#: down by its ``with`` block (detect-secrets' ``scan_files``) sends SIGTERM to every
#: worker still alive, one in the middle of that save included, which left a data file
#: the check cannot read. A process that ends in ``os._exit`` (a pool worker, the
#: express daemon's forked scans) is therefore not measured. ``core = sysmon`` is the
#: cheapest line tracer; branch, concurrency and dynamic contexts would each make
#: coverage fall back from it. The warnings are off because a measured process's
#: stderr is the block's output, which an output sample is compared against.
_COVERAGE_RC = """\
[run]
source_pkgs = automated_security_helper
parallel = True
data_file = {data_file}
context = ${{{context}-unattributed}}
core = sysmon
patch = fork
disable_warnings = no-data-collected, module-not-imported, module-not-measured,
    no-sysmon, already-imported, couldnt-parse
"""


@dataclass(frozen=True)
class DocsCoverage:
    """Where a docs examples run collects coverage and its per-page records.

    ``directory`` holds ``coverage.rc`` (written per run), ``data/`` (one coverage data
    file per measured process, each line labelled with the context of the block that ran
    it) and ``blocks/`` (one record per page of what the runner ran or saved).
    scripts/docs_feature_coverage.py reads the last two.
    """

    directory: Path

    @property
    def rcfile(self) -> Path:
        return self.directory / "coverage.rc"

    @classmethod
    def from_environment(cls, environ=None) -> DocsCoverage | None:
        """The collection the environment asks for, or None when it asks for none.

        A relative directory is refused: each session would resolve it in its own
        working directory.
        """
        value = (os.environ if environ is None else environ).get(
            COVERAGE_DIR_VARIABLE, ""
        )
        if not value.strip():
            return None
        directory = Path(value.strip())
        if not directory.is_absolute():
            raise ValueError(
                f"{COVERAGE_DIR_VARIABLE} must be an absolute path, not {value!r}"
            )
        return cls(directory)

    def session_environment(self) -> dict[str, str]:
        """What a session needs to be measured: the rc file, which this writes.

        Every session of every xdist worker asks for the file while processes that
        start meanwhile read it, and coverage.py started on an empty read measures
        with its defaults: the lines are lost and a stray data file lands in the
        page's project. So the file is never rewritten in place. The text is rendered
        once and written only when the file is missing or holds other text, to a
        temporary name beside it that is renamed over it, so a reader sees the old
        text or the whole new one.
        """
        (self.directory / "data").mkdir(parents=True, exist_ok=True)
        (self.directory / "blocks").mkdir(parents=True, exist_ok=True)
        text = _COVERAGE_RC.format(
            data_file=self.directory / "data" / ".coverage",
            context=COVERAGE_CONTEXT_VARIABLE,
        )
        try:
            current = self.rcfile.read_text(encoding="utf-8")
        except (FileNotFoundError, UnicodeDecodeError):
            current = None
        if current != text:
            pending = self.rcfile.with_name(f".{self.rcfile.name}.{os.getpid()}.tmp")
            pending.write_text(text, encoding="utf-8")
            os.replace(pending, self.rcfile)
        return {"COVERAGE_PROCESS_START": str(self.rcfile)}

    @staticmethod
    def context(page_rel: str, line: int) -> str:
        """The coverage context of the block whose fence is on ``line`` of a page."""
        return f"{page_rel}::{line}"

    def write_record(self, page_rel: str, blocks: list[dict]) -> Path:
        """Write a page's record whole: to a temporary name beside it, then renamed, so
        a reader never sees half of one. Named from the page, so parallel workers
        running different pages never share a file."""
        name = hashlib.sha256(page_rel.encode("utf-8")).hexdigest()[:16] + ".json"
        target = self.directory / "blocks" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        pending = target.with_name(f".{name}.{os.getpid()}.tmp")
        pending.write_text(
            json.dumps({"schema": RECORD_SCHEMA, "page": page_rel, "blocks": blocks}),
            encoding="utf-8",
        )
        os.replace(pending, target)
        return target


_SHELL_PRELUDE = """\
__ash_docs_state=$1
__ash_docs_cwd=$2
__ash_docs_save() {
  __ash_docs_rc=$?
  env -0 > "$__ash_docs_state"
  pwd > "$__ash_docs_cwd"
  exit "$__ash_docs_rc"
}
trap __ash_docs_save EXIT
set -a
set -e
(set -o pipefail) 2>/dev/null && set -o pipefail
"""

#: What a block's report says of a process left running that this host cannot name.
_UNNAMED_PROCESS = "a process this host could not name (no /proc, and ps failed)"
#: How much of a left process's command line a block's report shows.
_COMMAND_CHARS = 240


def _members_from_proc(group: int) -> list[tuple[int, str]] | None:
    """(pid, command line) of each running process of process group ``group``, read
    from /proc; None where there is no /proc to read."""
    try:
        names = os.listdir("/proc")
    except OSError:
        return None
    members = []
    for name in names:
        if not name.isdigit():
            continue
        try:
            stat = Path(f"/proc/{name}/stat").read_bytes().decode(errors="replace")
        except OSError:  # it ended while /proc was read
            continue
        # After the command name, which sits in parentheses and may hold ")": the
        # state, the parent's pid and the process group.
        called, _, rest = stat.rpartition(")")
        fields = rest.split()
        if len(fields) < 3 or fields[0] == "Z" or fields[2] != str(group):
            continue
        try:
            argv = Path(f"/proc/{name}/cmdline").read_bytes()
        except OSError:
            argv = b""
        command = argv.replace(b"\0", b" ").decode(errors="replace")
        members.append((int(name), command or f"[{called.partition('(')[2]}]"))
    return members


def _members_from_ps(group: int) -> list[tuple[int, str]] | None:
    """The same, from ``ps``, for a host with no /proc (macOS); None where ``ps``
    cannot be run or fails."""
    try:
        listed = subprocess.run(
            ["ps", "-A", "-ww", "-o", "pid=,pgid=,stat=,command="],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if listed.returncode != 0:
        return None
    members = []
    for row in listed.stdout.splitlines():
        fields = row.split(None, 3)
        if (
            len(fields) >= 3
            and fields[0].isdigit()
            and fields[1] == str(group)
            and not fields[2].startswith("Z")
        ):
            members.append((int(fields[0]), fields[3] if len(fields) > 3 else ""))
    return members


def _end_the_process_group(group: int) -> tuple[str, ...]:
    """End whatever still runs in a block's process group once its shell has exited.

    Each block starts in a session of its own, so the shell's pid is the group's id.
    The result names each process that was running, as ``<pid> <command line>``, and
    is empty when the group holds none: a zombie (a process that ended and is not
    reaped yet) is none. What ran is ended with SIGKILL, as the timeout path ends a
    block's processes. There is no grace period: a process a block starts and does not
    wait for is a process the block left.
    """
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return ()
    except PermissionError:
        pass  # a member this user may not signal is still there
    members = _members_from_proc(group)
    if members is None:
        members = _members_from_ps(group)
    if members == []:
        return ()
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(group, signal.SIGKILL)
    if members is None:
        return (_UNNAMED_PROCESS,)
    return tuple(
        f"{pid} {' '.join(command.split())[:_COMMAND_CHARS]}"
        for pid, command in sorted(members)
    )


class PageRunner:
    """Runs one page's blocks in one session and returns a result per block."""

    def __init__(
        self,
        page,
        scratch: Path,
        default_timeout: float | None = None,
        docs_root: Path | None = None,
        coverage: DocsCoverage | None = None,
    ):
        self.checks = load_docs_checks()
        self.page = page
        #: When set, every session is measured by coverage.py, each block under its
        #: own context, and ``run`` writes the page's record. Only the docs examples
        #: test sets it: the twins and the runner's own failure proofs do not, so
        #: their deliberately failing or synthetic blocks never reach the data.
        self.coverage = coverage
        # Fixtures are docs data, so they come from the docs tree; the commands run
        # with the ASH in this interpreter's environment, whichever tree that is.
        self.docs_root = docs_root or REPO_ROOT
        self.scratch = scratch
        self.default_timeout = default_timeout or self.checks.DEFAULT_TIMEOUT_S
        self.session: Session | None = None

    # -- sessions ----------------------------------------------------------

    def _base_env(self, root: Path, port: int) -> dict[str, str]:
        home = root / "home"
        for sub in (".config", ".cache", ".local/share", ".local/state", "tmp"):
            (home / sub).mkdir(parents=True, exist_ok=True)
        return session_environment(root, port, session_path())

    def _start(self, fixture: str) -> Session:
        if self.session is not None:
            self.session.blocked_port.close()
        root = Path(tempfile.mkdtemp(prefix="session-", dir=self.scratch))
        work = root / "project"
        source = self.docs_root / self.checks.DOC_FIXTURES_DIR / fixture
        # From git's listing of the fixture, not a copytree walk: a .keep file holds
        # an empty directory in git, so it makes that directory and is not copied.
        work.mkdir()
        for path in self.checks.listed_files(source):
            target = work / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.name != ".keep":
                shutil.copy2(path, target)
        port, port_number = _refusing_port()
        env = self._base_env(root, port_number)
        if self.coverage is not None:
            env.update(self.coverage.session_environment())
        for args in (
            ["init", "-q", "-b", "main"],
            ["add", "-A"],
            ["commit", "-q", "--allow-empty", "-m", "fixture"],
        ):
            subprocess.run(
                ["git", *args], cwd=work, env=env, check=True, capture_output=True
            )
        self.session = Session(
            root=root,
            fixture=fixture,
            cwd=work,
            env=env,
            blocked_port=port,
            project=work,
        )
        return self.session

    def close(self) -> None:
        if self.session is not None:
            self.session.blocked_port.close()
            self.session = None

    # -- blocks ------------------------------------------------------------

    def _marker_value(self, block, key: str, default):
        if block.marker is None:
            return default
        return block.marker.keys.get(key, default)

    def _run_process(
        self, argv: list[str], cwd: Path, env: dict[str, str], timeout: float
    ) -> tuple[int | None, str, bool, tuple[str, ...]]:
        """(exit code, output, whether it timed out, what it left running).

        What a block left running is what its process group still held when its shell
        had exited (``_end_the_process_group``); a block that timed out has had its
        whole group ended already and leaves none.
        """
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # The block's own children share its session; end all of them.
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            return None, output.decode("utf-8", errors="replace"), True, ()
        return (
            process.returncode,
            output.decode("utf-8", errors="replace"),
            False,
            _end_the_process_group(process.pid),
        )

    def _save(self, block, session: Session) -> tuple[Path | None, str | None]:
        """Write a save-as block into the session's project: (path, or why it was refused).

        The path must stay inside the project: no absolute path, no "..", and no
        existing link on the way, since a link could point anywhere.
        """
        relative = block.save_as
        problem = self.checks.save_as_problem(relative)
        if problem:
            return None, f"save-as refused: {problem}"
        project = session.project or session.cwd
        target = project
        for part in [
            p for p in relative.replace("\\", "/").split("/") if p not in ("", ".")
        ]:
            target = target / part
            if target.is_symlink():
                return (
                    None,
                    f"save-as refused: {relative} goes through a link ({target.name})",
                )
        if not target.resolve().is_relative_to(project.resolve()):
            return None, f"save-as refused: {relative} leaves the page's project"
        if target.is_dir():
            return None, f"save-as refused: {relative} is a directory"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(block.body + "\n", encoding="utf-8")
        return target, None

    def run_block(self, block) -> BlockResult:
        session = self.session
        if starts_session(block, None if session is None else session.fixture):
            session = self._start(block_fixture(block))
        saved: Path | None = None
        if block.save_as:
            saved, refused = self._save(block, session)
            if (
                refused
                or block.mode != "run"
                or block.family not in ("python", "shell")
            ):
                return BlockResult(
                    page=self.page.rel,
                    line=block.fence_line,
                    lang=block.lang,
                    command=f"save-as={block.save_as}",
                    expected="0",
                    exit_code=None if refused else 0,
                    output="",
                    seconds=0.0,
                    refused=refused,
                )
        timeout = float(self._marker_value(block, "timeout", self.default_timeout))
        expected = str(self._marker_value(block, "expect-exit", "0"))
        block_env = marker_env(block)
        if self.coverage is not None:
            # Like a marker's env=, for this block only (_carry_state drops it).
            block_env[COVERAGE_CONTEXT_VARIABLE] = self.coverage.context(
                self.page.rel, block.fence_line
            )
        env = {**session.env, **block_env}
        started = time.monotonic()

        if block.family == "python":
            # A saved module runs from where it was saved, so __file__ is that path.
            script = saved or session.root / f"block-{block.fence_line}.py"
            if saved is None:
                script.write_text(block.body + "\n", encoding="utf-8")
                # A reader runs the snippet as a script in the current directory, so
                # modules saved there earlier on the page import the way they would.
                env["PYTHONPATH"] = os.pathsep.join(
                    p for p in (str(session.cwd), env.get("PYTHONPATH", "")) if p
                )
            code, output, timed_out, left = self._run_process(
                [sys.executable, str(script)], session.cwd, env, timeout
            )
            command = block.body
        else:
            body = (
                self.checks.console_commands(block.body)
                if block.lang in self.checks.CONSOLE_LANGS
                else block.body
            )
            script = session.root / f"block-{block.fence_line}.sh"
            script.write_text(_SHELL_PRELUDE + body + "\n", encoding="utf-8")
            state = session.root / "state.env"
            cwd_file = session.root / "state.cwd"
            interpreter = "sh" if block.lang == "sh" else "bash"
            if os.name == "nt":
                # A bare "bash" given to CreateProcess is the WSL launcher in the
                # system directory ("Windows Subsystem for Linux has no installed
                # distributions"). Use the bash that ships with Git for Windows.
                from tests.utils.github_actions import git_for_windows_bash

                git_bash = git_for_windows_bash()
                if git_bash:
                    interpreter = git_bash
            code, output, timed_out, left = self._run_process(
                [interpreter, str(script), str(state), str(cwd_file)],
                session.cwd,
                env,
                timeout,
            )
            command = body
            self._carry_state(session, state, cwd_file, block_env)

        project = session.project or session.cwd
        home = session.root / "home"
        paths = {
            (str(project), "."),
            (str(project.resolve()), "."),
            (str(home), "~"),
            (str(home.resolve()), "~"),
        }
        return BlockResult(
            page=self.page.rel,
            line=block.fence_line,
            lang=block.lang,
            command=command,
            expected=expected,
            exit_code=code,
            output=output,
            seconds=time.monotonic() - started,
            timed_out=timed_out,
            paths=tuple(sorted(paths)),
            left_running=left,
        )

    def compare_sample(self, block, shown: BlockResult) -> BlockResult:
        """An output sample against the output of the block it shows."""
        problem = self.checks.output_sample_problem(
            block.body, shown.output, shown.paths
        )
        line = block.body_line + problem[0] if problem else block.fence_line
        return BlockResult(
            page=self.page.rel,
            line=line,
            lang=block.lang,
            command=block.body,
            # The sample has no exit code of its own; mismatch carries its verdict.
            expected="0",
            exit_code=0,
            output=shown.output,
            seconds=0.0,
            mismatch=(
                f"{problem[1]!r} is not in the output of the block at line {shown.line}"
                if problem
                else None
            ),
        )

    @staticmethod
    def _carry_state(
        session: Session, state: Path, cwd_file: Path, block_env: dict[str, str]
    ) -> None:
        """Take the environment and directory a shell block ended with into the session."""
        if state.is_file():
            entries = state.read_bytes().split(b"\0")
            carried = {}
            for entry in entries:
                name, sep, value = entry.decode("utf-8", errors="replace").partition(
                    "="
                )
                if sep and name and not name.startswith("__ash_docs"):
                    carried[name] = value
            # A marker's env= applies to its block only.
            for name in block_env:
                if name in session.env:
                    carried[name] = session.env[name]
                else:
                    carried.pop(name, None)
            if carried:
                session.env = carried
            state.unlink()
        if cwd_file.is_file():
            directory = Path(cwd_file.read_text(encoding="utf-8").strip())
            if directory.is_dir():
                session.cwd = directory
            cwd_file.unlink()

    def run(self) -> list[BlockResult]:
        samples = compared_samples(self.page)
        results: dict[int, BlockResult] = {}
        sample_ok: dict[int, bool] = {}
        try:
            ordered = []
            for block in session_blocks(self.page):
                shown = samples.get(id(block))
                if shown is not None:
                    compared = self.compare_sample(block, results[id(shown)])
                    sample_ok[id(shown)] = compared.ok
                    ordered.append(compared)
                    continue
                results[id(block)] = self.run_block(block)
                ordered.append(results[id(block)])
            if self.coverage is not None:
                self._write_record(results, sample_ok)
            return ordered
        finally:
            self.close()

    def _write_record(
        self, results: dict[int, BlockResult], sample_ok: dict[int, bool]
    ) -> None:
        """Record every block the page ran or saved, for the docs feature coverage gate.

        A block's ``ok`` is its own verdict together with its output sample's: an
        example whose sample no longer matches claims something it does not show.
        ``expected`` is the exit the block's marker names, which the gate reads to
        tell an example of ASH working from one of ASH refusing something. A run that
        raised never gets here, so that page leaves no record and gives no evidence.
        """
        assert self.coverage is not None
        sessions = {id(block): number for number, _, block in page_sessions(self.page)}
        blocks = []
        for block in session_blocks(self.page):
            result = results.get(id(block))
            if result is None:  # an output sample: compared, not run
                continue
            blocks.append(
                {
                    "line": block.fence_line,
                    "context": self.coverage.context(self.page.rel, block.fence_line),
                    "session": sessions[id(block)],
                    "runs": self.checks.runner_runs(block),
                    "save_as": block.save_as or None,
                    "expected": result.expected,
                    "ok": bool(result.ok and sample_ok.get(id(block), True)),
                }
            )
        self.coverage.write_record(self.page.rel, blocks)


def failure_report(results: list[BlockResult]) -> str:
    failed = [r for r in results if not r.ok]
    lines = [f"{len(failed)} of {len(results)} runnable block(s) failed."]
    for position, result in enumerate(failed):
        lines.append("")
        if position:
            lines.append(
                "  (after an earlier failure on this page; this one may follow from it)"
            )
        lines.append(result.report())
    return "\n".join(lines)

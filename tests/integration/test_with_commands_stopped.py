# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""with_commands_stopped, run in real bash with real processes.

run-ash-security-scan.yml's "Write the one_line helper" step writes the helper to
RUNNER_TEMP. Each cell writes it the same way (tests/utils/workflow_one_line.py runs
that step), runs a step script that loads it under the runner's command line for
`shell: bash`, and, where a cell cancels the step, cancels it as the runner does:
SIGINT to the step's shell alone, SIGTERM 7.5 s later, then SIGKILL 2.5 s after that
(actions/runner, ProcessInvoker.CancelAndKillProcessTree).

The cells start bash, sh, perl and the programs the helper uses, and read process
groups and sessions from /proc, so they run under --run-integration.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from tests.utils.workflow_one_line import write_helper

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "linux" or shutil.which("bash") is None,
        reason="runs the helper in bash and reads processes from /proc, as on "
        "ubuntu-latest",
    ),
]

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "run-ash-security-scan.yml"
)
#: The runner's waits: SIGTERM 7.5 s after SIGINT, SIGKILL 2.5 s after SIGTERM.
SIGINT_WAIT = 7.5
SIGTERM_WAIT = 2.5
#: How long a cell reads the step's output after its shell exits, while a process
#: left behind holds the output open.
POST_EXIT_READ = 1.0
OPEN = re.compile(r"^::stop-commands::([0-9a-f]{32})$", re.MULTILINE)
#: Part of the line the helper prints when it had to SIGKILL what the command left.
LEFT_RUNNING = "did not end in time"
#: The start of the helper's refusal of a call off the step's shell.
OFF_SHELL_REFUSAL = "::error::with_commands_stopped must run in the step's own shell"

#: Dies on SIGINT, like most tools.
TOOL = (
    '#!/bin/sh\necho "$$" > "${RECORD_DIR}/pid"\n'
    'echo "::warning::from-the-tool"\nexec sleep 20\n'
)
#: Exits at once; a process it started prints a command 0.5 s later, then ends.
LEAVES_A_BRIEF_PRINTER = (
    "#!/bin/sh\n"
    '( sleep 0.5; echo "::warning::from-what-the-tool-started" ) &\n'
    'echo "$!" > "${RECORD_DIR}/child"\n'
    "exit 0\n"
)
#: Exits at once; a process it started would run for 30 s, past the helper's 5 s.
LEAVES_A_PROCESS_RUNNING = (
    '#!/bin/sh\n( sleep 30 ) &\necho "$!" > "${RECORD_DIR}/child"\nexit 0\n'
)
CALLS = {
    "plain": "with_commands_stopped uvx scan",
    "stdout": 'with_commands_stopped --stdout "${RUNNER_TEMP}/out" uvx scan',
    "capture": "with_commands_stopped --capture got uvx scan",
}
#: What the helper and the stand-in run, apart from setsid: bash and sh, od and tr
#: for the token, mktemp, cat and rm for --capture, sleep for the waits and the tool.
HELPER_PROGRAMS = ("bash", "sh", "od", "tr", "mktemp", "cat", "rm", "sleep")


def _helper(runner_temp: Path) -> Path:
    """Write the helper as the job's definer step does, and return its path."""
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ash"]["steps"]
    return write_helper(steps, runner_temp)


class _Reader(threading.Thread):
    """Reads the step's output as it comes, as the runner does."""

    def __init__(self, stream) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.data = bytearray()

    def run(self) -> None:
        for chunk in iter(lambda: self.stream.read1(4096), b""):
            self.data.extend(chunk)

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", "replace")


def _run_step(
    tmp_path: Path,
    call: str,
    tool: str = TOOL,
    *,
    path: str | None = None,
    stderr: int = subprocess.STDOUT,
) -> tuple[subprocess.Popen, Path, _Reader]:
    """Start a step's shell that loads the helper and runs `call`, with the stand-in
    tool installed as uvx. `path` replaces this host's PATH after the stand-in's
    directory."""
    runner_temp = tmp_path / "runner_temp"
    helper = _helper(runner_temp)
    record = tmp_path / "record"
    record.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stand_in = bin_dir / "uvx"
    stand_in.write_text(tool, encoding="utf-8")
    stand_in.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(
        f'. "{helper}"\n{call}\necho "after the call"\n', encoding="utf-8"
    )
    bash = shutil.which("bash")
    assert bash, "bash is not on PATH"
    rest = os.environ.get("PATH", "") if path is None else path
    proc = subprocess.Popen(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr,
        env={
            "PATH": f"{bin_dir}{os.pathsep}{rest}",
            "RUNNER_TEMP": str(runner_temp),
            "RECORD_DIR": str(record),
        },
    )
    reader = _Reader(proc.stdout)
    reader.start()
    return proc, record, reader


def _end_what_is_left(record: Path) -> None:
    """End what the tool left running, as the runner's job-end cleanup does."""
    for name in ("pid", "child"):
        try:
            os.kill(int((record / name).read_text().strip()), signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass


def _cancel_like_the_runner(proc: subprocess.Popen) -> str:
    """Send what the runner sends on a cancel; return the signal the shell ended on."""
    for sig, wait in ((signal.SIGINT, SIGINT_WAIT), (signal.SIGTERM, SIGTERM_WAIT)):
        os.kill(proc.pid, sig)
        try:
            proc.wait(wait)
            return sig.name
        except subprocess.TimeoutExpired:
            continue
    proc.kill()
    proc.wait()
    return "SIGKILL"


def _wait_to_end(proc: subprocess.Popen, seconds: float) -> int:
    try:
        return proc.wait(seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.wait()


def _closes(output: str) -> list[int]:
    """The index of each line of `output` that resumes its one stopped region."""
    (token,) = OPEN.findall(output)
    return [i for i, line in enumerate(output.splitlines()) if line == f"::{token}::"]


def _path_without_setsid(tmp_path: Path) -> str:
    """A PATH holding only HELPER_PROGRAMS and perl, as on a runner without
    util-linux's setsid, such as the macOS ones."""
    directory = tmp_path / "no-setsid"
    directory.mkdir()
    for program in (*HELPER_PROGRAMS, "perl"):
        found = shutil.which(program)
        assert found, f"{program} is not on PATH"
        (directory / program).symlink_to(found)
    assert shutil.which("setsid", path=str(directory)) is None
    return str(directory)


def _parent_group_session(pid: int) -> tuple[int, int, int]:
    """The parent, process group and session of `pid`: fields 4 to 6 of
    /proc/<pid>/stat, read after the command name's closing parenthesis."""
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    ppid, pgrp, session = stat.rsplit(")", 1)[1].split()[1:4]
    return int(ppid), int(pgrp), int(session)


@pytest.mark.parametrize("mode", sorted(CALLS))
def test_without_setsid_perl_starts_the_tool_in_a_session_of_its_own(tmp_path, mode):
    """With no setsid on PATH, the helper starts the command through perl's
    POSIX::setsid. The tool then leads a session and a process group of its own,
    apart from the step's shell. Its parent is the step's shell, so perl did not
    fork and the tool has the process id the helper waits on. A cancel ends it, and
    the region closes once."""
    proc, record, reader = _run_step(
        tmp_path, CALLS[mode], path=_path_without_setsid(tmp_path)
    )
    pid_file = record / "pid"
    deadline = time.monotonic() + 10
    while not pid_file.exists() and proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not pid_file.exists():
        status = _wait_to_end(proc, 10)
        reader.join(5)
        pytest.fail(f"the tool did not start; step status {status}\n{reader.text()}")
    time.sleep(0.2)
    pid = int(pid_file.read_text().strip())
    ppid, pgrp, session = _parent_group_session(pid)
    shell_session = os.getsid(proc.pid)

    ended_by = _cancel_like_the_runner(proc)
    reader.join(POST_EXIT_READ)
    output = reader.text()
    _end_what_is_left(record)
    reader.join(5)

    report = (
        f"tool pid {pid}: parent {ppid}, group {pgrp}, session {session}; step shell "
        f"{proc.pid} in session {shell_session}; ended by {ended_by}\n{output}"
    )
    assert (pgrp, session) == (pid, pid), report
    assert session != shell_session, report
    assert ppid == proc.pid, report
    assert len(_closes(output)) == 1, report
    assert ended_by != "SIGKILL", report
    assert LEFT_RUNNING not in output, report


def test_a_call_in_a_subshell_fails_with_one_error_that_names_the_replacement(
    tmp_path,
):
    """The runner signals only the step's shell, so a call in a subshell could not
    close its region on a cancel. The helper refuses it: the step fails, the tool
    never starts, no region opens, and stderr carries one ::error:: line that names
    env -C DIR as the way to run a command in another directory."""
    proc, record, reader = _run_step(
        tmp_path,
        '(cd "${RUNNER_TEMP}" && with_commands_stopped uvx scan)',
        stderr=subprocess.PIPE,
    )
    try:
        status = _wait_to_end(proc, 30)
    finally:
        _end_what_is_left(record)
    reader.join(5)
    stdout = reader.text()
    stderr = proc.stderr.read().decode("utf-8", "replace")
    errors = [
        line for line in stderr.splitlines() if line.startswith(OFF_SHELL_REFUSAL)
    ]

    report = f"status {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    assert status != 0, report
    assert len(errors) == 1, report
    assert "env -C DIR" in errors[0], report
    assert OFF_SHELL_REFUSAL not in stdout, report
    assert not (record / "pid").exists(), report
    assert OPEN.findall(stdout) == [], report
    assert "after the call" not in stdout, report


def test_what_a_process_the_tool_left_prints_before_it_ends_stays_inside(tmp_path):
    """The tool exits at once and leaves a process that prints a command 0.5 s later,
    then ends. The region closes only once the tool's group is empty, so that line
    stays inside it; the process ended within the helper's 5 s wait for the group,
    so nothing is killed and the call succeeds."""
    proc, record, reader = _run_step(tmp_path, CALLS["plain"], LEAVES_A_BRIEF_PRINTER)
    status = _wait_to_end(proc, 15)
    reader.join(POST_EXIT_READ)
    output = reader.text()
    try:
        os.kill(int((record / "child").read_text().strip()), 0)
        left_running = True
    except (FileNotFoundError, ProcessLookupError, ValueError):
        left_running = False
    _end_what_is_left(record)
    reader.join(5)

    lines = output.splitlines()
    report = f"status {status}; left running {left_running}\n{output}"
    closes = _closes(output)
    printed = [
        i for i, line in enumerate(lines) if "from-what-the-tool-started" in line
    ]
    assert status == 0, report
    assert len(closes) == 1, report
    # Present at all, so the order check below is not vacuous.
    assert printed, report
    assert all(i < closes[0] for i in printed), report
    assert "after the call" in lines, report
    assert LEFT_RUNNING not in output, report
    assert not left_running, report


def test_a_process_the_tool_left_past_the_grace_is_killed_and_the_call_fails(
    tmp_path,
):
    """The tool exits at once and leaves a process that would run for 30 s. The
    helper waits 5 s for the tool's group, then sends it SIGKILL, closes the region,
    and fails the call with an ::error:: line the runner acts on, after the region
    closes. The step stops there, well before the process would have ended."""
    started = time.monotonic()
    proc, record, reader = _run_step(tmp_path, CALLS["plain"], LEAVES_A_PROCESS_RUNNING)
    status = _wait_to_end(proc, 20)
    took = time.monotonic() - started
    reader.join(POST_EXIT_READ)
    output = reader.text()
    try:
        os.kill(int((record / "child").read_text().strip()), 0)
        left_running = True
    except (FileNotFoundError, ProcessLookupError, ValueError):
        left_running = False
    _end_what_is_left(record)
    reader.join(5)

    lines = output.splitlines()
    report = (
        f"status {status}; left running {left_running}; took {took:.1f} s\n{output}"
    )
    closes = _closes(output)
    errors = [i for i, line in enumerate(lines) if LEFT_RUNNING in line]
    assert status != 0, report
    assert len(closes) == 1, report
    assert len(errors) == 1, report
    assert lines[errors[0]].startswith("::error::"), report
    assert errors[0] > closes[0], report
    assert "after the call" not in lines, report
    assert not left_running, report
    assert took < 12, report

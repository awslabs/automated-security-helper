# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan interrupted with Ctrl-C says so and exits 130, in every mode.

Each mode has its own way to get this wrong:
- container mode exits 241 when run_cmd_direct catches the KeyboardInterrupt, stops
  the runtime with SIGTERM (which kills it before it can pass the interrupt on
  to the container) and returns its -15, which sys.exit wraps to 241;
- local mode can exit 130 only after logging "ASH Security Scan completed" and
  "===== ASH Security Scan Completed in 0s =====" and printing the results table
  for a scan that never ran.

Every case here keeps guard stand-ins for docker, finch, nerdctl and podman first
on PATH, so no case can reach a real container runtime.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import signal
import stat
import subprocess  # nosec B404 - the host ASH under test runs as a child process
import sys
import threading
import time
import types
from pathlib import Path
from typing import Iterator

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.helpers import module_from_this_checkout

#: What a finished scan prints, none of which an interrupted one may print.
_COMPLETION_TEXT = (
    "Completed in",
    "ASH Security Scan completed",
    "Results Summary",
    "Next Steps",
)

#: What an interrupted scan prints instead.
_INTERRUPTED = "ASH scan interrupted"

_GUARD_RUNNER = """#!/bin/sh
echo "$(basename "$0") $*" >> "{log}"
exit 97
"""

#: The line a child prints on stdout once its SIGINT handler is set.
_WAITING = "waiting for the interrupt"

#: A container runtime that records its calls. Everything but `run` succeeds; `run`
#: waits for SIGINT, records it, and exits 130 as an interrupted inner scan does.
_FAKE_RUNTIME = """#!{python} -I
import os, signal, sys, time
log = os.environ["FAKE_LOG"]
with open(log, "a", encoding="utf-8") as handle:
    handle.write("call " + " ".join(sys.argv[1:2]) + "\\n")
if sys.argv[1:2] != ["run"]:
    sys.exit(0)
def _interrupted(signum, frame):
    with open(log, "a", encoding="utf-8") as handle:
        handle.write("INT\\n")
    sys.exit(130)
signal.signal(signal.SIGINT, _interrupted)
print("{waiting}", flush=True)
for _ in range(600):
    time.sleep(0.1)
"""

#: A child that takes a while to stop: `nix` (its `develop`) or a runtime (its
#: `build`), per FAKE_WAIT_ON. On the first SIGINT it records INT, takes a second to
#: clean up (longer than subprocess's 0.25 s, well inside the 5 s grace), records
#: CLEAN and exits 130. Everything else succeeds at once.
_SLOW_TO_STOP = """#!{python} -I
import os, signal, sys, time
log = os.environ["FAKE_LOG"]
def note(text):
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(text + "\\n")
note("call")
if os.environ["FAKE_WAIT_ON"] not in sys.argv[1:]:
    sys.exit(0)
interrupts = []
signal.signal(signal.SIGINT, lambda signum, frame: interrupts.append(signum))
print("{waiting}", flush=True)
deadline = time.monotonic() + 60
while not interrupts and time.monotonic() < deadline:
    time.sleep(0.05)
note("INT")
time.sleep(1.0)
note("CLEAN")
sys.exit(130)
"""

#: A runtime whose `build` writes the signals it was started ignoring (the SigIgn
#: mask of /proc/self/status, as hex) to FAKE_LOG. Every call succeeds at once.
_REPORTS_ITS_IGNORED_SIGNALS = """#!{python} -I
import os, sys
if "build" in sys.argv[1:]:
    with open("/proc/self/status", encoding="utf-8") as handle:
        [mask] = [line.split()[1] for line in handle if line.startswith("SigIgn:")]
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as handle:
        handle.write(mask + "\\n")
sys.exit(0)
"""


@contextlib.contextmanager
def _with_sigint_at_its_default() -> Iterator[None]:
    """Start a child with SIGINT at its default, as a terminal's foreground job has it.

    A child inherits an ignored SIGINT across exec, and ASH started that way keeps
    it ignored, as a background job must (test_the_runtime_keeps_the_sigint_
    disposition_ash_was_started_with). A test run started as ``cmd &`` has SIGINT
    ignored, so every host these tests interrupt dropped the Ctrl-C: the four
    cells that interrupt a host failed there, and only there. Python's own handler
    is set for the start, not SIG_DFL, so a SIGINT meant for this process in the
    meantime is still a KeyboardInterrupt and not its end; exec resets the handler
    to the default in the child.
    """
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


#: A child that says whether it was started with SIGINT ignored.
_SAYS_IF_SIGINT_IS_IGNORED = (
    "import signal; print(signal.getsignal(signal.SIGINT) == signal.SIG_IGN)"
)


@pytest.mark.skipif(os.name == "nt", reason="an ignored SIGINT is inherited on POSIX")
@pytest.mark.parametrize("held", [True, False], ids=["at-its-default", "control"])
@pytest.mark.integration
def test_a_host_starts_with_sigint_at_its_default_when_this_run_ignores_it(held):
    """What _interrupt's host starts with, under a test run started as ``cmd &``.

    The control shows the setup has its effect: without the hold, the child is
    started ignoring SIGINT."""
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        hold = _with_sigint_at_its_default() if held else contextlib.nullcontext()
        with hold:
            child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
                [sys.executable, "-I", "-c", _SAYS_IF_SIGINT_IS_IGNORED],
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
        still_ignored = signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, previous)

    assert child.stdout.strip() == ("False" if held else "True"), child
    assert still_ignored, "the hold did not put this process's disposition back"


def _interrupt(tmp_path: Path, env: dict, args: list, *, to_the_group: bool):
    """Run `ash <args>` in its own session; once the child is waiting, send SIGINT.

    To the process group, as a terminal's Ctrl-C reaches every process in it, or to
    the host alone, as `kill -INT` or a CI job's cancel does.

    "Waiting" is an event, not a time: the child's _WAITING line, printed once its
    handler is set, has come out of the host's stdout. A container runtime's output
    reaches there only through the threads ASH reads it with, so ASH is past
    starting the runtime and in its wait. A file the child writes says only that the
    child is waiting: under load the SIGINT can then reach ASH while it is still
    starting those threads, and the log be read before the child's cleanup. The
    Nix shell writes to the host's stdout itself, so for it the line says only that
    the shell is waiting; ASH waits on it as soon as Popen returns. The host runs
    unbuffered (-u) so the line is not held in its stdout's buffer.

    The host starts as a foreground job does, with SIGINT at its default
    (_with_sigint_at_its_default), whatever this process has.
    """
    with _with_sigint_at_its_default():
        host = subprocess.Popen(  # nosec B603 - fixed interpreter and arguments
            [
                sys.executable,
                "-I",
                "-u",
                "-c",
                module_from_this_checkout("automated_security_helper.cli.main"),
                *args,
            ],
            cwd=tmp_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    waiting = threading.Event()
    output: dict[str, list[str]] = {"stdout": [], "stderr": []}

    def drain(pipe, lines):
        for line in pipe:
            lines.append(line)
            if _WAITING in line:
                waiting.set()

    drains = [
        threading.Thread(
            target=drain, args=(host.stdout, output["stdout"]), daemon=True
        ),
        threading.Thread(
            target=drain, args=(host.stderr, output["stderr"]), daemon=True
        ),
    ]
    for thread in drains:
        thread.start()
    try:
        # Event.wait returns at once when the line comes; the timeout only bounds
        # how often a host that exited first is noticed.
        deadline = time.monotonic() + 120
        while not waiting.wait(timeout=0.5):
            assert host.poll() is None, "".join(output["stdout"] + output["stderr"])
            assert time.monotonic() < deadline, "the child never said it was waiting"
        if to_the_group:
            os.killpg(host.pid, signal.SIGINT)
        else:
            os.kill(host.pid, signal.SIGINT)
        host.wait(timeout=60)
    finally:
        if host.poll() is None:
            os.killpg(host.pid, signal.SIGKILL)
            host.wait()
        for thread in drains:
            thread.join(timeout=60)
    return host.returncode, "".join(output["stdout"]), "".join(output["stderr"])


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """A scratch HOME, guard runners first on PATH, and a source dir to scan."""
    guards = tmp_path / "guards"
    guards.mkdir()
    guard_log = tmp_path / "guards.log"
    for runner in ("docker", "finch", "nerdctl", "podman"):
        _executable(guards / runner, _GUARD_RUNNER.format(log=guard_log))
    env = {
        "PATH": f"{guards}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "home" / ".config"),
        "XDG_CACHE_HOME": str(tmp_path / "home" / ".cache"),
        "UV_TOOL_DIR": str(tmp_path / "home" / "uv-tools"),
        "ASH_BIN_PATH": str(tmp_path / "home" / "bin"),
        "UV_OFFLINE": "1",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    yield {"env": env, "guard_log": guard_log}
    assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")


def _assert_interrupted(output: str, out_dir: Path) -> None:
    assert _INTERRUPTED in output, output
    for text in _COMPLETION_TEXT:
        assert text not in output, (text, output)
    log = out_dir / "ash.log"
    if log.exists():
        logged = log.read_text(encoding="utf-8")
        for text in _COMPLETION_TEXT:
            assert text not in logged, (text, logged)


@pytest.mark.skipif(os.name == "nt", reason="a terminal's Ctrl-C is SIGINT on POSIX")
@pytest.mark.integration
def test_container_mode_passes_ctrl_c_to_the_runtime_and_exits_130(tmp_path, isolated):
    """SIGINT to the process group, as a terminal's Ctrl-C sends it."""
    runtime = _executable(
        tmp_path / "fake-runtime",
        _FAKE_RUNTIME.format(python=sys.executable, waiting=_WAITING),
    )
    runtime_log = tmp_path / "runtime.log"

    returncode, stdout, stderr = _interrupt(
        tmp_path,
        {**isolated["env"], "FAKE_LOG": str(runtime_log)},
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--oci-runner",
            str(runtime),
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
        ],
        to_the_group=True,
    )

    assert returncode == 130, stdout + stderr
    assert "INT" in runtime_log.read_text(encoding="utf-8").split(), (
        "the runtime was stopped before it got the interrupt"
    )
    _assert_interrupted(stdout + stderr, tmp_path / "out")


@pytest.mark.unit
def test_local_mode_says_it_was_interrupted_and_prints_no_results(
    tmp_path, isolated, monkeypatch
):
    """Ctrl-C in the scan phase, as SIGINT raises it in the main thread."""
    from automated_security_helper.core.phases import scan_phase

    def _interrupted(self, *args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(scan_phase.ScanPhase, "execute", _interrupted)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            "--scanners",
            "bandit",
        ],
    )

    assert result.exit_code == 130, result.output
    _assert_interrupted(result.output, tmp_path / "out")


@pytest.mark.unit
def test_nix_mode_says_it_was_interrupted_and_exits_130(
    tmp_path, isolated, monkeypatch
):
    from automated_security_helper.interactions import run_ash_scan as mod

    def _interrupted(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(mod, "run_ash_nix", _interrupted)
    monkeypatch.setattr(mod, "nix_preflight", lambda: None)

    result = CliRunner().invoke(
        app,
        ["scan", "--mode", "nix", "--source-dir", "src", "--output-dir", "out"],
    )

    assert result.exit_code == 130, result.output
    _assert_interrupted(result.output, tmp_path / "out")


def _slow_child(tmp_path: Path, env: dict, wait_on: str) -> tuple[Path, dict]:
    child = _executable(
        tmp_path / "slow-child",
        _SLOW_TO_STOP.format(python=sys.executable, waiting=_WAITING),
    )
    log = tmp_path / "child.log"
    env = {**env, "FAKE_WAIT_ON": wait_on, "FAKE_LOG": str(log)}
    env.pop("ASH_IN_NIX", None)
    return child, {**env, "_log": str(log)}


@pytest.mark.skipif(os.name == "nt", reason="a terminal's Ctrl-C is SIGINT on POSIX")
@pytest.mark.parametrize(
    "to_the_group",
    [pytest.param(True, id="terminal-ctrl-c"), pytest.param(False, id="kill-int")],
)
@pytest.mark.integration
def test_nix_mode_passes_ctrl_c_to_the_shell_and_gives_it_the_grace(
    tmp_path, isolated, to_the_group
):
    """As container mode does: SIGINT on to the shell, 5 s to stop, then a kill.

    `nix develop --command` execs the command in place, so the process ASH starts
    is the inner ASH (measured with nix 2.35.2). subprocess.run gave it 0.25 s and
    killed it, and passed nothing on when the interrupt reached the host alone.
    """
    child, env = _slow_child(tmp_path, isolated["env"], "develop")
    bin_dir = tmp_path / "nix-bin"
    bin_dir.mkdir()
    (bin_dir / "nix").symlink_to(child)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    log = Path(env.pop("_log"))

    returncode, stdout, stderr = _interrupt(
        tmp_path,
        env,
        ["scan", "--mode", "nix", "--source-dir", "src", "--output-dir", "out"],
        to_the_group=to_the_group,
    )

    assert returncode == 130, stdout + stderr
    assert log.read_text(encoding="utf-8").split()[-2:] == ["INT", "CLEAN"], (
        "the shell was not given the interrupt and the grace to stop"
    )
    _assert_interrupted(stdout + stderr, tmp_path / "out")


@pytest.mark.skipif(os.name == "nt", reason="a terminal's Ctrl-C is SIGINT on POSIX")
@pytest.mark.integration
def test_build_image_says_it_was_interrupted_and_exits_130(tmp_path, isolated):
    """It exited 130 through typer's own handler, and said nothing."""
    runtime, env = _slow_child(tmp_path, isolated["env"], "build")
    log = Path(env.pop("_log"))

    returncode, stdout, stderr = _interrupt(
        tmp_path,
        env,
        ["build-image", "--oci-runner", str(runtime), "--no-run"],
        to_the_group=True,
    )

    assert returncode == 130, stdout + stderr
    assert log.read_text(encoding="utf-8").split()[-2:] == ["INT", "CLEAN"]
    assert "ASH build-image interrupted before it finished." in stderr, stderr
    assert "verdict" not in stderr, stderr
    assert "Traceback" not in stdout + stderr


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads the runtime's /proc status"
)
@pytest.mark.parametrize(
    "ignored",
    [
        pytest.param(True, id="ash-started-with-sigint-ignored"),
        pytest.param(False, id="ash-started-with-sigint-default"),
    ],
)
@pytest.mark.integration
def test_the_runtime_keeps_the_sigint_disposition_ash_was_started_with(
    tmp_path, isolated, ignored
):
    """A script run as `cmd &` starts ASH with SIGINT ignored, and the runtime
    inherits that. The hold around the runtime's start put a handler in its place,
    which exec resets, so the runtime was started with SIGINT at its default and a
    Ctrl-C meant for the foreground job reached it. The control: started with
    SIGINT at its default, the runtime is not started ignoring SIGINT either. This
    test sees only the runtime's mask; that ASH holds its own Python handler there
    is checked in-process, by test_a_ctrl_c_while_the_runtime_is_started_stops_it.
    """
    runtime = _executable(
        tmp_path / "runtime",
        _REPORTS_ITS_IGNORED_SIGNALS.format(python=sys.executable),
    )
    log = tmp_path / "runtime.log"
    previous = signal.signal(
        signal.SIGINT, signal.SIG_IGN if ignored else signal.SIG_DFL
    )
    try:
        # ASH inherits this process's SIGINT disposition across fork and exec.
        result = subprocess.run(  # nosec B603 - fixed interpreter and arguments
            [
                sys.executable,
                "-I",
                "-c",
                module_from_this_checkout("automated_security_helper.cli.main"),
                "build-image",
                "--oci-runner",
                str(runtime),
                "--no-run",
            ],
            cwd=tmp_path,
            env={**isolated["env"], "FAKE_LOG": str(log)},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        signal.signal(signal.SIGINT, previous)

    assert result.returncode == 0, result.stdout + result.stderr
    masks = log.read_text(encoding="utf-8").split()
    assert masks, result.stdout + result.stderr
    sigint = 1 << (signal.SIGINT - 1)
    assert [bool(int(mask, 16) & sigint) for mask in masks] == [ignored] * len(masks)


#: Stand-in pids above 2**30 sit past the kernel's pid space, so a signal or
#: waitid aimed at one can only fail: no stray kill can reach a real process.
_STAND_IN_PIDS = itertools.count(2**30 + 201)


class _InterruptedRuntime:
    """A runtime Ctrl-C reaches while ASH waits on it, and that outlives the grace.

    Records what ASH does to it. Anything else Popen has raises AttributeError.
    """

    def __init__(self):
        self.stdout = iter(())
        self.stderr = iter(())
        self.returncode = None
        self.pid = next(_STAND_IN_PIDS)
        self.calls = []

    def poll(self):
        raise KeyboardInterrupt

    def send_signal(self, signum):
        self.calls.append("send_signal")

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")

    def wait(self, timeout=None):
        self.calls.append(f"wait({timeout})")
        if timeout is not None:
            raise subprocess.TimeoutExpired("runtime", timeout)
        return 1


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(["build-image", "--no-run"], id="build-image"),
        pytest.param(
            [
                "scan",
                "--mode",
                "container",
                "--no-build",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
            ],
            id="container-scan",
        ),
    ],
)
@pytest.mark.unit
def test_on_windows_with_a_console_the_runtime_gets_its_grace(
    tmp_path, isolated, monkeypatch, command
):
    """The runtime shares ASH's console, which sent it the Ctrl-C already.

    Windows passes a Ctrl-C to every process attached to the console
    (https://learn.microsoft.com/windows/console/ctrl-c-and-ctrl-break-signals), so it
    is not terminated at once, which cut short the runtime's own handling and can
    leave a `docker run --rm` container running after ASH exits. The platform and the
    console are stood in for; the windows-latest CI leg is the real check.
    """
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils

    from tests.utils.windows_console import as_windows

    runtime = _InterruptedRuntime()
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kwargs: runtime
    )
    # Resolved without a lookup, so the runtime need not be executable where this runs.
    runner = str(tmp_path / "runtime")
    monkeypatch.setattr(run_ash_container, "_find_runner", lambda name: runner)
    as_windows(monkeypatch, console=True)

    result = CliRunner().invoke(app, [*command, "--oci-runner", runner])

    assert result.exit_code == 130, result.output
    assert "interrupted before it finished" in result.stderr, result.stderr
    # The grace in slices, so a second Ctrl-C lands between them; then the kill.
    slice_seconds = subprocess_utils.INTERRUPT_WAIT_SLICE_SECONDS
    slices = round(subprocess_utils.INTERRUPT_GRACE_SECONDS / slice_seconds)
    assert runtime.calls == [f"wait({slice_seconds})"] * slices + [
        "kill",
        "wait(None)",
    ], runtime.calls


class _NoOutput:
    """A runtime pipe with nothing in it."""

    def readline(self):
        return ""


class _StartedRuntime:
    """A runtime that is running and writes nothing.

    Bounded: a cell using this stand-in interrupts the run before any wait
    loop, so being polled thousands of times means the interrupt never fired
    -- a missed patch. Unbounded, that mistake hung whole test runs at these
    cells; bounded, it fails with its reason.
    """

    returncode = None

    def __init__(self):
        self.stdout = _NoOutput()
        self.stderr = _NoOutput()
        self.pid = next(_STAND_IN_PIDS)
        self.polls_left = 2000

    def poll(self):
        self.polls_left -= 1
        if self.polls_left <= 0:
            raise RuntimeError(
                "the stand-in runtime was polled past the test's bound: "
                "the interrupt this cell plants never fired"
            )
        return None


@pytest.mark.parametrize(
    "interrupted_at",
    [
        pytest.param(("make", 1), id="making-the-first-reader"),
        pytest.param(("make", 2), id="making-the-second-reader"),
        pytest.param(("start", 1), id="starting-the-first-reader"),
        pytest.param(("start", 2), id="starting-the-second-reader"),
    ],
)
@pytest.mark.unit
def test_a_ctrl_c_while_the_readers_start_stops_the_runtime(
    monkeypatch, interrupted_at
):
    """Ctrl-C after the runtime started and before the wait loop went past the handler.

    The window is where run_cmd_direct starts the threads that read the runtime's
    output. Measured with it held open for a second: ASH exited 130 5 ms after the
    interrupt, without the runtime's grace, and the runtime finished its cleanup a
    second later, unwaited and unkilled. Under load the window was wide enough to make
    test_build_image_says_it_was_interrupted_and_exits_130 read the runtime's log
    before that cleanup.
    """
    import types

    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils import threads as ash_threads

    runtime = _StartedRuntime()
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kwargs: runtime
    )
    stopped = []
    monkeypatch.setattr(run_ash_container, "_stop_after_interrupt", stopped.append)
    step, count = interrupted_at
    seen = {"make": 0, "start": 0}

    class _Reader(threading.Thread):
        def __init__(self, *args, **kwargs):
            seen["make"] += 1
            if step == "make" and seen["make"] == count:
                raise KeyboardInterrupt
            super().__init__(*args, **kwargs)

        def start(self):
            seen["start"] += 1
            if step == "start" and seen["start"] == count:
                raise KeyboardInterrupt
            super().start()

    # The readers are made through ash_thread (utils.threads), so the window
    # under test -- the interrupt landing while a reader is made or started --
    # is intercepted at that factory's own threading binding. A patch of
    # run_ash_container.threading no longer reaches the construction: with the
    # interrupt never raised, run_cmd_direct waited on the stand-in runtime
    # for good, which wedged a whole test run at this cell.
    monkeypatch.setattr(ash_threads, "threading", types.SimpleNamespace(Thread=_Reader))

    # KeyboardInterrupt, not the RuntimeError of joining a reader never started.
    with pytest.raises(KeyboardInterrupt):
        run_ash_container.run_cmd_direct(["runtime", "build", "."])

    assert stopped == [runtime]
    assert seen[step] == count


@pytest.fixture
def default_sigint():
    """SIGINT handled as Python handles it by default, then put back as it was.

    A test worker may run with another handler; these tests send the process a real
    SIGINT and need it to raise KeyboardInterrupt unless ASH holds it.
    """
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    yield
    signal.signal(signal.SIGINT, previous)


def _sigint_to_myself() -> None:
    """A Ctrl-C arriving now, run as Python runs a handler: at the next bytecode."""
    os.kill(os.getpid(), signal.SIGINT)
    for _ in range(1000):
        pass


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_while_the_runtime_is_started_stops_it(monkeypatch, default_sigint):
    """Ctrl-C after Popen made the runtime and before it was handed back.

    The Ctrl-C is held while the runtime is started and raised once run_cmd_direct
    has it, where the interrupt handler stops it as any other. Raised inside Popen,
    it would leave run_cmd_direct no process to stop: ASH would exit 130 at once and
    the runtime, given neither its grace nor a kill, would run on.
    """
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils

    runtime = _StartedRuntime()

    def _started(**kwargs):
        _sigint_to_myself()
        return runtime

    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", _started)
    stopped = []
    monkeypatch.setattr(run_ash_container, "_stop_after_interrupt", stopped.append)

    with pytest.raises(KeyboardInterrupt):
        run_ash_container.run_cmd_direct(["runtime", "build", "."])

    assert stopped == [runtime]
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_while_the_nix_shell_is_started_stops_it(monkeypatch, default_sigint):
    """The Nix shell is started the same way, and had the same gap."""
    from automated_security_helper.interactions import run_ash_nix

    shell = _StartedRuntime()

    def _started(*args, **kwargs):
        _sigint_to_myself()
        return shell

    monkeypatch.setattr(run_ash_nix.subprocess, "Popen", _started)
    stopped = []
    monkeypatch.setattr(run_ash_nix, "stop_after_interrupt", stopped.append)

    with pytest.raises(KeyboardInterrupt):
        run_ash_nix._enter_shell(["nix", "develop"], env={})

    assert stopped == [shell]
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


class _ExitedChild:
    """A started child that has already exited: nothing left to stop.

    For the cells that call the runners directly: what they measure is over
    before any stop, and a child that reads as exited keeps the stop paths,
    which signal real pids, off the stand-in. No real process exists.
    """

    returncode = 0

    def __init__(self):
        self.pid = next(_STAND_IN_PIDS)
        self.stdout = None
        self.stderr = None
        self.stdin = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode


def _a_ctrl_c_inside_popen() -> None:
    """A Ctrl-C delivered while Popen runs, with no real signal sent.

    The installed handler is called directly, as Python would call it at the
    next bytecode: under the launch's hold that records it; unheld, it raises.
    """
    signal.getsignal(signal.SIGINT)(signal.SIGINT, None)


@pytest.mark.skipif(os.name == "nt", reason="SIGINT handling under test is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_held_at_the_launch_is_raised_with_the_child_recorded(monkeypatch):
    """The held Ctrl-C goes off only once the child is in the spawn records.

    _run_cancellable releases its hold after _record_spawn has recorded the
    child, as run_ash_container and run_ash_nix record their children before
    releasing. The KeyboardInterrupt the release raises then finds the child in
    _RUNNING_GROUPS and the die-now mirror: a stop that fails, or a second
    Ctrl-C escaping it, leaves a child kill_running_groups can still find.
    Released before the record, the interrupt went off with the child in
    neither, and _begin_spawn's count still held.
    """
    from automated_security_helper.utils import subprocess_utils

    child = _ExitedChild()
    seen = {}

    def _notes_the_record_then_raises(signum, frame):
        seen["recorded"] = child.pid in subprocess_utils._RUNNING_GROUPS
        raise KeyboardInterrupt

    def _started_under_a_ctrl_c(*args, **kwargs):
        _a_ctrl_c_inside_popen()
        return child

    previous = signal.signal(signal.SIGINT, _notes_the_record_then_raises)
    try:
        monkeypatch.setattr(subprocess, "Popen", _started_under_a_ctrl_c)
        starting_before = subprocess_utils._SPAWNS_STARTING
        with pytest.raises(KeyboardInterrupt):
            subprocess_utils._run_cancellable(
                ["/opt/ash-test/bin/tool", "scan"],
                cancel_event=threading.Event(),
                graceful_timeout=False,
                own_group=False,
            )
        assert seen["recorded"], "the interrupt went off before the child was recorded"
        assert subprocess_utils._SPAWNS_STARTING == starting_before
        assert signal.getsignal(signal.SIGINT) is _notes_the_record_then_raises
    finally:
        signal.signal(signal.SIGINT, previous)


class _StoppableChild(_ExitedChild):
    """A running stand-in child whose terminate is recorded. No real process."""

    def __init__(self):
        super().__init__()
        self.returncode = None
        self.terminated = False

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["stand-in"], timeout or 0)
        return self.returncode


@pytest.mark.skipif(os.name == "nt", reason="SIGINT handling under test is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_while_a_sandboxed_spawn_starts_stops_the_child(
    monkeypatch, default_sigint
):
    """_run_stoppable holds the launch Ctrl-C too, and its stop gets the child.

    It is the runner for every sandboxed spawn outside a cancel scope, and the
    sandbox wrapper calls setsid, so its child leads a session of its own and
    never had the terminal's Ctrl-C. Raised inside Popen, the interrupt left
    the runner no process to stop; held, it is raised inside the try whose
    handling terminates the child.
    """
    from automated_security_helper.utils import subprocess_utils

    child = _StoppableChild()

    def _started_under_a_ctrl_c(*args, **kwargs):
        _a_ctrl_c_inside_popen()
        return child

    monkeypatch.setattr(subprocess, "Popen", _started_under_a_ctrl_c)

    with pytest.raises(KeyboardInterrupt):
        subprocess_utils._run_stoppable(["/opt/ash-test/bin/tool", "scan"])

    assert child.terminated, "the child was not stopped after the held Ctrl-C"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(os.name == "nt", reason="SIGINT handling under test is POSIX")
@pytest.mark.unit
def test_a_popen_failure_after_a_held_ctrl_c_raises_the_interrupt(
    monkeypatch, default_sigint
):
    """A launch that fails under a held Ctrl-C raises the interrupt, cleaned up.

    Popen can fail after a Ctrl-C was held (the tool is gone, say). The failure
    branch must hand the held interrupt to the previous handler -- raised in
    place of the failure and chained from it -- give _begin_spawn's count back,
    and put the SIGINT handler back.
    """
    from automated_security_helper.utils import subprocess_utils

    def _fails_under_a_ctrl_c(*args, **kwargs):
        _a_ctrl_c_inside_popen()
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(subprocess, "Popen", _fails_under_a_ctrl_c)
    starting_before = subprocess_utils._SPAWNS_STARTING

    with pytest.raises(KeyboardInterrupt) as interrupted:
        subprocess_utils._run_cancellable(
            ["/opt/ash-test/bin/tool", "scan"],
            cancel_event=threading.Event(),
            graceful_timeout=False,
            own_group=False,
        )

    assert isinstance(interrupted.value.__cause__, OSError)
    assert subprocess_utils._SPAWNS_STARTING == starting_before
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_at_the_pre_spawn_check_starts_no_runtime(monkeypatch, default_sigint):
    """A Ctrl-C arriving at the pre-spawn cancel check starts nothing.

    The check sits before the held window, as the spawn paths in
    utils/subprocess_utils.py place theirs, so an interrupt here is an
    ordinary unheld one and the runtime is never started. The start count is
    the discriminator: a check inside the held window held this interrupt,
    started the runtime, and only then stopped it -- a start the operator's
    Ctrl-C asked never to make.
    """
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils

    real = run_ash_container.raise_if_cancelled

    def _interrupt_arrives_at_the_check():
        _sigint_to_myself()
        real()

    monkeypatch.setattr(
        run_ash_container, "raise_if_cancelled", _interrupt_arrives_at_the_check
    )
    spawned = []
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: spawned.append(kw)
    )

    with pytest.raises(KeyboardInterrupt):
        run_ash_container.run_cmd_direct(["runtime", "run", "scan"])

    assert spawned == [], "the interrupt at the check must start no runtime"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_a_ctrl_c_at_the_shells_pre_spawn_check_starts_no_shell(
    monkeypatch, default_sigint
):
    """The Nix shell's pre-spawn check sits before its held window the same
    way, so an interrupt at the check starts no shell."""
    from automated_security_helper.interactions import run_ash_nix

    real = run_ash_nix.raise_if_cancelled

    def _interrupt_arrives_at_the_check():
        _sigint_to_myself()
        real()

    monkeypatch.setattr(
        run_ash_nix, "raise_if_cancelled", _interrupt_arrives_at_the_check
    )
    spawned = []
    monkeypatch.setattr(
        run_ash_nix.subprocess,
        "Popen",
        lambda *args, **kw: spawned.append((args, kw)),
    )

    with pytest.raises(KeyboardInterrupt):
        run_ash_nix._enter_shell(["nix", "develop"], env={})

    assert spawned == [], "the interrupt at the check must start no shell"
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_a_runtime_that_fails_to_start_during_a_ctrl_c_reports_the_ctrl_c(
    monkeypatch, default_sigint
):
    """No process to stop, so nothing is stopped; the Ctrl-C is still the outcome,
    and the handler is put back."""
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils

    def _failed(**kwargs):
        _sigint_to_myself()
        raise FileNotFoundError("runtime")

    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", _failed)
    stopped = []
    monkeypatch.setattr(run_ash_container, "_stop_after_interrupt", stopped.append)

    with pytest.raises(KeyboardInterrupt):
        run_ash_container.run_cmd_direct(["runtime", "build", "."])

    assert stopped == []
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads the child's /proc status"
)
@pytest.mark.parametrize(
    "disposition",
    [
        pytest.param(signal.SIG_IGN, id="ignored"),
        pytest.param(signal.SIG_DFL, id="default"),
    ],
)
@pytest.mark.integration
def test_a_sigint_disposition_that_raises_nothing_is_left_alone(disposition):
    """Only a Python handler raises KeyboardInterrupt, so only one is held.

    A script run as `cmd &` starts with SIGINT ignored, and its children inherit
    that. A recording handler put in its place would be reset by exec, so a runtime
    started inside the hold would stop ignoring SIGINT, and a SIGINT in the hold
    would raise KeyboardInterrupt where it is ignored.
    """
    from automated_security_helper.utils.subprocess_utils import HeldInterrupt

    previous = signal.signal(signal.SIGINT, disposition)
    try:
        with HeldInterrupt() as held:
            assert signal.getsignal(signal.SIGINT) is disposition
            child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
                [sys.executable, "-I", "-c", "print(open('/proc/self/status').read())"],
                capture_output=True,
                text=True,
                check=True,
            )
            if disposition is signal.SIG_IGN:
                _sigint_to_myself()
            held.release()
        assert signal.getsignal(signal.SIGINT) is disposition
    finally:
        signal.signal(signal.SIGINT, previous)
    [ignored] = [
        int(line.split()[1], 16)
        for line in child.stdout.splitlines()
        if line.startswith("SigIgn:")
    ]
    sigint_ignored = bool(ignored & (1 << (signal.SIGINT - 1)))
    assert sigint_ignored is (disposition is signal.SIG_IGN)


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.parametrize(
    "leaves_by",
    [
        pytest.param("release", id="released"),
        pytest.param("failure", id="the-child-failed-to-start"),
    ],
)
@pytest.mark.unit
def test_a_held_ctrl_c_goes_to_a_handler_that_raises_nothing(leaves_by):
    """A Python handler is held whatever it does with a Ctrl-C, and the held one
    was raised as KeyboardInterrupt, so a handler that only records it was skipped
    and the caller got an exception the handler never raised. The held Ctrl-C is
    handed to that handler instead."""
    from automated_security_helper.utils.subprocess_utils import HeldInterrupt

    seen = []

    def _recorded(signum, frame):
        seen.append(signum)

    previous = signal.signal(signal.SIGINT, _recorded)
    try:
        if leaves_by == "release":
            with HeldInterrupt() as held:
                _sigint_to_myself()
                assert seen == []
                held.release()
        else:
            with pytest.raises(FileNotFoundError):
                with HeldInterrupt():
                    _sigint_to_myself()
                    raise FileNotFoundError("runtime")
        handler_after = signal.getsignal(signal.SIGINT)
    except KeyboardInterrupt:
        # Caught here: pytest reads a KeyboardInterrupt as the run being stopped.
        pytest.fail("the held Ctrl-C was raised, not handed to the handler held")
    finally:
        signal.signal(signal.SIGINT, previous)
    assert seen == [signal.SIGINT]
    assert handler_after is _recorded


@pytest.mark.skipif(os.name == "nt", reason="a SIGINT sent to a process is POSIX")
@pytest.mark.unit
def test_each_held_ctrl_c_reaches_the_handler_as_python_delivers_it():
    """Python calls a handler once per SIGINT, with its number as an int and the
    frame it arrived in. The hold handed two Ctrl-Cs over as one, and passed
    signal.SIGINT, an enum member."""
    from automated_security_helper.utils.subprocess_utils import HeldInterrupt

    seen = []

    def _recorded(signum, frame):
        arrived_in = (
            frame.f_code.co_name if isinstance(frame, types.FrameType) else None
        )
        seen.append((type(signum), signum, arrived_in))

    previous = signal.signal(signal.SIGINT, _recorded)
    try:
        with HeldInterrupt() as held:
            _sigint_to_myself()
            _sigint_to_myself()
            held.release()
    except KeyboardInterrupt:
        # Caught here: pytest reads a KeyboardInterrupt as the run being stopped.
        pytest.fail("a held Ctrl-C was raised, not handed to the handler held")
    finally:
        signal.signal(signal.SIGINT, previous)

    assert seen == [(int, int(signal.SIGINT), _sigint_to_myself.__name__)] * 2


@pytest.mark.unit
def test_the_runtime_is_started_off_the_main_thread(monkeypatch):
    """Only the main thread can set a signal handler, so off it nothing is held."""
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils

    class _Finished(_StartedRuntime):
        returncode = 0

        def poll(self):
            return 0

    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kwargs: _Finished()
    )
    before = signal.getsignal(signal.SIGINT)
    outcome = []
    worker = threading.Thread(
        target=lambda: outcome.append(
            run_ash_container.run_cmd_direct(["runtime", "build", "."], check=False)
        )
    )
    worker.start()
    worker.join(timeout=30)

    assert [result.returncode for result in outcome] == [0]
    assert signal.getsignal(signal.SIGINT) is before


@pytest.mark.parametrize(
    "args, says",
    [
        pytest.param(
            ["--no-run"],
            "ASH build-image interrupted before it finished.",
            id="build-only",
        ),
        pytest.param(
            [],
            "ASH build-image interrupted before it finished: there is no verdict",
            id="build-and-scan",
        ),
    ],
)
@pytest.mark.unit
def test_build_image_names_a_verdict_only_when_it_would_have_scanned(
    isolated, monkeypatch, args, says
):
    """Without --no-run, build-image goes on to scan, so a verdict was owed."""
    from automated_security_helper.cli import image

    def _interrupted(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(image, "run_ash_scan", _interrupted)

    result = CliRunner().invoke(app, ["build-image", *args])

    assert result.exit_code == 130, result.output
    assert says in result.stderr, result.stderr
    if "--no-run" in args:
        assert "verdict" not in result.stderr, result.stderr

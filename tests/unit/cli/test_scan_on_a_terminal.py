# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash scan` with the live progress display finishes, wherever Rich decides it is
on a terminal.

The live display only runs on a terminal: off one, or under CI, ASH prints the log
instead. On a terminal Rich's Live replaces sys.stdout (and sys.stderr) with a
proxy, and a console stream that wrote into that proxy fed every write back into
its own console, so the scan hung after "Executing phases" and wrote no report.
CliRunner and a captured stdout are not terminals, so these run the CLI for real:
on a pseudo-terminal, on one with the log sent to stderr, and into a pipe with
the variables that make Rich treat a pipe as a terminal (FORCE_COLOR,
TTY_COMPATIBLE, and Azure Pipelines' TF_BUILD with FORCE_COLOR).

Each scan runs in a child on the checkout under test, with this process's
environment (HOME included) minus CI and the container marker, one scanner that
ships in the environment and needs no network (detect-secrets), local mode, and
a deadline. Each child starts its own session, so at the deadline the scan and
every scanner it started are killed together.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

needs_a_pty = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "openpty"),
    reason="needs a pseudo-terminal",
)

DEADLINE_SECONDS = 180
#: The child's probes are answered first (CHILD_TOOL_PROBE_STUBS): it found the uv
#: installed with ASH beside its interpreter, and detect-secrets' dependency check
#: ran ``uv tool run detect-secrets --version``, which fetched detect-secrets and
#: its dependencies into the uv cache in the test's HOME.
ASH = CHILD_TOOL_PROBE_STUBS + (
    "import sys; sys.argv[0] = 'ash'; "
    "from automated_security_helper.cli.entrypoint import main; main()"
)
#: Variables that decide where ASH logs and whether Rich sees a terminal; each
#: test sets the ones it is about.
_CHOSEN_PER_TEST = (
    "CI",
    "ASH_IN_CONTAINER",
    "ASH_LOG_TO_STDERR",
    "TTY_COMPATIBLE",
    "FORCE_COLOR",
    "NO_COLOR",
    "TF_BUILD",
    "GITHUB_ACTIONS",
)


def _child_env(extra: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    for name in _CHOSEN_PER_TEST:
        env.pop(name, None)
    env.update(TERM="xterm-256color", COLUMNS="120", LINES="40")
    env.update(extra)
    return checkout_env(env)


def _scan_args(tmp_path: Path) -> tuple[list[str], Path]:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n"
        "    return subprocess.call(cmd, shell=True)\n"
    )
    output = tmp_path / "out"
    args = [
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        "detect-secrets",
    ]
    return args, output


def _kill_session(child: subprocess.Popen) -> None:
    """Kill *child* and everything it started: it leads its own session."""
    if hasattr(os, "killpg"):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        child.kill()
    child.wait()


def _run_on_a_pty(
    args: list[str], cwd: Path, extra: dict[str, str] | None = None
) -> tuple[int, str]:
    """Run ``ash *args`` with a pty as stdin, stdout and stderr; return its exit
    code and everything it wrote, or fail at the deadline."""
    env = _child_env(extra or {})
    main, child_side = os.openpty()
    child = subprocess.Popen(
        [sys.executable, "-c", ASH, *args],
        stdin=child_side,
        stdout=child_side,
        stderr=child_side,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    os.close(child_side)
    written = bytearray()
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_session(child)
                pytest.fail(
                    f"still running after {DEADLINE_SECONDS} s; last output: "
                    f"{bytes(written[-1500:])!r}"
                )
            ready, _, _ = select.select([main], [], [], min(remaining, 1.0))
            if ready:
                try:
                    chunk = os.read(main, 65536)
                except OSError:  # EIO once the child side is closed (Linux)
                    chunk = b""
                if not chunk:
                    break
                written += chunk
            elif child.poll() is not None:
                break
        return child.wait(timeout=30), written.decode("utf-8", errors="replace")
    finally:
        os.close(main)
        if child.poll() is None:
            _kill_session(child)


@needs_a_pty
@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({}, id="log-on-stdout"),
        pytest.param({"ASH_LOG_TO_STDERR": "1"}, id="log-on-stderr"),
    ],
)
def test_a_scan_with_the_live_display_finishes(tmp_path, extra):
    args, output = _scan_args(tmp_path)

    code, written = _run_on_a_pty(args, cwd=tmp_path, extra=extra)

    assert code in (0, 2), (code, written[-3000:])
    assert any((output / "reports").iterdir()), written[-3000:]
    # The live display ran: its panel title reached the terminal.
    assert "ASH Security Scan Progress" in written, written[-3000:]


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({"FORCE_COLOR": "1"}, id="force-color"),
        pytest.param({"TTY_COMPATIBLE": "1"}, id="tty-compatible"),
        pytest.param({"TF_BUILD": "True", "FORCE_COLOR": "1"}, id="azure-force-color"),
    ],
)
def test_a_scan_into_a_pipe_rich_takes_for_a_terminal_finishes(tmp_path, extra):
    """With these, Rich treats a pipe as a terminal and starts Live's redirect, so
    the cycle reached CI logs too, on every platform."""
    args, output = _scan_args(tmp_path)

    code, written = _run_into_a_pipe(args, cwd=tmp_path, extra=extra)

    assert code in (0, 2), (code, written[-3000:])
    assert any((output / "reports").iterdir()), written[-3000:]
    # Rich took the pipe for a terminal: the live display hid the cursor. Without
    # this, a change that turned progress off off a terminal would pass here.
    assert "\x1b[?25l" in written, written[-3000:]


def test_a_scan_with_the_inspect_phase_finishes(tmp_path):
    """Every phase runs, convert and inspect included: a phase calling a progress
    method that no longer exists would end the scan with AttributeError."""
    args, output = _scan_args(tmp_path)

    code, written = _run_into_a_pipe([*args, "--inspect"], cwd=tmp_path, extra={})

    assert code in (0, 2), (code, written[-3000:])
    assert "AttributeError" not in written, written[-3000:]
    assert any((output / "reports").iterdir()), written[-3000:]
    # What the inspect phase writes: present only when the phase ran through.
    assert (output / "analysis" / "sarif_fields.json").is_file(), written[-3000:]


def _run_into_a_pipe(
    args: list[str], cwd: Path, extra: dict[str, str]
) -> tuple[int, str]:
    child = subprocess.Popen(
        [sys.executable, "-c", ASH, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
        env=_child_env(extra),
        start_new_session=True,
    )
    try:
        written, _ = child.communicate(timeout=DEADLINE_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_session(child)
        written, _ = child.communicate()
        pytest.fail(
            f"still running after {DEADLINE_SECONDS} s; last output: "
            f"{written[-1500:]!r}"
        )
    return child.returncode, written.decode("utf-8", errors="replace")

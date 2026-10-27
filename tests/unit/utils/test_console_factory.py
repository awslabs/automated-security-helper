# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No line of ASH's console output is a CI command, however Rich lays it out.

A CI runner reads each line of a job's output: GitHub Actions takes one that
starts, after whitespace, with "::" as a workflow command ("::add-mask::",
"::error", "::stop-commands::"), its legacy "##[cmd]" anywhere in a line, and
Azure Pipelines "##vso[". The message-level rule (utils/terminal_text.py) sees
only the line starts in a message's own text, but Rich wraps the message column
at the console width (80 off a terminal, as on a runner; 150 in the container)
and folds a long word at a character position, and either can start a new line
with text from the middle of the message: a suppression reason
"w w w w w w w w w ::add-mask::hidden" quoted by the expiration check would put an
"::add-mask::hidden" line under CI.

Every console ASH prints through comes from utils/console.py's factory, whose
stream checks each line Rich actually writes when it is not a terminal. A
terminal is passed everything as is.
"""

from __future__ import annotations

import ast
import datetime
import io
import itertools
import logging
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.log import get_logger
from tests.utils.helpers import importing_this_checkout

#: Output a CI runner reads as a command: a line starting, after whitespace, with
#: "::", or "##" with an optional name and "[" anywhere ("##[", "##vso[",
#: "##teamcity["). A bare "##", a Markdown heading's, is none.
COMMAND = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

_names = itertools.count()

#: Messages that each printed a command line at the console width given: a wrap,
#: a fold inside a word, and the two forms a runner reads anywhere in a line.
REPROS = [
    pytest.param(
        "x" * 50 + " ::error title=injected::from a wrapped line", 80, id="wrapped"
    ),
    pytest.param("k=" + "b" * 51 + "::error::pwned", 80, id="folded-word"),
    pytest.param("see ##[add-mask]hidden", 80, id="legacy-command"),
    pytest.param("see ##vso[task.setvariable variable=x]y", 80, id="azure-command"),
]

#: npm-audit's "Target directory <dir> is empty" for a directory whose name folds
#: so that "::add-mask::hidden" starts a line (k, the length that does it, for
#: each width).
FOLDED_PATHS = [
    pytest.param(23, 80, id="k23-80"),
    pytest.param(74, 80, id="k74-80"),
    pytest.param(125, 80, id="k125-80"),
    pytest.param(93, 150, id="k93-150"),
]


@pytest.fixture
def ci_logger(capsys, monkeypatch):
    """get_logger's console as a CI runner gets it: not a terminal, time and level
    columns on, as wide as the run's console."""
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    monkeypatch.delenv("ASH_IN_CONTAINER", raising=False)
    monkeypatch.delenv("COLUMNS", raising=False)
    built = []

    def build(width: int):
        if width == 150:
            monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
        logger = get_logger(
            name=f"ash-ci-console-{next(_names)}",
            level=5,
            show_progress=False,
            use_color=False,
            simple_format=False,
        )
        built.append(logger)
        capsys.readouterr()
        return logger

    yield build
    for logger in built:
        logger.handlers = []


@pytest.mark.parametrize("message, width", REPROS)
def test_no_wrapped_or_folded_line_of_a_log_message_is_a_command(
    ci_logger, capsys, message, width
):
    ci_logger(width).warning(message)

    out = capsys.readouterr().out
    assert not COMMAND.search(out), out


@pytest.mark.parametrize("width", [80, 150])
def test_no_wrap_or_fold_position_starts_a_command(ci_logger, capsys, width):
    """The repros above at every offset, so whichever column Rich breaks at, the
    "::" or "##[" after it is checked."""
    logger = ci_logger(width)
    for n in range(2 * width):
        logger.warning("k=" + "b" * n + "::error::pwned")
        logger.warning("x" * n + " ::error title=injected::w")
        logger.warning("y" * n + "##[add-mask]hidden")

    out = capsys.readouterr().out
    assert out.count("WARNING") == 3 * 2 * width, out[:2000]
    assert not COMMAND.search(out), COMMAND.search(out)


def test_no_wrap_position_in_the_live_panel_starts_a_command():
    """The panel lays its rows out at the console width the same way."""
    from automated_security_helper.utils.console import ash_console
    from automated_security_helper.utils.rich_log_handler import (
        LiveDisplayLogHandler,
        RichLogPanel,
    )

    out = io.StringIO()
    console = ash_console(file=out, width=80, color_system=None)
    for n in range(0, 160, 3):
        panel = RichLogPanel(max_lines=3)
        handler = LiveDisplayLogHandler(panel, level=logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger = logging.getLogger(f"ash-ci-panel-{next(_names)}")
        logger.propagate = False
        logger.addHandler(handler)
        logger.warning("x" * n + " ::error title=panel::w " + "y" * n + "##[x]")
        console.print(panel)

    assert not COMMAND.search(out.getvalue()), COMMAND.search(out.getvalue())


@pytest.mark.parametrize("k, width", FOLDED_PATHS)
def test_a_folded_plugin_message_does_not_start_a_command(
    ci_logger, capsys, monkeypatch, k, width
):
    """_plugin_log logs with MARKUP; the message is npm-audit's, naming the target."""
    from automated_security_helper.base import plugin_base

    monkeypatch.setattr(plugin_base, "ASH_LOGGER", ci_logger(width))
    plugin = SimpleNamespace(
        config=SimpleNamespace(name="npm-audit"), errors=[], output=[]
    )
    target = "/home/runner/work/repo/repo/" + "A" * k + "::add-mask::hidden"

    plugin_base.PluginBase._plugin_log(
        plugin, f"Target directory {target} is empty", level=logging.INFO
    )

    out = capsys.readouterr().out
    assert "Target directory" in out, out
    assert not COMMAND.search(out), out


def test_a_wrapped_suppression_reason_does_not_start_a_command(
    ci_logger, capsys, monkeypatch
):
    """End to end: the expiration check quotes the reason, which Rich wraps."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
        suppression_expiration_checker as checker,
    )

    monkeypatch.setattr(checker, "ASH_LOGGER", ci_logger(80))
    soon = (datetime.date.today() + datetime.timedelta(days=10)).isoformat()
    config = AshConfig(
        project_name="p",
        global_settings={
            "suppressions": [
                {
                    "rule_id": "R1",
                    "path": "src/app.py",
                    "reason": "w w w w w w w w w ::add-mask::hidden",
                    "expiration": soon,
                }
            ]
        },
    )

    checker.handle_suppression_expiration_check(
        plugin_context=SimpleNamespace(config=config, ignore_suppressions=False)
    )

    out = capsys.readouterr().out
    assert "add-mask" in out, out
    assert not COMMAND.search(out), out


def test_a_wrapped_traceback_does_not_start_a_command(ci_logger, capsys):
    logger = ci_logger(80)
    for n in range(0, 120, 5):
        try:
            raise RuntimeError("x" * n + " ::error title=tb::from a wrapped traceback")
        except RuntimeError:
            logger.exception("the scan failed")

    out = capsys.readouterr().out
    assert "Traceback" in out, out[:2000]
    assert not COMMAND.search(out), COMMAND.search(out)


@pytest.mark.parametrize("message, width", REPROS)
def test_the_live_display_off_a_terminal_starts_no_command(
    capsys, monkeypatch, message, width
):
    """LiveProgressDisplay, as a scan runs it: off a terminal Rich prints the
    panel once, at stop, laid out at the console width."""
    from automated_security_helper.core.progress import LiveProgressDisplay
    from automated_security_helper.utils import log

    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(log.ASH_LOGGER, "level", logging.DEBUG)
    monkeypatch.setattr(log.ASH_LOGGER, "handlers", [])
    display = LiveProgressDisplay(show_progress=True, max_log_lines=4)
    phase = list(display.tasks)[0]
    display.start()
    try:
        log.ASH_LOGGER.warning(message)
        task = display.add_task(phase=phase, description="Scanning")
        # Escaped, as every phase escapes what a description quotes.
        display.update_task(
            phase=phase, task_id=task, description=log.escape_markup(message)
        )
    finally:
        display.stop()

    out = capsys.readouterr().out
    assert not COMMAND.search(out), out


def test_a_status_off_a_terminal_starts_no_command(capsys):
    from automated_security_helper.utils.console import ash_console

    console = ash_console()
    with console.status("x" * 70 + " ::error::from a status"):
        console.print("k=" + "b" * 90 + "::error::pwned")

    out = capsys.readouterr().out
    assert not COMMAND.search(out), out


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


#: Runners that read workflow commands from a job's output, by the variable each
#: sets in every job.
CI_RUNNERS = [
    pytest.param("GITHUB_ACTIONS", "true", id="github-actions"),
    pytest.param("TF_BUILD", "True", id="azure-pipelines"),
    pytest.param("TEAMCITY_VERSION", "2024.12", id="teamcity"),
]


def test_a_terminal_gets_the_output_as_rendered(monkeypatch):
    """Only a stream that is not a terminal is checked, outside a CI runner."""
    from automated_security_helper.utils.console import ash_console

    for name in ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION"):
        monkeypatch.delenv(name, raising=False)
    # Rich sizes a TERM=dumb or TERM=unknown terminal at 80 columns whatever width
    # it is given, so the line would not wrap: the cell names its terminal.
    monkeypatch.setenv("TERM", "xterm-256color")
    tty = _Tty()
    ash_console(file=tty, width=40).print("x" * 30 + " ::error::shown as is")

    assert re.search(r"^::error::shown as is", tty.getvalue(), re.MULTILINE)


@pytest.mark.parametrize("name, value", CI_RUNNERS)
def test_a_terminal_under_a_ci_runner_is_checked_too(monkeypatch, name, value):
    """A CI job can give ASH a terminal (docker run -t, script, unbuffer, container
    mode's own -t): the runner still reads every line of it."""
    from automated_security_helper.utils.console import ash_console

    monkeypatch.setenv(name, value)
    # Rich sizes a TERM=dumb or TERM=unknown terminal at 80 columns whatever width
    # it is given, so the line would not wrap: the cell names its terminal.
    monkeypatch.setenv("TERM", "xterm-256color")
    tty = _Tty()
    ash_console(file=tty, width=40).print("x" * 30 + " ::error::from a wrapped line")

    assert not COMMAND.search(tty.getvalue()), tty.getvalue()
    assert "\\x3a:error::from a wrapped line" in tty.getvalue(), tty.getvalue()


needs_a_pty = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "openpty"),
    reason="needs a pseudo-terminal",
)

#: A warning whose wrap on a pty starts a line with "::error": the log's message
#: column is narrower than the line.
_WRAPPED_WARNING = "x" * 50 + " ::error title=injected::from a wrapped line"
_PTY_CHILD = (
    "from automated_security_helper.utils.log import get_logger\n"
    "logger = get_logger(name='ash-pty', level=5, show_progress=False,"
    " use_color=False, simple_format=False)\n"
    f"logger.warning({_WRAPPED_WARNING!r})\n"
)
#: Variables that decide whether output is checked or how Rich sees the pty; each
#: test sets the ones it is about.
_CHOSEN_PER_PTY_TEST = (
    "CI",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "TEAMCITY_VERSION",
    "FORCE_COLOR",
    "TTY_COMPATIBLE",
    "TTY_INTERACTIVE",
    "NO_COLOR",
    "ASH_LOG_TO_STDERR",
    "ASH_IN_CONTAINER",
)
#: A terminal sequence, which a runner skips at a line start.
_TERMINAL_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _log_on_a_pty(extra: dict[str, str]) -> str:
    """Run _PTY_CHILD with a pty as stdin, stdout and stderr, as `docker run -t`,
    `script` or `unbuffer` give one; return what it wrote, without terminal
    sequences, or fail at the deadline."""
    env = dict(os.environ)
    for name in _CHOSEN_PER_PTY_TEST:
        env.pop(name, None)
    env.update(TERM="xterm-256color", COLUMNS="80", LINES="40")
    env.update(extra)
    repo_root = Path(__file__).resolve().parents[3]
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    main, child_side = os.openpty()
    child = subprocess.Popen(
        [sys.executable, "-c", importing_this_checkout(_PTY_CHILD)],
        stdin=child_side,
        stdout=child_side,
        stderr=child_side,
        env=env,
        start_new_session=True,
    )
    os.close(child_side)
    written = bytearray()
    deadline = time.monotonic() + 60
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                pytest.fail(f"still running after 60 s: {bytes(written[-1500:])!r}")
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
        assert child.wait(timeout=30) == 0, bytes(written[-1500:])
    finally:
        os.close(main)
        if child.poll() is None:
            # The child leads its own session: kill it with all it started.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
    return _TERMINAL_SEQUENCE.sub("", written.decode("utf-8", errors="replace"))


@needs_a_pty
@pytest.mark.parametrize("name, value", CI_RUNNERS)
def test_a_wrapped_warning_on_a_pty_under_a_ci_runner_starts_no_command(name, value):
    written = _log_on_a_pty({name: value})

    assert "from a wrapped line" in written, written
    assert not COMMAND.search(written), (COMMAND.search(written), written)


@needs_a_pty
def test_a_wrapped_warning_on_a_pty_outside_ci_is_written_as_rendered():
    written = _log_on_a_pty({})

    assert re.search(r"^\s*::error title=injected::", written, re.MULTILINE), written


def test_a_line_start_after_a_carriage_return_or_color_codes_is_checked():
    from automated_security_helper.utils.console import CommandSafeStream

    target = io.StringIO()
    stream = CommandSafeStream(lambda: target)
    stream.write("a\r::error::one\n\x1b[31m  ::error::two\x1b[0m\n  ")
    stream.write("::error::three across writes\nok ##vso[x]\n")

    assert not COMMAND.search(target.getvalue()), target.getvalue()
    assert target.getvalue().count("\\x3a:error") == 3, target.getvalue()


@pytest.mark.parametrize("sink", ["stream", "console", "stdout"])
def test_a_markdown_heading_is_no_command(sink, capsys):
    """A bare "##" at a line start, a Markdown heading's ("## Scan Metadata"), is
    no command to any runner: only "::" at a line start and "##" with an optional
    name and "[" anywhere are. It is printed as written on a pipe, through a
    console and on stdout, and the commands beside it are still broken."""
    from automated_security_helper.utils.console import (
        CommandSafeStream,
        ash_console,
        echo,
    )

    text = (
        "## Scan Metadata\n"
        "##[group]g\n"
        "x ##vso[task.setvariable variable=x]y\n"
        "::warning::w\n"
    )
    if sink == "stream":
        target = io.StringIO()
        CommandSafeStream(lambda: target).write(text)
        written = target.getvalue()
    elif sink == "console":
        out = io.StringIO()
        ash_console(file=out).print(text, end="", markup=False, highlight=False)
        written = out.getvalue()
    else:
        echo(text, nl=False)
        written = capsys.readouterr().out

    assert written.splitlines()[0] == "## Scan Metadata", written
    assert "\\x23#[group]g" in written, written
    assert "\\x23#vso[task.setvariable" in written, written
    assert "\\x3a:warning::w" in written, written


@pytest.mark.parametrize(
    "written",
    [
        pytest.param("see ##vso\x1b[0m\x1b[32m[task.complete]x\n", id="sgr-in-name"),
        pytest.param("see #\x1b[1m#[error]x\n", id="sgr-between-hashes"),
        pytest.param("\x1b[1m:\x1b[0m:error::x\n", id="sgr-between-colons"),
        pytest.param("  #\x1b[2m#[add-mask]x\n", id="sgr-in-line-start-hashes"),
    ],
)
def test_a_command_split_by_color_codes_is_checked(written):
    """A runner that drops color codes before it reads a line reads these as
    commands: Rich's highlighter puts codes inside a word it colors in parts."""
    from automated_security_helper.utils.console import CommandSafeStream

    target = io.StringIO()
    CommandSafeStream(lambda: target).write(written)

    plain = _TERMINAL_SEQUENCE.sub("", target.getvalue())
    assert not COMMAND.search(plain), (plain, target.getvalue())


@pytest.mark.parametrize("value", ["x ##vso[task.complete]y", "x ##[error]y"])
def test_a_highlighted_value_starts_no_command_once_color_is_stripped(
    monkeypatch, value
):
    """Debug locals and Pretty print a value through the repr highlighter, which
    colors a "[" on its own, so a code lands between "##vso" and "["."""
    from rich.pretty import Pretty

    from automated_security_helper.utils.console import ash_console

    monkeypatch.setenv("TF_BUILD", "True")
    tty = _Tty()
    console = ash_console(file=tty, force_terminal=True, color_system="truecolor")
    console.print(Pretty({"k": value}))

    plain = _TERMINAL_SEQUENCE.sub("", tty.getvalue())
    assert "k" in plain, plain
    assert not COMMAND.search(plain), (plain, tty.getvalue())


def test_rich_print_and_its_global_console_write_through_the_check(capsys):
    """run_ash_scan, merge, scan, config and dependencies print with this print,
    and rich's Progress and Live default to the same global console."""
    import rich

    from automated_security_helper.utils.console import CommandSafeStream
    from automated_security_helper.utils.console import print as ash_print

    ash_print("x" * 75 + " ::error::from print")
    rich.get_console().print("y" * 75 + " ##[add-mask]from the global console")

    out = capsys.readouterr().out
    assert "from print" in out and "from the global console" in out, out
    assert not COMMAND.search(out), out
    assert isinstance(rich.get_console().file, CommandSafeStream)


def test_the_global_console_the_factory_hands_out_is_richs():
    """global_console is how code outside this module reaches it: the same object,
    so a test that points rich._console at a recording console sees its output."""
    import rich

    from automated_security_helper.utils.console import global_console

    assert global_console() is rich.get_console()


#: Longer than the 80 columns Rich gives a console off a terminal, with a "::"
#: after column 80, where a wrap put it at the start of a line.
_LONG = "a" * 70 + " ::error::stays mid-line"


def test_text_off_a_terminal_is_not_wrapped():
    """Off a terminal (a pipe, a file, a CI log) there is no screen to fit, and a
    reader wraps long lines itself. Rich hard-wrapping printed text at the width
    would split a path or name, and a "::" past the break would start a line the
    check then broke: the text would no longer be shown whole. A printed str or
    Text stays one line, and its mid-line "::" is no command and is left as is."""
    from rich.text import Text

    from automated_security_helper.utils.console import ash_console

    out = io.StringIO()
    console = ash_console(file=out, width=80)
    console.print(_LONG)
    console.print(Text(_LONG))

    assert out.getvalue() == f"{_LONG}\n{_LONG}\n", out.getvalue()


def test_a_line_of_unwrapped_text_still_has_its_command_broken():
    """A long str whose own newline puts a "::" past the break at a line start:
    its lines are not wrapped, and that line's command is broken."""
    from automated_security_helper.utils.console import ash_console

    out = io.StringIO()
    ash_console(file=out, width=80).print("b" * 90 + "\n::error::own line")

    assert out.getvalue() == "b" * 90 + "\n\\x3a:error::own line\n", out.getvalue()


def test_the_global_console_does_not_wrap_text_off_a_terminal(capsys):
    """rich's global console, through the factory's print and as handed out."""
    from automated_security_helper.utils.console import global_console
    from automated_security_helper.utils.console import print as ash_print

    ash_print(_LONG)
    global_console().print(_LONG)

    assert capsys.readouterr().out == f"{_LONG}\n{_LONG}\n"


def test_the_snapshot_harness_prints_through_ashs_global_console():
    """tests/snapshot's pinned_console replaces rich's global console for a run. It
    dropped it, and rich then built a plain one: no line check, and text wrapped
    off a terminal, so a snapshot showed output ASH does not print."""
    import rich

    from automated_security_helper.utils.console import CommandSafeStream
    from tests.snapshot.support.cli import pinned_console

    with pinned_console():
        console = rich.get_console()
        assert isinstance(console.file, CommandSafeStream), console.file
        assert type(console).__name__ == "_AshConsole", type(console)


def test_a_table_or_panel_off_a_terminal_keeps_its_layout(monkeypatch):
    """Only text is left unwrapped: a renderable with a layout of its own is laid
    out at the console's width."""
    from rich.panel import Panel

    from automated_security_helper.utils.console import ash_console

    # Off a terminal is the case: a caller's FORCE_COLOR or TTY_COMPATIBLE made
    # Rich treat the StringIO as one.
    for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)
    out = io.StringIO()
    ash_console(file=out, width=40).print(Panel("word " * 30))

    lines = out.getvalue().splitlines()
    assert len(lines) > 3 and {len(line) for line in lines} == {40}, out.getvalue()


def test_a_terminal_wraps_text_at_its_width(monkeypatch):
    """On a terminal Rich keeps fitting the screen."""
    from automated_security_helper.utils.console import ash_console

    for name in ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION"):
        monkeypatch.delenv(name, raising=False)
    tty = _Tty()
    ash_console(file=tty, width=40, color_system=None).print(_LONG)

    assert len(tty.getvalue().splitlines()) > 1, tty.getvalue()


def test_a_callers_own_soft_wrap_wins_off_a_terminal():
    """Text off a terminal is left unwrapped only when the caller did not say."""
    from automated_security_helper.utils.console import ash_console

    out = io.StringIO()
    ash_console(file=out, width=40).print("word " * 20, soft_wrap=False)

    assert len(out.getvalue().splitlines()) > 1, out.getvalue()


def test_force_color_on_a_pipe_leaves_text_unwrapped(monkeypatch):
    """FORCE_COLOR makes rich treat any stream as a terminal, for color. The
    stream is still a pipe, with no screen to fit, so text stays one line."""
    from automated_security_helper.utils.console import ash_console

    monkeypatch.setenv("FORCE_COLOR", "1")
    out = io.StringIO()
    console = ash_console(file=out, width=40)
    console.print("word " * 20)

    assert console.is_terminal, "FORCE_COLOR no longer forces rich's terminal"
    assert len(out.getvalue().splitlines()) == 1, out.getvalue()


def test_the_report_sink_off_a_terminal_leaves_text_unwrapped_and_unchecked():
    """check_commands=False drops only the line check: its text is not wrapped
    either, as every factory console's is."""
    from automated_security_helper.utils.console import ash_console

    out = io.StringIO()
    ash_console(file=out, width=80, check_commands=False).print(
        "b" * 90 + "\n::error::kept as written"
    )

    assert out.getvalue() == "b" * 90 + "\n::error::kept as written\n", out.getvalue()


def test_an_arn_mid_line_is_left_readable():
    from automated_security_helper.utils.console import ash_console

    out = io.StringIO()
    ash_console(file=out, width=200).print("role arn:aws:iam::123456789012:role/x")

    assert "arn:aws:iam::123456789012:role/x" in out.getvalue()


def test_importing_the_stream_module_leaves_richs_global_console_alone():
    """utils/command_safe_stream.py holds the stream and only what it calls, so a
    module that wraps a stream can import it without console.py's set-up of rich's
    global console. Importing it loads neither rich, typer nor console.py, and
    rich's global console keeps its class and its file. As a control, importing
    console.py afterwards does change both. console.py's names are the stream
    module's own objects, so a check against either class holds for both."""
    import json

    repo_root = Path(__file__).resolve().parents[3]
    out = _run_on_a_fake_terminal(
        """
import json
import automated_security_helper.utils.command_safe_stream as stream_module
loaded = sorted(
    name
    for name in sys.modules
    if name in ("rich", "typer", "automated_security_helper.utils.console")
    or name.startswith(("rich.", "typer."))
)
import rich
fresh = rich.get_console()
before = (type(fresh).__module__ + "." + type(fresh).__qualname__, type(fresh.file).__name__)
from automated_security_helper.utils import console
after = rich.get_console()
print(json.dumps({
    "file": stream_module.__file__,
    "loaded": loaded,
    "class_before": before[0],
    "file_before": before[1],
    "same_console": after is fresh,
    "class_after": type(after).__qualname__,
    "file_after": type(after.file).__name__,
    "same_stream_class": console.CommandSafeStream is stream_module.CommandSafeStream,
    "same_runners": console.COMMAND_READING_RUNNERS is stream_module.COMMAND_READING_RUNNERS,
}))
"""
    )
    seen = json.loads(out.strip().splitlines()[-1])

    assert Path(seen["file"]) == (
        repo_root / "automated_security_helper" / "utils" / "command_safe_stream.py"
    ), seen
    assert seen["loaded"] == [], seen
    assert seen["class_before"] == "rich.console.Console", seen
    assert seen["file_before"] != "CommandSafeStream", seen
    # The control: console.py's import does reconfigure the same console.
    assert seen["same_console"], seen
    assert (seen["class_after"], seen["file_after"]) == (
        "_AshConsole",
        "CommandSafeStream",
    ), seen
    assert seen["same_stream_class"] and seen["same_runners"], seen


#: Run in a child, so a console that feeds its writes back into Live's proxy (which
#: spins rather than raising) ends at the timeout instead of hanging the worker.
_TERMINAL_CHILD_PRELUDE = """
import io, sys
class Tty(io.StringIO):
    def isatty(self):
        return True
"""


def _run_on_a_fake_terminal(body: str) -> str:
    """Run *body* in a child Python on the checkout under test; return its stdout.

    The child keeps this process's environment (HOME included), minus the
    variables that make Rich decide for itself whether it is on a terminal, and
    with the terminal's kind and size chosen here: a caller's TERM=dumb, or a
    COLUMNS and LINES too small for the panel, changed what the child drew.
    """
    repo_root = Path(__file__).resolve().parents[3]
    env = dict(os.environ)
    for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE", "NO_COLOR"):
        env.pop(name, None)
    env.update(TERM="xterm-256color", COLUMNS="80", LINES="40")
    env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
    try:
        done = subprocess.run(
            [
                sys.executable,
                "-c",
                importing_this_checkout(_TERMINAL_CHILD_PRELUDE + body),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
    except subprocess.TimeoutExpired as expired:
        pytest.fail(f"still writing after {expired.timeout} s: {expired.stderr!r}")
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_a_console_under_live_on_a_terminal_writes_past_its_stdout_proxy():
    """On a terminal, Rich's Live replaces sys.stdout with a FileProxy that prints
    into its console. Rich's own Console writes to the file behind the proxy; a
    stream that looked up sys.stdout at write time wrote into the proxy, which
    printed back into the console, and a scan with the live display hung there."""
    out = _run_on_a_fake_terminal(
        """
tty = Tty()
sys.stdout = tty
from rich.live import Live
from automated_security_helper.utils.console import ash_console
console = ash_console(force_terminal=True, color_system=None, width=80)
with Live("live", console=console, auto_refresh=False, redirect_stdout=True, redirect_stderr=False):
    console.print("from the console")
    print("from print, through the proxy")
sys.__stdout__.write(tty.getvalue())
"""
    )

    assert "from the console" in out, out
    assert "from print, through the proxy" in out, out


def test_a_stderr_console_under_live_on_a_terminal_writes_past_its_stderr_proxy():
    """The same cycle on stderr: dependencies' error console, given a Live (a
    status spinner) on a terminal, with Live's redirect_stderr."""
    out = _run_on_a_fake_terminal(
        """
tty = Tty()
sys.stderr = tty
from rich.live import Live
from automated_security_helper.utils.console import ash_console
console = ash_console(stderr=True, force_terminal=True, color_system=None, width=80)
with Live("live", console=console, auto_refresh=False, redirect_stdout=False, redirect_stderr=True):
    console.print("from the console")
    print("from print, through the proxy", file=sys.stderr)
sys.__stdout__.write(tty.getvalue())
"""
    )

    assert "from the console" in out, out
    assert "from print, through the proxy" in out, out


def test_the_live_display_on_a_terminal_starts_and_stops():
    """LiveProgressDisplay as an interactive scan runs it: its console finds the
    terminal for itself, starts Live, logs into the panel, updates a task, stops."""
    out = _run_on_a_fake_terminal(
        """
tty = Tty()
sys.stdout = tty
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER
display = LiveProgressDisplay(show_progress=True, color_system=None)
assert display.console.is_terminal
phase = list(display.tasks)[0]
display.start()
task = display.add_task(phase=phase, description="Scanning")
ASH_LOGGER.warning("a log line in the panel")
display.update_task(phase=phase, task_id=task, completed=100)
display.stop()
sys.__stdout__.write(tty.getvalue())
"""
    )

    assert "Scanning" in out, out[-2000:]


#: rich's own global console, which nobody configured but utils/console.py, and
#: the helpers that print through it.
_GLOBAL_CONSOLE = {
    "print",
    "print_json",
    "inspect",
    "get_console",
    "reconfigure",
    "_console",
}
#: Modules whose install() puts a hook in place that prints through a Console of
#: rich's own making (rich.traceback's excepthook, rich.pretty's displayhook).
_INSTALLERS = {"rich.traceback", "rich.pretty"}
#: Functions that print through a Console of their own module's making.
_PRINTERS = {"rich.pretty.pprint"}
#: Names that build or fetch a Console wherever the name comes from: rich's class,
#: or a module that re-exports it (utils/console.py imports it, and so does
#: typer.rich_utils), and typer's own console getter. A call by one of these names
#: is refused even when the guard can't tell where the name was bound.
_CONSOLE_NAMES = {"Console", "_get_rich_console"}


def _console_offenders(tree: ast.AST, relative: str) -> list[str]:
    """Every way *tree* reaches a Console or a printer that is not the factory's.

    Import aliases are followed: ``import rich as r``, ``import rich.console as m``,
    ``from rich import console``, ``from rich.console import Console as C`` and
    ``from rich.traceback import install as i`` all bind a name that is checked
    where it is used, as is a Console subclass. A call by a name in
    _CONSOLE_NAMES, or an assignment of one, is refused wherever the name came
    from (a re-export, a star import, typer.rich_utils), and so are
    getattr and setattr of rich's global console helpers. So is pointing any
    object's ``file`` elsewhere, by assignment or setattr, and a console's
    capture (``with console.capture()``), begin_capture, end_capture and pager:
    a factory console given another file writes past its checked stream, capture
    takes the text before the stream sees it, and a pager is handed it unchecked.
    """
    modules: dict[str, str] = {}  # bound name -> rich module it stands for
    consoles: set[str] = set()  # bound names for rich.console.Console
    installers: set[str] = set()  # bound names for an install() above
    globals_: dict[str, str] = {}  # bound names for rich.print and the rest
    functions: dict[str, str] = {}  # bound names for a function of a rich module
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("rich.")
        ):
            for alias in node.names:
                functions[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "rich" or alias.name.startswith("rich."):
                    if alias.asname:
                        modules[alias.asname] = alias.name
                    else:
                        modules["rich"] = "rich"
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                bound = alias.asname or alias.name
                if node.module == "rich" and alias.name in {
                    "console",
                    "traceback",
                    "pretty",
                }:
                    modules[bound] = f"rich.{alias.name}"
                elif (
                    node.module in {"rich", "rich.console"} and alias.name == "Console"
                ):
                    consoles.add(bound)
                elif node.module == "rich" and alias.name in _GLOBAL_CONSOLE:
                    globals_[bound] = alias.name
                elif node.module in _INSTALLERS and alias.name == "install":
                    installers.add(bound)

    def resolve(node: ast.AST) -> str | None:
        """The dotted rich name an expression stands for, if it is one."""
        if isinstance(node, ast.Name):
            if node.id in consoles:
                return "rich.console.Console"
            if node.id in installers:
                return "<installer>.install"
            if node.id in globals_:
                return f"rich.{globals_[node.id]}"
            return modules.get(node.id) or functions.get(node.id)
        if isinstance(node, ast.Attribute):
            base = resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    offenders = []
    for node in ast.walk(tree):
        where = f"{relative}:{getattr(node, 'lineno', 0)}"
        if isinstance(node, ast.ClassDef):
            if any(resolve(base) == "rich.console.Console" for base in node.bases):
                offenders.append(f"{where} subclass of Console: {node.name}")
                consoles.add(node.name)
        elif isinstance(node, ast.Call):
            target = resolve(node.func)
            called = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if target == "rich.console.Console" or called in _CONSOLE_NAMES:
                offenders.append(f"{where} {called}()")
            elif target and (
                target == "<installer>.install"
                or any(target == f"{m}.install" for m in _INSTALLERS)
                or target in _PRINTERS
            ):
                offenders.append(f"{where} {target}()")
            elif (
                called in {"getattr", "setattr"}
                and len(node.args) >= 2
                and resolve(node.args[0]) == "rich"
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in _GLOBAL_CONSOLE
            ):
                offenders.append(f"{where} {called}(rich, {node.args[1].value!r})")
            elif (
                called == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "file"
            ):
                # A console given another file writes past its checked stream.
                offenders.append(f"{where} setattr(..., 'file', ...)")
            elif called in {
                "begin_capture",
                "end_capture",
                "capture",
                "pager",
            } and isinstance(node.func, ast.Attribute):
                # Capture takes the text before the stream checks it, and a pager
                # is handed it before the stream sees it.
                offenders.append(f"{where} {called}()")
        elif isinstance(node, ast.Assign) and (
            (isinstance(node.value, ast.Name) and node.value.id in _CONSOLE_NAMES)
            or (
                isinstance(node.value, ast.Attribute)
                and node.value.attr in _CONSOLE_NAMES
            )
        ):
            offenders.append(f"{where} alias of {ast.unparse(node.value)}")
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and any(
            isinstance(target, ast.Attribute) and target.attr == "file"
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        ):
            # A console given another file writes past its checked stream.
            offenders.append(f"{where} .file stored")
        elif isinstance(node, ast.ImportFrom) and node.module == "rich":
            offenders.extend(
                f"{where} rich.{alias.name}"
                for alias in node.names
                if alias.name in _GLOBAL_CONSOLE
            )
        elif isinstance(node, ast.Attribute) and node.attr in _GLOBAL_CONSOLE:
            if resolve(node.value) == "rich":
                offenders.append(f"{where} rich.{node.attr}")
    return offenders


PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"


def _package_sources(package: Path = PACKAGE) -> list[Path]:
    # Refused unless every part of the package is in the walk (walked_package).
    from tests.unit.walked_package import package_sources

    return package_sources(package)


def test_the_factory_guard_refuses_a_tree_with_nothing_to_check(tmp_path):
    """Moved or pointed elsewhere, the guard would pass having read no module."""
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _package_sources(tmp_path)


def test_every_console_comes_from_the_factory():
    """A Console built anywhere else would write past the stream's check, and so
    would rich's own print, whose global console nobody configured, and the
    tracebacks rich.traceback.install would print."""
    offenders = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative == "utils/console.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        offenders.extend(_console_offenders(tree, relative))

    assert offenders == [], offenders


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param("from rich.console import Console\nConsole()\n", 2, id="console"),
        pytest.param(
            "from rich.console import Console as _C\n\n_C()\n", 3, id="console-alias"
        ),
        pytest.param("import rich.console as m\nm.Console()\n", 2, id="module-alias"),
        pytest.param(
            "from rich import console\nconsole.Console(file=None)\n", 2, id="from-rich"
        ),
        pytest.param("import rich\nrich.console.Console()\n", 2, id="dotted"),
        pytest.param(
            "from rich.console import Console\n\nclass Mine(Console):\n    pass\n",
            3,
            id="subclass",
        ),
        pytest.param("import rich as _r\n_r.print('x')\n", 2, id="rich-alias-print"),
        pytest.param("from rich import print as p\n", 1, id="from-rich-print"),
        pytest.param("import rich\nrich._console = None\n", 2, id="global-console"),
        pytest.param(
            "import rich.traceback\nrich.traceback.install()\n", 2, id="traceback"
        ),
        pytest.param(
            "from rich.traceback import install as i\ni(show_locals=True)\n",
            2,
            id="traceback-alias",
        ),
        pytest.param("from rich import pretty\npretty.install()\n", 2, id="pretty"),
        # utils/console.py imports rich's Console, so it can be reached through it.
        pytest.param(
            "from automated_security_helper.utils.console import Console\nConsole()\n",
            2,
            id="console-from-ash-console",
        ),
        pytest.param(
            "from automated_security_helper.utils import console as c\nc.Console()\n",
            2,
            id="ash-console-module",
        ),
        pytest.param("from rich.console import *\nConsole()\n", 2, id="star-import"),
        pytest.param("import typer\ntyper.rich_utils.Console()\n", 2, id="typer-rich"),
        pytest.param(
            "import typer\ntyper.rich_utils._get_rich_console()\n",
            2,
            id="typer-rich-console",
        ),
        pytest.param(
            "from rich.console import Console\nC = Console\n", 2, id="assigned-alias"
        ),
        pytest.param("import rich\nrich.print_json('{}')\n", 2, id="print-json"),
        pytest.param("import rich\nrich.inspect(x)\n", 2, id="inspect"),
        pytest.param("from rich import inspect\n", 1, id="from-rich-inspect"),
        pytest.param(
            "from rich.pretty import pprint\npprint(x)\n", 2, id="pretty-pprint"
        ),
        pytest.param(
            "from rich import pretty\npretty.pprint(x)\n", 2, id="pretty-module-pprint"
        ),
        pytest.param(
            "import rich\nsetattr(rich, '_console', None)\n", 2, id="setattr-console"
        ),
        pytest.param(
            "import rich\ngetattr(rich, 'print')('x')\n", 2, id="getattr-print"
        ),
        # A factory console pointed past its checked stream, or captured.
        pytest.param(
            "c = global_console()\nc.file = sys.__stdout__\n", 2, id="file-stored"
        ),
        pytest.param(
            "c = global_console()\nsetattr(c, 'file', sys.__stdout__)\n",
            2,
            id="file-set",
        ),
        pytest.param(
            "c = global_console()\nc.begin_capture()\n", 2, id="begin-capture"
        ),
        pytest.param("text = console.end_capture()\n", 1, id="end-capture"),
        # Capture calls begin_capture and end_capture itself; a pager is handed
        # the text before the stream sees it.
        pytest.param(
            "with console.capture() as captured:\n    pass\n", 1, id="capture"
        ),
        pytest.param("with global_console().pager():\n    pass\n", 1, id="pager"),
    ],
)
def test_the_guard_finds_each_way_past_the_factory(source, line):
    offenders = _console_offenders(ast.parse(source), "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders

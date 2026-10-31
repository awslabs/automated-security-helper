# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one place ASH builds a rich Console, so no output line is a CI command.

A CI runner reads each line of a job's output. GitHub Actions takes a line that
starts, after whitespace, with "::" as a workflow command ("::add-mask::",
"::error", "::stop-commands::"), and its legacy "##[cmd]" form anywhere in a
line; Azure Pipelines takes "##vso[". ASH's messages quote text from the scanned
repository, and utils/terminal_text.py breaks those forms in a message's own
text, but Rich wraps a log message, a table cell or a panel at the console width
(80 off a terminal) and folds a long word at a character position, so a line can
start with text from the middle of a message: a suppression reason
"w w w w w w w w w ::add-mask::hidden" printed an "::add-mask::hidden" line.

Every console therefore writes through :class:`CommandSafeStream`
(utils/command_safe_stream.py, which has no import-time effects of its own and is
re-exported here). When the stream is not a terminal it checks each line as
written, after Rich's layout: a
line that starts, after whitespace and color codes, with "::" gets its first
colon written ``\\x3a``, and "##" followed by an optional name and "[" ("##[cmd]",
"##vso[", "##teamcity[") anywhere gets its first "#" written ``\\x23``. A bare
"##", a Markdown heading's, is no command and is left. Color codes inside one of
these forms don't hide it:
Rich's highlighter colors a "[" on its own, so a debug traceback's locals wrote
"##vso", a code, then "[", which a runner that drops color codes reads whole. A
terminal is passed everything as is, except under a
runner that reads these commands (GitHub Actions, Azure Pipelines, TeamCity,
known by the variable each sets in every job): a CI job can give ASH a terminal
(``docker run -t``, ``script``, ``unbuffer``, container mode's own ``-t``), and
the runner still reads every line of it. An ARN's mid-line "::" stays readable,
and the layout is the one Rich chose.

Off a terminal, printed text is not wrapped at all (:class:`_AshConsole`): there
is no screen to fit, a reader of a pipe, a file or a CI log wraps long lines
itself, and a wrap split a path or a name and could start a line with text from
its middle. Rich's soft wrap does not reach table cells or panels, so the log's
message column, panels and tracebacks are still laid out at the width, and the
stream's check is what keeps their lines from being commands. Considered and not
taken: an unbounded width instead, which pads every expanding renderable (the log
grid, panels, the progress layout) to it.

:func:`ash_console` builds a Console; :func:`print` stands in for rich's
``print``, whose global console nobody configured. tests/unit/utils/
test_console_factory.py fails when a module builds a Console any other way.

Machine output must not go through these consoles. The escapes stop a runner
from reading a line, but they change the text, and neither is a JSON or a YAML
escape: a JSON line holding "##[error]", printed off a terminal, no longer
parses, and a YAML single-quoted scalar keeps the backslash as a character, so
its value changes. Text a program reads goes to a regular file, as ``ash
report``'s stdout does when it is one, or through :func:`echo_raw`. To a pipe or
a terminal ``ash report`` breaks the command forms too, a JSON report with JSON's
own escape so it still parses (cli/report.py's _write_report).
``ash config get`` shows the configuration's YAML to a person through this
console, so off a terminal its output is not always the configuration
character for character.

Limits: a command form split across two writes is not seen. Rich writes each
print's render in one write, so that needs ASH to print one message in two
parts.
"""

from __future__ import annotations

import os
import sys
from typing import IO, Any, Callable, Optional, TextIO

import rich
import typer
from rich.console import Console
from rich.text import Text

# The stream lives in its own module, which has no import-time effects, so a
# module that only wraps a stream needn't import this one. Its names are re-exported
# here as the same objects.
from automated_security_helper.utils.command_safe_stream import (
    COMMAND_READING_RUNNERS as COMMAND_READING_RUNNERS,
)
from automated_security_helper.utils.command_safe_stream import (
    CommandSafeStream,
    _is_terminal,
)
from automated_security_helper.utils.terminal_text import (
    ShownText,
    shown_not_obeyed,
)


class _AshConsole(Console):
    """A Console that does not wrap printed text when it is not writing to a
    terminal.

    Rich takes 80 columns, or COLUMNS, as the width of a pipe, a file or a CI
    log, and by default hard-wraps each printed line there: a long path or name
    is split, and a "::" past the break starts a line, which the stream's check
    then breaks, so the text is not shown whole. When every object
    printed is a str or a Text and the stream behind the console is not a
    terminal, the print is soft-wrapped: no line breaks are added and nothing
    is cropped. A table, a panel, a traceback or a Syntax keeps the layout Rich
    gives it at the width, and on a terminal nothing changes. A caller's own
    ``soft_wrap`` wins, and so does a Text's own ``overflow`` or ``no_wrap``:
    under a soft wrap Rich divides no line, so a Text asking to be folded at the
    width was cropped there instead.
    """

    def print(
        self, *objects: Any, soft_wrap: Optional[bool] = None, **kwargs: Any
    ) -> None:
        _follow_the_stream(self)
        if (
            soft_wrap is None
            and objects
            and all(_takes_the_soft_wrap(item) for item in objects)
            and not _is_terminal(self.file)
        ):
            soft_wrap = True
        super().print(*objects, soft_wrap=soft_wrap, **kwargs)


def _takes_the_soft_wrap(item: Any) -> bool:
    """Whether printing *item* off a terminal may be soft-wrapped: a str, or a
    Text that sets neither an overflow method nor ``no_wrap`` of its own."""
    if isinstance(item, Text):
        return item.overflow is None and item.no_wrap is None
    return isinstance(item, str)


def ash_console(
    *,
    file: Optional[TextIO] = None,
    stderr: bool = False,
    check_commands: bool = True,
    **kwargs: Any,
) -> Console:
    """A rich Console that writes through :class:`CommandSafeStream`.

    Takes Console's own arguments. Without *file* it writes to sys.stdout, or
    sys.stderr with *stderr*, whichever is current at each write.

    *check_commands* False is for a *file* that checks its lines already, a
    :class:`CommandSafeStream`, so a line is not checked twice (``ash report``'s
    console under such a stdout). Anything else ASH prints keeps the check.
    Either way, text printed off a terminal is not wrapped (:class:`_AshConsole`).
    """
    if not check_commands:
        return _AshConsole(file=file, stderr=stderr, **kwargs)
    if file is not None:
        target: Callable[[], TextIO] = lambda: file  # noqa: E731
    elif stderr:
        target = lambda: sys.stderr  # noqa: E731
    else:
        target = lambda: sys.stdout  # noqa: E731
    return _AshConsole(file=CommandSafeStream(target), stderr=stderr, **kwargs)  # type: ignore[arg-type]


def check_commands_of(console: Console) -> None:
    """Have *console*, one a library built, write through :class:`CommandSafeStream`
    on the stream it writes to now, keeping the width, color and theme it has.

    For a library's log handler (utils/log.py's
    route_library_handlers_through_command_check). A console on the current
    sys.stderr or sys.stdout looks that up at each write. A
    console writing through the check already is left as it is.
    """
    target = console.file
    if isinstance(target, CommandSafeStream):
        return
    if target is sys.stderr:
        stream: Callable[[], Any] = lambda: sys.stderr  # noqa: E731
    elif target is sys.stdout:
        stream = lambda: sys.stdout  # noqa: E731
    else:
        stream = lambda: target  # noqa: E731
    console.file = CommandSafeStream(stream)  # type: ignore[assignment]


def typer_console(*, stderr: bool = True) -> Console:
    """A factory console set up as typer's own console is.

    For what ASH prints in typer's place, a usage error and an escaping
    exception's traceback, so they look as typer prints them: typer's theme and
    option highlighter, its color system, a terminal forced under GITHUB_ACTIONS,
    FORCE_COLOR or PY_COLORS (whose logs show color) and turned off by
    _TYPER_FORCE_DISABLE_TERMINAL, and its width (TERMINAL_WIDTH, else the
    console's). typer reads those variables once, when it is imported; here they
    are read by the same rules each time a console is built. TERMINAL_WIDTH is
    read as typer reads it, with ``int()``: a value with surrounding whitespace
    or a sign counts, and one ``int()`` refuses (``str.isdigit`` admits
    superscript and circled digits that ``int()`` does not) leaves the width to
    the console rather than raising.
    """
    from rich.theme import Theme
    from typer import rich_utils

    force_terminal: Optional[bool] = None
    if any(
        os.environ.get(name) for name in ("GITHUB_ACTIONS", "FORCE_COLOR", "PY_COLORS")
    ):
        force_terminal = True
    if os.environ.get("_TYPER_FORCE_DISABLE_TERMINAL"):
        force_terminal = False
    width = _typer_terminal_width(os.environ.get("TERMINAL_WIDTH", ""))
    return ash_console(
        stderr=stderr,
        theme=Theme(
            {
                "option": rich_utils.STYLE_OPTION,
                "switch": rich_utils.STYLE_SWITCH,
                "negative_option": rich_utils.STYLE_NEGATIVE_OPTION,
                "negative_switch": rich_utils.STYLE_NEGATIVE_SWITCH,
                "types": rich_utils.STYLE_TYPES,
                "types_sep": rich_utils.STYLE_TYPES_SEPARATOR,
                "usage": rich_utils.STYLE_USAGE,
            }
        ),
        highlighter=rich_utils.highlighter,
        color_system=rich_utils.COLOR_SYSTEM,
        force_terminal=force_terminal,
        width=width,
    )


def _typer_terminal_width(value: str) -> Optional[int]:
    """The width TERMINAL_WIDTH's *value* names by typer's rule, ``int()``, or
    None for an empty value, one ``int()`` refuses, or one below 1."""
    if not value:
        return None
    try:
        width = int(value)
    except ValueError:
        return None
    return width if width > 0 else None


def _shown(message: Any) -> Any:
    if message is None or isinstance(message, (bytes, bytearray)):
        return message
    # A ShownText is returned as it is; str() of one would be shown again.
    return shown_not_obeyed(message if isinstance(message, ShownText) else str(message))


def echo(
    message: Any = None,
    file: Optional[IO[Any]] = None,
    nl: bool = True,
    err: bool = False,
    color: Optional[bool] = None,
) -> None:
    """typer.echo for text ASH prints for a person: shown, not obeyed.

    typer.echo writes its text as given, and ASH's messages quote paths, names and
    errors from the scanned repository and its configuration. The text goes
    through utils/terminal_text.py's shown_not_obeyed first: controls as
    escapes, CI command forms broken. typer.echo does not wrap, so the text rule
    is enough. Bytes are written as given.
    """
    typer.echo(_shown(message), file=file, nl=nl, err=err, color=color)


def secho(
    message: Any = None,
    file: Optional[IO[Any]] = None,
    nl: bool = True,
    err: bool = False,
    color: Optional[bool] = None,
    **styles: Any,
) -> None:
    """typer.secho, with the text shown as :func:`echo` shows it."""
    typer.secho(_shown(message), file=file, nl=nl, err=err, color=color, **styles)


def prompt(
    text: str, default: Any = None, *, show_default: bool = True, **kwargs: Any
) -> Any:
    """typer.prompt, with its text and the default it shows shown as :func:`echo`
    shows them.

    typer.prompt writes the question through click's echo as given, followed by
    the default in brackets, and ASH's questions quote the configuration being
    edited: the wizard's first default is the project name the file holds. The
    bracketed default is built here, from the shown text, so typer prints it
    no more; an empty answer still returns *default* as written.
    """
    question = _shown(text)
    if show_default and default is not None:
        question = f"{question} [{_shown(default)}]"
    return typer.prompt(question, default=default, show_default=False, **kwargs)


def confirm(text: str, default: Optional[bool] = False, **kwargs: Any) -> bool:
    """typer.confirm, with its text shown as :func:`echo` shows it. The [y/N] it
    adds is its own."""
    return typer.confirm(_shown(text), default=default, **kwargs)


def echo_raw(
    message: Any = None,
    file: Optional[IO[Any]] = None,
    nl: bool = True,
    err: bool = False,
) -> None:
    """typer.echo as given, for machine output only: text a script parses (a JSON
    skeleton), which an escape would change. Never for a message to a person."""
    typer.echo(message, file=file, nl=nl, err=err)


def global_console() -> Console:
    """rich's global console, the one rich.print, Progress and Live use when given
    no console.

    It writes through :class:`CommandSafeStream` because this module reconfigures
    it on import, and it is the one tests point at a recording console (they set
    ``rich._console``). For a caller that needs a Console's own methods or options
    (``render_str``, ``print(soft_wrap=...)``), where :func:`print` takes only
    print's.
    """
    return rich.get_console()


def _global_console_settings() -> dict[str, Any]:
    """How this module sets up rich's global console: its stream checks each line."""
    return {"file": CommandSafeStream(lambda: sys.stdout)}


def new_global_console() -> Console:
    """A new console set up as this module sets up rich's global console.

    For a test harness that drops rich's global console so the next one reads a
    pinned environment (tests/snapshot/support/cli.py): set ``rich._console`` to
    this instead of None, and the runs it pins print through the console ASH
    really uses, not one rich builds with no line check.
    """
    return _AshConsole(**_global_console_settings())


def print(  # noqa: A001 - stands in for rich's print, which shadows the builtin too
    *objects: Any,
    sep: str = " ",
    end: str = "\n",
    file: Optional[TextIO] = None,
    flush: bool = False,
) -> None:
    """rich's ``print``: :func:`global_console`, or one for *file* from the factory."""
    write_console = global_console() if file is None else ash_console(file=file)
    write_console.print(*objects, sep=sep, end=end)
    if flush:
        write_console.file.flush()


# Rich decides a console's color system once, when the console is built, by asking
# its file whether it is a terminal. The global console is built when this module
# is imported, and a stream that is a terminal then (or only claims to be one, as a
# worker's null device can) but is not at the time of a print, would still get
# escape sequences around every styled span: a captured stream on one OS held them
# and nowhere else. So the decision is made again against the stream whenever the
# stream's answer changes, never per print, and it is left to Rich's "auto" so
# FORCE_COLOR and TTY_COMPATIBLE keep the say they have. The record below is the
# answer the console was built under; the object is the one this module set up,
# which a test that points rich at another console must keep to itself.
_configured_for_tty: Optional[bool] = None
_configured_console: Optional[Console] = None


def _set_up_global_console() -> None:
    """Set rich's global console up as this module does, and note what its stream
    answered when it was built."""
    global _configured_for_tty
    settings = _global_console_settings()
    answer = _is_terminal(settings["file"])
    rich.reconfigure(**settings)
    _configured_for_tty = answer


def _follow_the_stream(console: Console) -> None:
    """Build the global console again when its stream's terminal answer has changed
    since it was built. Any other console, and a global console some other code
    swapped in, is left as it is."""
    if console is not _configured_console or rich.get_console() is not console:
        return
    if _is_terminal(console.file) != _configured_for_tty:
        _set_up_global_console()


# rich's own global console, which rich.print, Progress and Live use when given no
# console, writes through the stream too. reconfigure keeps the object (code that
# already holds it sees the change) and replaces its settings; it is called here
# only, so nothing else may reconfigure it (the factory test fails on any other).
_set_up_global_console()
# Its class becomes the factory's too, so it doesn't wrap text off a terminal
# either. Like reconfigure, this keeps the object: code that holds it already
# prints through the new class. _AshConsole adds no state of its own.
rich.get_console().__class__ = _AshConsole
_configured_console = rich.get_console()

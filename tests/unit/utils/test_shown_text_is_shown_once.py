# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Text a call site has shown already is shown once, by every sink.

Every log sink (the console handler, the live panel, ash.log, the stand-in for
logging's last resort), the console's echo and escape_markup show the text they
are given: each control as an escape, each CI command broken, and a run of
backslashes before text that reads as an escape doubled. A call site that shows a
value itself, to write a newline in it as \\x0a so the warning stays one line,
would have that \\x0a shown again as \\\\x0a: the reader would see the text
"\\x0a", not a newline. So a call site can hand a sink text that is shown already: the value
shown_not_obeyed or shown_on_one_line returns is a ShownText, and each sink
leaves one as it is.

Only those two functions make a ShownText from text, and shown_in_ascii one
from a ShownText, for a stream that takes only ASCII (WindowsSafeFilter, on a
Windows console or CI runner). The class cannot be called or
subclassed, every str operation on one gives a plain str, and a copy or a pickle
is a plain str too, so text from anywhere else is shown by the sink in full.
The last test reads the package's source and refuses any other way of making one:
a single call site that wrapped a repository's text as shown would undo the sink.
"""

from __future__ import annotations

import ast
import builtins
import copy
import importlib
import io
import itertools
import logging
import pickle
import random
import re
import sys
from collections import Counter
from pathlib import Path

import pytest
from rich.console import Console

import automated_security_helper
from automated_security_helper.utils import terminal_text
from automated_security_helper.utils.log import escape_markup, get_logger
from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)

pytestmark = pytest.mark.unit

_names = itertools.count()

#: A raw control, other than tab and newline, that a terminal acts on.
_RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

#: A line a CI runner reads as a command: "::" at its start, or "##" with an
#: optional name and "[" anywhere. A bare "##" (a Markdown heading) is none.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

#: A repository's text: an escape sequence, a newline that would start a forged
#: line, a tab, a Windows segment that reads as an escape, and a CI command.
_VALUE = "C:\\x64\\a\x1b[2Kb\nc\td\r\n::add-mask::x"


def _shown_once() -> str:
    """What a call site that shows _VALUE on one line wants the reader to see."""
    return "C:\\\\x64\\a\\x1b[2Kb\\x0ac\\x09d\\x0d\\x0a::add-mask::x"


def _on_one_line(text: str) -> str:
    return terminal_text.shown_on_one_line(text)


# -- what each sink writes ---------------------------------------------------


def _console(monkeypatch, capsys, log) -> str:
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    logger = get_logger(
        name=f"ash-shown-console-{next(_names)}",
        level=logging.INFO,
        show_progress=False,
        use_color=False,
        simple_format=True,
    )
    capsys.readouterr()
    try:
        log(logger)
    finally:
        logger.handlers = []
    # The console folds a long line; the words are what is compared.
    return " ".join(capsys.readouterr().out.split())


def _ash_log(tmp_path, log) -> str:
    name = f"ash-shown-file-{next(_names)}"
    logger = get_logger(
        name=name,
        level=logging.INFO,
        output_dir=tmp_path,
        show_progress=False,
        use_color=False,
    )
    try:
        log(logger)
        for handler in logger.handlers:
            handler.flush()
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers = []
    # Read as text, so the platform's line terminator (CR LF on Windows, where
    # the file handler writes in text mode) comes back as "\n": the raw-control
    # check below judges what the record wrote, not how the file ends its lines.
    return (tmp_path / f"{name}.log").read_text(encoding="utf-8")


def _live_panel(log) -> str:
    panel = RichLogPanel(max_lines=5)
    handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger(f"ash-shown-panel-{next(_names)}")
    logger.propagate = False
    logger.addHandler(handler)
    log(logger)
    console = Console(record=True, width=400, color_system=None)
    console.print(panel)
    return console.export_text()


def _last_resort(capsys, log) -> str:
    """A logger under "ash" with no handler: the stand-in for logging's last resort."""
    logger = logging.getLogger(f"ash.shown-last-resort-{next(_names)}")
    logger.propagate = False
    capsys.readouterr()
    log(logger)
    return capsys.readouterr().err


_SINKS = ["console", "ash.log", "live-panel", "last-resort"]


def _written(sink, log, *, tmp_path, monkeypatch, capsys) -> str:
    if sink == "console":
        return _console(monkeypatch, capsys, log)
    if sink == "ash.log":
        return _ash_log(tmp_path, log)
    if sink == "live-panel":
        return _live_panel(log)
    return _last_resort(capsys, log)


@pytest.mark.parametrize("sink", _SINKS)
def test_a_message_shown_by_the_call_site_is_shown_once(
    sink, tmp_path, monkeypatch, capsys
):
    """shown_not_obeyed's text, logged as the message: the sink showed it again,
    so ESC printed as the text "\\\\x1b" and the Windows segment as "\\\\\\\\x64"."""
    message = terminal_text.shown_not_obeyed("key C:\\x64 a\x1b[2Kb")

    written = _written(
        sink,
        lambda logger: logger.warning(message),
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert "key C:\\\\x64 a\\x1b[2Kb" in written, repr(written)
    assert "\\\\\\" not in written and "\\\\x1b" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)


@pytest.mark.parametrize("sink", _SINKS)
def test_a_value_shown_on_one_line_stays_one_line_and_is_shown_once(
    sink, tmp_path, monkeypatch, capsys
):
    """The narrowing a call site wants: a newline, a tab or a carriage return in a
    repository's text written as an escape, so the warning is one line, and the
    rest shown as the sink would show it."""
    message = _on_one_line(f"Ignoring {_VALUE} from the file")

    written = _written(
        sink,
        lambda logger: logger.warning(message),
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert f"Ignoring {_shown_once()} from the file" in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert not _COMMAND_LINE.search(written), repr(written)


@pytest.mark.parametrize("sink", _SINKS)
def test_a_shown_message_with_arguments_is_shown_whole(
    sink, tmp_path, monkeypatch, capsys
):
    """The arguments are the logger's to put in, as given, so the sink shows the
    whole message: only a shown message with nothing left to put in is passed on."""
    message = terminal_text.shown_not_obeyed("key %s")

    written = _written(
        sink,
        lambda logger: logger.warning(message, "a\x1b[2Kb\n::add-mask::x"),
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert "a\\x1b[2Kb" in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert not _COMMAND_LINE.search(written), repr(written)


@pytest.mark.parametrize("added", ["exc_info", "stack_info"])
@pytest.mark.parametrize("sink", _SINKS)
def test_a_shown_message_with_its_traceback_is_shown_once(
    sink, added, tmp_path, monkeypatch, capsys
):
    """With exc_info or stack_info, a formatter writes the traceback or the stack
    after the message, and the console without rich tracebacks and the live panel
    showed the two together, the shown message a second time with them: its ESC
    printed as the text "\\\\x1b". The traceback or stack is shown on its own, and
    the message passed on, by each sink, the last resort's stand-in included."""
    message = terminal_text.shown_not_obeyed("key C:\\x64 a\x1b[2Kb")
    # Built here, so the traceback's quoted source line holds no escape text.
    error = "boom" + chr(0x1B) + "[31m"

    def log(logger):
        if added == "stack_info":
            logger.warning(message, stack_info=True)
            return
        try:
            raise RuntimeError(error)
        except RuntimeError:
            logger.exception(message)

    written = _written(
        sink, log, tmp_path=tmp_path, monkeypatch=monkeypatch, capsys=capsys
    )

    assert "key C:\\\\x64 a\\x1b[2Kb" in written, repr(written)
    if added == "stack_info":
        assert "Stack (most recent call last)" in written, repr(written)
    else:
        assert "boom\\x1b[31m" in written, repr(written)
    assert "\\\\\\" not in written and "\\\\x1b" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)


#: U+00E9 and U+2705, written with chr() so this file stays ASCII.
_E_ACUTE, _CHECK_MARK = chr(0xE9), chr(0x2705)


@pytest.mark.parametrize("sink", ["console", "ash.log"])
def test_a_shown_message_is_shown_once_on_a_windows_ci_runner(
    sink, tmp_path, monkeypatch, capsys
):
    """On Windows under CI, get_logger's WindowsSafeFilter rewrites each message
    for a console that cannot encode it. It rebuilt a shown message as plain text,
    so the sink showed it again: ESC printed as the text "\\\\x1b". Its other
    characters outside ASCII are written as escapes, not dropped.

    The filter sits on the logger, so ash.log's handler sees the rewrite too; the
    record keeps what was logged, and the file formatter writes that, since the
    file is UTF-8 and the rewrite is for the console (log.py, _UNFILTERED_ATTR).
    So ash.log keeps the accented letter and the check mark, shown once."""
    from automated_security_helper.utils import log as log_module
    from tests.utils.windows_console import windows_logging_kept_in_the_test

    monkeypatch.setattr(log_module.platform, "system", lambda: "Windows")
    monkeypatch.setenv("CI", "1")
    windows_logging_kept_in_the_test(monkeypatch)
    message = terminal_text.shown_not_obeyed(
        f"key C:\\x64 caf{_E_ACUTE} {_CHECK_MARK} a\x1b[2Kb"
    )

    written = _written(
        sink,
        lambda logger: logger.warning(message),
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    if sink == "console":
        assert "key C:\\\\x64 caf\\xe9 [OK] a\\x1b[2Kb" in written, repr(written)
        assert written.isascii(), repr(written)
    else:
        kept = f"key C:\\\\x64 caf{_E_ACUTE} {_CHECK_MARK} a\\x1b[2Kb"
        assert kept in written, repr(written)
        assert "caf\\xe9" not in written and "[OK]" not in written, repr(written)
    assert "\\\\\\" not in written and "\\\\x1b" not in written, repr(written)


def test_escape_markup_shows_shown_text_once():
    """For a MARKUP record's value and rich.print's text."""
    shown = terminal_text.shown_not_obeyed("a\x1b[2Kb")

    assert escape_markup(shown) == "a\\x1b[2Kb"


def test_echo_shows_shown_text_once(capsys):
    from automated_security_helper.utils.console import echo

    echo(terminal_text.shown_not_obeyed("a\x1b[2Kb C:\\x64"))

    assert capsys.readouterr().out == "a\\x1b[2Kb C:\\\\x64\n"


# -- the escapers ------------------------------------------------------------


def test_the_escapers_return_shown_text_and_show_it_once():
    shown = terminal_text.shown_not_obeyed("a\x1bb")
    one_line = _on_one_line("a\nb")

    assert isinstance(shown, terminal_text.ShownText) and shown == "a\\x1bb"
    assert isinstance(one_line, terminal_text.ShownText) and one_line == "a\\x0ab"
    assert terminal_text.shown_not_obeyed(shown) is shown
    assert _on_one_line(one_line) == one_line


#: The characters that interact: backslashes, escape-like text, the layout
#: characters, controls and the command prefixes.
_ALPHABET = ["\\", "x", "u", "0", "a", "9", ":", "#", "[", "v", " ", "\n", "\r"]
_ALPHABET += ["\t", "\x1b", "\x85", "\u2028", "\N{ZERO WIDTH SPACE}", "U"]

_ESCAPE = re.compile(r"(\\+)(x[0-9a-f]{2}|u[0-9a-f]{4}|U[0-9a-f]{8})")


def _decoded(shown: str) -> str:
    """Read shown text back: an odd run of backslashes ends in an escape."""

    def one(match: re.Match) -> str:
        run, token = match.group(1), match.group(2)
        literal = "\\" * (len(run) // 2)
        if len(run) % 2 == 0:
            return literal + token
        return literal + chr(int(token[1:], 16))

    return _ESCAPE.sub(one, shown)


def test_one_line_text_decodes_back_and_has_no_layout_character():
    """From raw text, and from text shown_not_obeyed showed with its layout kept:
    each a one-line text that reads back as the original, one to one."""
    chooser = random.Random(20261012)
    for _ in range(20000):
        text = "".join(chooser.choice(_ALPHABET) for _ in range(chooser.randint(0, 14)))
        for one_line in (
            _on_one_line(text),
            _on_one_line(terminal_text.shown_not_obeyed(text)),
        ):
            assert not re.search(r"[\t\n\r]", one_line), (text, one_line)
            assert not _RAW_CONTROL.search(one_line), (text, one_line)
            assert not _COMMAND_LINE.search(one_line), (text, one_line)
            assert _decoded(one_line) == text, (text, one_line)


#: Characters outside ASCII that interact with the rest: a mapped emoji and its
#: variation-selector form, an unmapped letter, Unicode whitespace the runner
#: trims, and a zero-width space, which is shown as an escape already.
_WIDE = [_E_ACUTE, _CHECK_MARK, chr(0x26A0), chr(0xFE0F), chr(0xA0), chr(0x200B)]


def test_shown_text_in_ascii_reads_back_and_is_still_shown():
    """For a console that cannot encode more: what was shown is put in ASCII, a
    mapped character as its replacement and any other as its escape, so it reads
    back as the text with the replacements made. Nothing is dropped, since a
    dropped character could join "::" or "##[" into a command."""
    from automated_security_helper.utils.log import _get_default_emoji_fallback_map

    replacements = _get_default_emoji_fallback_map()

    def replaced(text: str) -> str:
        for key, value in replacements.items():
            text = text.replace(key, value)
        return text

    chooser = random.Random(20261013)
    alphabet = _ALPHABET + _WIDE
    for _ in range(20000):
        text = "".join(chooser.choice(alphabet) for _ in range(chooser.randint(0, 14)))
        for shown in (
            terminal_text.shown_not_obeyed(text),
            _on_one_line(text),
        ):
            in_ascii = terminal_text.shown_in_ascii(shown, replacements)

            assert isinstance(in_ascii, terminal_text.ShownText), (text, in_ascii)
            assert in_ascii.isascii(), (text, in_ascii)
            # A carriage return before a newline is layout, kept as shown.
            laid_out = in_ascii.replace("\r\n", "\n")
            assert not _RAW_CONTROL.search(laid_out), (text, in_ascii)
            assert not _COMMAND_LINE.search(in_ascii), (text, in_ascii)
            assert _decoded(in_ascii) == replaced(_decoded(shown)), (text, in_ascii)


@pytest.mark.parametrize(
    "replacement",
    [
        "",
        "a\\b",
        "x41",
        "u0041",
        "U00000041",
        "tab\there",
        "e" + chr(0xE9),
        "b",
        "7f",
        "F00D",
    ],
)
def test_shown_text_in_ascii_refuses_a_replacement_that_could_join_its_neighbors(
    replacement,
):
    shown = terminal_text.shown_not_obeyed(_CHECK_MARK)

    with pytest.raises(ValueError):
        terminal_text.shown_in_ascii(shown, {_CHECK_MARK: replacement})


def test_shown_text_in_ascii_refuses_a_value_that_would_finish_an_escape():
    """Shown text can end in an escape's start: a backslash, its letter and some of
    its digits, as "\\x1" before U+00BD. A value starting with a hex digit would
    finish it, "\\x1" and "b" reading as ESC."""
    shown = terminal_text.shown_not_obeyed("\\x1" + chr(0xBD) + "c")

    with pytest.raises(ValueError):
        terminal_text.shown_in_ascii(shown, {chr(0xBD): "b"})


def test_shown_text_in_ascii_takes_a_word_that_cannot_read_as_an_escape():
    shown = terminal_text.shown_not_obeyed(f"\\{_CHECK_MARK} \\{_E_ACUTE}")

    in_ascii = terminal_text.shown_in_ascii(shown, {_CHECK_MARK: "unknown"})

    assert in_ascii == "\\unknown \\\\\\xe9", in_ascii


def test_shown_text_in_ascii_takes_only_shown_text():
    with pytest.raises(TypeError):
        terminal_text.shown_in_ascii("plain", {})  # type: ignore[arg-type]


# -- nothing else makes one --------------------------------------------------


def test_the_class_cannot_be_called_or_subclassed():
    shown_text = terminal_text.ShownText

    with pytest.raises(TypeError):
        shown_text("a\x1bb")
    with pytest.raises(TypeError):
        shown_text.__new__(shown_text, "a\x1bb")
    with pytest.raises(TypeError):
        type("Forged", (shown_text,), {})
    with pytest.raises(TypeError):
        type(terminal_text.shown_not_obeyed("a"))("a\x1bb")


def test_what_is_made_from_shown_text_is_plain_text():
    """So a sink shows it: an operation on shown text can join it to text that is
    not shown, or cut it where an escape starts. An operation that leaves the
    text as it is (a format with nothing to fill in, a partition that does not
    find its separator) returns the same object, the escaper's own text."""
    shown = terminal_text.shown_not_obeyed("a\\x64b\x1bc")
    template = terminal_text.shown_not_obeyed("a%sb{}c%%d{{")
    changed = {
        "percent-fills": template % ("RAW\x1b",),
        "format-fills": template.format("RAW\x1b"),
        "format-map": terminal_text.shown_not_obeyed("a{name}b").format_map(
            {"name": "RAW\x1b"}
        ),
        "percent-escape": terminal_text.shown_not_obeyed("a%%b") % (),
        "partition-hit": shown.partition("x")[0],
        "rpartition-hit": shown.rpartition("x")[2],
    }
    assert {name: type(value) for name, value in changed.items()} == dict.fromkeys(
        changed, str
    )
    made = {
        "add": shown + "",
        "radd": "" + shown,
        "repeat": shown * 1,
        "slice": shown[:],
        "index": shown[0],
        "f-string": f"{shown}",
        "percent": "%s" % shown,
        "own-percent": shown % (),
        "format": "{}".format(shown),
        "own-format": shown.format(),
        "format()": format(shown),
        "str()": str(shown),
        "join": "".join([shown]),  # noqa: FLY002 - the join is what is checked
        "own-join": shown.join(["", ""]),
        "strip": shown.strip(),
        "replace": shown.replace("a", "a"),
        "lower": shown.lower(),
        "removeprefix": shown.removeprefix(""),
        "expandtabs": shown.expandtabs(),
        "ljust": shown.ljust(0),
        "translate": shown.translate({}),
        "split": shown.split("\x00")[0],
        "partition": shown.partition("\x00")[0],
        "rpartition": shown.rpartition("\x00")[2],
        "own-format-map": shown.format_map({}),
        "own-percent-map": shown % {},
        "copy": copy.copy(shown),
        "deepcopy": copy.deepcopy(shown),
        "pickle": pickle.loads(pickle.dumps(shown)),
        # A reduction's own constructor, called with its own arguments.
        "reduce": (lambda reduced: reduced[0](*reduced[1]))(shown.__reduce__()),
        "reduce-ex": (lambda reduced: reduced[0](*reduced[1]))(shown.__reduce_ex__(2)),
    }

    kept = {name for name, value in made.items() if type(value) is not str}
    assert all(made[name] is shown for name in kept), kept
    assert kept <= {
        "own-percent",
        "own-format",
        "partition",
        "rpartition",
        "own-format-map",
        "own-percent-map",
    }, kept
    assert all(value == shown or name == "index" for name, value in made.items())


def test_a_shown_text_holds_no_attribute_and_text_cannot_become_one():
    """Python lets an instance of another str subclass with the same layout be
    given ShownText as its class, so the guard below refuses an assignment to
    __class__ in the package unless the class given cannot be a str subclass; a
    str itself cannot be given it."""
    shown = terminal_text.shown_not_obeyed("a")

    with pytest.raises(AttributeError):
        shown.forged = True  # type: ignore[attr-defined]
    plain = "a\x1bb"
    with pytest.raises(TypeError):
        plain.__class__ = terminal_text.ShownText  # type: ignore[misc]
    with pytest.raises(TypeError):
        object.__setattr__(plain, "__class__", terminal_text.ShownText)


#: The one function that may make a ShownText, and the escapers that may call it.
_MAKER = "_as_shown"
_ESCAPERS = {"shown_not_obeyed", "shown_on_one_line", "shown_in_ascii"}
_TERMINAL_TEXT = "automated_security_helper/utils/terminal_text.py"


def _mentions_marker(node: ast.AST) -> bool:
    return any(
        (isinstance(inner, ast.Name) and inner.id == "ShownText")
        or (isinstance(inner, ast.Attribute) and inner.attr == "ShownText")
        or (isinstance(inner, ast.Constant) and inner.value == "ShownText")
        for inner in ast.walk(node)
    )


#: Calls that can bind a module's names with no assignment the guard reads.
_REBINDERS = {"globals", "vars", "locals", "setattr", "exec", "eval", "__import__"}


def _bindings(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Each node of *tree* that binds a name, in any scope, by the name it binds."""
    bound: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, ast.alias):
            names = [(node.asname or node.name).split(".")[0]]
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            names = [node.id]
        elif isinstance(node, ast.arg):
            names = [node.arg]
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names = list(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names = [node.name]
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names = [node.name]
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names = [node.rest]
        for name in names:
            bound.setdefault(name, []).append(node)
    return bound


#: Modules that hand out a module, or a frame and its globals, by lookup.
_MODULE_LOOKUPS = {"importlib", "inspect"}


def _binds_behind_the_guard(tree: ast.Module) -> bool:
    """Whether *tree* could bind a name with no assignment :func:`_bindings` sees:
    a call of one of :data:`_REBINDERS`, a ``__dict__`` or ``__setattr__``,
    ``sys.modules`` or ``sys._getframe``, importlib or inspect (either can hand
    back this module, ``import_module(__name__)``, or a frame's globals), or a
    star import."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _REBINDERS
        ):
            return True
        if isinstance(node, ast.alias) and node.name.split(".")[0] in _MODULE_LOOKUPS:
            return True
        if isinstance(node, ast.ImportFrom) and node.module in _MODULE_LOOKUPS:
            return True
        if isinstance(node, ast.Attribute) and node.attr == "_getframe":
            return True
        if isinstance(node, ast.Attribute) and (
            node.attr in ("__dict__", "__setattr__")
            or (
                node.attr == "modules"
                and isinstance(node.value, ast.Name)
                and node.value.id == "sys"
            )
        ):
            return True
        if isinstance(node, ast.alias) and node.name == "*":
            return True
    return False


def _cannot_be_text(
    name: str,
    tree: ast.Module,
    bound: dict[str, list[ast.AST]],
    seen: frozenset[str] = frozenset(),
) -> bool:
    """Whether *name*, read at the top level of *tree*, is a class that is not str
    and does not derive from it.

    Two kinds are: a class the module defines once, at its top level, with no
    decorator and no keyword (a metaclass), whose bases are each one of these; and
    a name the module binds once, by a top-level ``from <module> import <name>``,
    that resolves to a class that is not a str subclass and whose metaclass is
    type itself (a metaclass's __new__ could make the class anything). A name the
    module never binds is looked up in builtins (``object``). Anything else cannot
    be told and is not: a name bound more than once or another way, a base that is
    not a plain name, an import that does not resolve.

    Resolving an import imports that module in the test process, so its code runs
    there and could steer the answer: the check holds for the package's own
    modules and its pinned dependencies, not for code that sets out to fool it.
    """
    if name in seen:
        return False
    binders = bound.get(name, [])
    if not binders:
        builtin = getattr(builtins, name, None)
        return isinstance(builtin, type) and not issubclass(builtin, str)
    if len(binders) != 1:
        return False
    (binder,) = binders
    if isinstance(binder, ast.ClassDef):
        if binder not in tree.body or binder.decorator_list or binder.keywords:
            return False
        return all(
            isinstance(base, ast.Name)
            and _cannot_be_text(base.id, tree, bound, seen | {name})
            for base in binder.bases
        )
    if isinstance(binder, ast.alias):
        importers = [
            statement
            for statement in tree.body
            if isinstance(statement, ast.ImportFrom) and binder in statement.names
        ]
        if len(importers) != 1 or importers[0].level or not importers[0].module:
            return False
        try:
            imported = getattr(
                importlib.import_module(importers[0].module), binder.name
            )
        except (ImportError, AttributeError):
            return False
        return (
            isinstance(imported, type)
            and type(imported) is type
            and not issubclass(imported, str)
        )
    return False


def _gives_a_class_that_cannot_be_text(
    node: ast.Assign, tree: ast.Module, bound: dict[str, list[ast.AST]]
) -> bool:
    """Whether *node* is a top-level ``<value>.__class__ = <Name>`` (one or more
    such targets, each with no other ``__class__`` in it) whose Name cannot be
    text (:func:`_cannot_be_text`), in a module that binds no name behind the
    guard's back. A ShownText can only come of a str subclass."""
    return (
        node in tree.body
        and all(
            isinstance(target, ast.Attribute)
            and target.attr == "__class__"
            and sum(
                isinstance(inner, ast.Attribute) and inner.attr == "__class__"
                for inner in ast.walk(target)
            )
            == 1
            for target in node.targets
        )
        and isinstance(node.value, ast.Name)
        and not _binds_behind_the_guard(tree)
        and _cannot_be_text(node.value.id, tree, bound)
    )


#: The reductions object gives every instance: called past ShownText's own, they
#: name copyreg's constructor and the class, with no name the guard reads.
_REDUCTIONS = {"__reduce__", "__reduce_ex__"}

#: The modules that load a pickle or hold the constructors a pickle calls.
_PICKLERS = {"pickle", "_pickle", "copyreg", "shelve", "multiprocessing.reduction"}

#: Calls in the package given a class taken from a value, by module, callee and
#: argument: each a plugin's class, handed to code that records it or keys on it.
_CLASS_ARGUMENT_SITES = {
    (
        "automated_security_helper/core/phases/report_phase.py",
        "plugin_config_key",
        "type(plugin_instance)",
    ): "names the config section a plugin's class reads",
    (
        "automated_security_helper/core/phases/report_phase.py",
        "warn_off_host_section_without_enabled",
        "type(plugin_instance)",
    ): "names the off-host reporter whose section leaves it off",
    (
        "automated_security_helper/core/phases/scan_phase.py",
        "self.validation_manager.update_scanner_state",
        "plugin_instance.__class__",
    ): "records each registered scanner's class",
    (
        "automated_security_helper/core/phases/scan_phase.py",
        "enabled_scanner_classes.append",
        "plugin_instance.__class__",
    ): "lists the enabled scanners' classes",
    (
        "automated_security_helper/models/scanner_validation.py",
        "self._tracker.update_scanner_state",
        "scanner_instance.__class__",
    ): "records each registered scanner's class",
}

#: Assignments to ``__class__`` in the package other than the maker's, by module,
#: target and the Name assigned: each adopts an object into a class that cannot
#: be text, in a function (so not the top-level shape
#: :func:`_gives_a_class_that_cannot_be_text` admits) of a module whose own
#: ``setattr`` calls on log records keep that proof from being read. The key holds
#: the Name's text, so a value that is no longer that Name is refused again.
_CLASS_ASSIGNMENT_SITES = {
    (
        "automated_security_helper/utils/log.py",
        "logger.__class__",
        "ASHLogger",
    ): (
        'adopts an "ash" logger made before utils/log.py set the logger class; '
        "ASHLogger subclasses logging.Logger, not str"
    ),
}

#: The calls in the package given an exception's info, ``(type(e), e, ...)``, by
#: module, callee and argument: the one form of a taken class with its own value
#: allowed, and only here, since a function of the module's own given both could
#: still pass the class to a constructor with other text.
_EXCEPTION_INFO_SITES = {
    (
        "automated_security_helper/cli/entrypoint.py",
        "hook",
        "type(exc)",
    ): "calls the installed exception hook with the failure",
    (
        "automated_security_helper/cli/entrypoint.py",
        "_ash_traceback",
        "type(exc)",
    ): "prints the failure's traceback through ASH's console",
    (
        "automated_security_helper/cli/entrypoint.py",
        "traceback.format_exception",
        "type(exc)",
    ): "formats the failure's traceback for the last-resort report",
    (
        "automated_security_helper/utils/log.py",
        "traceback.format_exception_only",
        "type(raw_error)",
    ): "formats the error a raw MARKUP message raises",
}


def _listed_site_problems(
    hits: list[tuple[str, str, str]], rows: set[tuple[str, str, str]]
) -> list[str]:
    """Each row of *rows* not found exactly once among *hits*: one that is gone
    would let a new call in under its key, and one found twice lets the second
    call pass under the first one's reason."""
    counts = Counter(hits)
    return [f"{row}: {counts[row]} hits" for row in sorted(rows) if counts[row] != 1]


def _class_assignment_site(node: ast.AST, path: str) -> tuple[str, str, str] | None:
    """The :data:`_CLASS_ASSIGNMENT_SITES` key of *node*: ``<target>.__class__ =
    <Name>``, one target, the ``__class__`` its only one; None for any other
    shape, which the listing never admits."""
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    (target,) = node.targets
    if not (isinstance(target, ast.Attribute) and target.attr == "__class__"):
        return None
    if not isinstance(node.value, ast.Name):
        return None
    if (
        sum(
            isinstance(inner, ast.Attribute) and inner.attr == "__class__"
            for inner in ast.walk(target)
        )
        != 1
    ):
        return None
    return (path, ast.unparse(target), node.value.id)


def _is_pickler(module: str) -> bool:
    return any(module == name or module.startswith(name + ".") for name in _PICKLERS)


def _reads_a_named_attribute(call: ast.Call, argument: ast.AST) -> bool:
    """``getattr(cls, "name"[, default])`` or ``hasattr(cls, "name")``: a read of
    an attribute named by a constant, which makes nothing ("__new__" as a string
    is refused on its own)."""
    return (
        isinstance(call.func, ast.Name)
        and call.func.id in ("getattr", "hasattr")
        and len(call.args) >= 2
        and call.args[0] is argument
        and isinstance(call.args[1], ast.Constant)
        and isinstance(call.args[1].value, str)
    )


def _is_exception_info(call: ast.Call, argument: ast.AST) -> bool:
    """``f(type(e), e, ...)``, as an exception's info is passed: the class with the
    very value it was taken from, so a constructor given both makes a copy of that
    value, shown already if it was shown."""
    return (
        len(call.args) >= 2
        and call.args[0] is argument
        and isinstance(argument, ast.Call)
        and isinstance(argument.func, ast.Name)
        and argument.func.id == "type"
        and len(argument.args) == 1
        and isinstance(argument.args[0], ast.Name)
        and isinstance(call.args[1], ast.Name)
        and call.args[1].id == argument.args[0].id
    )


def _forged(
    source: str, path: str, sites: list[tuple[str, str, str]] | None = None
) -> list[str]:
    """Each way *source* makes, or could make, a ShownText other than the escapers'.

    Allowed: the class's own definition and an import of it under its own name;
    ShownText in an isinstance or issubclass check, in an annotation and in
    ``__all__``; the maker's definition, and a call of it from the escapers in
    utils/terminal_text.py; a top-level assignment to __class__ of a class that
    cannot be text (:func:`_gives_a_class_that_cannot_be_text`), or one listed in
    :data:`_CLASS_ASSIGNMENT_SITES` by module, target and Name. Refused: calling
    the class, naming it anywhere else (an alias can be called, or handed to a
    __new__), importing it under another name, looking it up by its name as a
    string, a cast to it, any __new__ but the maker's (called, handed on uncalled,
    or looked up by its name as a string), the maker named, imported or looked up
    outside the escapers, any other assignment to __class__, a setattr with a
    computed name given a class taken by type() or ``.__class__``, a walrus in a
    check or an annotation (it binds the class to a name), copyreg (a copy's and a
    pickle's constructors), loading a pickle, a read of ``__reduce__`` or
    ``__reduce_ex__`` (by attribute or string) outside ShownText's own, since
    object's give copyreg's constructor and the class; pickle, _pickle, copyreg,
    shelve and multiprocessing.reduction imported or named in a string; an
    attribute of str looked up by a computed name, by any of the lookups
    :func:`attribute_lookup` names (getattr, inspect.getattr_static, a
    ``__getattribute__`` call, operator.attrgetter); any read of str's namespace
    (``vars(str)``, ``str.__dict__``, ``getattr(str, "__dict__")``), subscripted,
    .get or not, since each can give its __new__ by a computed key; and a class
    taken from a value given to any call but a check, a getattr or hasattr of an
    attribute named by a constant, or a site listed in
    :data:`_CLASS_ARGUMENT_SITES` or, as an exception's ``(type(e), e, ...)``, in
    :data:`_EXCEPTION_INFO_SITES` (*sites*, when given, collects each listed site
    found, once per call). A class is taken by type(), by ``.__class__``, or by
    "__class__" looked up by any of those lookups. type, str, getattr and vars are
    known by their own names, as builtins.<name>, imported from builtins under
    another name, and by any name bound to one of those, to a fixpoint; a name
    bound to a class taken from a value, or to a name bound to one, holds it too.

    Not seen: a class taken from a value and put in a container, or returned by a
    function, before it is used; type, str, getattr or vars reached another way (a
    container, a function's return, ``type("")``, ``"".__class__.__mro__``); a
    lookup wrapped by a function of another module, or one that builds the name it
    looks up rather than taking it;
    ``__class__`` by a computed name; a loader of pickles outside the standard
    library (dill, cloudpickle, pandas.read_pickle); and anything exec or a frame
    builds at run time.
    """
    tree = ast.parse(source)
    bound = _bindings(tree)
    found: list[str] = []
    allowed: set[int] = set()
    own_class: set[int] = set()
    in_terminal_text = path == _TERMINAL_TEXT

    # Names the module binds to the builtins module, and to the builtins a class
    # or str's attributes can be reached through: type, str, getattr and vars.
    # The builtins module by name, and the namespace every module sees it through.
    builtins_names = {"builtins", "__builtins__"}
    names_of: dict[str, set[str]] = {
        builtin: {builtin} for builtin in ("type", "str", "getattr", "vars")
    }
    type_names, str_names = names_of["type"], names_of["str"]
    getattr_names, vars_names = names_of["getattr"], names_of["vars"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            builtins_names |= {
                alias.asname
                for alias in node.names
                if alias.name == "builtins" and alias.asname
            }
        if isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name in names_of:
                    names_of[alias.name].add(alias.asname or alias.name)

    def named(value: ast.AST) -> str | None:
        if isinstance(value, ast.Name):
            return value.id
        return value.attr if isinstance(value, ast.Attribute) else None

    def is_builtins_namespace(value: ast.AST) -> bool:
        """The builtins as a mapping: ``__builtins__``, ``globals()["__builtins__"]``
        (any subscript by that name), ``vars(builtins)`` or ``builtins.__dict__``."""
        if isinstance(value, ast.Name):
            return value.id == "__builtins__"
        if isinstance(value, ast.Subscript):
            return (
                isinstance(value.slice, ast.Constant)
                and value.slice.value == "__builtins__"
            )
        if isinstance(value, ast.Attribute):
            return (
                value.attr == "__dict__"
                and isinstance(value.value, ast.Name)
                and value.value.id in builtins_names
            )
        return (
            isinstance(value, ast.Call)
            and named(value.func) == "vars"
            and bool(value.args)
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id in builtins_names
        )

    def is_builtin(value: ast.AST, name: str, names: set[str]) -> bool:
        """*value* is the builtin *name*: by one of *names*, as builtins.<name>, or
        read from the builtins namespace by its name (``__builtins__["getattr"]``,
        ``__builtins__.get("getattr")``)."""
        if isinstance(value, ast.Name):
            return value.id in names
        if isinstance(value, ast.Attribute):
            return (
                value.attr == name
                and isinstance(value.value, ast.Name)
                and value.value.id in builtins_names
            )
        if isinstance(value, ast.Subscript):
            return (
                isinstance(value.slice, ast.Constant)
                and value.slice.value == name
                and is_builtins_namespace(value.value)
            )
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "get"
            and bool(value.args)
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value == name
            and is_builtins_namespace(value.func.value)
        )

    #: Functions and lambdas of the module that look an attribute up by name for
    #: their caller: name -> (the index of the object parameter, the index of the
    #: name parameter, or the constant name it looks up).
    wrappers: dict[str, tuple[int, int | ast.Constant]] = {}

    def wrapper_positions(function: ast.AST) -> tuple[int, int | ast.Constant] | None:
        """Where *function*, a def or a lambda, takes the object and the name of
        the attribute it returns: a getattr form over a parameter, by another
        parameter or by "__class__"."""
        arguments = function.args  # type: ignore[attr-defined]
        params = [a.arg for a in arguments.posonlyargs + arguments.args]
        if isinstance(function, ast.Lambda):
            returned = [function.body]
        else:
            returned = [
                node.value
                for node in ast.walk(function)
                if isinstance(node, ast.Return) and node.value is not None
            ]
        for value in returned:
            lookup = attribute_lookup(value) if isinstance(value, ast.Call) else None
            if lookup is None or not (
                isinstance(lookup[0], ast.Name) and lookup[0].id in params
            ):
                continue
            target, attribute = params.index(lookup[0].id), lookup[1]
            if isinstance(attribute, ast.Name) and attribute.id in params:
                return target, params.index(attribute.id)
            if isinstance(attribute, ast.Constant) and attribute.value == "__class__":
                return target, attribute
        return None

    def attribute_lookup(call: ast.Call) -> tuple[ast.AST, ast.AST] | None:
        """(object, name) of a call that looks an attribute up by its name:
        getattr by any name bound to it or as builtins.getattr,
        inspect.getattr_static, a ``__getattribute__`` called unbound
        (``object.__getattribute__(v, n)``) or bound (``v.__getattribute__(n)``),
        ``operator.attrgetter(n)(v)``, ``methodcaller("__getattribute__", ...)``,
        ``functools.partial(getattr, ...)``, and a function or lambda of the
        module that wraps one of those (:data:`wrappers`)."""
        func = call.func
        positions = None
        if isinstance(func, ast.Name) and func.id in wrappers:
            positions = wrappers[func.id]
        elif isinstance(func, ast.Lambda):
            positions = wrapper_positions(func)
        if positions is not None:
            target, attribute = positions
            if len(call.args) <= target:
                return None
            if isinstance(attribute, int):
                if len(call.args) <= attribute:
                    return None
                return call.args[target], call.args[attribute]
            return call.args[target], attribute
        if (
            isinstance(func, ast.Call)
            and named(func.func) == "partial"
            and func.args
            and is_builtin(func.args[0], "getattr", getattr_names)
        ):
            given = list(func.args[1:]) + list(call.args)
            return (given[0], given[1]) if len(given) >= 2 else None
        if (
            isinstance(func, ast.Call)
            and named(func.func) == "methodcaller"
            and func.args
            and isinstance(func.args[0], ast.Constant)
            and func.args[0].value == "__getattribute__"
            and len(call.args) == 1
        ):
            rest = func.args[1:]
            if len(rest) == 1:
                return call.args[0], rest[0]
            # Called on a class with the object and the name: unbound.
            return (rest[0], rest[1]) if len(rest) == 2 else None
        if is_builtin(func, "getattr", getattr_names) or named(func) == (
            "getattr_static"
        ):
            return (call.args[0], call.args[1]) if len(call.args) >= 2 else None
        if isinstance(func, ast.Attribute) and func.attr == "__getattribute__":
            if len(call.args) == 2:
                return call.args[0], call.args[1]
            return (func.value, call.args[0]) if len(call.args) == 1 else None
        if (
            isinstance(func, ast.Call)
            and named(func.func) == "attrgetter"
            and len(func.args) == 1
            and len(call.args) == 1
        ):
            return call.args[0], func.args[0]
        return None

    def takes_a_class(value: ast.AST) -> bool:
        """A class taken from a value: type(x), x.__class__ read, or "__class__"
        looked up by name (:func:`attribute_lookup`)."""
        if isinstance(value, ast.Call):
            if len(value.args) == 1 and is_builtin(value.func, "type", type_names):
                return True
            lookup = attribute_lookup(value)
            return (
                lookup is not None
                and isinstance(lookup[1], ast.Constant)
                and lookup[1].value == "__class__"
            )
        return (
            isinstance(value, ast.Attribute)
            and value.attr == "__class__"
            and isinstance(value.ctx, ast.Load)
        )

    # Names the module binds to type, str, getattr or vars, and to a class taken
    # from a value, through other names bound to one, to a fixpoint.
    bindings: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and (
            node.value is not None
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            bindings += [(t.id, node.value) for t in targets if isinstance(t, ast.Name)]
    taken: set[str] = set()

    def settle() -> None:
        changed = True
        while changed:
            changed = False
            for name, value in bindings:
                for builtin, names in names_of.items():
                    if name not in names and is_builtin(value, builtin, names):
                        names.add(name)
                        changed = True
                if name not in taken and (
                    takes_a_class(value)
                    or (isinstance(value, ast.Name) and value.id in taken)
                ):
                    taken.add(name)
                    changed = True

    settle()
    # The functions and lambdas that wrap a lookup, through each other, to a
    # fixpoint; then the names again, since a wrapper can take a class.
    candidates: list[tuple[str, ast.AST]] = [
        (node.name, node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ] + [
        (target.id, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda)
        for target in node.targets
        if isinstance(target, ast.Name)
    ]
    grew = True
    while grew:
        grew = False
        for name, function in candidates:
            if name not in wrappers:
                positions = wrapper_positions(function)
                if positions is not None:
                    wrappers[name] = positions
                    grew = True
    if wrappers:
        settle()

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ShownText":
            if not in_terminal_text:
                found.append(f"{path}:{node.lineno}: a class named ShownText")
            for inner in ast.walk(node):
                allowed.add(id(inner))
                if in_terminal_text:
                    own_class.add(id(inner))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for annotation in [node.returns] + [
                a.annotation
                for a in node.args.args
                + node.args.kwonlyargs
                + node.args.posonlyargs
                + [x for x in (node.args.vararg, node.args.kwarg) if x is not None]
            ]:
                if annotation is not None:
                    for inner in ast.walk(annotation):
                        allowed.add(id(inner))
        if isinstance(node, ast.AnnAssign):
            for inner in ast.walk(node.annotation):
                allowed.add(id(inner))
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        ):
            for inner in ast.walk(node.value):
                allowed.add(id(inner))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("isinstance", "issubclass")
            and len(node.args) == 2
        ):
            for inner in ast.walk(node.args[1]):
                allowed.add(id(inner))

    def visit(node: ast.AST, function: str | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == _MAKER and not (in_terminal_text and function is None):
                found.append(f"{path}:{node.lineno}: a function named {_MAKER}")
            function = node.name
        if isinstance(node, ast.Call):
            callee = node.func
            if (isinstance(callee, ast.Name) and callee.id == "ShownText") or (
                isinstance(callee, ast.Attribute) and callee.attr == "ShownText"
            ):
                found.append(f"{path}:{node.lineno}: ShownText called")
            if isinstance(callee, ast.Attribute) and callee.attr == "__new__":
                if not (in_terminal_text and function == _MAKER):
                    found.append(f"{path}:{node.lineno}: a __new__ call")
            setter = (isinstance(callee, ast.Name) and callee.id == "setattr") or (
                isinstance(callee, ast.Attribute) and callee.attr == "__setattr__"
            )
            if setter and len(node.args) >= 3:
                name, value = node.args[1], node.args[2]
                if not isinstance(name, ast.Constant) and (
                    takes_a_class(value)
                    or (isinstance(value, ast.Name) and value.id in taken)
                ):
                    found.append(
                        f"{path}:{node.lineno}: a class from a value set by a "
                        "computed name"
                    )
            loader = callee.attr if isinstance(callee, ast.Attribute) else None
            if (
                loader in ("loads", "load", "Unpickler")
                and isinstance(callee.value, ast.Name)
                and callee.value.id in ("pickle", "_pickle")
            ):
                found.append(f"{path}:{node.lineno}: a pickle loaded")
            named = callee.id if isinstance(callee, ast.Name) else None
            named = callee.attr if isinstance(callee, ast.Attribute) else named
            if named == "cast" and node.args and _mentions_marker(node.args[0]):
                found.append(f"{path}:{node.lineno}: a cast to ShownText")
            checked = isinstance(callee, ast.Name) and callee.id in (
                "isinstance",
                "issubclass",
            )
            if not checked:
                for argument in list(node.args) + [k.value for k in node.keywords]:
                    if not (
                        takes_a_class(argument)
                        or (isinstance(argument, ast.Name) and argument.id in taken)
                    ):
                        continue
                    if _reads_a_named_attribute(node, argument):
                        continue
                    site = (path, ast.unparse(callee), ast.unparse(argument))
                    if site in _CLASS_ARGUMENT_SITES or (
                        site in _EXCEPTION_INFO_SITES
                        and _is_exception_info(node, argument)
                    ):
                        if sites is not None:
                            sites.append(site)
                        continue
                    found.append(
                        f"{path}:{node.lineno}: a class from a value given to "
                        f"{ast.unparse(callee)}"
                    )
        lookup = attribute_lookup(node) if isinstance(node, ast.Call) else None
        if lookup is not None and is_builtin(lookup[0], "str", str_names):
            if not isinstance(lookup[1], ast.Constant):
                found.append(
                    f"{path}:{node.lineno}: str's attribute by a computed name"
                )
            elif lookup[1].value == "__dict__":
                found.append(f"{path}:{node.lineno}: str's namespace read")
        # Any read of str's namespace: a .get, a subscript or an iteration of it
        # can each give its __new__ by a computed key.
        if (
            isinstance(node, ast.Call)
            and is_builtin(node.func, "vars", vars_names)
            and node.args
            and is_builtin(node.args[0], "str", str_names)
        ) or (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and is_builtin(node.value, "str", str_names)
        ):
            found.append(f"{path}:{node.lineno}: str's namespace read")
        if (
            (isinstance(node, ast.Attribute) and node.attr in _REDUCTIONS)
            or (isinstance(node, ast.Constant) and node.value in _REDUCTIONS)
        ) and id(node) not in own_class:
            found.append(f"{path}:{node.lineno}: a reduction looked up")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_pickler(alias.name):
                    found.append(f"{path}:{node.lineno}: {alias.name} imported")
        if isinstance(node, ast.ImportFrom) and not node.level:
            module = node.module or ""
            if _is_pickler(module) or any(
                _is_pickler(f"{module}.{alias.name}") for alias in node.names
            ):
                found.append(f"{path}:{node.lineno}: from {module} import")
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _is_pickler(node.value)
        ):
            found.append(f"{path}:{node.lineno}: {node.value!r} as a string")
        if (isinstance(node, ast.Name) and node.id == "ForkingPickler") or (
            isinstance(node, ast.Attribute)
            and node.attr in ("ForkingPickler", "reduction")
        ):
            found.append(f"{path}:{node.lineno}: multiprocessing's pickler")
        if isinstance(node, ast.Attribute) and node.attr == "__new__":
            if not (in_terminal_text and function == _MAKER):
                found.append(f"{path}:{node.lineno}: __new__ looked up")
        if isinstance(node, ast.Constant) and node.value == "__new__":
            found.append(f"{path}:{node.lineno}: '__new__' as a string")
        if (isinstance(node, ast.Name) and node.id == "copyreg") or (
            isinstance(node, ast.Attribute)
            and node.attr in ("_reconstructor", "__newobj__", "__newobj_ex__")
        ):
            found.append(f"{path}:{node.lineno}: copyreg's constructors")
        if isinstance(node, ast.NamedExpr) and id(node) in allowed:
            found.append(f"{path}:{node.lineno}: a walrus in a check or annotation")
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            in_maker = in_terminal_text and function == _MAKER
            if name == "ShownText" and id(node) not in allowed and not in_maker:
                found.append(f"{path}:{node.lineno}: ShownText named outside a check")
            if name == _MAKER and not (
                in_terminal_text
                and function in _ESCAPERS
                and isinstance(node, ast.Name)
            ):
                found.append(f"{path}:{node.lineno}: {_MAKER} named")
        if isinstance(node, ast.alias):
            if node.name == "ShownText" and node.asname not in (None, "ShownText"):
                found.append(f"{path}: ShownText imported as {node.asname}")
            if node.name == _MAKER:
                found.append(f"{path}: {_MAKER} imported")
        if isinstance(node, ast.Constant) and node.value in ("ShownText", _MAKER):
            if id(node) not in allowed:
                found.append(f"{path}:{node.lineno}: {node.value!r} as a string")
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and not (
            isinstance(node, ast.Assign)
            and _gives_a_class_that_cannot_be_text(node, tree, bound)
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            site = _class_assignment_site(node, path)
            if site in _CLASS_ASSIGNMENT_SITES:
                if sites is not None:
                    sites.append(site)
                targets = []
            for target in targets:
                for inner in ast.walk(target):
                    if isinstance(inner, ast.Attribute) and inner.attr == "__class__":
                        found.append(f"{path}:{node.lineno}: __class__ assigned")
        if (
            isinstance(node, ast.Call)
            and (
                (isinstance(node.func, ast.Name) and node.func.id == "setattr")
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "__setattr__"
                )
            )
            and any(
                isinstance(argument, ast.Constant) and argument.value == "__class__"
                for argument in node.args
            )
        ):
            # setattr, object.__setattr__: a class set by its name.
            found.append(f"{path}:{node.lineno}: __class__ set")
        for child in ast.iter_child_nodes(node):
            visit(child, function)

    visit(tree, None)
    return found


_FORGERIES = {
    "call": "from x import ShownText\nShownText(raw)\n",
    "alias": "from x import ShownText as S\nS(raw)\n",
    "module-call": "from x import terminal_text\nterminal_text.ShownText(raw)\n",
    "assigned": "from x import ShownText\nkind = ShownText\n",
    "str-new": "from x import ShownText\nstr.__new__(ShownText, raw)\n",
    "type-new": "str.__new__(type(shown_not_obeyed('')), raw)\n",
    "cast": "from typing import cast\ncast(ShownText, raw)\n",
    "string-cast": "import typing\ntyping.cast('ShownText', raw)\n",
    "getattr": "import x\ngetattr(x, 'ShownText')\n",
    "namespace": "import x\nvars(x)['ShownText']\n",
    "maker": "from x import _as_shown\n_as_shown(raw)\n",
    "maker-alias": "from x import _as_shown as show\nshow(raw)\n",
    "maker-attribute": "from x import terminal_text\nterminal_text._as_shown(raw)\n",
    "maker-getattr": "import x\ngetattr(x, '_as_shown')(raw)\n",
    "class-assigned": "value.__class__ = kind\n",
    "class-setattr": "setattr(value, '__class__', kind)\n",
    "class-object-setattr": "object.__setattr__(value, '__class__', kind)\n",
    "own-class": "class ShownText(str):\n    pass\n",
    "own-maker": "def _as_shown(text):\n    return text\n",
    # A class of the module's own given to __class__ is allowed only when none of
    # its bases can be str (below); each of these can be, or cannot be told.
    "class-local-str": "class K(str):\n    pass\nvalue.__class__ = K\n",
    "class-local-shown": (
        "from x import ShownText\nclass K(ShownText):\n    pass\nvalue.__class__ = K\n"
    ),
    "class-local-imported": (
        "from x import Imported\nclass K(Imported):\n    pass\nvalue.__class__ = K\n"
    ),
    "class-local-str-chain": (
        "class A(str):\n    pass\nclass K(A):\n    pass\nvalue.__class__ = K\n"
    ),
    "class-local-attribute-base": (
        "import x\nclass K(x.Base):\n    pass\nvalue.__class__ = K\n"
    ),
    "class-local-decorated": "@d\nclass K:\n    pass\nvalue.__class__ = K\n",
    "class-local-metaclass": "class K(metaclass=M):\n    pass\nvalue.__class__ = K\n",
    "class-local-rebound": "class K:\n    pass\nK = kind\nvalue.__class__ = K\n",
    "class-local-shadowed": (
        "class K:\n    pass\ndef f(value, K):\n    value.__class__ = K\n"
    ),
    "class-local-via-globals": (
        "class K:\n    pass\nglobals()['K'] = kind\nvalue.__class__ = K\n"
    ),
    "class-local-augmented": "class K:\n    pass\nvalue.__class__ |= K\n",
    # str's __new__ looked up or handed on uncalled, then called with the class.
    "new-by-getattr": "getattr(str, '__new__')(kind, raw)\n",
    "new-uncalled": "from functools import partial\npartial(str.__new__, kind)(raw)\n",
    "new-by-namespace": "vars(str)['__new__'](kind, raw)\n",
    # The constructors a copy or a pickle uses, called or loaded directly.
    "copyreg": "import copyreg\ncopyreg._reconstructor(kind, str, raw)\n",
    "copyreg-from": "from copyreg import _reconstructor\n_reconstructor(kind, str, raw)\n",
    "crafted-pickle": "import pickle\npickle.loads(crafted)\n",
    "crafted-pickle-from": "from pickle import loads\nloads(crafted)\n",
    # The class taken from shown text, given by a setattr whose name is computed.
    "class-by-computed-setattr": (
        "kind = type(shown_not_obeyed(''))\nsetattr(value, name, kind)\n"
    ),
    "class-by-computed-object-setattr": (
        "object.__setattr__(value, '__cl' + 'ass__', shown.__class__)\n"
    ),
    # A walrus inside a check or an annotation binds the class to a name.
    "walrus-in-isinstance": (
        "from x import ShownText\nisinstance(raw, (kind := ShownText))\n"
    ),
    "walrus-in-annotation": (
        "from x import ShownText\ndef f(value: (kind := ShownText)):\n    pass\n"
    ),
    # A module class rebound through a lookup of the module itself.
    "class-local-via-import-module": (
        "import importlib\nclass K:\n    pass\n"
        "importlib.import_module(__name__).K = kind\nvalue.__class__ = K\n"
    ),
    "class-local-via-inspect": (
        "import inspect\nclass K:\n    pass\n"
        "inspect.getmodule(K).K = kind\nvalue.__class__ = K\n"
    ),
    # An imported base whose metaclass could make the class anything.
    "class-local-metaclass-base": (
        "from abc import ABC\nclass K(ABC):\n    pass\nvalue.__class__ = K\n"
    ),
    # A reduction of shown text names copyreg's constructor and the class without
    # either being written: object's own, called past ShownText's.
    "reduce-method": "f, args = shown.__reduce__()\nf(args[0], args[1], raw)\n",
    "reduce-object": "f, args = object.__reduce__(shown)\nf(args[0], args[1], raw)\n",
    "reduce-ex-object": (
        "f, args = object.__reduce_ex__(shown, 1)[:2]\nf(args[0], args[1], raw)\n"
    ),
    # A pickle loaded by another name, or another loader.
    "pickle-aliased": "import pickle as p\np.loads(crafted)\n",
    "pickle-private-loads": "import pickle\npickle._loads(crafted)\n",
    "pickle-private-loads-from": "from pickle import _loads\n_loads(crafted)\n",
    "pickle-private-unpickler": (
        "import io\nimport pickle\npickle._Unpickler(io.BytesIO(crafted)).load()\n"
    ),
    "pickle-import-module": (
        "import importlib\nimportlib.import_module('pickle').loads(crafted)\n"
    ),
    "pickle-dunder-import": "__import__('pickle').loads(crafted)\n",
    "forking-pickler": (
        "from multiprocessing.reduction import ForkingPickler\n"
        "ForkingPickler.loads(crafted)\n"
    ),
    # str's __new__ looked up by a computed name, given the class shown text has.
    "new-computed-getattr": "getattr(str, '__ne' + 'w__')(type(shown), raw)\n",
    "new-computed-namespace": "vars(str)['__ne' + 'w__'](type(shown), raw)\n",
    # An exception's info handed to a function of the module's own that makes one.
    "exception-info-to-a-maker": (
        "def mk(cls, value, t):\n    return getattr(str, '__ne' + 'w__')(cls, t)\n"
        "mk(type(shown), shown, raw)\n"
    ),
    # str's __new__ by a computed name, given a class as a parameter.
    "new-computed-on-str": (
        "def mk(cls, t):\n    return getattr(str, '__ne' + 'w__')(cls, t)\n"
    ),
    "new-computed-on-str-namespace": (
        "def mk(cls, t):\n    return vars(str)['__ne' + 'w__'](cls, t)\n"
    ),
    # The class taken by other names for type() and .__class__.
    "class-by-getattr": "register(getattr(shown, '__class__'))\n",
    "class-by-builtins-type": "import builtins\nregister(builtins.type(shown))\n",
    "class-by-type-alias": "t = type\nregister(t(shown))\n",
    # str's namespace read with no subscript, and str, getattr and vars by other
    # names: the class from builtins.getattr handed to a maker that reads
    # vars(str).get made a real ShownText of raw text.
    "namespace-get": (
        "def mk(cls, t):\n    return vars(str).get('__ne' + 'w__')(cls, t)\n"
    ),
    "dict-get": (
        "def mk(cls, t):\n    return str.__dict__.get('__ne' + 'w__')(cls, t)\n"
    ),
    "dict-by-getattr": "getattr(str, '__dict__').get('__ne' + 'w__')(kind, raw)\n",
    "namespace-get-given-builtins-getattr-class": (
        "import builtins\n"
        "def mk(cls, t):\n    return vars(str).get('__ne' + 'w__')(cls, t)\n"
        "mk(builtins.getattr(shown, '__class__'), raw)\n"
    ),
    "str-alias-getattr": "S = str\ngetattr(S, '__ne' + 'w__')(kind, raw)\n",
    "str-alias-namespace": "S = str\nvars(S)['__ne' + 'w__'](kind, raw)\n",
    "str-alias-chain": "S = str\nT = S\nT.__dict__.get('__ne' + 'w__')(kind, raw)\n",
    "str-imported-alias": (
        "from builtins import str as S\ngetattr(S, '__ne' + 'w__')(kind, raw)\n"
    ),
    "getattr-alias-on-str": "g = getattr\ng(str, '__ne' + 'w__')(kind, raw)\n",
    "vars-alias-on-str": "v = vars\nv(str).get('__ne' + 'w__')(kind, raw)\n",
    "getattribute-on-str": ("type.__getattribute__(str, '__ne' + 'w__')(kind, raw)\n"),
    "getattr-static-on-str": (
        "import inspect\ninspect.getattr_static(str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "attrgetter-on-str": (
        "from operator import attrgetter\nattrgetter('__ne' + 'w__')(str)(kind, raw)\n"
    ),
    "class-by-builtins-getattr": (
        "import builtins\nregister(builtins.getattr(shown, '__class__'))\n"
    ),
    "class-by-getattr-alias": "g = getattr\nregister(g(shown, '__class__'))\n",
    "class-by-object-getattribute": (
        "register(object.__getattribute__(shown, '__class__'))\n"
    ),
    "class-by-bound-getattribute": "register(shown.__getattribute__('__class__'))\n",
    "class-by-attrgetter": (
        "from operator import attrgetter\nregister(attrgetter('__class__')(shown))\n"
    ),
    # An attribute looked up through methodcaller, a partial of getattr, or a
    # function or lambda of the module's own that wraps getattr; and getattr
    # reached through the builtins namespace.
    "methodcaller-class": (
        "from operator import methodcaller\n"
        "register(methodcaller('__getattribute__', '__class__')(shown))\n"
    ),
    "methodcaller-unbound-on-str": (
        "from operator import methodcaller\n"
        "methodcaller('__getattribute__', str, '__ne' + 'w__')(type)(kind, raw)\n"
    ),
    "partial-getattr-on-str": (
        "from functools import partial\n"
        "partial(getattr, str)('__ne' + 'w__')(kind, raw)\n"
    ),
    "partial-getattr-class": (
        "from functools import partial\nregister(partial(getattr, shown)('__class__'))\n"
    ),
    "lambda-wrapping-getattr-on-str": (
        "look = lambda o, n: getattr(o, n)\nlook(str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "function-wrapping-getattr-on-str": (
        "def look(o, n):\n    return getattr(o, n)\n"
        "look(str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "lambda-called-at-once-on-str": (
        "(lambda o, n: getattr(o, n))(str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "wrapper-taking-the-class": (
        "look = lambda o, n: getattr(o, n)\nregister(look(shown, '__class__'))\n"
    ),
    "builtins-namespace-getattr": (
        "__builtins__['getattr'](str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "globals-builtins-getattr": (
        "globals()['__builtins__']['getattr'](str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "builtins-namespace-get-getattr": (
        "__builtins__.get('getattr')(str, '__ne' + 'w__')(kind, raw)\n"
    ),
    "builtins-attribute-getattr": (
        "__builtins__.getattr(str, '__ne' + 'w__')(kind, raw)\n"
    ),
}

#: A class of the module's own, none of whose bases is or can be str.
_TEXT_FREE_CLASSES = {
    "no-bases": "class K:\n    pass\nvalue.__class__ = K\n",
    "object": "class K(object):\n    pass\nvalue.__class__ = K\n",
    "local-chain": "class A:\n    pass\nclass K(A):\n    pass\nvalue.__class__ = K\n",
    "imported-class": (
        "from rich.console import Console\n"
        "class K(Console):\n    pass\n"
        "value.__class__ = K\n"
    ),
}


@pytest.mark.parametrize("source", _FORGERIES.values(), ids=list(_FORGERIES))
def test_the_guard_refuses_each_way_of_forging_one(source):
    """The guard below is only as good as what it catches."""
    assert _forged(source, "automated_security_helper/x.py"), source


@pytest.mark.parametrize(
    "source", _TEXT_FREE_CLASSES.values(), ids=list(_TEXT_FREE_CLASSES)
)
def test_the_guard_allows_giving_a_value_a_class_that_cannot_be_text(source):
    """utils/console.py gives rich's global console its own Console subclass, so
    code that already holds that console prints through it. A ShownText can only
    come of a str subclass, and none of these is one."""
    assert _forged(source, "automated_security_helper/x.py") == []


@pytest.mark.parametrize(
    "source, path",
    [
        pytest.param(
            "isinstance(value, type(shown))\n",
            "automated_security_helper/x.py",
            id="check",
        ),
        pytest.param(
            "getattr(type(value), 'model_fields', {})\n",
            "automated_security_helper/x.py",
            id="named-attribute",
        ),
        pytest.param(
            "traceback.format_exception_only(type(raw_error), raw_error)\n",
            "automated_security_helper/utils/log.py",
            id="exception-info-at-a-listed-site",
        ),
    ],
)
def test_the_guard_allows_a_class_from_a_value_where_it_makes_nothing(source, path):
    assert _forged(source, path) == []


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("register(type(value))\n", id="plain-call"),
        pytest.param("kind = value.__class__\nregister(plugin=kind)\n", id="keyword"),
        pytest.param("getattr(type(value), name)\n", id="computed-attribute"),
        pytest.param("f(type(value), other)\n", id="not-its-value"),
        pytest.param(
            "traceback.format_exception(type(error), error, error.__traceback__)\n",
            id="exception-info-elsewhere",
        ),
        pytest.param("k = type(value)\nk2 = k\nregister(k2)\n", id="rebound-name"),
    ],
)
def test_the_guard_refuses_a_class_from_a_value_given_elsewhere(source):
    assert _forged(source, "automated_security_helper/x.py"), source


def test_a_listed_site_is_allowed_once():
    """A second call of the same text in the same module, listed or not, would
    pass under the first one's row: each row is found exactly once."""
    path, callee, argument = next(iter(_CLASS_ARGUMENT_SITES))
    call = f"{callee}({argument})\n"
    hits: list = []

    assert _forged(call + call, path, hits) == []
    assert _listed_site_problems(hits, {(path, callee, argument)}) == [
        f"{(path, callee, argument)}: 2 hits"
    ]
    assert _listed_site_problems(hits[:1], {(path, callee, argument)}) == []


def test_a_listed_class_assignment_is_allowed_once_and_only_as_listed():
    """A __class__ assignment in a function body is refused unless its module,
    target and Name are listed; the listed one is found exactly once, and the
    same text in another module, or with another value, is refused."""
    path, target, name = next(iter(_CLASS_ASSIGNMENT_SITES))
    body = f"def adopt(logger):\n    {target} = {name}\n"
    hits: list = []

    assert _forged(body, path, hits) == []
    assert _listed_site_problems(hits, {(path, target, name)}) == []
    assert _forged(body + body, path, hits := []) == []
    assert _listed_site_problems(hits, {(path, target, name)}) == [
        f"{(path, target, name)}: 2 hits"
    ]
    assert "automated_security_helper/x.py:2: __class__ assigned" in _forged(
        body, "automated_security_helper/x.py"
    )
    assert f"{path}:2: __class__ assigned" in _forged(
        f"def adopt(logger):\n    {target} = type(logger)\n", path
    )


def test_the_guard_allows_a_check_an_annotation_and_the_escapers():
    source = (
        "from x import ShownText, shown_not_obeyed\n"
        "def show(value: object) -> 'str':\n"
        "    shown: ShownText = shown_not_obeyed(str(value))\n"
        "    if isinstance(value, ShownText) or issubclass(type(value), (ShownText,)):\n"
        "        return value\n"
        "    return shown\n"
        "def typed(value: ShownText) -> ShownText:\n"
        "    return value\n"
    )
    assert _forged(source, "automated_security_helper/x.py") == []


def test_only_the_escapers_make_shown_text_in_the_package():
    """Read every module of the package: no other construction of a ShownText."""
    from tests.unit.walked_package import package_sources

    root = Path(automated_security_helper.__file__).resolve().parent
    found = []
    sites: list[tuple[str, str, str]] = []
    # Refused unless every part of the package is in the walk (walked_package).
    for module in package_sources(root):
        path = module.relative_to(root.parent).as_posix()
        found += _forged(module.read_text(encoding="utf-8"), path, sites)

    assert found == []
    # Each listed site is there, once.
    listed = (
        set(_CLASS_ARGUMENT_SITES)
        | set(_EXCEPTION_INFO_SITES)
        | set(_CLASS_ASSIGNMENT_SITES)
    )
    assert _listed_site_problems(sites, listed) == []
    # And the escapers do make it: the maker is there, called from both.
    source = (root / "utils" / "terminal_text.py").read_text(encoding="utf-8")
    assert f"def {_MAKER}(" in source
    assert len(re.findall(rf"\b{_MAKER}\(", source)) >= 3


def test_a_lone_surrogate_shown_on_one_line_encodes(monkeypatch):
    """A file name read from a byte that is not UTF-8, on a strict stdout."""
    # newline="\n": the bytes compared below are the text's own; without it the
    # wrapper writes the platform's line terminator, CR LF on Windows.
    stream = io.TextIOWrapper(
        io.BytesIO(), encoding="utf-8", errors="strict", newline="\n"
    )
    monkeypatch.setattr(sys, "stdout", stream)
    from automated_security_helper.utils.console import echo

    echo(_on_one_line("out" + chr(0xDC80) + "\ndir"))
    stream.flush()

    assert stream.buffer.getvalue() == b"out\\udc80\\x0adir\n"

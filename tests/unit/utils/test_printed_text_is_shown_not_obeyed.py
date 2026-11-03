# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH prints without a console is shown, not obeyed.

Builtin print writes its text as given, and several places print text from the
scanned repository or from a tool: the scan set listing (file names), the
content-database helper's refusals (a database name, a build time read from
grype's output), the output container mode and run_command_stream_output stream
from a tool, Nix mode's debug line (where bare print also wrote "[bold blue]" as
text), and error fallbacks quoting an exception. Through bare print, a file name
or a tool's output with an OSC 52 clipboard write, or with a newline then
"::add-mask::", would reach the terminal or a CI log as is.

So each goes through utils/console.py's echo (terminal_text's shown_not_obeyed),
echo_raw for machine output, or shown_not_obeyed itself in a module that must
import nothing but the standard library. Container mode streams the containerized
ASH's own rendered output, so it writes through the console stream's line check
instead, which keeps that output's colors on a terminal.

The guard fails on any builtin print with an argument that is neither a constant
nor shown_not_obeyed(...), unless the call carries a "# print-ok: <reason>"
comment.
"""

from __future__ import annotations

import ast
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Set, Tuple

import pytest

from tests.unit.walked_package import package_sources

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

_BIDI = "".join(chr(c) for c in (0x061C, 0x200E, 0x200F))
_BIDI += f"{chr(0x202A)}-{chr(0x202E)}{chr(0x2066)}-{chr(0x2069)}"
#: A raw control a terminal acts on (tab and newline lay text out and are kept).
_RAW = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")
#: A line a CI runner reads as a command.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

#: Built with chr() for the override, so this file holds none.
HOSTILE = (
    "p\x1b]52;c;ZXZpbA==\x07\x9b2K"
    + chr(0x202E)
    + "\n::add-mask::hidden ##vso[task.setvariable variable=x]y"
)

posix_names = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names cannot hold control characters"
)


def _assert_shown(text: str) -> None:
    assert not _RAW.search(text), repr(text)
    assert not _COMMAND_LINE.search(text), (_COMMAND_LINE.search(text), text)


@pytest.mark.integration
@posix_names
def test_the_scan_set_listing_shows_the_file_names(tmp_path, capsys, monkeypatch):
    """`python -m automated_security_helper.utils.get_scan_set` lists the scan set
    on stdout and the returned list on stderr."""
    from automated_security_helper.utils import get_scan_set

    source = tmp_path / "src"
    source.mkdir()
    (source / f"{HOSTILE}.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["get_scan_set", "--source", str(source), "--debug"]
    )

    assert get_scan_set.main() == 0

    out, err = capsys.readouterr()
    assert "add-mask" in out and "add-mask" in err, (out, err)
    _assert_shown(out)
    _assert_shown(err)


@pytest.mark.unit
def test_an_unknown_content_database_name_is_shown(capsys):
    from automated_security_helper.utils import content_databases

    code = content_databases.main(
        ["check-age", HOSTILE, "--built", "2026-01-01T00:00:00Z", "--for", "use"]
    )

    err = capsys.readouterr().err
    assert code == 2
    assert "add-mask" in err, err
    _assert_shown(err)


@pytest.mark.unit
def test_a_build_time_that_does_not_parse_is_refused_without_the_value(capsys):
    """--built is read from grype's own report of its database, and the workflows
    print this helper's output into a step log, where a line holding "::" or "##["
    is a workflow command. So a value that does not parse is refused with the rule
    named and the value itself NOT printed (the check-age cases of
    test_content_databases.py pin the same): stricter than shown, and what the
    text that is printed must still be is shown, not obeyed."""
    from automated_security_helper.utils import content_databases

    code = content_databases.main(
        ["check-age", "grype-db", "--built", HOSTILE, "--for", "use"]
    )

    err = capsys.readouterr().err
    assert code == 2
    assert "add-mask" not in err, err
    assert "RFC 3339" in err, err
    _assert_shown(err)


@pytest.mark.integration
def test_a_streamed_tool_output_is_shown(capsys):
    from automated_security_helper.utils.subprocess_utils import (
        run_command_stream_output,
    )

    code = run_command_stream_output(
        [sys.executable, "-c", f"import sys; sys.stdout.write({HOSTILE!r} + '\\n')"]
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "add-mask" in out, out
    _assert_shown(out)


@pytest.mark.integration
def test_container_mode_streams_the_inner_output_with_its_lines_checked(capsys):
    """Off a terminal, a line that starts with a command is broken; the inner ASH
    already showed the controls its own messages quote."""
    from automated_security_helper.interactions.run_ash_container import (
        run_cmd_direct,
    )

    script = (
        "import sys; sys.stdout.write('x\\n::add-mask::hidden\\n'); "
        "sys.stderr.write('see ##vso[task.complete]x\\n')"
    )

    result = run_cmd_direct([sys.executable, "-c", script], check=False)

    out, err = capsys.readouterr()
    assert result.returncode == 0
    assert "add-mask" in out and "task.complete" in err, (out, err)
    assert not _COMMAND_LINE.search(out), out
    assert not _COMMAND_LINE.search(err), err


@pytest.mark.integration
def test_container_mode_relays_text_the_inner_scan_already_showed_as_is(capsys):
    """Off a terminal, the containerized ASH has already shown the controls and
    broken the commands its text holds. The relay's line check finds nothing left
    to break, and it must not show the text a second time: running the text rule
    again would double every backslash of the escapes the inner scan wrote."""
    from automated_security_helper.interactions.run_ash_container import (
        run_cmd_direct,
    )

    shown = (
        "see \\x1b]52;c;ZXZpbA==\\x07 in C:\\\\x1b\\out\n"
        "\\x3a:add-mask::hidden and \\x23#vso[task.complete]x\n"
    )
    script = f"import sys; sys.stdout.write({shown!r})"

    result = run_cmd_direct([sys.executable, "-c", script], check=False)

    assert result.returncode == 0
    assert capsys.readouterr().out == shown


@pytest.mark.integration
def test_container_mode_streams_a_terminal_its_colors(monkeypatch):
    """On a terminal the inner ASH ran with -t and colored its output; that passes."""
    import io

    from automated_security_helper.interactions.run_ash_container import (
        run_cmd_direct,
    )

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    for name in ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION"):
        monkeypatch.delenv(name, raising=False)
    tty = Tty()
    monkeypatch.setattr(sys, "stdout", tty)

    run_cmd_direct(
        [sys.executable, "-c", "print('\\x1b[31mred\\x1b[0m')"],
        check=False,
    )

    assert "\x1b[31mred\x1b[0m" in tty.getvalue(), repr(tty.getvalue())


@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
@pytest.mark.unit
def test_a_summary_line_shows_the_path_it_quotes(monkeypatch, errors):
    """The scan's and the workspace's summaries print paths, project labels and
    errors through run_ash_scan's _print_text, which reads no markup in them and
    shows their controls: an OSC 52 is shown as text, and a byte that is not
    UTF-8 is shown as its escape on a strict or a lenient stdout."""
    import io

    from automated_security_helper.interactions import run_ash_scan

    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors=errors)
    monkeypatch.setattr(sys, "stdout", stream)
    path = "out" + chr(0xDC80) + HOSTILE

    run_ash_scan._print_text(f"  - SARIF: '{path}/reports/ash.sarif'")
    run_ash_scan._print_text("  ", ("failed", "bold red"), f"   {path}: boom")
    stream.flush()

    written = stream.buffer.getvalue().decode("utf-8")
    assert written.count("out\\udc80p\\x1b]52;c;ZXZpbA==\\x07") == 2, repr(written)
    _assert_shown(written)


@pytest.mark.unit
def test_the_nix_debug_line_is_shown_and_not_a_literal_tag(capsys, monkeypatch):
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.delenv(run_ash_nix.ASH_IN_NIX_ENV_VAR, raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda name: "/opt/nix/bin/nix")
    # The one call that would enter the shell, as the Nix mode's own tests replace it.
    monkeypatch.setattr(
        run_ash_nix,
        "_enter_shell",
        lambda cmd, env: subprocess.CompletedProcess(cmd, 0),
    )

    run_ash_nix.run_ash_nix(
        argv=["--source-dir", HOSTILE], flake_ref="path:/flake", debug=True
    )

    out = capsys.readouterr().out
    assert "Nix command" in out.replace("Nix Command", "Nix command"), out
    assert "[bold blue]" not in out, out
    assert "add-mask" in out, out
    _assert_shown(out)


def _assert_shown_once(text: str) -> None:
    """HOSTILE's controls are each shown once: it holds no backslash of its own."""
    _assert_shown(text)
    assert "\\x1b]52;c;ZXZpbA==\\x07\\x9b2K" in text, text
    assert "\\\\x" not in text, text


@pytest.mark.unit
def test_a_live_display_that_does_not_start_shows_the_traceback(capsys, monkeypatch):
    """The live display prints the error that stopped it, then its traceback."""
    from automated_security_helper.core import progress

    class _Refuses:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise RuntimeError(HOSTILE)

    monkeypatch.setattr(progress, "Live", _Refuses)
    display = progress.LiveProgressDisplay(show_progress=True)
    try:
        display.start()
    finally:
        progress.ASH_LOGGER.removeHandler(display.log_handler)

    err = capsys.readouterr().err
    assert "Traceback" in err and "RuntimeError" in err, err
    _assert_shown_once(err)


class _Unprintable:
    """A logged argument whose text cannot be made: its error quotes HOSTILE."""

    def __str__(self) -> str:
        raise RuntimeError(HOSTILE)


def _handler(kind: str, tmp_path: Path) -> logging.Handler:
    from automated_security_helper.utils.log import ConsoleHandler, get_logger
    from automated_security_helper.utils.rich_log_handler import (
        LiveDisplayLogHandler,
        RichLogPanel,
    )

    if kind == "live":
        return LiveDisplayLogHandler(RichLogPanel(max_lines=5))
    logger = get_logger(
        name=f"ash-handler-errors-{kind}",
        output_dir=tmp_path,
        log_format="BOTH",
        show_progress=False,
        use_color=False,
    )
    handlers, logger.handlers = list(logger.handlers), []
    wanted = {
        "console": lambda h: isinstance(h, ConsoleHandler),
        "jsonl": lambda h: getattr(h, "baseFilename", "").endswith(".jsonl"),
        "tabular": lambda h: getattr(h, "baseFilename", "").endswith(".log"),
    }[kind]
    (handler,) = [h for h in handlers if wanted(h)]
    for other in handlers:
        if other is not handler:
            other.close()
    return handler


@pytest.mark.parametrize("kind", ["jsonl", "tabular", "live"])
@pytest.mark.unit
def test_a_record_a_handler_cannot_write_is_reported_shown(
    kind, tmp_path, capsys, monkeypatch
):
    """logging.Handler.handleError prints the error's traceback to stderr as given.

    Each handler catches what failed while it wrote a record, here an argument
    whose text raises, and reports it there: through ASH's handlers, shown.
    """
    monkeypatch.setattr(logging, "raiseExceptions", True)
    handler = _handler(kind, tmp_path)
    record = logging.LogRecord(
        "ash", logging.WARNING, "app.py", 7, "value %s", (_Unprintable(),), None
    )
    try:
        handler.handle(record)
    finally:
        handler.close()

    err = capsys.readouterr().err
    assert "Logging error" in err and "RuntimeError" in err, err
    _assert_shown_once(err)


@pytest.mark.parametrize("fails", ["argument", "markup"])
@pytest.mark.unit
def test_the_console_handler_reports_its_errors_shown(
    fails, tmp_path, capsys, monkeypatch
):
    """Rich's RichHandler.emit formats the record and renders its markup outside
    its try, which covers only the print, so an argument whose text raises, or a
    MARKUP message that does not parse, would escape the log call itself. The
    console handler catches it and reports it as the others do, shown, and the
    call returns."""
    monkeypatch.setattr(logging, "raiseExceptions", True)
    handler = _handler("console", tmp_path)
    if fails == "argument":
        record = logging.LogRecord(
            "ash", logging.WARNING, "app.py", 7, "value %s", (_Unprintable(),), None
        )
    else:
        # Rich's error quotes the tag it could not close. Rich reads the message
        # after the console has shown its controls, so the tag holds the escape
        # the console wrote for ESC; the report shows it once, "[/x p\x1b]", and
        # does not show it again as the text "\x1b".
        record = logging.LogRecord(
            "ash", logging.WARNING, "app.py", 7, f"[/x {HOSTILE}", None, None
        )
        record.markup = True
    try:
        handler.handle(record)
    finally:
        handler.close()

    err = capsys.readouterr().err
    assert "Logging error" in err, err
    if fails == "argument":
        assert "RuntimeError" in err, err
        _assert_shown_once(err)
    else:
        assert "MarkupError" in err and "[/x p\\x1b]" in err, err
        assert "\\\\x" not in err, err
        _assert_shown(err)


@pytest.mark.parametrize("raw", ["parses", "raises"])
@pytest.mark.unit
def test_a_markup_error_the_raw_message_does_not_repeat_is_reported_as_raised(
    raw, tmp_path, capsys, monkeypatch
):
    """When the shown MARKUP message does not parse but the raw one parses, or
    fails some other way, there is no raw tag to quote: the console handler
    reports the error as Rich raised it, with the report shown once as a whole, so
    the tag's backslash prints doubled, no control prints raw, and the call
    returns."""
    from rich.text import Text

    real = Text.from_markup

    def from_markup(text, *args, **kwargs):
        # The raw message holds ESC as given; the shown one holds its escape.
        if chr(0x1B) in text:
            if raw == "raises":
                raise ValueError("the raw message is refused")
            return Text(text)
        return real(text, *args, **kwargs)

    monkeypatch.setattr(Text, "from_markup", staticmethod(from_markup))
    monkeypatch.setattr(logging, "raiseExceptions", True)
    handler = _handler("console", tmp_path)
    record = logging.LogRecord(
        "ash", logging.WARNING, "app.py", 7, f"[/x {HOSTILE}", None, None
    )
    record.markup = True
    try:
        handler.handle(record)
    finally:
        handler.close()

    err = capsys.readouterr().err
    assert "Logging error" in err and "MarkupError" in err, err
    assert "[/x p\\\\x1b]" in err, err
    assert "the raw message is refused" not in err, err
    _assert_shown(err)


#: Modules that can import nothing from the package, with the reason. Their prints
#: are not checked here.
STANDALONE = {
    "assets/install-pinned-tool.py": (
        "the container build runs it by path before ASH or anything ASH depends on "
        "is installed"
    ),
}
#: What exempts one call: a reason, given where the call is.
_PRAGMA = re.compile(r"#\s*print-ok:\s*\S")
#: terminal_text's escapers that show a whole text, and their module.
_SHOWN = {"shown_not_obeyed", "shown_on_one_line"}
_TERMINAL_TEXT_MODULE = "automated_security_helper.utils.terminal_text"


def _shown_names(tree: ast.AST) -> Tuple[Set[str], Set[str]]:
    """(names bound to an escaper, names bound to its module) by an import from
    terminal_text (at module level or in a function, as the standard-library-only
    helpers import it), unless the module also binds the name itself."""
    names: Set[str] = set()
    modules: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _TERMINAL_TEXT_MODULE:
            names |= {a.asname or a.name for a in node.names if a.name in _SHOWN}
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == (_TERMINAL_TEXT_MODULE.rsplit(".", 1)[0])
        ):
            modules |= {
                a.asname or a.name for a in node.names if a.name == "terminal_text"
            }
        if isinstance(node, ast.Import):
            modules |= {
                a.asname
                for a in node.names
                if a.name == _TERMINAL_TEXT_MODULE and a.asname
            }
    for node in ast.walk(tree):
        rebound = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound = [node.name]
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            rebound = [t.id for t in targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.arg):
            rebound = [node.arg]
        names -= set(rebound)
        modules -= set(rebound)
    return names, modules


def _package_sources(package: Path = PACKAGE) -> list[Path]:
    # Refused unless every part of the package is in the walk (walked_package).
    return package_sources(package)


def _is_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp):
        return _is_constant(node.left) and _is_constant(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    return False


def _is_shown(node: ast.AST, shown: Tuple[Set[str], Set[str]]) -> bool:
    """A call of terminal_text's escaper, by a name or module the module imported
    from terminal_text: a local function, or an attribute of anything else, of the
    same name could return the text as given."""
    if not isinstance(node, ast.Call):
        return False
    names, modules = shown
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in names
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _SHOWN
        and isinstance(func.value, ast.Name)
        and func.value.id in modules
    )


#: The one import that makes the name print mean something other than the
#: builtin in a module: ASH's console print, at module level.
_CONSOLE_PRINT_MODULE = "automated_security_helper.utils.console"
#: The keywords of print whose text is written too.
_TEXT_KEYWORDS = {"sep", "end"}


def _builtin_prints(source: str):
    """Each use of builtin print in *source*: (node, call or None, pragma).

    A use is a call, or any other reference that hands the builtin on (bound to a
    name, passed to map or functools.partial), which is refused outright. The
    builtin is reached by the name print, unless a module-level import of ASH's
    console print rebinds it (a method named print, an assignment, or an import
    from anywhere else does not); by an alias from ``from builtins import``; as an
    attribute or a ``"print"`` item of the builtins module, its ``__dict__``,
    ``vars()`` of it, ``__import__("builtins")``, ``sys.modules["builtins"]`` or
    ``__builtins__``; and by ``getattr`` of either with a constant "print".

    Not seen: a name or key computed at run time, exec and eval, the builtin
    taken from a container or an object it was stored on, and a module bound to a
    local name other than by import.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    builtins_names = {"__builtins__"}  # names for the builtins module, or its dict
    printers = {"print"}  # names for builtins.print
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == _CONSOLE_PRINT_MODULE:
            if any(a.name == "print" and a.asname is None for a in node.names):
                printers.discard("print")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "builtins":
                    builtins_names.add(alias.asname or "builtins")
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name == "print":
                    printers.add(alias.asname or "print")

    def is_builtins(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in builtins_names
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            # vars(builtins), and __import__("builtins").
            if node.func.id == "vars" and node.args:
                return is_builtins(node.args[0])
            return (
                node.func.id == "__import__"
                and bool(node.args)
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "builtins"
            )
        if isinstance(node, ast.Subscript):
            # sys.modules["builtins"]
            return (
                isinstance(node.slice, ast.Constant)
                and node.slice.value == "builtins"
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "modules"
            )
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and is_builtins(node.value)
        )

    def names_print(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in printers and isinstance(node.ctx, ast.Load)
        if isinstance(node, ast.Attribute):
            return node.attr == "print" and is_builtins(node.value)
        if isinstance(node, ast.Subscript):
            key = node.slice
            return (
                isinstance(key, ast.Constant)
                and key.value == "print"
                and is_builtins(node.value)
            )
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and is_builtins(node.args[0])
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "print"
        )

    called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    uses = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and names_print(node.func):
            span = lines[node.lineno - 1 : node.end_lineno or node.lineno]
            pragma = any(_PRAGMA.search(line) for line in span)
            uses.append((node, node, pragma))
        elif names_print(node) and id(node) not in called:
            uses.append((node, None, False))
    return uses


def _print_offenders(source: str, relative: str) -> list[str]:
    """Every use of builtin print in *source* that writes text as given.

    A ``**`` argument is refused unless the call is exempted: what it holds, sep
    and end included, cannot be read here.
    """
    shown = _shown_names(ast.parse(source))
    offenders = []
    for node, call, pragma in _builtin_prints(source):
        where = f"{relative}:{node.lineno} {ast.unparse(node)[:80]}"
        if call is None:
            offenders.append(f"{where} (the builtin handed on)")
            continue
        texts = list(call.args) + [
            keyword.value
            for keyword in call.keywords
            if keyword.arg in _TEXT_KEYWORDS or keyword.arg is None
        ]
        if all(_is_constant(text) or _is_shown(text, shown) for text in texts):
            continue
        if not pragma:
            offenders.append(where)
    return offenders


def _print_exemptions(source: str) -> list[str]:
    """The calls in *source* that a "# print-ok:" comment exempts."""
    return [ast.unparse(call) for _, call, pragma in _builtin_prints(source) if pragma]


@pytest.mark.unit
def test_no_builtin_print_writes_text_as_given():
    offenders = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative in STANDALONE:
            continue
        offenders.extend(_print_offenders(source.read_text(encoding="utf-8"), relative))

    assert offenders == [], offenders


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param("print(name)\n", 1, id="name"),
        pytest.param("print(f'{x}')\n", 1, id="f-string"),
        pytest.param("print('a', x)\n", 1, id="constant-and-name"),
        pytest.param("print(*parts)\n", 1, id="starred"),
        pytest.param("import builtins\nbuiltins.print(x)\n", 2, id="builtins"),
        pytest.param("import builtins as b\nb.print(x)\n", 2, id="builtins-alias"),
        pytest.param("from builtins import print as p\np(x)\n", 2, id="print-alias"),
        pytest.param(
            "import builtins\ngetattr(builtins, 'print')(x)\n", 2, id="getattr"
        ),
        pytest.param("print(x)  # print-ok:\n", 1, id="pragma-without-a-reason"),
        # The builtin handed on, bound or reached another way.
        pytest.param("p = print\np(x)\n", 1, id="bound-to-a-name"),
        pytest.param("list(map(print, xs))\n", 1, id="map"),
        pytest.param(
            "import functools\nfunctools.partial(print, file=f)\n", 2, id="partial"
        ),
        pytest.param("__builtins__['print'](x)\n", 1, id="builtins-dict"),
        pytest.param("__builtins__.print(x)\n", 1, id="builtins-attribute"),
        pytest.param(
            "import builtins\nf = getattr(builtins, 'print')\nf(x)\n",
            2,
            id="getattr-bound",
        ),
        pytest.param(
            "import builtins\nbuiltins.__dict__['print'](x)\n", 2, id="module-dict"
        ),
        pytest.param("import builtins\nvars(builtins)['print'](x)\n", 2, id="vars"),
        pytest.param("__import__('builtins').print(x)\n", 1, id="dunder-import"),
        pytest.param(
            "import sys\nsys.modules['builtins'].print(x)\n", 2, id="sys-modules"
        ),
        # Text in arguments the guard cannot read.
        pytest.param("print('a', **{'end': x})\n", 1, id="double-star"),
        pytest.param("print('a', **options)\n", 1, id="double-star-name"),
        # An escaper that is not terminal_text's.
        pytest.param(
            "def shown_not_obeyed(text):\n    return text\nprint(shown_not_obeyed(x))\n",
            3,
            id="a-local-escaper",
        ),
        pytest.param(
            "print(other.shown_not_obeyed(x))\n", 1, id="an-attribute-escaper"
        ),
        pytest.param(
            "from automated_security_helper.utils.terminal_text import "
            "shown_not_obeyed\n"
            "shown_not_obeyed = str\n"
            "print(shown_not_obeyed(x))\n",
            3,
            id="an-escaper-rebound",
        ),
        # Text in the separators.
        pytest.param("print('', end=x)\n", 1, id="end"),
        pytest.param("print('a', sep=x)\n", 1, id="sep"),
        # Only a module-level import of ASH's console print rebinds the name.
        pytest.param(
            "class C:\n    def print(self):\n        pass\nprint(x)\n",
            4,
            id="a-method-named-print",
        ),
        pytest.param("print = log\nprint(x)\n", 2, id="assigned"),
        pytest.param("from other import print\nprint(x)\n", 2, id="imported-elsewhere"),
        pytest.param(
            "def f():\n"
            "    from automated_security_helper.utils.console import print\n"
            "    print(x)\n"
            "print(y)\n",
            4,
            id="console-print-in-a-function",
        ),
    ],
)
@pytest.mark.unit
def test_the_print_guard_finds_each_way_to_print_text_as_given(source, line):
    offenders = _print_offenders(source, "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("print('a', '=' * 50, f'b')\n", id="constants"),
        pytest.param(
            "from automated_security_helper.utils.terminal_text import "
            "shown_not_obeyed\n"
            "print(shown_not_obeyed(x), file=sys.stderr)\n",
            id="shown",
        ),
        pytest.param(
            "from automated_security_helper.utils import terminal_text\n"
            "print(terminal_text.shown_on_one_line(x))\n",
            id="shown-through-the-module",
        ),
        pytest.param(
            "from automated_security_helper.utils.console import print\nprint(x)\n",
            id="ash-console-print",
        ),
        pytest.param("print(abi)  # print-ok: an int the parent reads\n", id="pragma"),
        pytest.param("print('a', end='', sep=' ')\n", id="constant-separators"),
    ],
)
@pytest.mark.unit
def test_the_print_guard_passes_what_is_not_text_as_given(source):
    assert _print_offenders(source, "fixture.py") == []


#: Every builtin print the package exempts with a "# print-ok:" comment, by module
#: and call. A new exemption is added here, so a reviewer sees it.
EXEMPTED_CALLS = {
    ("utils/content_databases.py", "print(cache_key_suffix(entry, now))"),
    ("utils/content_databases.py", "print(f'{name}={value}')"),
    ("utils/sandbox/landlock_exec.py", "print(abi)"),
}


@pytest.mark.unit
def test_the_exempted_prints_are_the_ones_listed():
    exempted = set()
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative in STANDALONE:
            continue
        exempted |= {
            (relative, call)
            for call in _print_exemptions(source.read_text(encoding="utf-8"))
        }

    assert exempted == EXEMPTED_CALLS
    assert set(STANDALONE) == {"assets/install-pinned-tool.py"}


@pytest.mark.unit
def test_the_print_guard_refuses_a_tree_with_nothing_to_check(tmp_path):
    """Moved or pointed elsewhere, the guard would pass having read no module."""
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _package_sources(tmp_path)


#: The streams a process writes to the terminal or the CI log.
_STREAMS = {"stdout", "stderr", "__stdout__", "__stderr__"}

#: A module that can import nothing from ASH, and the escaper it defines for
#: itself, which tests/unit/utils/test_landlock_exec_shows_text.py proves writes
#: what terminal_text's shown_on_one_line writes.
INLINE_ESCAPERS = {"utils/sandbox/landlock_exec.py": "_shown"}


def _stream_write_offenders(source: str, relative: str) -> list[str]:
    """Each ``write`` or ``writelines`` on sys's stdout or stderr (``__stdout__``
    and ``__stderr__`` too) in *source* given text that is not a constant,
    terminal_text's escaper, or the module's own escaper listed in
    INLINE_ESCAPERS. The stream is found as ``sys.stderr`` with sys by any import
    name, as a name ``from sys import stderr`` binds (aliased or not), and as
    ``getattr(sys, "stderr")``. writelines is given a list or tuple of such text.
    A ``# print-ok:`` comment with a reason exempts one call.

    Not seen: a stream bound to another name first, its ``buffer``, and
    ``os.write`` to a file descriptor.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    shown = _shown_names(tree)
    inline = INLINE_ESCAPERS.get(relative)
    sys_names = {"sys"}
    stream_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            sys_names |= {a.asname or a.name for a in node.names if a.name == "sys"}
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            stream_names |= {
                a.asname or a.name for a in node.names if a.name in _STREAMS
            }

    def is_stream(value: ast.AST) -> bool:
        if isinstance(value, ast.Name):
            return value.id in stream_names
        if isinstance(value, ast.Attribute):
            return (
                value.attr in _STREAMS
                and isinstance(value.value, ast.Name)
                and value.value.id in sys_names
            )
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id in sys_names
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value in _STREAMS
        )

    offenders = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("write", "writelines")
            and is_stream(node.func.value)
        ):
            continue
        span = lines[node.lineno - 1 : node.end_lineno or node.lineno]
        if any(_PRAGMA.search(line) for line in span):
            continue

        def allowed(text: ast.AST) -> bool:
            if isinstance(text, ast.BinOp) and isinstance(text.op, ast.Add):
                # Shown text and a constant line end, joined.
                return allowed(text.left) and allowed(text.right)
            return (
                _is_constant(text)
                or _is_shown(text, shown)
                or (
                    inline is not None
                    and isinstance(text, ast.Call)
                    and isinstance(text.func, ast.Name)
                    and text.func.id == inline
                )
            )

        texts = list(node.args) + [keyword.value for keyword in node.keywords]
        if node.func.attr == "writelines":
            # Lines given one by one in a literal; any other iterable is unseen.
            texts = [
                line
                for text in texts
                for line in (
                    text.elts if isinstance(text, (ast.List, ast.Tuple)) else [text]
                )
            ]
            if any(isinstance(text, ast.Starred) for text in texts) or not all(
                isinstance(text, (ast.List, ast.Tuple)) for text in node.args
            ):
                offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)[:80]}")
                continue
        if all(allowed(text) for text in texts):
            continue
        offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)[:80]}")
    return offenders


@pytest.mark.unit
def test_no_stream_write_writes_text_as_given():
    """sys.stderr.write is print without its name: the standard-library-only
    helpers (the sandbox's exec wrapper, the workers) write their errors with it."""
    offenders = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative in STANDALONE:
            continue
        offenders.extend(
            _stream_write_offenders(source.read_text(encoding="utf-8"), relative)
        )

    assert offenders == [], offenders


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param("import sys\nsys.stderr.write(x)\n", 2, id="stderr"),
        pytest.param("import sys\nsys.stdout.write(f'{x}\\n')\n", 2, id="stdout"),
        pytest.param("import sys as s\ns.__stderr__.write(x)\n", 2, id="aliased"),
        pytest.param(
            "import sys\nsys.stderr.write(_shown(x))\n", 2, id="an-unlisted-escaper"
        ),
        pytest.param("import sys\nsys.stderr.writelines(x)\n", 2, id="writelines"),
        pytest.param(
            "import sys\nsys.stdout.writelines([x, '\\n'])\n", 2, id="writelines-list"
        ),
        pytest.param("from sys import stderr\nstderr.write(x)\n", 2, id="from-import"),
        pytest.param(
            "from sys import __stdout__ as out\nout.write(x)\n", 2, id="from-alias"
        ),
        pytest.param(
            "import sys\ngetattr(sys, 'stderr').write(x)\n", 2, id="getattr-stream"
        ),
    ],
)
@pytest.mark.unit
def test_the_stream_guard_finds_each_write_of_text_as_given(source, line):
    offenders = _stream_write_offenders(source, "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("import sys\nsys.stderr.write('usage: x\\n')\n", id="constant"),
        pytest.param(
            "import sys\n"
            "from automated_security_helper.utils.terminal_text import "
            "shown_on_one_line\n"
            "sys.stderr.write(shown_on_one_line(x))\n",
            id="shown",
        ),
        pytest.param(
            "from sys import stderr\nstderr.writelines(['usage: x', '\\n'])\n",
            id="constant-lines",
        ),
    ],
)
@pytest.mark.unit
def test_the_stream_guard_passes_what_is_not_text_as_given(source):
    assert _stream_write_offenders(source, "fixture.py") == []


#: traceback's functions that print a traceback, its error's text included, as
#: given (to stderr by default). traceback.format_exc and its kin return the text.
_TRACEBACK_PRINTS = {
    "print_exc",
    "print_exception",
    "print_tb",
    "print_stack",
    "print_last",
}


def _traceback_print_offenders(source: str, relative: str) -> list[str]:
    """Every way *source* reaches one of traceback's print functions.

    The module by an import, an alias, ``__import__("traceback")`` or
    ``sys.modules["traceback"]``; a print function as its attribute, by
    ``getattr`` with a constant name, or imported from it; TracebackException's
    print method, on the class's result or on a name it was assigned to; and the
    interpreter's exception hook called directly (``sys.excepthook``,
    ``sys.__excepthook__``), which prints the traceback as given. Not seen: a name
    computed at run time, exec, a TracebackException kept in a container or an
    attribute, the hook reached through anything but the sys module, and a hook
    held in a name and called through it (``hook = sys.excepthook; hook(...)``).
    cli/entrypoint.py's floor holds one that way: it puts ASH's shown traceback
    in place of typer's hook and the interpreter's own, and calls any other with
    sys.stdout and sys.stderr writing each line shown.
    """
    tree = ast.parse(source)
    modules = set()  # names bound to the traceback module
    exceptions = set()  # names bound to traceback.TracebackException
    held = set()  # names a TracebackException was assigned to
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules |= {a.asname or a.name for a in node.names if a.name == "traceback"}
        elif isinstance(node, ast.ImportFrom) and node.module == "traceback":
            offenders.extend(
                f"{relative}:{node.lineno} from traceback import {alias.name}"
                for alias in node.names
                if alias.name in _TRACEBACK_PRINTS or alias.name == "*"
            )
            exceptions |= {
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "TracebackException"
            }

    def is_module(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in modules
        if isinstance(node, ast.Subscript):
            return (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "modules"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "sys"
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "traceback"
            )
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            and bool(node.args)
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "traceback"
        )

    def names_exception_class(node: ast.AST) -> bool:
        return any(
            (isinstance(inner, ast.Name) and inner.id in exceptions)
            or (
                isinstance(inner, ast.Attribute)
                and inner.attr == "TracebackException"
                and is_module(inner.value)
            )
            for inner in ast.walk(node)
        )

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            if names_exception_class(node.value):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                held |= {t.id for t in targets if isinstance(t, ast.Name)}

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "print"
            and isinstance(node.value, ast.Name)
            and node.value.id in held
        ):
            offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)}")
        if isinstance(node, ast.Attribute) and node.attr in _TRACEBACK_PRINTS:
            if is_module(node.value):
                offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if (
                node.func.id == "getattr"
                and len(node.args) >= 2
                and is_module(node.args[0])
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in _TRACEBACK_PRINTS
            ):
                offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)}")
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "print"
            and names_exception_class(node.value)
        ):
            offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("excepthook", "__excepthook__")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "sys"
        ):
            offenders.append(f"{relative}:{node.lineno} {ast.unparse(node.func)}(...)")
    return offenders


@pytest.mark.unit
def test_no_traceback_is_printed_as_given():
    """A traceback quotes its error's text: print shown_not_obeyed(format_exc())."""
    offenders = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative in STANDALONE:
            continue
        offenders.extend(
            _traceback_print_offenders(source.read_text(encoding="utf-8"), relative)
        )

    assert offenders == [], offenders


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param("import traceback\ntraceback.print_exc()\n", 2, id="print-exc"),
        pytest.param(
            "import traceback as tb\ntb.print_exception(e)\n", 2, id="aliased"
        ),
        pytest.param("from traceback import print_stack\n", 1, id="from-import"),
        pytest.param(
            "import traceback\ngetattr(traceback, 'print_exc')()\n", 2, id="getattr"
        ),
        pytest.param("__import__('traceback').print_exc()\n", 1, id="dunder-import"),
        pytest.param(
            "import traceback\n"
            "traceback.TracebackException.from_exception(e).print()\n",
            2,
            id="traceback-exception",
        ),
        pytest.param(
            "from traceback import TracebackException as T\nT(*info).print(file=f)\n",
            2,
            id="traceback-exception-imported",
        ),
        pytest.param("import sys\nsys.excepthook(*info)\n", 2, id="excepthook"),
        pytest.param(
            "import sys\nsys.__excepthook__(*info)\n", 2, id="dunder-excepthook"
        ),
        pytest.param(
            "import traceback\n"
            "held = traceback.TracebackException.from_exception(e)\n"
            "held.print()\n",
            3,
            id="held-traceback-exception",
        ),
        pytest.param(
            "import sys\nsys.modules['traceback'].print_exc()\n", 2, id="sys-modules"
        ),
    ],
)
@pytest.mark.unit
def test_the_traceback_guard_finds_each_way_to_print_one(source, line):
    offenders = _traceback_print_offenders(source, "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders


@pytest.mark.unit
def test_the_traceback_guard_passes_a_traceback_made_into_text():
    source = "import traceback\nprint(shown_not_obeyed(traceback.format_exc()))\n"

    assert _traceback_print_offenders(source, "fixture.py") == []


#: What reports a handler's errors as shown text (utils/log.py).
_SHOWN_ERRORS = "ShownHandlerErrors"
#: Handlers that never report an error, with the reason.
_HANDLERS_THAT_DO_NOT_REPORT = {
    ("utils/cdk_nag_worker.py", "_RecordCollector"): (
        "its emit only appends to a list, and never calls handleError"
    ),
    ("utils/download_utils.py", "_HttpsOnlyRedirects"): (
        "a urllib.request redirect handler, not a log handler: it has no "
        "handleError and writes no record"
    ),
}


#: The modules whose handler classes report a failed record as given.
_HANDLER_MODULES = {"logging", "logging.handlers", "rich.logging"}


def _handler_offenders(source: str, relative: str) -> list[str]:
    """Each log handler *source* defines or builds that reports its errors as given.

    A class whose base is a handler (a name ending in "Handler", one imported
    from logging, logging.handlers or rich.logging under any name, or a name a
    handler class was assigned to) and does not have ShownHandlerErrors as its
    first base, where it comes first in the method order; one that has it and
    defines its own handleError, which replaces the mix-in's; a handler of those
    modules built directly, through the module or by its imported name; and
    logging.basicConfig, which builds a stream handler. Not seen: a class made with
    type(), a handleError set on a class or an instance, a handler built by a
    function of another module, and a base reached through a name bound at run
    time.
    """
    tree = ast.parse(source)
    imported = set()  # names a handler class of those modules is bound to
    configurers = set()  # names logging.basicConfig is bound to
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _HANDLER_MODULES:
            imported |= {
                alias.asname or alias.name
                for alias in node.names
                if alias.name.endswith("Handler")
            }
            configurers |= {
                alias.asname or alias.name
                for alias in node.names
                if node.module == "logging" and alias.name == "basicConfig"
            }

    def is_handler(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Name) and expression.id in imported:
            return True
        return ast.unparse(expression).endswith("Handler")

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, (ast.Name, ast.Attribute))
            and is_handler(node.value)
        ):
            imported.add(node.targets[0].id)

    def is_library_handler(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Name):
            return expression.id in imported
        called = ast.unparse(expression)
        return called.startswith(("logging.", "rich.logging.")) and called.endswith(
            "Handler"
        )

    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = [ast.unparse(base) for base in node.bases]
            if not any(is_handler(base) for base in node.bases):
                continue
            if (relative, node.name) in _HANDLERS_THAT_DO_NOT_REPORT:
                continue
            if _SHOWN_ERRORS not in bases:
                offenders.append(f"{relative}:{node.lineno} class {node.name}")
            elif bases[0] != _SHOWN_ERRORS:
                # A base before the mix-in whose handleError comes first replaces it.
                offenders.append(
                    f"{relative}:{node.lineno} class {node.name} has "
                    f"{_SHOWN_ERRORS} after another base"
                )
            elif any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "handleError"
                for item in node.body
            ):
                offenders.append(
                    f"{relative}:{node.lineno} class {node.name} defines handleError"
                )
        elif isinstance(node, ast.Call) and (
            is_library_handler(node.func)
            or ast.unparse(node.func) == "logging.basicConfig"
            or (isinstance(node.func, ast.Name) and node.func.id in configurers)
        ):
            offenders.append(f"{relative}:{node.lineno} {ast.unparse(node.func)}(...)")
    return offenders


@pytest.mark.unit
def test_every_log_handler_reports_its_errors_shown():
    """logging.Handler.handleError prints the failed record's traceback as given."""
    offenders = []
    for source in _package_sources():
        relative = source.relative_to(PACKAGE).as_posix()
        if relative in STANDALONE:
            continue
        offenders.extend(
            _handler_offenders(source.read_text(encoding="utf-8"), relative)
        )

    assert offenders == [], offenders


@pytest.mark.parametrize(
    "source, line",
    [
        pytest.param(
            "import logging\nclass H(logging.Handler):\n    pass\n", 2, id="subclass"
        ),
        pytest.param(
            "import logging\nh = logging.FileHandler('a.log')\n", 2, id="built-directly"
        ),
        pytest.param(
            "from logging import FileHandler\nh = FileHandler('a.log')\n",
            2,
            id="built-by-its-imported-name",
        ),
        pytest.param(
            "from logging import Handler as Base\nclass H(Base):\n    pass\n",
            2,
            id="an-aliased-base",
        ),
        pytest.param(
            "from rich.logging import RichHandler\nh = RichHandler()\n",
            2,
            id="rich-handler-built-directly",
        ),
        pytest.param(
            "class H(ShownHandlerErrors, logging.Handler):\n"
            "    def handleError(self, record):\n"
            "        super(ShownHandlerErrors, self).handleError(record)\n",
            1,
            id="the-mix-in-overridden",
        ),
        pytest.param(
            "import logging\nlogging.basicConfig(level=10)\n", 2, id="basic-config"
        ),
        pytest.param(
            "from logging import basicConfig as setup\nsetup()\n",
            2,
            id="basic-config-imported",
        ),
        pytest.param(
            "import logging\nBase = logging.Handler\nclass H(Base):\n    pass\n",
            3,
            id="a-base-bound-by-assignment",
        ),
        pytest.param(
            "class First:\n"
            "    def handleError(self, record):\n"
            "        pass\n"
            "class H(First, ShownHandlerErrors, logging.Handler):\n"
            "    pass\n",
            4,
            id="the-mix-in-behind-another-base",
        ),
    ],
)
@pytest.mark.unit
def test_the_handler_guard_finds_a_handler_that_reports_as_given(source, line):
    offenders = _handler_offenders(source, "fixture.py")

    assert any(o.startswith(f"fixture.py:{line} ") for o in offenders), offenders


@pytest.mark.unit
def test_the_handler_guard_passes_a_handler_with_the_mix_in():
    source = "class H(ShownHandlerErrors, logging.Handler):\n    pass\n"

    assert _handler_offenders(source, "fixture.py") == []


_REDIRECT_HANDLER = (
    "import urllib.request\n"
    "class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):\n"
    "    pass\n"
)


@pytest.mark.unit
def test_the_handler_guard_passes_the_download_redirect_handler_by_name():
    assert _handler_offenders(_REDIRECT_HANDLER, "utils/download_utils.py") == []


@pytest.mark.unit
def test_the_handler_guard_still_finds_a_redirect_handler_anywhere_else():
    """The exemption is for one class in one module, not for the base."""
    offenders = _handler_offenders(_REDIRECT_HANDLER, "utils/other_module.py")

    assert any(o.startswith("utils/other_module.py:2 ") for o in offenders), offenders

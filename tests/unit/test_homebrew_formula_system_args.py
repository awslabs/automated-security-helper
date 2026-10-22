# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every argument Formula/ash.rb passes to ``system`` is a string.

Why this exists
---------------
The formula passed Pathname objects to ``system``: ``venv.root/"bin/python"`` in
``def install``, and ``bin/"ash"``, ``testpath/"src"`` and ``testpath/"out"`` in
``test do``. Whether ``system`` accepts a Pathname depends on the Homebrew version
and its type signatures, and the only check that runs this code is a real
``brew install`` and ``brew test`` on a CI runner. Converting each argument with
``.to_s`` takes the question away.

What the test checks
--------------------
Each ``system`` call in the formula, including those continued onto further
lines, is split into its arguments, and each argument must be a string literal
or end in ``.to_s``. That is stricter than "no Pathname": an argument that is
neither is code whose type this test cannot see, so it has to say ``.to_s`` too.
The checker is tested on snippets of its own, so a parser that finds nothing, or
accepts everything, fails here rather than passing.

Homebrew is not run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

FORMULA_PATH = Path(__file__).resolve().parents[2] / "Formula" / "ash.rb"

SYSTEM_CALL = re.compile(r"^[ \t]*system\b[ \t(]", re.MULTILINE)
HEREDOC = re.compile(r"<<[~-]?(?P<id>[A-Z_][A-Z0-9_]*)")
QUOTES = "\"'"


def _skip_string(text: str, start: int) -> int:
    """Index just past the string literal opening at ``text[start]``.

    In a double-quoted literal, ``#{...}`` interpolations are skipped as code, so
    a quote inside one (as in ``"#{Formula["node"].opt_bin}"``) does not end it.
    """
    quote = text[start]
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        if char == quote:
            return i + 1
        if quote == '"' and text.startswith("#{", i):
            i = _skip_code(text, i + 2, closer="}")
            continue
        i += 1
    raise ValueError(f"unterminated string literal at offset {start}")


def _skip_code(text: str, start: int, closer: str) -> int:
    """Index just past the ``closer`` that balances code starting at ``start``."""
    depth = 0
    i = start
    while i < len(text):
        char = text[i]
        if char in QUOTES:
            i = _skip_string(text, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0 and char == closer:
                return i + 1
            depth -= 1
        i += 1
    raise ValueError(f"unbalanced code at offset {start}")


def _arguments(statement: str) -> list[str]:
    """The top-level, comma-separated arguments of ``statement``'s call."""
    arguments, depth, current, i = [], 0, [], 0
    while i < len(statement):
        char = statement[i]
        if char in QUOTES:
            end = _skip_string(statement, i)
            current.append(statement[i:end])
            i = end
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        i += 1
    arguments.append("".join(current).strip())
    return arguments


def _without_comments_and_heredocs(text: str) -> str:
    """``text`` with comments and heredoc bodies removed, string literals kept.

    A heredoc's body is not code: a quote or a ``#`` in it would otherwise be read
    as one. Each removed body keeps its newlines, so offsets stay on their lines.
    """
    out, i = [], 0
    pending_heredocs: list[str] = []
    while i < len(text):
        char = text[i]
        if char in QUOTES:
            end = _skip_string(text, i)
            out.append(text[i:end])
            i = end
            continue
        if char == "#":
            i = text.find("\n", i)
            i = len(text) if i < 0 else i
            continue
        heredoc = HEREDOC.match(text, i)
        if heredoc:
            pending_heredocs.append(heredoc["id"])
            out.append(heredoc[0])
            i = heredoc.end()
            continue
        if char == "\n" and pending_heredocs:
            out.append(char)
            i += 1
            for identifier in pending_heredocs:
                terminator = re.compile(rf"^[ \t]*{identifier}[ \t]*$", re.MULTILINE)
                found = terminator.search(text, i)
                if not found:
                    raise ValueError(f"heredoc {identifier} is not terminated")
                out.append("\n" * text.count("\n", i, found.end()))
                i = found.end()
            pending_heredocs = []
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _statement_end(text: str, start: int) -> int:
    """End of the statement starting at ``start``: a newline outside any string
    and bracket that does not follow a comma or a ``\\``."""
    depth, i = 0, start
    while i < len(text):
        char = text[i]
        if char in QUOTES:
            i = _skip_string(text, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "\n" and depth == 0:
            before = text[start:i].rstrip()
            if not before.endswith((",", "\\")):
                return i
        i += 1
    return len(text)


def system_calls(text: str) -> list[list[str]]:
    """The argument lists of every ``system`` call in a Ruby source."""
    text = _without_comments_and_heredocs(text)
    calls = []
    for match in SYSTEM_CALL.finditer(text):
        opening = match.end() - 1
        if text[opening] == "(":
            # system(...): the arguments are what the parentheses hold.
            statement = text[opening + 1 : _skip_code(text, opening + 1, ")") - 1]
        else:
            statement = text[opening : _statement_end(text, opening)]
        calls.append(_arguments(statement.replace("\\\n", " ").strip()))
    return calls


def _is_a_string(argument: str) -> bool:
    if argument.endswith(".to_s"):
        return True
    if argument[:1] in QUOTES:
        return _skip_string(argument, 0) == len(argument)
    return False


def non_string_arguments(text: str) -> list[str]:
    return [
        argument
        for arguments in system_calls(text)
        for argument in arguments
        if not _is_a_string(argument)
    ]


class TestTheChecker:
    """The checker is held to snippets, so it cannot pass by finding nothing."""

    @pytest.mark.parametrize(
        "source, flagged",
        [
            ('    system bin/"ash", "--version"\n', ['bin/"ash"']),
            (
                '    system "uv", "sync",\n           "--python", venv.root/"bin/python"\n',
                ['venv.root/"bin/python"'],
            ),
            ('    system "ash", "--source-dir", testpath\n', ["testpath"]),
            ('    system("ash", testpath/"out")\n', ['testpath/"out"']),
            (
                '    system "ash", \\\n           buildpath/"x"\n',
                ['buildpath/"x"'],
            ),
            (
                '    system (bin/"ash"), (testpath/"x")\n',
                ['(bin/"ash")', '(testpath/"x")'],
            ),
        ],
        ids=[
            "first",
            "continued-line",
            "bare-pathname",
            "parenthesized",
            "backslash",
            "parenthesized-arguments",
        ],
    )
    def test_a_pathname_argument_is_flagged(self, source, flagged):
        assert non_string_arguments(source) == flagged

    @pytest.mark.parametrize(
        "source",
        [
            '    system (bin/"ash").to_s, "--version"\n',
            '    system "uv", "sync",\n           "--python", (venv.root/"bin/python").to_s\n',
            '    system "#{bin}/ash", "--out", "#{testpath}/out"\n',
            '    system "sh", "-c", "echo \\"#{Formula["node"].opt_bin}\\", done"\n',
            '    system "ash", "--version" # a comment, with a comma: bin/"x"\n',
            "    system 'ash', '--version'\n",
            '    x = <<~SH\n      it\'s "\n      system bin/"x"\n    SH\n    system "ash"\n',
        ],
        ids=[
            "to_s",
            "continued-to_s",
            "interpolated",
            "nested-quotes",
            "comment",
            "single-quoted",
            "heredoc-body",
        ],
    )
    def test_a_string_argument_passes(self, source):
        assert system_calls(source), "the snippet's system call was not found"
        assert non_string_arguments(source) == []

    def test_the_formulas_calls_are_found(self):
        """Control: both of the formula's system calls are read, with their lines."""
        calls = system_calls(FORMULA_PATH.read_text(encoding="utf-8"))
        sync = [arguments for arguments in calls if arguments[:2] == ['"uv"', '"sync"']]
        assert sync and '"--python"' in sync[0], calls
        scan = [arguments for arguments in calls if '"scan"' in arguments]
        assert scan and '"--scanners"' in scan[0], calls


def test_every_system_argument_in_the_formula_is_a_string():
    flagged = non_string_arguments(FORMULA_PATH.read_text(encoding="utf-8"))
    assert flagged == [], (
        f"{FORMULA_PATH.name} passes these to `system` without `.to_s`: {flagged}"
    )

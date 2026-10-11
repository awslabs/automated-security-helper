# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Find text that installs or runs ASH from a package index by a bare name.

ASH is distributed from git. On PyPI the distribution name
``automated-security-helper`` belongs to an unrelated placeholder project whose
version number outranks every ASH release, and ``ash`` belongs to a second
unrelated project. So ``pip install "automated-security-helper[symbols]"``
installs an unrelated project instead of the extra, and an MCP client entry that
runs ``uvx --with=. ash mcp`` resolves the unrelated ``ash`` as the tool it runs.

Two kinds of caller use this module: the repository gate in
``tests/unit/test_no_bare_name_install_hints.py``, and the tests that pin one
runtime hint each (the symbols-extra hints in
``tests/unit/utils/test_symbol_suppressions.py``, the detect-secrets reason in
``tests/unit/plugin_modules/ash_builtin/test_detect_secrets_scanner_behavior.py``).

What is reported
----------------
1. An install or run command whose target is a bare name. The commands are
   ``pip install`` (any ``pip``/``pip3``, ``python -m pip``, ``uv pip``),
   ``pipx install``, ``pipx run``, ``uv add``, ``uv tool install``,
   ``uv tool run`` and ``uvx``, plus the value of any ``--with``/``-w``,
   ``--from`` or ``--spec`` option on a uv, uvx, pipx or pip command line. For
   ``uvx``, ``uv tool run`` and ``pipx run`` the first positional word is the
   package unless ``--from``/``--spec`` names one, so ``uvx --with=. ash mcp``
   runs the ``ash`` package and ``uvx --from=git+... ash mcp`` does not.
2. A requirement spelling of ASH's distribution name anywhere in the text:
   ``automated-security-helper[extra]`` or ``automated-security-helper==1.2``.
   Those only ever mean "resolve this name from an index", with or without an
   installer in front of them; this is what catches a prose hint such as
   ``Install automated-security-helper[symbols]``. In a Python string literal
   the spelling counts only when the same literal contains the word "install":
   a literal can be a fragment, such as ``f"automated-security-helper[{extra}]"``
   in a helper that appends the git reference next, and the fragment alone tells
   a user nothing.
3. MCP client entries written as JSON, ``"command": "uvx", "args": [...]``,
   rebuilt into one command line and checked as in 1. The arguments sit on
   separate lines there, so a line-based check cannot see them.

A name counts as bare when it is, after PEP 503 normalization (case, ``-``,
``_`` and ``.`` are equivalent), ``automated-security-helper`` or ``ash``, and
no direct reference follows it. ``name[extra] @ git+URL`` (spaced or not, quoted
or not), a ``git+`` URL, a local path and ``name:tag`` are not bare. A pinned
version (``==3.7.0``, uvx's ``ash@3.7.0``) is still bare: it is resolved from the
index like any other name.

What is not reported
--------------------
``pipx upgrade``, which reuses the requirement recorded at install time, and
``uv run``'s command word, which names a script in the current project. Prose
that follows an install command on the same line without a code span or a
``;``/``&&``/``|`` between them is read as more install targets, so
"pip install -e . then run ash" is reported; put the commands in separate code
spans. Commands built at runtime from pieces that never appear together in one
string literal are invisible here; the runtime-hint tests check those messages
as users see them.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

#: PEP 503-normalized names that do not resolve to ASH on a package index.
BARE_NAMES = frozenset({"automated-security-helper", "ash"})

#: Suffixes the repository gate skips because they are not text. Any other file
#: that is not valid UTF-8 fails the gate rather than being skipped silently.
BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".webp",
        ".pdf",
        ".zip",
        ".gz",
        ".tgz",
        ".whl",
        ".pyc",
        ".woff",
        ".woff2",
        ".ttf",
    }
)

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_EXTRAS = re.compile(r"\s*\[[^\]]*\]")
_DIRECT_REFERENCE = re.compile(
    r"\s*@\s*(?:git\+|hg\+|svn\+|bzr\+|https?://|file:)", re.IGNORECASE
)
_PIP = re.compile(r"pip(?:3(?:\.\d+)?)?")
_WORD = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
_SEPARATORS = re.compile(r"&&|\|\||[;|]")
_RICH_TAG = re.compile(r"^\[[^\]]*\]")
_INSTALL_WORD = re.compile(r"install", re.IGNORECASE)

#: Options of uvx / uv tool run / pipx run whose value is a separate word. The
#: value is skipped when looking for the command word.
_RUN_VALUE_OPTIONS = frozenset(
    {
        "--from",
        "--spec",
        "--with",
        "-w",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--directory",
        "--project",
        "--index",
        "--index-url",
        "-i",
        "--default-index",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--constraints",
        "-c",
        "--overrides",
        "--env-file",
        "--pip-args",
        "--cache-dir",
        "--config-file",
    }
)

#: Options whose value is itself a requirement, on any uv/uvx/pipx/pip line.
_REQUIREMENT_OPTIONS = frozenset({"--with", "-w", "--from", "--spec"})
#: Of those, the ones that name the package a runner runs.
_SOURCE_OPTIONS = frozenset({"--from", "--spec"})

_ASH_REQUIREMENT_SPELLING = re.compile(
    r"(?<![\w/\\.@:-])automated[-_.]security[-_.]helper(?![\w-])"
    r"(?P<extras>\s*\[[^\]\n]*\])?"
    r"(?P<spec>\s*(?:===|==|~=|!=|>=|<=|<|>)\s*[\w.*+!{}-]+)?",
    re.IGNORECASE,
)

_JSON_STRING = r'"(?:[^"\\]|\\.)*"'
_JSON_ARGS = rf"\[(?P<args>(?:\s*{_JSON_STRING}\s*,?)*)\s*\]"
_JSON_COMMAND = rf'"command"\s*:\s*(?P<command>{_JSON_STRING})'
_JSON_ENTRIES = (
    re.compile(rf'{_JSON_COMMAND}\s*,\s*"args"\s*:\s*{_JSON_ARGS}'),
    re.compile(rf'"args"\s*:\s*{_JSON_ARGS}\s*,\s*{_JSON_COMMAND}'),
)


def normalize(name: str) -> str:
    """PEP 503 normalization: the form an index looks a name up by."""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_bare_requirement(word: str, rest: str = "") -> bool:
    """Whether ``word`` asks an index for ASH or ``ash`` by name.

    ``rest`` is the text after the word in the same command, so that the
    unquoted ``name[extra] @ git+URL`` form, which is three words, is read as the
    direct reference it is.
    """
    word = word.strip("\"'`()<>,")
    match = _NAME.match(word)
    if match is None or normalize(match.group(0)) not in BARE_NAMES:
        return False
    tail = word[match.end() :]
    if tail[:1] in ("/", "\\", ":"):
        # A directory (``automated-security-helper/``) or an image ``name:tag``.
        return False
    extras = _EXTRAS.match(tail)
    if extras:
        tail = tail[extras.end() :]
    return _DIRECT_REFERENCE.match(f"{tail} {rest}") is None


def _executable(word: str) -> str:
    word = _RICH_TAG.sub("", word.strip("\"'"))
    return re.split(r"[\\/]", word)[-1].lower().removesuffix(".exe")


def _commands(words: list[str]) -> Iterator[tuple[str, int]]:
    """``(kind, index of the first argument)`` for each installer or runner."""
    exes = [_executable(w) for w in words] + ["", ""]
    for i, exe in enumerate(exes[:-2]):
        nxt, nxt2 = exes[i + 1], exes[i + 2]
        if _PIP.fullmatch(exe) and nxt == "install":
            yield "install", i + 2
        elif exe == "uv" and nxt == "add":
            yield "install", i + 2
        elif exe == "uv" and nxt == "tool" and nxt2 == "install":
            yield "install", i + 3
        elif exe == "uv" and nxt == "tool" and nxt2 == "run":
            yield "run", i + 3
        elif exe == "pipx" and nxt == "install":
            yield "install", i + 2
        elif exe == "pipx" and nxt == "run":
            yield "run", i + 2
        elif exe == "uvx":
            yield "run", i + 1


def _rest(words: list[str], index: int) -> str:
    return " ".join(w.strip("\"'") for w in words[index + 1 :])


def _split_requirements(value: str) -> list[str]:
    """Split ``--with a,b[x,y]`` on the commas outside brackets."""
    parts, depth, current = [], 0, ""
    for char in value:
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return [p for p in parts if p.strip()]


def _bare_option_values(words: list[str]) -> bool:
    for i, raw in enumerate(words):
        word = raw.strip("\"'")
        option, eq, value = word.partition("=")
        if option not in _REQUIREMENT_OPTIONS:
            continue
        if eq:
            values, rest = _split_requirements(value), _rest(words, i)
        elif i + 1 < len(words):
            values = _split_requirements(words[i + 1].strip("\"'"))
            rest = _rest(words, i + 1)
        else:
            continue
        if any(is_bare_requirement(v, rest) for v in values):
            return True
    return False


def _run_command_is_bare(words: list[str], start: int) -> bool:
    i = start
    while i < len(words):
        word = words[i].strip("\"'")
        option, eq, _ = word.partition("=")
        if option in _SOURCE_OPTIONS:
            # The package comes from this option; its value is checked by
            # _bare_option_values, and the command word is only a command.
            return False
        if word.startswith("-"):
            i += 2 if (not eq and option in _RUN_VALUE_OPTIONS) else 1
            continue
        return is_bare_requirement(word, _rest(words, i))
    return False


def command_is_bare_install(segment: str) -> bool:
    """Whether one shell command installs or runs a bare name (rule 1)."""
    words = _WORD.findall(segment)
    exes = {_executable(w) for w in words}
    if not exes & {"uv", "uvx", "pipx"} and not any(_PIP.fullmatch(e) for e in exes):
        return False
    if _bare_option_values(words):
        return True
    for kind, start in _commands(words):
        if kind == "run":
            if _run_command_is_bare(words, start):
                return True
            continue
        for i in range(start, len(words)):
            word = words[i].strip("\"'")
            if not word.startswith("-") and is_bare_requirement(word, _rest(words, i)):
                return True
    return False


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """``(1-based line, text)`` with shell ``\\`` continuations joined."""
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        yield start, pending + line
        pending = ""
    if pending:
        yield start, pending


def _segments(line: str) -> Iterator[str]:
    # A code span ends a command: "run `pip install -e .` then `ash scan`" is
    # two commands, not a pip install of ``then`` and ``ash``.
    for part in line.split("`"):
        for segment in _SEPARATORS.split(part):
            if segment.strip():
                yield segment.strip()


def _requirement_spellings(line: str, *, literal: str | None = None) -> Iterator[str]:
    """Rule 2: ``automated-security-helper[extra]`` or ``...==ver`` with no URL.

    ``literal`` is the whole Python string literal ``line`` came from; when it is
    given, a spelling counts only if that literal contains the word "install".
    """
    if literal is not None and not _INSTALL_WORD.search(literal):
        return
    for match in _ASH_REQUIREMENT_SPELLING.finditer(line):
        if not (match.group("extras") or match.group("spec")):
            continue
        if _DIRECT_REFERENCE.match(line, match.end()):
            continue
        yield match.group(0).strip()


def _json_entries(text: str) -> Iterator[tuple[int, str]]:
    """Rule 3: ``"command": ..., "args": [...]`` rebuilt as one command line."""
    for pattern in _JSON_ENTRIES:
        for match in pattern.finditer(text):
            command = match.group("command")[1:-1]
            args = [a[1:-1] for a in re.findall(_JSON_STRING, match.group("args"))]
            quoted = [f'"{a}"' if re.search(r"\s", a) else a for a in args]
            line = text.count("\n", 0, match.start()) + 1
            yield line, " ".join([command, *quoted])


def find_in_text(text: str, *, python_literal: bool = False) -> list[tuple[int, str]]:
    """Every bare-name install in ``text``, as ``(1-based line, snippet)``.

    ``python_literal`` marks ``text`` as one Python string literal, which may be
    a fragment of a message (see rule 2 in the module docstring).
    """
    found: list[tuple[int, str]] = []
    literal = text if python_literal else None
    for number, line in _logical_lines(text):
        for segment in _segments(line):
            if command_is_bare_install(segment):
                found.append((number, segment))
        found.extend((number, s) for s in _requirement_spellings(line, literal=literal))
    for number, command_line in _json_entries(text):
        if command_is_bare_install(command_line):
            found.append((number, command_line))
    return sorted(set(found))


def find_bare_installs(text: str) -> list[str]:
    """The snippets of :func:`find_in_text`, for asserting on one message."""
    return [snippet for _, snippet in find_in_text(text)]


def _python_strings(source: str, path: Path) -> Iterator[tuple[int, str]]:
    """Every string literal in a Python file, docstrings included.

    Docstrings are included because mkdocstrings renders some of them into the
    docs site. Comments are not: no user reads them, and they are where the
    history of a changed hint belongs. Adjacent literals are one node, so a hint
    split over two source lines is checked whole; an f-string's replacement
    fields read as ``{}``.
    """
    tree = ast.parse(source, filename=str(path))
    inside_fstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            inside_fstrings.update(id(v) for v in ast.walk(node) if v is not node)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and id(node) not in inside_fstrings:
            text = "".join(
                v.value if isinstance(v, ast.Constant) else "{}" for v in node.values
            )
            yield node.lineno, text
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in inside_fstrings
        ):
            yield node.lineno, node.value


def find_in_file(path: Path) -> list[tuple[int, str]]:
    """Bare-name installs in one file, as ``(1-based line, snippet)``.

    Raises ``UnicodeDecodeError`` for a file that is not UTF-8 text and
    ``SyntaxError`` for Python that does not parse, so a file the gate cannot
    read fails it instead of passing it unread.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".py":
        return find_in_text(text)
    found = [(line, snippet) for line, snippet in _json_entries(text)]
    found = [(line, s) for line, s in found if command_is_bare_install(s)]
    for line, value in _python_strings(text, path):
        found.extend(
            (line, snippet) for _, snippet in find_in_text(value, python_literal=True)
        )
    return sorted(set(found))

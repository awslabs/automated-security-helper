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
   ``pipx install``, ``pipx run``, ``pipx inject``, ``uv add``,
   ``uv tool install``, ``uv tool run``, ``uvx``, ``poetry add`` and
   ``pdm add``, plus the value of any ``--with``/``-w``, ``--from`` or
   ``--spec`` option on a uv, uvx, pipx or pip command line. For ``uvx``,
   ``uv tool run`` and ``pipx run`` the first positional word is the package
   unless ``--from``/``--spec`` names one, so ``uvx --with=. ash mcp`` runs the
   ``ash`` package and ``uvx --from=git+... ash mcp`` does not; every option uv
   documents as taking a value (``uv tool run --help``) has its value skipped
   when looking for that word. ``pipx inject <venv> <packages>`` installs its
   packages, not its venv name. A command is found inside code spans, HTML
   ``<code>``/``<pre>`` (entities decoded), ``$(...)``, and a JSON array of
   strings such as a Dockerfile's exec form ``RUN ["pip", "install", ...]``.
2. A requirement spelling of ASH's distribution name anywhere in the text:
   ``automated-security-helper[extra]`` or ``automated-security-helper==1.2``.
   Those only ever mean "resolve this name from an index", with or without an
   installer in front of them; this is what catches a prose hint such as
   ``Install automated-security-helper[symbols]`` or "Add
   automated-security-helper[symbols] to your environment". A Python literal
   that is only such a spelling is reported too, even when a later literal adds
   a direct reference to it: build the requirement in one expression instead.
3. MCP client entries, ``"command": "uvx", "args": [...]`` in any key order and
   with any keys between them, rebuilt into one command line and checked as in
   1. Every ``{...}`` object in the text is parsed with ``json.loads``; one that
   is not JSON (JSONC, a JavaScript object, a Python dict) is read with a
   pattern over its own top-level keys.
4. Outside Python source: a line that is only a requirement on ASH's name (a
   requirements file line, with an optional extra, version, marker, hash or
   comment), a quoted array element that is one (a pyproject ``dependencies``
   entry), and a poetry dependency given as a version string
   (``automated-security-helper = "^3.7"``).

In Python files every string expression is read whole: adjacent literals, an
f-string, ``+`` concatenation, ``%`` and ``str.format`` with constant arguments,
and module-level names assigned once to a string are folded into one text, with
anything not constant read as ``{}``. Every list and tuple with a string in it
is rebuilt into one command line, so an argv list such as
``[sys.executable, "-m", "pip", "install", "automated-security-helper[cdk]"]``
is read as the command it runs. A requirement followed by ``@ {}`` there is a
direct reference whose URL is computed, and is not reported.

A name counts as bare when it is, after PEP 503 normalization (case, ``-``,
``_`` and ``.`` are equivalent), ``automated-security-helper`` or ``ash``, and
no direct reference follows it. ``name[extra] @ git+URL`` (spaced or not, quoted
or not), a ``git+`` URL, a local path and ``name:tag`` are not bare. A pinned
version (``==3.7.0``, uvx's ``ash@3.7.0``) is still bare: it is resolved from the
index like any other name.

What is not reported
--------------------
``pipx upgrade``, which reuses the requirement recorded at install time, and
``uv run``'s command word, which names a script in the current project. The
name alone in a Python literal (``"automated-security-helper"``), which is how
code refers to the distribution without installing it; it is reported once it
becomes a command or a requirement spelling. Prose that follows an install
command on the same line without a code span or a ``;``/``&&``/``|`` between
them is read as more install targets, so "pip install -e . then run ash" is
reported; put the commands in separate code spans. Commands built at runtime
from values that are not module-level constants are invisible here; the
runtime-hint tests check those messages as users see them. ``setup.py``
``install_requires`` lists and MCP client configs in YAML or TOML are not read
as dependency lists.
"""

from __future__ import annotations

import ast
import html
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

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
        ".mcpb",
    }
)

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_EXTRAS = re.compile(r"\s*\[[^\]]*\]")
_DIRECT_REFERENCE = re.compile(
    r"\s*@\s*(?:git\+|hg\+|svn\+|bzr\+|https?://|file:)", re.IGNORECASE
)
#: In a folded Python expression, ``name[extra] @ {}`` is a direct reference
#: whose URL is computed at runtime.
_DIRECT_REFERENCE_IN_PYTHON = re.compile(
    r"\s*@\s*(?:git\+|hg\+|svn\+|bzr\+|https?://|file:|\{\})", re.IGNORECASE
)
_PIP = re.compile(r"pip(?:3(?:\.\d+)?)?")
_WORD = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
_SEPARATORS = re.compile(r"&&|\|\||\$\(|[;|()]")
_RICH_TAG = re.compile(r"^\[[^\]]*\]")
_HTML_TAG = re.compile(r"</?[A-Za-z][^<>]*>")

#: Options of uvx / uv tool run / pipx run whose value is a separate word. The
#: value is skipped when looking for the command word. The uv list is every
#: option ``uv tool run --help`` (uv 0.12) shows with a value; the pipx ones are
#: from ``pipx run --help``.
_RUN_VALUE_OPTIONS = frozenset(
    {
        # uv tool run / uvx
        "--from",
        "-w",
        "--with",
        "--with-editable",
        "--with-requirements",
        "-c",
        "--constraints",
        "-b",
        "--build-constraints",
        "--overrides",
        "--env-file",
        "--python-platform",
        "--torch-backend",
        "--index",
        "--default-index",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--index-strategy",
        "--keyring-provider",
        "-P",
        "--upgrade-package",
        "--upgrade-group",
        "--resolution",
        "--prerelease",
        "--fork-strategy",
        "--exclude-newer",
        "--exclude-newer-package",
        "--no-sources-package",
        "--reinstall-package",
        "--link-mode",
        "-C",
        "--config-setting",
        "--config-settings-package",
        "--no-build-isolation-package",
        "--no-build-package",
        "--no-binary-package",
        "--cache-dir",
        "--refresh-package",
        "-p",
        "--python",
        "--color",
        "--allow-insecure-host",
        "--directory",
        "--project",
        "--config-file",
        # pipx run
        "--spec",
        "--pip-args",
        "--backend",
    }
)

#: Options whose value is itself a requirement, on any uv/uvx/pipx/pip line.
_REQUIREMENT_OPTIONS = frozenset({"--with", "-w", "--from", "--spec"})
#: Of those, the ones that name the package a runner runs.
_SOURCE_OPTIONS = frozenset({"--from", "--spec"})
#: Executables whose presence makes a segment worth parsing as a command.
_INSTALLERS = frozenset({"uv", "uvx", "pipx", "poetry", "pdm"})

_ASH = r"automated[-_.]security[-_.]helper"
_ASH_REQUIREMENT_SPELLING = re.compile(
    rf"(?<![\w/\\.@:-]){_ASH}(?![\w-])"
    r"(?P<extras>\s*\[[^\]\n]*\])?"
    r"(?P<spec>\s*(?:===|==|~=|!=|>=|<=|<|>)\s*[\w.*+!{}-]+)?",
    re.IGNORECASE,
)
_SPECIFIER = r"(?:===|==|~=|!=|>=|<=|<|>)\s*[\w.*+!-]+"
#: A requirement on ASH's name with nothing after it but an optional extra,
#: version specifiers and a marker: what pip resolves from an index. Spelled
#: with hyphens only: ``automated_security_helper`` alone on a line or in an
#: array is the import name, as in a build ``include`` list or a coverage
#: ``source``, and is read as that.
_BARE_REQUIREMENT = (
    r"automated-security-helper(?![\w-])(?:\s*\[[^\]\n]*\])?"
    rf"(?:\s*{_SPECIFIER}(?:\s*,\s*{_SPECIFIER})*)?"
    r"(?:\s*;[^#\n\"']*)?"
)
#: Rule 4: a requirements-file line.
_REQUIREMENT_LINE = re.compile(
    rf"^\s*{_BARE_REQUIREMENT}(?:\s+--hash[=\s]\S+)*\s*(?:#.*)?$", re.IGNORECASE
)
#: Rule 4: a quoted array element, as in a pyproject dependencies list: after a
#: ``[`` or ``,`` in an inline array, or alone at the start of a line with a
#: ``,`` or ``]`` after it in a multi-line one. A quoted name anywhere else is a
#: value of some other kind (a JSON ``"id"``, a default image name, an argument).
_REQUIREMENT_ELEMENTS = (
    re.compile(
        rf"[\[,]\s*([\"'])(?P<requirement>{_BARE_REQUIREMENT})\s*\1", re.IGNORECASE
    ),
    re.compile(
        rf"^\s*([\"'])(?P<requirement>{_BARE_REQUIREMENT})\s*\1\s*[,\]]",
        re.IGNORECASE,
    ),
)
#: Rule 4: a poetry dependency on ASH's name given as a version string. The value
#: has to look like a version constraint, so an entry point
#: (``automated-security-helper = "pkg.module:main"``) is not one.
_POETRY_VERSION_DEPENDENCY = re.compile(
    r"""^\s*["']?automated-security-helper["']?\s*=\s*["'][\^~*<>=!\d]""",
    re.IGNORECASE,
)

_JSON_STRING = r'"(?:[^"\\\n]|\\.)*"'
_STRING_ARRAY = re.compile(rf"\[\s*{_JSON_STRING}(?:\s*,\s*{_JSON_STRING})*\s*,?\s*\]")
_ANY_STRING = rf"{_JSON_STRING}|'[^'\n]*'"
_COMMAND_KEY = re.compile(
    rf"""(?:"command"|'command'|\bcommand)\s*:\s*({_ANY_STRING})"""
)
_ARGS_KEY = re.compile(r"""(?:"args"|'args'|\bargs)\s*:\s*\[([^\]]*)\]""")


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
        elif exe in ("uv", "poetry", "pdm") and nxt == "add":
            yield "install", i + 2
        elif exe == "uv" and nxt == "tool" and nxt2 == "install":
            yield "install", i + 3
        elif exe == "uv" and nxt == "tool" and nxt2 == "run":
            yield "run", i + 3
        elif exe == "pipx" and nxt == "install":
            yield "install", i + 2
        elif exe == "pipx" and nxt == "inject":
            yield "inject", i + 2
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


def _positionals(words: list[str], start: int) -> Iterator[int]:
    """Indexes of the words from ``start`` on that are not options or values."""
    i = start
    while i < len(words):
        word = words[i].strip("\"'")
        option, eq, _ = word.partition("=")
        if word.startswith("-"):
            i += 2 if (not eq and option in _RUN_VALUE_OPTIONS) else 1
            continue
        yield i
        i += 1


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
    if not exes & _INSTALLERS and not any(_PIP.fullmatch(e) for e in exes):
        return False
    if _bare_option_values(words):
        return True
    for kind, start in _commands(words):
        if kind == "run":
            if _run_command_is_bare(words, start):
                return True
            continue
        if kind == "inject":
            # pipx inject <venv> <packages>: the first word names a venv, which
            # may well be ASH's own; the packages are what gets installed.
            targets = list(_positionals(words, start))[1:]
        else:
            targets = [
                i
                for i in range(start, len(words))
                if not words[i].strip("\"'").startswith("-")
            ]
        for i in targets:
            if is_bare_requirement(words[i], _rest(words, i)):
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
    # two commands, not a pip install of ``then`` and ``ash``. An HTML tag ends
    # one the same way.
    for part in _HTML_TAG.sub("`", line).split("`"):
        for segment in _SEPARATORS.split(part):
            if segment.strip():
                yield segment.strip()


def _quoted_line(words: list[str]) -> str:
    return " ".join(f'"{w}"' if re.search(r"\s", w) else w for w in words)


def _string_arrays(line: str) -> Iterator[str]:
    """Each JSON array of strings in ``line``, rebuilt as one command line."""
    for match in _STRING_ARRAY.finditer(line):
        try:
            items = json.loads(re.sub(r",\s*\]$", "]", match.group(0)))
        except ValueError:
            continue
        yield _quoted_line([str(item) for item in items])


def _requirement_spellings(line: str, *, python_literal: bool) -> Iterator[str]:
    """Rule 2: ``automated-security-helper[extra]`` or ``...==ver`` with no URL."""
    direct_reference = (
        _DIRECT_REFERENCE_IN_PYTHON if python_literal else _DIRECT_REFERENCE
    )
    for match in _ASH_REQUIREMENT_SPELLING.finditer(line):
        if not (match.group("extras") or match.group("spec")):
            continue
        if direct_reference.match(line, match.end()):
            continue
        yield match.group(0).strip()


def _requirement_lines(line: str) -> Iterator[str]:
    """Rule 4: requirements lines, dependency array elements, poetry versions."""
    if _REQUIREMENT_LINE.match(line):
        yield line.strip()
    for pattern in _REQUIREMENT_ELEMENTS:
        for match in pattern.finditer(line):
            yield match.group("requirement").strip()
    if _POETRY_VERSION_DEPENDENCY.match(line):
        yield line.strip()


def _objects(text: str) -> Iterator[tuple[int, int]]:
    """``(start, end)`` of every balanced ``{...}`` in ``text``.

    Braces inside double-quoted strings do not count, and a newline ends a
    string, since a JSON string cannot hold one; a stray quote in prose then
    cannot swallow the rest of the file.
    """
    stack: list[int] = []
    in_string = escaped = False
    for i, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char in ('"', "\n"):
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            stack.append(i)
        elif char == "}" and stack:
            yield stack.pop(), i + 1


def _top_level(obj: str) -> str:
    """``obj`` with every nested object blanked out, offsets preserved."""
    out, depth = [], 0
    for char in obj:
        if char == "{":
            depth += 1
        if depth > 1:
            out.append("\n" if char == "\n" else " ")
        else:
            out.append(char)
        if char == "}":
            depth -= 1
    return "".join(out)


def _unquote(value: str) -> str:
    if value.startswith('"'):
        try:
            return json.loads(value)
        except ValueError:
            return value[1:-1]
    return value[1:-1]


def _mcp_entries(text: str) -> Iterator[tuple[int, str]]:
    """Rule 3: ``"command": ..., "args": [...]`` rebuilt as one command line."""
    for start, end in _objects(text):
        obj = text[start:end]
        if "command" not in obj or "args" not in obj:
            continue
        top = _top_level(obj)
        command_key = _COMMAND_KEY.search(top)
        if command_key is None:
            continue
        line = text.count("\n", 0, start + command_key.start()) + 1
        try:
            parsed = json.loads(obj)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            command, args = parsed.get("command"), parsed.get("args")
            if isinstance(command, str) and isinstance(args, list):
                yield line, _quoted_line([command, *(str(a) for a in args)])
            continue
        args_key = _ARGS_KEY.search(top)
        if args_key is None:
            continue
        args = [_unquote(a) for a in re.findall(_ANY_STRING, args_key.group(1))]
        yield line, _quoted_line([_unquote(command_key.group(1)), *args])


def find_in_text(text: str, *, python_literal: bool = False) -> list[tuple[int, str]]:
    """Every bare-name install in ``text``, as ``(1-based line, snippet)``.

    ``python_literal`` marks ``text`` as one folded Python string expression:
    rule 4 does not apply to it, and ``@ {}`` counts as a direct reference.
    """
    found: list[tuple[int, str]] = []
    for number, raw_line in _logical_lines(text):
        line = html.unescape(raw_line)
        for command_line in [*_segments(line), *_string_arrays(line)]:
            if command_is_bare_install(command_line):
                found.append((number, command_line))
        found.extend(
            (number, s)
            for s in _requirement_spellings(line, python_literal=python_literal)
        )
        if not python_literal:
            found.extend((number, s) for s in _requirement_lines(line))
    for number, command_line in _mcp_entries(text):
        if command_is_bare_install(command_line):
            found.append((number, command_line))
    return sorted(set(found))


def find_bare_installs(text: str) -> list[str]:
    """The snippets of :func:`find_in_text`, for asserting on one message."""
    return [snippet for _, snippet in find_in_text(text)]


_FOLD_UNKNOWN = "{}"


def _fold(node: ast.AST, constants: dict[str, str]) -> Optional[str]:
    """The text of a string expression, or None if ``node`` is not one.

    Anything inside the expression that is not a constant reads as ``{}``.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue) and value.format_spec is None:
                parts.append(_fold(value.value, constants) or _FOLD_UNKNOWN)
            else:
                parts.append(_FOLD_UNKNOWN)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left, constants), _fold(node.right, constants)
        if left is None and right is None:
            return None
        return (left or _FOLD_UNKNOWN) + (right or _FOLD_UNKNOWN)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        template = _fold(node.left, constants)
        if template is None:
            return None
        if isinstance(node.right, ast.Tuple):
            values = tuple(
                _fold(e, constants) or _FOLD_UNKNOWN for e in node.right.elts
            )
        else:
            values = (_fold(node.right, constants) or _FOLD_UNKNOWN,)
        try:
            return template % values
        except (TypeError, ValueError):
            return template
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        template = _fold(node.func.value, constants)
        if template is None:
            return None
        args = [_fold(a, constants) or _FOLD_UNKNOWN for a in node.args]
        kwargs = {
            k.arg: _fold(k.value, constants) or _FOLD_UNKNOWN
            for k in node.keywords
            if k.arg is not None
        }
        try:
            return template.format(*args, **kwargs)
        except (IndexError, KeyError, ValueError):
            return template
    return None


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level names assigned exactly once to a string expression."""
    constants: dict[str, str] = {}
    assigned: dict[str, int] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            targets, value = statement.targets, statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            targets, value = [statement.target], statement.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            assigned[target.id] = assigned.get(target.id, 0) + 1
            text = _fold(value, constants)
            if text is not None:
                constants[target.id] = text
    return {name: text for name, text in constants.items() if assigned[name] == 1}


def _python_strings(source: str, path: Path) -> Iterator[tuple[int, str]]:
    """Every string expression in a Python file, folded, docstrings included.

    Docstrings are included because mkdocstrings renders some of them into the
    docs site. Comments are not: no user reads them, and they are where the
    history of a changed hint belongs. Only the outermost string expression is
    read, so ``"name[extra]" + " @ git+..."`` is one direct reference and not a
    bare requirement plus a URL. Lists and tuples are also rebuilt into one
    command line each.
    """
    tree = ast.parse(source, filename=str(path))
    constants = _module_constants(tree)
    composite = (ast.JoinedStr, ast.BinOp, ast.Call)
    inner: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, composite) and _fold(node, constants) is not None:
            inner.update(id(child) for child in ast.walk(node) if child is not node)
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)):
            words = [_fold(e, constants) for e in node.elts]
            if any(w is not None for w in words):
                yield node.lineno, _quoted_line([w or _FOLD_UNKNOWN for w in words])
        if id(node) in inner or isinstance(node, ast.Name):
            continue
        if isinstance(node, (ast.Constant, *composite)):
            text = _fold(node, constants)
            if text is not None:
                yield node.lineno, text


def find_in_file(path: Path) -> list[tuple[int, str]]:
    """Bare-name installs in one file, as ``(1-based line, snippet)``.

    Raises ``UnicodeDecodeError`` for a file that is not UTF-8 text and
    ``SyntaxError`` for Python that does not parse, so a file the gate cannot
    read fails it instead of passing it unread.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix != ".py":
        return find_in_text(text)
    found = [(line, s) for line, s in _mcp_entries(text) if command_is_bare_install(s)]
    for line, value in _python_strings(text, path):
        found.extend(
            (line, snippet) for _, snippet in find_in_text(value, python_literal=True)
        )
    return sorted(set(found))

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every child ASH starts outside utils/subprocess_utils.py says what its stdin is.

ASH's own standard input is whatever started it: a terminal nobody is typing
into, a pipe a CI step holds open, a FIFO, or the MCP client's channel. A child
started without ``stdin=`` inherits it, and a tool that reads stdin then waits
until its timeout, or reads input meant for someone else. utils/subprocess_utils.py
gives its children /dev/null itself; a call that goes around it has to say.

This reads the package's source and finds each call of ``subprocess.run``,
``Popen``, ``call``, ``check_call``, ``check_output``, ``getoutput`` and
``getstatusoutput`` outside that module. The module is followed through
``import subprocess`` and ``from <any module> import subprocess`` (under any
name), and as ``<anything>.subprocess``; a starter through ``from subprocess
import`` it (under any name). A call passes when it gives ``stdin=`` or
``input=`` by keyword, and neither is the constant ``None``, which leaves the
child ASH's stdin. ``getoutput`` and ``getstatusoutput`` take neither, so each
of their calls is found.

Three other ways to reach a starter are found where they are, since the call
they lead to cannot be judged: the module, or a starter, used other than as a
call, an attribute lookup or a type (``getattr(subprocess, "run")``,
``sp = subprocess``, ``functools.partial(subprocess.run)``, a subclass of
``subprocess.Popen``); a starter imported by name that is neither called nor
named as a type in its module (a re-export); and ``from subprocess import *``.
A starter named in an annotation, or as the class isinstance or issubclass is
given, starts nothing and is not found. A call in either place is judged like any
other, and so is anything inside it. As the class isinstance or issubclass is
given, the call runs every time. In an annotation it runs only where Python
evaluates the annotation: a function's at its def and a module-level one at its
line, before Python 3.14. Python never evaluates a local variable's annotation or
any annotation under ``from __future__ import annotations``, and on 3.14 a
function's or a module's only when something reads it. The check judges those
calls too, which is the safe side.

Not judged: a stdin value held in a variable, which may be None (``stdin=NONE``,
or a helper's ``stdin=stdin`` that defaults to it), and the module imported by
``importlib.import_module("subprocess")``.

Each finding must be in ``ALLOWED``, keyed by file and the function it is in,
with the number of findings there and the reason the child may keep ASH's stdin.
The test fails on a finding that is not listed and on a listed entry that no
longer matches, so the list only shrinks.

A call that passes its keywords as ``**kwargs`` is not judged by what the
caller passes; it is listed like any other. Out of scope: the asyncio spawners
(``asyncio.create_subprocess_exec`` and ``create_subprocess_shell``) and the os
ones (``os.system``, ``os.popen``, ``os.spawn*``, ``os.exec*``, ``os.posix_spawn``).
Calls in other modules of a starter that a module of the package re-exports are
not followed: the re-export is found at its import when that module never calls
the starter itself, and not otherwise.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Iterator, Tuple

import pytest

pytestmark = pytest.mark.unit

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

#: The module that gives every child it starts /dev/null itself.
EXEMPT = "utils/subprocess_utils.py"

#: The subprocess functions that start a child. getoutput and getstatusoutput
#: take no stdin, so the child always has ASH's.
STARTERS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    }
)

#: The keywords that say what the child's stdin is.
STDIN_KEYWORDS = frozenset({"stdin", "input"})

#: (file under the package, enclosing function) -> (calls, why stdin is inherited).
ALLOWED: Dict[Tuple[str, str], Tuple[int, str]] = {}


def _subprocess_names(tree: ast.Module) -> Tuple[set, Dict[str, str], bool]:
    """The names subprocess is bound to (``import subprocess``, or ``from <a
    module> import subprocess``), each starter imported by name, and whether
    ``from subprocess import *`` appears."""
    modules = set()
    functions: Dict[str, str] = {}
    star = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    modules.add(alias.asname or "subprocess")
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            for alias in node.names:
                if alias.name == "*":
                    star = True
                elif alias.name in STARTERS:
                    functions[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "subprocess":
                    modules.add(alias.asname or "subprocess")
    return modules, functions, star


def _is_module_attribute(node: ast.AST) -> bool:
    """Whether *node* is ``<something>.subprocess``: the module reached through
    another module that holds it."""
    return isinstance(node, ast.Attribute) and node.attr == "subprocess"


def _is_starter_reference(
    node: ast.AST, modules: set, functions: Dict[str, str]
) -> bool:
    """Whether *node* names a starter: ``<module>.<starter>``, with the module
    a name it is bound to or ``<something>.subprocess``, or a name a starter
    was imported as."""
    if isinstance(node, ast.Attribute) and node.attr in STARTERS:
        value = node.value
        return (
            isinstance(value, ast.Name) and value.id in modules
        ) or _is_module_attribute(value)
    if isinstance(node, ast.Name):
        return node.id in functions
    return False


def _type_positions(nodes: list) -> set:
    """The nodes inside an annotation, or inside the class argument of
    isinstance or issubclass: there a starter is named as a type, and nothing
    is started. Not a call there, or anything inside one: a call in such a
    position is evaluated, so a starter called there runs."""
    roots: list = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
                arguments.vararg,
                arguments.kwarg,
            ):
                if argument is not None and argument.annotation is not None:
                    roots.append(argument.annotation)
            if node.returns is not None:
                roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("isinstance", "issubclass")
            and len(node.args) == 2
        ):
            roots.append(node.args[1])
    positions: set = set()
    pending = list(roots)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Call):
            continue
        positions.add(id(node))
        pending.extend(ast.iter_child_nodes(node))
    return positions


def _gives_stdin(call: ast.Call) -> bool:
    """A ``stdin=`` or ``input=`` keyword that is not the constant None, which
    leaves the child ASH's stdin."""
    return any(
        keyword.arg in STDIN_KEYWORDS
        and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value is None
        )
        for keyword in call.keywords
    )


def _calls_without_stdin(source: str, filename: str) -> Iterator[str]:
    """The enclosing function's qualified name for each finding in *source*;
    "<module>" at the top level. A finding is a starter call that does not say
    what its stdin is, or a starter reached other than by a direct call (the
    module docstring lists the ways)."""
    tree = ast.parse(source, filename=filename)
    modules, functions, star = _subprocess_names(tree)
    nodes = list(ast.walk(tree))
    if not modules and not functions and not star:
        if not any(_is_module_attribute(node) for node in nodes):
            return
    call_funcs = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    looked_up = {id(node.value) for node in nodes if isinstance(node, ast.Attribute)}
    typed = _type_positions(nodes)
    # A starter imported by name is used when it is called or named as a type;
    # one that is neither is there to be imported from this module.
    used = {
        node.func.id
        for node in nodes
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } | {node.id for node in nodes if isinstance(node, ast.Name) and id(node) in typed}

    def finding(child: ast.AST) -> bool:
        if id(child) in typed:
            return False
        if isinstance(child, ast.Call):
            return _is_starter_reference(
                child.func, modules, functions
            ) and not _gives_stdin(child)
        if isinstance(child, ast.ImportFrom) and child.module == "subprocess":
            return any(
                alias.name == "*"
                or (alias.name in STARTERS and (alias.asname or alias.name) not in used)
                for alias in child.names
            )
        if id(child) in call_funcs:
            return False
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            if child.id in modules:
                return id(child) not in looked_up
            return child.id in functions
        if _is_module_attribute(child):
            return id(child) not in looked_up
        return isinstance(child, ast.Attribute) and _is_starter_reference(
            child, modules, functions
        )

    def visit(node: ast.AST, scope: Tuple[str, ...]) -> Iterator[str]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from visit(child, (*scope, child.name))
                continue
            if finding(child):
                yield ".".join(scope) or "<module>"
            yield from visit(child, scope)

    yield from visit(tree, ())


def _found(package: Path) -> Dict[Tuple[str, str], int]:
    found: Dict[Tuple[str, str], int] = {}
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package).as_posix()
        if relative == EXEMPT:
            continue
        source = path.read_text(encoding="utf-8")
        for scope in _calls_without_stdin(source, relative):
            found[(relative, scope)] = found.get((relative, scope), 0) + 1
    return found


def test_each_direct_call_says_what_its_stdin_is_or_is_listed():
    found = _found(PACKAGE)
    allowed = {key: count for key, (count, _reason) in ALLOWED.items()}

    unlisted = {key: n for key, n in found.items() if key not in allowed}
    stale = {key: n for key, n in allowed.items() if found.get(key) != n}

    assert not unlisted, (
        "A child started without stdin= inherits ASH's own stdin. Pass "
        "stdin=subprocess.DEVNULL, or list the call in ALLOWED with the reason "
        f"it may keep it: {sorted(unlisted.items())}"
    )
    assert not stale, (
        "These ALLOWED entries no longer match the calls in their function; "
        f"remove or update them: {sorted((k, found.get(k, 0)) for k in stale)}"
    )


def test_every_listed_call_has_a_reason():
    assert all(reason.strip() for _count, reason in ALLOWED.values())


def test_a_bare_run_is_found_however_subprocess_was_imported():
    """The check itself: each spelling of a call that inherits stdin is found,
    and one that says what its stdin is passes."""
    source = (
        "import subprocess\n"
        "import subprocess as sp\n"
        "from subprocess import check_output as co, Popen\n"
        "def bare():\n"
        "    subprocess.run(['tool'])\n"
        "class Runner:\n"
        "    def go(self):\n"
        "        sp.Popen(['tool'])\n"
        "        co(['tool'])\n"
        "        Popen(['tool'], **{})\n"
        "def told():\n"
        "    subprocess.run(['tool'], stdin=subprocess.DEVNULL)\n"
        "    subprocess.run(['tool'], input=b'')\n"
        "def told_none():\n"
        "    subprocess.run(['tool'], stdin=None)\n"
        "    subprocess.run(['tool'], input=None)\n"
        "subprocess.call(['tool'])\n"
    )

    found = list(_calls_without_stdin(source, "fixture.py"))

    assert sorted(found) == sorted(
        [
            "bare",
            "Runner.go",
            "Runner.go",
            "Runner.go",
            "told_none",
            "told_none",
            "<module>",
        ]
    )


def test_a_starter_reached_other_than_by_a_direct_call_is_found():
    """A starter the check cannot follow to its call is found where it is
    reached: looked up by name, wrapped, re-exported, subclassed, or reached
    through another name for the module. getoutput and getstatusoutput take no
    stdin, so each of their calls is found."""
    source = (
        "import functools\n"
        "import subprocess\n"
        "from subprocess import check_call\n"
        "from subprocess import *\n"
        "def by_name():\n"
        "    getattr(subprocess, 'run')(['tool'], stdin=subprocess.DEVNULL)\n"
        "def wrapped():\n"
        "    functools.partial(subprocess.run, stdin=subprocess.DEVNULL)\n"
        "def aliased():\n"
        "    sp = subprocess\n"
        "class Child(subprocess.Popen):\n"
        "    pass\n"
        "def shell():\n"
        "    subprocess.getoutput('tool')\n"
        "    subprocess.getstatusoutput('tool')\n"
        "def fine():\n"
        "    subprocess.run(['tool'], stdin=subprocess.DEVNULL)\n"
        "    raise subprocess.CalledProcessError(1, 'tool')\n"
    )

    found = list(_calls_without_stdin(source, "fixture.py"))

    assert sorted(found) == sorted(
        [
            "<module>",  # check_call, imported and never called: a re-export
            "<module>",  # from subprocess import *
            "by_name",
            "wrapped",
            "aliased",
            "Child",
            "shell",
            "shell",
        ]
    )


def test_the_module_reached_through_another_module_is_followed():
    """``from <a module> import subprocess`` binds the module as ``import
    subprocess`` does, and ``<module>.subprocess.run`` reaches the starter
    through another module's attribute: each is judged as a direct call."""
    source = (
        "import wrapper\n"
        "from automated_security_helper.utils import subprocess_utils\n"
        "from automated_security_helper.x import subprocess\n"
        "def through_an_import():\n"
        "    subprocess.run(['tool'])\n"
        "def through_an_attribute():\n"
        "    wrapper.subprocess.Popen(['tool'])\n"
        "def held():\n"
        "    sp = wrapper.subprocess\n"
        "def told():\n"
        "    subprocess.run(['tool'], stdin=subprocess.DEVNULL)\n"
        "    wrapper.subprocess.run(['tool'], stdin=wrapper.subprocess.DEVNULL)\n"
        "    subprocess_utils.run_command(['tool'])\n"
    )

    found = list(_calls_without_stdin(source, "fixture.py"))

    assert sorted(found) == sorted(
        ["through_an_import", "through_an_attribute", "held"]
    )


def test_a_starter_named_only_as_a_type_is_not_found():
    """An annotation, or the class isinstance or issubclass is given, names
    Popen and starts nothing; a starter imported only for one is no
    re-export."""
    source = (
        "import subprocess\n"
        "from subprocess import Popen\n"
        "from typing import Optional\n"
        "def typed(\n"
        "    p: subprocess.Popen, *rest: Popen, q: Optional[Popen] = None\n"
        ") -> subprocess.Popen:\n"
        "    held: subprocess.Popen = p\n"
        "    assert isinstance(held, subprocess.Popen)\n"
        "    assert issubclass(type(held), (Popen, object))\n"
        "    return held\n"
    )

    assert list(_calls_without_stdin(source, "fixture.py")) == []


def test_a_call_in_a_type_position_runs_and_is_found():
    """A call there can run: as the class isinstance is given, every time, and in
    a function's or a module-level annotation where Python evaluates it (see the
    module docstring). So a starter called there, by its module or by the name it
    was imported as, is found, and so is a starter named inside such a call."""
    source = (
        "import subprocess\n"
        "from subprocess import run\n"
        "def annotated(x: subprocess.run(['tool'])):\n"
        "    pass\n"
        "held: subprocess.run(['tool']) = None\n"
        "def checked(x):\n"
        "    return isinstance(x, subprocess.run(['tool']))\n"
        "def by_name(x: run(['tool'])):\n"
        "    pass\n"
        "def wrapped(x):\n"
        "    return isinstance(x, wrap(subprocess.Popen))\n"
    )

    found = list(_calls_without_stdin(source, "fixture.py"))

    assert sorted(found) == sorted(
        ["annotated", "<module>", "checked", "by_name", "wrapped"]
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A parameter value in an MCP test is the same in every process that collects it.

Why this file exists
--------------------
pytest puts a parameter's text into the test id. With pytest-xdist every worker
collects the tests on its own, and the controller stops the whole run ("Different
tests were collected between gw0 and gw1") when two workers disagree about an id.
A value built while the module is imported with ``uuid.uuid4()``, the clock or a
random source gives each worker a different id. The same ids also key ``--lf`` and
``--deselect``, which then never find the test again.

What is checked
---------------
Every ``test_*.py`` file in this directory is parsed (nothing is imported or run).
A ``parametrize`` decorator that calls a per-process source directly, or names a
module-level constant built from one, is reported with its line. A value that is
generated inside the test body is fine: only the decorator is read at collection.
So is a value whose test id is written out: ``ids=[...]`` on the decorator, or
``id=`` on a ``pytest.param``, keeps the id the same whatever the value is.

The rule is for this directory, where the session-id and workspace-name tests
build many id-shaped values. A constant built in one statement and unpacked
elsewhere is outside what a syntax-tree read can follow; give such a value a fixed
literal or pass ``ids=[...]``.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Iterator, List

import pytest

pytestmark = pytest.mark.unit

#: Calls whose answer differs from one process to the next.
_PER_PROCESS_CALLS = frozenset(
    {
        "uuid.uuid1",
        "uuid.uuid4",
        "uuid1",
        "uuid4",
        "time.time",
        "time.time_ns",
        "time.monotonic",
        "time.perf_counter",
        "os.getpid",
        "os.urandom",
        "random.random",
        "random.randint",
        "random.choice",
        "random.getrandbits",
        "secrets.token_hex",
        "secrets.token_urlsafe",
        "secrets.token_bytes",
        "tempfile.mkdtemp",
        "tempfile.mkstemp",
    }
)

_TESTS_DIRECTORY = Path(__file__).parent


def _dotted(node: ast.expr) -> str:
    """``a.b.c`` for a name or an attribute chain, else an empty string."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _per_process_call_in(node: ast.AST) -> str:
    """The first per-process call inside ``node``, or an empty string."""
    for inner in ast.walk(node):
        if isinstance(inner, ast.Call) and _dotted(inner.func) in _PER_PROCESS_CALLS:
            return _dotted(inner.func)
    return ""


def _reaching_the_id(node: ast.AST) -> Iterator[ast.AST]:
    """``ast.walk`` that reads only the ``id=`` of a ``pytest.param`` that has one."""
    if (
        isinstance(node, ast.Call)
        and _dotted(node.func).split(".")[-1] == "param"
        and any(keyword.arg == "id" for keyword in node.keywords)
    ):
        for keyword in node.keywords:
            if keyword.arg == "id":
                yield from _reaching_the_id(keyword.value)
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _reaching_the_id(child)


def _expressions_reaching_the_id(decorator: ast.Call) -> List[ast.AST]:
    """The parts of a ``parametrize`` decorator that decide the test ids.

    Written-out ``ids`` (a list or tuple) decide them alone; with a callable or no
    ``ids``, the values do.
    """
    ids = next((k.value for k in decorator.keywords if k.arg == "ids"), None)
    if isinstance(ids, (ast.List, ast.Tuple)):
        return [ids]
    return [*decorator.args[1:], *(k.value for k in decorator.keywords)]


def per_process_values_in_parametrize(source: str) -> List[str]:
    """What a ``parametrize`` decorator in ``source`` evaluates that differs per process.

    One entry per finding, ``"line N: <what>"``. A module-level assignment built
    from a per-process call taints its name, and a decorator that names it is
    reported too.
    """
    tree = ast.parse(source)
    tainted: Dict[str, int] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            names = [t.id for t in statement.targets if isinstance(t, ast.Name)]
        elif isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            names = [statement.target.id]
        else:
            continue
        if statement.value is not None and _per_process_call_in(statement.value):
            for name in names:
                tainted[name] = statement.lineno

    found: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not _dotted(decorator.func).endswith("parametrize"):
                continue
            for expression in _expressions_reaching_the_id(decorator):
                for inner in _reaching_the_id(expression):
                    if (
                        isinstance(inner, ast.Call)
                        and _dotted(inner.func) in _PER_PROCESS_CALLS
                    ):
                        found.append(f"line {inner.lineno}: {_dotted(inner.func)}()")
                    elif isinstance(inner, ast.Name) and inner.id in tainted:
                        found.append(
                            f"line {inner.lineno}: {inner.id}, built from a "
                            f"per-process call at line {tainted[inner.id]}"
                        )
    return found


def test_no_test_here_builds_a_parameter_value_that_differs_per_process() -> None:
    files = sorted(_TESTS_DIRECTORY.glob("test_*.py"))
    assert len(files) > 50, f"the scan found only {len(files)} test files"

    offenders = {
        path.name: found
        for path in files
        if (
            found := per_process_values_in_parametrize(path.read_text(encoding="utf-8"))
        )
    }

    assert offenders == {}, offenders


_FLAGGED = {
    "a-uuid4-call": (
        "import uuid\n"
        "import pytest\n"
        "\n"
        '@pytest.mark.parametrize("name", ["a", f"b-{uuid.uuid4()}"])\n'
        "def test_x(name): ...\n"
    ),
    "a-bare-uuid4-import": (
        "from uuid import uuid4\n"
        "import pytest\n"
        "\n"
        '@pytest.mark.parametrize("name", [str(uuid4())])\n'
        "def test_x(name): ...\n"
    ),
    "the-clock": (
        "import time\n"
        "import pytest\n"
        "\n"
        '@pytest.mark.parametrize("stamp", [time.time()])\n'
        "def test_x(stamp): ...\n"
    ),
    "ids-is-a-callable": (
        "import uuid\n"
        "import pytest\n"
        "\n"
        '@pytest.mark.parametrize("name", [str(uuid.uuid4())], ids=str)\n'
        "def test_x(name): ...\n"
    ),
    "a-constant-built-from-uuid4": (
        "import uuid\n"
        "import pytest\n"
        "\n"
        'NAMES = [f"b-{uuid.uuid4()}"]\n'
        "\n"
        '@pytest.mark.parametrize("name", NAMES)\n'
        "def test_x(name): ...\n"
    ),
}


@pytest.mark.parametrize("source", list(_FLAGGED.values()), ids=list(_FLAGGED))
def test_the_scan_reports_a_value_that_differs_per_process(source: str) -> None:
    """Must-flag inputs: each spelling of a per-process value is reported once."""
    assert len(per_process_values_in_parametrize(source)) == 1, source


def test_the_scan_leaves_a_fixed_value_and_a_value_built_in_the_test_body() -> None:
    """Must-not-flag input: literals, a constant built from literals, a uuid made
    inside the test body (read at run time, not at collection), and a value whose
    test id is written out with ``ids=[...]`` or ``pytest.param(id=...)``."""
    source = (
        "import uuid\n"
        "import pytest\n"
        "\n"
        '@pytest.mark.parametrize("name", [f"b-{uuid.uuid4()}"], ids=["written-out"])\n'
        "def test_y(name): ...\n"
        "\n"
        "@pytest.mark.parametrize(\n"
        '    "name", [pytest.param(str(uuid.uuid4()), id="written-out")]\n'
        ")\n"
        "def test_z(name): ...\n"
    )
    assert per_process_values_in_parametrize(source) == []

    source = (
        "import uuid\n"
        "import pytest\n"
        "\n"
        'FIXED = "b-0f8fad5b-d9cb-469f-a165-70867728950e"\n'
        'SPREAD = [FIXED, "c"]\n'
        "\n"
        '@pytest.mark.parametrize("name", ["a", FIXED, *SPREAD])\n'
        "def test_x(name):\n"
        "    other = uuid.uuid4()\n"
        "    assert other\n"
        "\n"
        '@pytest.fixture(params=["p"])\n'
        "def a_fixture(request):\n"
        "    return uuid.uuid4()\n"
    )

    assert per_process_values_in_parametrize(source) == []

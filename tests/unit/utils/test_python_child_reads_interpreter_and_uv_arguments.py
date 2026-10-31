# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""python_child reads interpreter options as the interpreter does.

Properties of ``utils/python_child.py`` that nothing else pins:

- ``runs_module_or_code`` sees ``-m`` and ``-c`` attached to their value
  (``-mpip``), combined with other short options (``-Bc``), and behind an
  option that takes the next argument (``--check-hash-based-pycs always``);
- ``python_module_arguments`` reads the module and its arguments out of the same
  spellings, and nothing out of ``-c``, a script, ``-`` or ``--``;
- ``python_code_argv`` builds a program that compiles around a source that opens
  with a docstring, a compound statement or a ``from __future__`` import (one
  line or several), and the dropping statement is the first thing the program
  runs: no statement of the caller's source is at its top level.

The tests of ``uv_child_overrides`` are in
``test_uv_overrides_read_uvs_own_arguments.py``.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.python_child import (
    python_code_argv,
    python_module_arguments,
    runs_module_or_code,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "argv",
    [
        [sys.executable, "-mpip", "install", "x"],
        [sys.executable, "-Bc", "pass"],
        [sys.executable, "--check-hash-based-pycs", "always", "-m", "x"],
        [sys.executable, "-Xdev", "-m", "x"],
        [sys.executable, "-W", "ignore", "-m", "x"],
        [sys.executable, "-P", "-m", "uv", "pip", "list"],
    ],
    ids=[
        "attached -m",
        "combined -c",
        "hash-based-pycs value",
        "-X attached",
        "-W",
        "-P -m",
    ],
)
def test_runs_module_or_code_reads_every_spelling_of_the_option(argv):
    assert runs_module_or_code(argv) is True


@pytest.mark.parametrize(
    "argv",
    [
        [sys.executable, "script.py", "-m"],
        [sys.executable, "-W", "ignore", "script.py", "-c", "x"],
        [sys.executable, "-B", "script.py"],
        [sys.executable, "-", "-m"],
        ["/elsewhere/python", "-m", "pip"],
    ],
    ids=[
        "script then -m",
        "-W value then script",
        "-B script",
        "stdin",
        "other python",
    ],
)
def test_runs_module_or_code_stops_at_the_script(argv):
    assert runs_module_or_code(argv) is False


def test_a_path_in_argv_is_a_script_and_never_an_error():
    """Plugins put Paths in argv and subprocess accepts them: a scanner's command
    `[python, Path("worker.py"), ...]` is a script, read as text. It used to raise
    AttributeError out of the spawn, so the command never ran."""
    assert runs_module_or_code([sys.executable, Path("worker.py"), "-m"]) is False
    assert runs_module_or_code([sys.executable, b"-m", b"uv"]) is True
    assert python_module_arguments([Path("worker.py")]) is None
    assert python_module_arguments([3]) is None  # subprocess refuses it too


@pytest.mark.parametrize(
    "options, expected",
    [
        (["-m", "uv", "run", "x"], ("uv", ["run", "x"])),
        (["-muv", "run", "x"], ("uv", ["run", "x"])),
        (["-Im", "uv", "pip", "list"], ("uv", ["pip", "list"])),
        (["-m", "uv.__main__"], ("uv.__main__", [])),
        (["-W", "ignore", "-Bm", "pip", "install", "x"], ("pip", ["install", "x"])),
        (["--check-hash-based-pycs", "always", "-m", "uv"], ("uv", [])),
        (["-Xutf8", "-m", "uv"], ("uv", [])),
        (["-c", "import uv"], None),
        (["-Bc", "pass", "-m", "uv"], None),
        (["script.py", "-m", "uv"], None),
        (["-", "-m", "uv"], None),
        (["--", "-m", "uv"], None),
        (["-m"], None),
        ([], None),
    ],
    ids=[
        "-m uv",
        "-muv",
        "-Im cluster",
        "uv.__main__",
        "-W value then -Bm",
        "long option value",
        "-X attached",
        "-c",
        "-Bc then -m",
        "script",
        "stdin",
        "end of options",
        "-m alone",
        "nothing",
    ],
)
def test_python_module_arguments_reads_the_module_as_the_interpreter_does(
    options, expected
):
    assert python_module_arguments(options) == expected


@pytest.mark.parametrize(
    "source",
    [
        "if True:\n    x = 1\n",
        "for i in range(2):\n    pass\n",
        "from __future__ import annotations\nx: int = 1\n",
        "# a comment first\n\nfrom __future__ import annotations\ndef f():\n    pass\n",
        "import os; print(os.getcwd())",
        "from __future__ import annotations; import os; print(os.getcwd())",
        '"""A module docstring."""\nfrom __future__ import annotations\nx: int = 1\n',
        "from __future__ import (\n    annotations,\n    division,\n)\nx = 1\n",
    ],
    ids=[
        "if",
        "for",
        "future import",
        "comment then future",
        "one line",
        "future on the one line",
        "docstring then future",
        "parenthesized future import",
    ],
)
def test_python_code_argv_builds_a_source_that_compiles(source):
    argv = python_code_argv(source)
    assert argv[-2] == "-c"
    compile(argv[-1], "<python_code_argv>", "exec")
    # The caller's own source compiles as the unit it is run as: a future
    # import is legal there whatever precedes it (a docstring, a comment) and
    # however many lines it takes.
    compile(source, "<ash>", "exec")
    # The dropping statement is the first statement, always, and the caller's
    # source follows it whole, as its own compiled unit: the program's top level
    # is the drop's two statements and the one call that runs the source, so no
    # statement of the caller's source can run ahead of the drop.
    assert "sys.path[:1] = []" in argv[-1]
    statements = ast.parse(argv[-1]).body
    assert [type(node) for node in statements] == [ast.Import, ast.Assign, ast.Expr]
    assert source.strip().splitlines()[-1] in argv[-1]


def test_the_drop_runs_before_a_one_line_source_with_a_leading_future_import():
    """Nothing of the caller's source runs ahead of the working-directory drop.

    The earlier shape moved every leading ``from __future__ import`` LINE ahead of
    the drop, whole. The one caller writes its source as a single ``;``-joined
    line, so a future import at its head would have carried the rest of the line,
    the package import among it, in front of the drop: the import this helper
    exists to keep out of the working directory ran with that directory first on
    ``sys.path``. Now the source is one compiled unit behind the drop, and the
    future import is the first statement of that unit, where it is legal.
    """
    source = "from __future__ import annotations; import os; print(os.getcwd())"
    program = python_code_argv(source)[-1]
    statements = ast.parse(program).body
    # The drop's two statements come first; no statement of the source is at the
    # program's top level, future import included.
    assert isinstance(statements[0], ast.Import)
    assert statements[0].names[0].name == "sys"
    assert isinstance(statements[1], ast.Assign)
    assert not any(isinstance(node, ast.ImportFrom) for node in statements)
    # The source runs behind the drop as one unit, and it compiles there with its
    # future import first.
    run = statements[-1]
    assert isinstance(run, ast.Expr) and isinstance(run.value, ast.Call)
    assert run.value.func.id == "exec"
    compiled = run.value.args[0]
    assert isinstance(compiled, ast.Call) and compiled.func.id == "compile"
    assert compiled.args[0].value == source
    compile(source, "<ash>", "exec")

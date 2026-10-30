# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""python_child reads interpreter options and uv's arguments as the tools do.

Properties of ``utils/python_child.py`` that nothing else pins:

- ``runs_module_or_code`` sees ``-m`` and ``-c`` attached to their value
  (``-mpip``), combined with other short options (``-Bc``), and behind an
  option that takes the next argument (``--check-hash-based-pycs always``);
- ``python_module_arguments`` reads the module and its arguments out of the same
  spellings, and nothing out of ``-c``, a script, ``-`` or ``--``;
- ``python_code_argv`` builds a source that compiles when it opens with a
  compound statement or a ``from __future__`` import, and the dropping
  statement runs before anything of the caller's source, a one-line source
  with a leading future import included;
- ``uv_child_overrides`` takes a path-like program, reads the subcommand past
  the value of a global option it does not know, counts a ``UV_SYSTEM_PYTHON``
  uv reads as false as no choice, and decides from the environment the child
  gets when the caller passes it.
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
    uv_child_overrides,
)

pytestmark = pytest.mark.unit

BOTH = {"UV_NO_PROJECT": "1", "UV_PYTHON": sys.executable}


@pytest.fixture(autouse=True)
def _no_operator_choice(monkeypatch):
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)


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
    assert uv_child_overrides([sys.executable, Path("worker.py"), "x"]) == {}
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
    ],
    ids=[
        "if",
        "for",
        "future import",
        "comment then future",
        "one line",
        "future on the one line",
    ],
)
def test_python_code_argv_builds_a_source_that_compiles(source):
    argv = python_code_argv(source)
    assert argv[-2] == "-c"
    compile(argv[-1], "<python_code_argv>", "exec")
    # The dropping statement is the first statement, always, and the caller's
    # source follows it whole, as its own compiled unit.
    assert "sys.path[:1] = []" in argv[-1]
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


def test_uv_overrides_take_a_path_like_program():
    assert uv_child_overrides([Path("/opt/bin/uv"), "pip", "list"]) == BOTH


def test_the_value_of_an_unknown_global_option_is_not_the_subcommand():
    # "value" is not a uv subcommand; the subcommand is the next positional
    # that names one, and uv tool commands get nothing.
    assert uv_child_overrides(["uv", "--new-option", "value", "tool", "run", "x"]) == {}
    assert uv_child_overrides(["uv", "--new-option", "value", "pip", "list"]) == BOTH


@pytest.mark.parametrize(
    "value", ["0", "false", "f", "F", "no", "n", "N", "off", "OFF", "False", ""]
)
def test_a_false_uv_system_python_is_no_choice_of_interpreter(monkeypatch, value):
    """Every spelling uv's boolish parser reads as false, ``n`` and ``f``
    included: counted as a choice, they left UV_PYTHON out while uv read them as
    false and ran the tree's ``.venv``."""
    monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
    assert uv_child_overrides(["uv", "pip", "list"]) == BOTH


@pytest.mark.parametrize("value", ["1", "true", "t", "yes", "y", "on", "TRUE", " 1 "])
def test_a_true_uv_system_python_is_a_choice_of_interpreter(monkeypatch, value):
    monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
    assert uv_child_overrides(["uv", "pip", "list"]) == {"UV_NO_PROJECT": "1"}


def test_the_choice_is_read_from_the_environment_the_child_gets(monkeypatch):
    # The child's own environment names an interpreter: the merge of the
    # overrides over it must not replace it.
    assert uv_child_overrides(["uv", "pip", "list"], env={"UV_PYTHON": "/x/py"}) == {
        "UV_NO_PROJECT": "1"
    }
    # And this process's environment does not count when the child's is given.
    monkeypatch.setenv("UV_PYTHON", "/elsewhere/py")
    assert uv_child_overrides(["uv", "pip", "list"], env={}) == BOTH

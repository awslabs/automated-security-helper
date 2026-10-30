# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""python_child reads interpreter options and uv's arguments as the tools do.

Properties of ``utils/python_child.py`` that nothing else pins:

- ``runs_module_or_code`` sees ``-m`` and ``-c`` attached to their value
  (``-mpip``), combined with other short options (``-Bc``), and behind an
  option that takes the next argument (``--check-hash-based-pycs always``);
- ``python_code_argv`` builds a source that compiles when it opens with a
  compound statement or a ``from __future__`` import;
- ``uv_child_overrides`` takes a path-like program, reads the subcommand past
  the value of a global option it does not know, counts a ``UV_SYSTEM_PYTHON``
  uv reads as false as no choice, and decides from the environment the child
  gets when the caller passes it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.python_child import (
    python_code_argv,
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


@pytest.mark.parametrize(
    "source",
    [
        "if True:\n    x = 1\n",
        "for i in range(2):\n    pass\n",
        "from __future__ import annotations\nx: int = 1\n",
        "# a comment first\n\nfrom __future__ import annotations\ndef f():\n    pass\n",
        "import os; print(os.getcwd())",
    ],
    ids=["if", "for", "future import", "comment then future", "one line"],
)
def test_python_code_argv_builds_a_source_that_compiles(source):
    argv = python_code_argv(source)
    assert argv[-2] == "-c"
    compile(argv[-1], "<python_code_argv>", "exec")
    # The dropping statement is still the first real statement after any
    # future import, and the caller's source follows it whole.
    assert "sys.path[:1] = []" in argv[-1]
    assert source.strip().splitlines()[-1] in argv[-1]


def test_uv_overrides_take_a_path_like_program():
    assert uv_child_overrides([Path("/opt/bin/uv"), "pip", "list"]) == BOTH


def test_the_value_of_an_unknown_global_option_is_not_the_subcommand():
    # "value" is not a uv subcommand; the subcommand is the next positional
    # that names one, and uv tool commands get nothing.
    assert uv_child_overrides(["uv", "--new-option", "value", "tool", "run", "x"]) == {}
    assert uv_child_overrides(["uv", "--new-option", "value", "pip", "list"]) == BOTH


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_a_false_uv_system_python_is_no_choice_of_interpreter(monkeypatch, value):
    monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
    assert uv_child_overrides(["uv", "pip", "list"]) == BOTH


def test_a_true_uv_system_python_is_a_choice_of_interpreter(monkeypatch):
    monkeypatch.setenv("UV_SYSTEM_PYTHON", "1")
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

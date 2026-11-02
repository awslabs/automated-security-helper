# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""uv_child_overrides knows uv by every name it runs under, and reads only uv's
own arguments.

Properties of utils/python_child.py's uv_child_overrides that nothing else
pinned:

- the program is uv when argv names the binary by any of its spellings (uv,
  uv.exe, and Windows' uv.cmd and uv.bat shims) or when ASH's own interpreter runs
  the uv module in any spelling the interpreter reads (``-m uv``, ``-muv``,
  ``-Im uv``, ``-m uv.__main__``). Only ``uv`` and ``uv.exe``, and a separate
  ``-m`` then ``uv``, counted, so the other forms got no UV_NO_PROJECT and no
  UV_PYTHON, and read the scanned tree's project and ``.venv``;
- a subcommand the module's list lacks is read from the first positional
  argument and gets the overrides; only ``tool``, by name, gets none;
- for ``uv run`` the scan for ``--project``, ``--python``, ``-p`` and ``--system``
  stops where the program uv runs begins (the first positional argument, or
  ``--``). That program's own ``-p`` or ``--system`` says nothing about uv's
  interpreter, yet suppressed UV_PYTHON or UV_NO_PROJECT;
- the subcommand is the first positional that names a listed one, whatever
  unlisted option or word comes before it;
- a path-like program or argument is read as text, and bytes too;
- the operator's choice of interpreter is read from the environment the child
  gets: ``UV_PYTHON`` for every subcommand, and a ``UV_SYSTEM_PYTHON`` uv reads as
  true only for the ``uv pip`` family, the one that has ``--system``.

Nothing here starts uv: the function reads argv and the environment only. These
are the only tests of ``uv_child_overrides``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.python_child import uv_child_overrides

pytestmark = pytest.mark.unit

#: What a uv command that names neither a project nor an interpreter gets.
BOTH = {"UV_NO_PROJECT": "1", "UV_PYTHON": sys.executable}


@pytest.fixture
def no_operator_choice(monkeypatch):
    monkeypatch.delenv("UV_PYTHON", raising=False)
    monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)


@pytest.mark.parametrize(
    "program",
    [
        "uv",
        "uv.exe",
        "uv.cmd",
        "uv.bat",
        "UV.CMD",
        r"C:\tools\uv.bat",
        "/opt/uv/bin/uv",
    ],
)
def test_every_spelling_of_the_uv_launcher_is_uv(no_operator_choice, program):
    assert uv_child_overrides([program, "pip", "install", "bandit"]) == BOTH


def test_the_uv_module_run_by_ashs_interpreter_is_uv(no_operator_choice):
    assert (
        uv_child_overrides([sys.executable, "-m", "uv", "pip", "install", "x"]) == BOTH
    )
    assert (
        uv_child_overrides([sys.executable, "-P", "-m", "uv", "run", "bandit"]) == BOTH
    )


@pytest.mark.parametrize(
    "argv",
    [
        [sys.executable, "-muv", "run", "x"],
        [sys.executable, "-Im", "uv", "pip", "install", "x"],
        [sys.executable, "-m", "uv.__main__", "pip", "install", "x"],
        [sys.executable, "-W", "ignore", "-Bm", "uv", "sync"],
    ],
    ids=["-muv attached", "-Im cluster", "uv.__main__", "-W value then -Bm"],
)
def test_every_spelling_of_the_uv_module_is_uv(no_operator_choice, argv):
    """The module is read as the interpreter reads its options: attached to
    ``-m``, in a cluster, or as ``uv.__main__``. These spellings got no overrides,
    so the uv they ran found the scanned tree's project and ``.venv``."""
    assert uv_child_overrides(argv) == BOTH


def test_a_subcommand_the_list_lacks_still_gets_the_overrides(no_operator_choice):
    """A uv subcommand this module does not list (one uv gained, or an alias) is
    read from the first positional argument: a gap in the list adds the
    overrides, never drops them. Only ``tool`` is left out, and only by name."""
    assert uv_child_overrides(["uv", "virtualenv", ".venv"]) == BOTH
    assert uv_child_overrides(["uv", "--new-option", "value", "newcmd", "x"]) == BOTH
    assert uv_child_overrides(["uv", "--new-option", "value", "tool", "run", "x"]) == {}


def test_the_subcommand_is_the_first_positional_that_names_one(no_operator_choice):
    """One rule, pinned by its deciding cases. The value of a global option this
    module does not list is not the subcommand: the next positional that names a
    listed one is. A boolean flag it does not list takes no value, so the word
    after it is already the subcommand. And an unlisted word before ``tool``
    gives way to ``tool``, so the command gets nothing."""
    assert uv_child_overrides(["uv", "--new-option", "value", "pip", "list"]) == BOTH
    assert uv_child_overrides(["uv", "--new-flag", "pip", "list"]) == BOTH
    assert uv_child_overrides(["uv", "newcmd", "tool", "run", "x"]) == {}


def test_a_path_like_program_is_uv(no_operator_choice):
    assert uv_child_overrides([Path("/opt/bin/uv"), "pip", "list"]) == BOTH
    # A path-like argument of a program that is not uv is no error either.
    assert uv_child_overrides([sys.executable, Path("worker.py"), "x"]) == {}


@pytest.mark.parametrize(
    "value", ["0", "false", "f", "F", "no", "n", "N", "off", "OFF", "False", ""]
)
def test_a_false_uv_system_python_is_no_choice_of_interpreter(
    no_operator_choice, monkeypatch, value
):
    """Every spelling uv's boolish parser reads as false, ``n`` and ``f``
    included: counted as a choice, they left UV_PYTHON out while uv read them as
    false and ran the tree's ``.venv``."""
    monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
    assert uv_child_overrides(["uv", "pip", "list"]) == BOTH


@pytest.mark.parametrize("value", ["1", "true", "t", "yes", "y", "on", "TRUE", " 1 "])
def test_a_true_uv_system_python_is_a_choice_of_interpreter(
    no_operator_choice, monkeypatch, value
):
    monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
    assert uv_child_overrides(["uv", "pip", "list"]) == {"UV_NO_PROJECT": "1"}


def test_the_choice_is_read_from_the_environment_the_child_gets(
    no_operator_choice, monkeypatch
):
    # The child's own environment names an interpreter: the merge of the
    # overrides over it must not replace it.
    assert uv_child_overrides(["uv", "pip", "list"], env={"UV_PYTHON": "/x/py"}) == {
        "UV_NO_PROJECT": "1"
    }
    # And this process's environment does not count when the child's is given.
    monkeypatch.setenv("UV_PYTHON", "/elsewhere/py")
    assert uv_child_overrides(["uv", "pip", "list"], env={}) == BOTH


def test_other_interpreters_modules_and_programs_are_not_uv(no_operator_choice):
    assert (
        uv_child_overrides(["/elsewhere/python", "-m", "uv", "pip", "install", "x"])
        == {}
    )
    assert uv_child_overrides([sys.executable, "-m", "pip", "install", "uv"]) == {}
    assert uv_child_overrides([sys.executable, "-c", "import uv"]) == {}
    assert uv_child_overrides(["uvx", "bandit"]) == {}
    assert uv_child_overrides(["uv", "tool", "run", "bandit"]) == {}


@pytest.mark.parametrize(
    "argv",
    [
        ["uv", "run", "bandit", "-p", "3.12"],
        ["uv", "run", "bandit", "--python", "3.12"],
        ["uv", "run", "bandit", "--python=3.12"],
        ["uv", "run", "bandit", "--system"],
        ["uv", "run", "--", "-p", "3.12"],
        ["uv", "run", "--with", "requests", "bandit", "-p", "3.12"],
    ],
)
def test_the_run_programs_interpreter_option_is_not_uvs(no_operator_choice, argv):
    assert uv_child_overrides(argv)["UV_PYTHON"] == sys.executable


def test_the_run_programs_project_option_is_not_uvs(no_operator_choice):
    assert (
        uv_child_overrides(["uv", "run", "tool", "--project", "x"])["UV_NO_PROJECT"]
        == "1"
    )
    assert (
        uv_child_overrides(["uv", "run", "tool", "--project=x"])["UV_NO_PROJECT"] == "1"
    )


def test_uvs_own_run_options_still_count(no_operator_choice):
    assert "UV_PYTHON" not in uv_child_overrides(["uv", "run", "-p", "3.12", "bandit"])
    assert "UV_PYTHON" not in uv_child_overrides(
        ["uv", "run", "--python=3.12", "bandit"]
    )
    assert "UV_PYTHON" not in uv_child_overrides(
        ["uv", "run", "--system", "bandit", "-p", "x"]
    )
    assert "UV_NO_PROJECT" not in uv_child_overrides(
        ["uv", "run", "--project", "here", "x"]
    )
    assert "UV_NO_PROJECT" not in uv_child_overrides(
        ["uv", "--project", "here", "run", "x"]
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["uv", "run", "bandit"],
        ["uv", "sync"],
        ["uv", "venv", ".venv"],
        ["uv", "newcmd", "x"],
    ],
    ids=["run", "sync", "venv", "unlisted subcommand"],
)
def test_uv_system_python_is_no_choice_where_uv_does_not_read_it(
    no_operator_choice, monkeypatch, argv
):
    """``UV_SYSTEM_PYTHON`` is the environment form of ``--system``, which only
    the ``uv pip`` family has. A subcommand that does not read it still needs
    ASH's interpreter named: counted as the operator's choice there, ``uv run
    bandit`` got no ``UV_PYTHON`` and ran the scanned tree's own ``.venv``."""
    monkeypatch.setenv("UV_SYSTEM_PYTHON", "1")
    assert uv_child_overrides(argv) == BOTH


def test_uv_system_python_is_a_choice_where_uv_reads_it(
    no_operator_choice, monkeypatch
):
    monkeypatch.setenv("UV_SYSTEM_PYTHON", "1")
    assert uv_child_overrides(["uv", "pip", "install", "x"]) == {"UV_NO_PROJECT": "1"}
    # UV_PYTHON is read by every subcommand.
    monkeypatch.setenv("UV_PYTHON", "/x/py")
    assert uv_child_overrides(["uv", "run", "bandit"]) == {"UV_NO_PROJECT": "1"}


def test_a_path_or_bytes_argument_is_read_as_text_never_raised_on(no_operator_choice):
    """subprocess accepts a Path or bytes anywhere in argv, and plugins put them
    there. The words were compared and ``startswith``-ed as they came, so a
    ``Path`` argument raised AttributeError and a bytes program TypeError out of
    the spawn, recorded as a spawn failure of a command that is fine."""
    path = Path("requirements.txt")
    assert uv_child_overrides(["uv", "pip", "install", "-r", path]) == BOTH
    assert uv_child_overrides([b"uv", "pip", "list"]) == BOTH
    assert uv_child_overrides([Path("/opt/bin/uv"), "run", Path("tool.py")]) == BOTH
    assert (
        uv_child_overrides([sys.executable, "-m", "uv", "pip", "install", path]) == BOTH
    )
    # Not decodable as subprocess would not: no uv command is read.
    assert uv_child_overrides(["uv", "pip", 3]) == {}


def test_a_subcommand_that_runs_no_program_reads_every_argument(no_operator_choice):
    assert "UV_PYTHON" not in uv_child_overrides(
        ["uv", "pip", "install", "bandit", "-p", "3"]
    )
    assert "UV_NO_PROJECT" not in uv_child_overrides(
        ["uv", "sync", "--project", "here"]
    )

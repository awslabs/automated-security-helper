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
  interpreter, yet suppressed UV_PYTHON or UV_NO_PROJECT.

Nothing here starts uv: the function reads argv and the environment only.
"""

from __future__ import annotations

import sys

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


def test_a_subcommand_that_runs_no_program_reads_every_argument(no_operator_choice):
    assert "UV_PYTHON" not in uv_child_overrides(
        ["uv", "pip", "install", "bandit", "-p", "3"]
    )
    assert "UV_NO_PROJECT" not in uv_child_overrides(
        ["uv", "sync", "--project", "here"]
    )

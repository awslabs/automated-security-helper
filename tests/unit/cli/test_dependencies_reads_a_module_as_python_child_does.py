# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The installer reads ``<python> -m uv`` the way ``python_child`` reads it.

``cli/dependencies.py`` kept its own reader of a Python command line's ``-m``
module for the uv overrides, beside ``python_child.python_module_arguments``,
which the uv child's overrides read. Two readers of one grammar drift: a
spelling one accepts (``-muv``, ``-Im uv``, a ``--check-hash-based-pycs`` value
before ``-m``) the other could miss. The installer now asks ``python_child``, so
there is one reader; these cells pin that every spelling reads the same on both
sides and that the installer's answer is python_child's answer.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli import dependencies
from automated_security_helper.utils import python_child

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "options",
    [
        ["-m", "uv", "pip", "install", "x"],
        ["-Im", "uv", "tool", "run", "y"],
        ["-muv", "pip", "install", "x"],
        ["-m", "uv.__main__", "pip", "install", "x"],
        ["-X", "utf8", "-m", "uv", "pip", "install", "x"],
        ["-Xutf8", "-m", "uv", "pip", "install", "x"],
        ["--check-hash-based-pycs", "always", "-m", "uv", "pip", "install", "x"],
        ["-W", "ignore", "-muv", "pip"],
        ["-c", "import uv; uv.main()"],
        ["script.py", "-m", "uv"],
        ["-", "-m", "uv"],
        ["--", "-m", "uv"],
        ["-m", "pip", "install", "uv"],
        ["-m"],
        [],
    ],
)
def test_the_installer_reads_the_module_as_python_child_does(options):
    found = python_child.python_module_arguments(options)
    expected = (
        found[1] if found is not None and found[0] in dependencies._UV_MODULES else None
    )

    assert dependencies._python_module_arguments(list(options)) == expected


def test_a_uv_module_spelling_gives_uvs_arguments():
    """The control: the shared reader is the one that answers, with uv's own
    arguments after the module."""
    assert dependencies._python_module_arguments(["-Im", "uv", "tool", "run", "y"]) == [
        "tool",
        "run",
        "y",
    ]
    assert dependencies._python_module_arguments(["-m", "pip", "install", "uv"]) is None


def test_the_installer_has_no_reader_of_its_own(monkeypatch):
    """Replacing python_child's reader changes the installer's answer: there is
    no second copy left to answer instead."""
    monkeypatch.setattr(
        dependencies,
        "python_module_arguments",
        lambda options: ("uv", ["stood-in"]),
    )

    assert dependencies._python_module_arguments(["-m", "pip"]) == ["stood-in"]

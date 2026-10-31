# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sibling link of the running interpreter is the running interpreter.

The in-tree refusal exempts the Python running ASH, compared by path so that a
tree's venv link to the base interpreter is not mistaken for it. When ASH itself
runs from the tree's venv (installed there as a dev dependency, started through
``<tree>/.venv/bin/python``), a lookup of ``python3`` finds ``<tree>/.venv/bin/python3``,
a link beside it to the same file, which reads the same pyvenv.cfg: it is the
running interpreter under another name. Compared by path alone it was refused,
and the tool read as MISSING. A link in another directory, such as another venv's
link to the base interpreter, stays refused.

The interpreter is stood in for by a file of this test's own, so the host's
Python install is never read or written.
"""

import os

import pytest

from automated_security_helper.utils import subprocess_utils

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="symlinks are the POSIX shape"),
]


@pytest.fixture
def venv(tmp_path, monkeypatch):
    """A venv-shaped directory whose ``python`` is what ASH runs from."""
    base = tmp_path / "base" / "bin" / "python3.12"
    base.parent.mkdir(parents=True)
    base.write_text("#!/bin/sh\n", encoding="utf-8")
    bin_dir = tmp_path / "repo" / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python").symlink_to(base)
    (bin_dir / "python3").symlink_to(base)
    monkeypatch.setattr(subprocess_utils.sys, "executable", str(bin_dir / "python"))
    return tmp_path


def test_the_interpreters_own_path_is_exempt(venv):
    assert subprocess_utils._is_running_interpreter(
        str(venv / "repo" / ".venv" / "bin" / "python")
    )


def test_a_sibling_link_to_the_same_file_is_the_running_interpreter(venv):
    assert subprocess_utils._is_running_interpreter(
        str(venv / "repo" / ".venv" / "bin" / "python3")
    )


def test_another_directorys_link_to_the_base_interpreter_stays_refused(venv):
    other = venv / "repo" / "other" / ".venv" / "bin"
    other.mkdir(parents=True)
    (other / "python").symlink_to(venv / "base" / "bin" / "python3.12")
    assert not subprocess_utils._is_running_interpreter(str(other / "python"))


def test_a_sibling_that_is_another_file_stays_refused(venv):
    tool = venv / "repo" / ".venv" / "bin" / "tool"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    assert not subprocess_utils._is_running_interpreter(str(tool))


def test_a_sibling_name_that_does_not_exist_is_not_the_interpreter(venv):
    assert not subprocess_utils._is_running_interpreter(
        str(venv / "repo" / ".venv" / "bin" / "python3.99")
    )

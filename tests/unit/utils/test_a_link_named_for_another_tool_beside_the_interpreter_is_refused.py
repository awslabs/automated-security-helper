# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only a python-named sibling of the running interpreter is exempt.

When ASH runs from a tree's venv (started through ``<tree>/.venv/bin/python``),
a link beside it that is the same file reads the same pyvenv.cfg, so ``python3``
there is the running interpreter under another name and is exempt from the
in-tree refusal. A link in that directory named for ANOTHER tool, such as
``<tree>/.venv/bin/ruff`` pointing at the interpreter, is not: started under
that name, the interpreter would run with that tool's arguments, and the
function's own description says such a link is refused. Compared by file
identity alone the same-directory arm admitted it.

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
    monkeypatch.setattr(subprocess_utils.sys, "executable", str(bin_dir / "python"))
    return bin_dir, base


def test_a_link_named_for_another_tool_is_refused(venv):
    bin_dir, base = venv
    (bin_dir / "ruff").symlink_to(base)
    assert os.path.samefile(bin_dir / "ruff", bin_dir / "python")
    assert not subprocess_utils._is_running_interpreter(str(bin_dir / "ruff"))


def test_a_tool_name_that_only_starts_with_python_is_refused(venv):
    bin_dir, base = venv
    (bin_dir / "python-lint").symlink_to(base)
    assert not subprocess_utils._is_running_interpreter(str(bin_dir / "python-lint"))


@pytest.mark.parametrize("name", ["python3", "python3.12", "pythonw"])
def test_a_python_named_link_to_the_same_file_stays_exempt(venv, name):
    bin_dir, base = venv
    (bin_dir / name).symlink_to(base)
    assert subprocess_utils._is_running_interpreter(str(bin_dir / name))


def test_a_sibling_named_like_a_non_python_interpreter_is_exempt_beside_it(
    tmp_path, monkeypatch
):
    base = tmp_path / "base" / "bin" / "pypy3.10"
    base.parent.mkdir(parents=True)
    base.write_text("#!/bin/sh\n", encoding="utf-8")
    bin_dir = tmp_path / "repo" / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "pypy3").symlink_to(base)
    (bin_dir / "pypy").symlink_to(base)
    (bin_dir / "ruff").symlink_to(base)
    monkeypatch.setattr(subprocess_utils.sys, "executable", str(bin_dir / "pypy3"))
    assert subprocess_utils._is_running_interpreter(str(bin_dir / "pypy"))
    assert not subprocess_utils._is_running_interpreter(str(bin_dir / "ruff"))

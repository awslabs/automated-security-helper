# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``get_shortest_name`` compares the input to the working directory by path
components, not by text.

With the working directory ``<root>/app`` and the input ``<root>/app-src/f.py``,
the input's text starts with the working directory's text, so the function took
the relative branch and ``Path.relative_to`` raised ValueError. Every scanner that
names its working directory and every converter that names an archive or a
notebook this way failed on such a layout.
"""

from pathlib import Path

import pytest

from automated_security_helper.utils.get_shortest_name import get_shortest_name

pytestmark = pytest.mark.unit


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    cwd = tmp_path / "app"
    sibling = tmp_path / "app-src"
    cwd.mkdir()
    sibling.mkdir()
    (sibling / "f.py").write_text("x = 1\n", encoding="utf-8")
    (cwd / "inside.py").write_text("y = 2\n", encoding="utf-8")
    return cwd, sibling


def test_a_sibling_whose_name_extends_the_cwd_is_not_made_relative(
    tmp_path, monkeypatch
):
    cwd, sibling = _layout(tmp_path)
    monkeypatch.chdir(cwd)

    target = sibling / "f.py"

    # Raised ValueError before the fix: "... is not in the subpath of ...".
    assert get_shortest_name(target) == target.as_posix()


def test_a_file_below_the_cwd_is_still_made_relative(tmp_path, monkeypatch):
    cwd, _ = _layout(tmp_path)
    monkeypatch.chdir(cwd)

    assert get_shortest_name(cwd / "inside.py") == "inside.py"


def test_the_cwd_itself_is_returned_as_given(tmp_path, monkeypatch):
    cwd, _ = _layout(tmp_path)
    monkeypatch.chdir(cwd)

    assert get_shortest_name(cwd) == cwd.as_posix()

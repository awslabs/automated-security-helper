# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``is_inside_tree``: a path that leaves the root through ``..`` is judged by
where it resolves, not by the components it starts with.

``<root>/../elsewhere/tool`` begins with the root's own components, so the
lexical check answered True for a file that is not in the tree, and a tool found
outside the tree was refused as an in-tree one.
"""

from pathlib import Path

import pytest

from automated_security_helper.utils.scanned_tree import is_inside_tree

pytestmark = pytest.mark.unit


@pytest.fixture
def layout(tmp_path):
    root = tmp_path / "tree"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "tool").write_text("", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "tool").write_text("", encoding="utf-8")
    return root, elsewhere


def test_a_path_that_leaves_the_root_through_dot_dot_is_outside(layout):
    root, elsewhere = layout
    spelled_through_root = root / ".." / elsewhere.name / "tool"
    assert spelled_through_root.resolve() == (elsewhere / "tool").resolve()

    assert is_inside_tree(spelled_through_root, root) is False


def test_a_path_that_returns_into_the_root_through_dot_dot_is_inside(layout):
    root, _elsewhere = layout
    assert is_inside_tree(root / "bin" / ".." / "bin" / "tool", root) is True


@pytest.mark.parametrize("steps", [("..",), ("bin", "..", "..")])
def test_the_roots_own_parent_is_outside(layout, steps):
    """``<root>/..`` names the root's parent. Its directory is the root, so the
    spelling with the directory resolved read ``<real root>/..``, which starts
    with the root's components; only the resolved path is asked for a ``..``
    spelling now."""
    root, _elsewhere = layout
    spelled = root.joinpath(*steps)
    assert spelled.resolve() == root.resolve().parent

    assert is_inside_tree(spelled, root) is False


def test_a_dot_dot_that_stays_below_the_root_is_inside(layout):
    root, _elsewhere = layout
    (root / "tool").write_text("", encoding="utf-8")
    assert is_inside_tree(root / "bin" / ".." / "tool", root) is True


def test_a_plain_path_below_the_root_is_inside(layout):
    root, _elsewhere = layout
    assert is_inside_tree(root / "bin" / "tool", root) is True
    assert is_inside_tree(Path(root / "bin" / "tool"), str(root)) is True

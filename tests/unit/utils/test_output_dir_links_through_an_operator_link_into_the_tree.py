# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository link is refused when the output directory is spelled through an
operator link that lands inside the scanned tree.

``linked_output_component`` examines a link on the way to the output directory
only when that component is below ``root``. "Below" was decided by name and by
whether a parent IS the root (by device and inode), so with ``/opt/link`` pointing
at ``<root>/sub`` every component spelled below ``/opt/link`` read as outside the
tree: a link the repository committed at ``<root>/sub/evil`` was stepped through
unexamined, and the output directory it leads to was accepted. The parent is now
also compared with its links resolved, so a component whose real parent is the
root or below it is the tree's and is examined.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    linked_output_component,
    refuse_linked_output_dir,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _tree(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    root = tree / "repo"
    (root / "sub").mkdir(parents=True)
    (tree / "elsewhere").mkdir()
    (tree / "opt").mkdir()
    return tree, root


def test_a_repository_link_behind_an_operator_link_into_the_tree_is_named(tmp_path):
    tree, root = _tree(tmp_path)
    (tree / "opt" / "link").symlink_to(root / "sub")
    (root / "sub" / "evil").symlink_to(tree / "elsewhere")
    output_dir = tree / "opt" / "link" / "evil" / "out"

    found = linked_output_component(root, output_dir)

    assert found is not None
    assert found.startswith(
        f"{(tree / 'opt' / 'link' / 'evil').as_posix()} is a symlink"
    )
    with pytest.raises(OutputDirLinkRefused):
        refuse_linked_output_dir(root, output_dir)


def test_control_the_operator_link_itself_is_not_examined(tmp_path):
    tree, root = _tree(tmp_path)
    (tree / "opt" / "link").symlink_to(root / "sub")
    output_dir = tree / "opt" / "link" / "out"

    assert linked_output_component(root, output_dir) is None


def test_control_an_operator_link_landing_outside_the_tree_is_not_examined(tmp_path):
    tree, root = _tree(tmp_path)
    (tree / "opt" / "link").symlink_to(tree / "elsewhere")
    (tree / "elsewhere" / "hop").symlink_to(tree / "opt")
    output_dir = tree / "opt" / "link" / "hop" / "out"

    assert linked_output_component(root, output_dir) is None

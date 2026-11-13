# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_remove_tree`` on a path that is gone before the delete acts.

The read that decides whether the tree is gone is one guarded ``os.lstat``: a
path the stat cannot reach is gone, and the stat's error never leaves the
function. The test makes the module's ``os.lstat`` raise ``FileNotFoundError``
for the tree, with the tree absent on disk, and reads that the delete answers
True without raising. The last stat the delete makes names the tree, so the
guarded read is the one that answered.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from tests.utils import source_delivery_doubles as doubles

pytestmark = pytest.mark.unit


def _lstat_that_finds_nothing_at(gone: Path, calls: list):
    """An ``os.lstat`` that raises ``FileNotFoundError`` for ``gone`` and reads
    through to the real one for every other path."""

    def lstat(path, *args, **kwargs):
        calls.append(os.fspath(path))
        if os.fspath(path) == os.fspath(gone):
            raise FileNotFoundError(errno.ENOENT, "gone before the delete", str(gone))
        return os.lstat(path, *args, **kwargs)

    return lstat


def test_a_tree_gone_before_the_delete_is_reported_gone(tmp_path, monkeypatch):
    tree = tmp_path / "scratch"
    assert not tree.exists()
    calls: list = []
    monkeypatch.setattr(
        sd,
        "os",
        doubles.ModuleWith(os, lstat=_lstat_that_finds_nothing_at(tree, calls)),
    )

    assert sd._remove_tree(tree) is True

    assert calls, "the delete read the tree's presence through os.lstat"
    assert calls[-1] == str(tree)
    assert not tree.exists()
